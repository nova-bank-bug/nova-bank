require("dotenv").config();
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");

const app = express();
const isProduction = process.env.NODE_ENV === "production";
const port = Number(process.env.PORT || 3000);

if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("Set SESSION_SECRET to a random value at least 32 characters long.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: true }
});

app.set("trust proxy", isProduction ? 1 : false);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: isProduction ? [] : null
    }
  }
}));
app.use(express.json({ limit: "12kb" }));
app.use(express.urlencoded({ extended: false, limit: "12kb" }));

app.use(session({
  store: new PgSession({
    pool,
    tableName: "nova_sessions",
    createTableIfMissing: true
  }),
  name: "nova.demo.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many attempts. Please wait and try again." }
});

function cleanText(value, max = 80) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}
function validUsername(value) {
  return /^[a-z0-9_]{3,24}$/.test(value);
}
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derived) => {
      if (err) return reject(err);
      resolve(`${salt}:${derived.toString("hex")}`);
    });
  });
}
function verifyPassword(password, stored) {
  return new Promise((resolve, reject) => {
    const [salt, key] = String(stored).split(":");
    if (!salt || !key) return resolve(false);
    crypto.scrypt(password, salt, 64, (err, derived) => {
      if (err) return reject(err);
      const expected = Buffer.from(key, "hex");
      resolve(expected.length === derived.length && crypto.timingSafeEqual(expected, derived));
    });
  });
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Please sign in." });
  next();
}
function accountDto(row) {
  return {
    id: row.id,
    username: row.username,
    fullName: row.full_name,
    email: row.email,
    accountNumber: `•••• ${row.account_last4}`,
    balanceKobo: Number(row.balance_kobo),
    createdAt: row.created_at
  };
}
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS nova_users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(24) UNIQUE NOT NULL,
      full_name VARCHAR(55) NOT NULL,
      email VARCHAR(120) NOT NULL,
      password_hash TEXT NOT NULL,
      account_last4 CHAR(4) NOT NULL,
      balance_kobo BIGINT NOT NULL DEFAULT 50000000,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS nova_transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES nova_users(id) ON DELETE CASCADE,
      description VARCHAR(100) NOT NULL,
      details VARCHAR(140) NOT NULL,
      amount_kobo BIGINT NOT NULL,
      kind VARCHAR(3) NOT NULL CHECK (kind IN ('in','out')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS nova_transactions_user_date
      ON nova_transactions(user_id, created_at DESC);
  `);
}

app.get("/api/health", async (_req, res) => {
  try { await pool.query("SELECT 1"); res.json({ ok: true, service: "Nova Bank fictional demo" }); }
  catch { res.status(503).json({ ok: false }); }
});

app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const fullName = cleanText(req.body.fullName, 55);
    const username = cleanText(req.body.username, 24).toLowerCase();
    const email = cleanText(req.body.email, 120).toLowerCase();
    const password = typeof req.body.password === "string" ? req.body.password : "";
    if (!fullName || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: "Enter a name and a valid demo email address." });
    if (!validUsername(username))
      return res.status(400).json({ error: "Username must be 3–24 characters: lowercase letters, numbers or underscores." });
    if (password.length < 10 || password.length > 128)
      return res.status(400).json({ error: "Use a demo password between 10 and 128 characters." });

    const passwordHash = await hashPassword(password);
    const accountLast4 = String(crypto.randomInt(0, 10000)).padStart(4, "0");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `INSERT INTO nova_users (username, full_name, email, password_hash, account_last4)
         VALUES ($1,$2,$3,$4,$5) RETURNING *`,
        [username, fullName, email, passwordHash, accountLast4]
      );
      const user = result.rows[0];
      await client.query(
        `INSERT INTO nova_transactions (user_id, description, details, amount_kobo, kind)
         VALUES ($1,'Welcome demo credit','Fictional starter balance',50000000,'in')`,
        [user.id]
      );
      await client.query("COMMIT");
      req.session.userId = user.id;
      res.status(201).json({ user: accountDto(user) });
    } catch (err) {
      await client.query("ROLLBACK");
      if (err.code === "23505") return res.status(409).json({ error: "That username is already in use." });
      throw err;
    } finally { client.release(); }
  } catch (err) {
    console.error("Registration error:", err.message);
    res.status(500).json({ error: "Could not create the demo account." });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const username = cleanText(req.body.username, 24).toLowerCase();
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const result = await pool.query("SELECT * FROM nova_users WHERE username=$1", [username]);
    const user = result.rows[0];
    const valid = user ? await verifyPassword(password, user.password_hash) : false;
    if (!valid) return res.status(401).json({ error: "Username or password is incorrect." });
    await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
    req.session.userId = user.id;
    res.json({ user: accountDto(user) });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "Could not sign in right now." });
  }
});

app.get("/api/me", requireAuth, async (req, res) => {
  const result = await pool.query("SELECT * FROM nova_users WHERE id=$1", [req.session.userId]);
  if (!result.rows[0]) return req.session.destroy(() => res.status(401).json({ error: "Please sign in." }));
  res.json({ user: accountDto(result.rows[0]) });
});

app.get("/api/transactions", requireAuth, async (req, res) => {
  const result = await pool.query(
    `SELECT id, description, details, amount_kobo, kind, created_at
     FROM nova_transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`,
    [req.session.userId]
  );
  res.json({ transactions: result.rows.map(t => ({
    id: t.id, description: t.description, details: t.details,
    amountKobo: Number(t.amount_kobo), kind: t.kind, createdAt: t.created_at
  })) });
});

app.post("/api/demo-transfer", requireAuth, async (req, res) => {
  const recipient = cleanText(req.body.recipient, 45);
  const reference = cleanText(req.body.reference, 24);
  const note = cleanText(req.body.note, 60);
  const amountNaira = Number(req.body.amountNaira);
  if (!recipient || !reference || !Number.isSafeInteger(amountNaira) || amountNaira < 1 || amountNaira > 100000)
    return res.status(400).json({ error: "Enter valid demo transfer details (maximum ₦100,000)." });
  const amountKobo = amountNaira * 100;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const updated = await client.query(
      `UPDATE nova_users SET balance_kobo=balance_kobo-$1
       WHERE id=$2 AND balance_kobo >= $1 RETURNING id`,
      [amountKobo, req.session.userId]
    );
    if (!updated.rowCount) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Insufficient demo balance." });
    }
    await client.query(
      `INSERT INTO nova_transactions (user_id, description, details, amount_kobo, kind)
       VALUES ($1,$2,$3,$4,'out')`,
      [req.session.userId, `Demo transfer to ${recipient}`, `${note || "Simulated transfer"} · ${reference}`, amountKobo]
    );
    await client.query("COMMIT");
    const balance = await pool.query("SELECT balance_kobo FROM nova_users WHERE id=$1", [req.session.userId]);
    res.json({ ok: true, balanceKobo: Number(balance.rows[0].balance_kobo) });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Transfer error:", err.message);
    res.status(500).json({ error: "Could not complete the demo transfer." });
  } finally { client.release(); }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: "Could not sign out." });
    res.clearCookie("nova.demo.sid", { httpOnly: true, sameSite: "strict", secure: isProduction });
    res.json({ ok: true });
  });
});

app.use(express.static(path.join(__dirname, "public")));
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Something went wrong." });
});

initDb().then(() => {
  app.listen(port, () => console.log(`Nova Bank demo running on port ${port}`));
}).catch(err => {
  console.error("Database initialization failed:", err);
  process.exit(1);
});
