// Escrow backend with Postgres persistence and refresh tokens
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

/* ===============================
   DATABASE
================================ */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function query(text, params) {
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
}

/* ===============================
   CREATE TABLES
================================ */

async function createTable() {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT,
      phone TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id SERIAL PRIMARY KEY,
      token TEXT NOT NULL,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMP NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS listings (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id),
      title TEXT,
      description TEXT,
      price_cents INTEGER,
      currency TEXT,
      status TEXT
    );
  `);

  console.log("All tables ready");
}

/* ===============================
   AUTH CONFIG
================================ */

const ACCESS_SECRET =
  process.env.JWT_ACCESS_SECRET || 'access_secret_dev';

const REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET || 'refresh_secret_dev';

/* ===============================
   AUTH MIDDLEWARE
================================ */

async function authMiddleware(req, res, next) {

  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer '))
    return res.status(401).json({ error: 'missing_token' });

  try {
    const token = authHeader.split(' ')[1];

    const payload = jwt.verify(token, ACCESS_SECRET);

    const r = await query(
      'SELECT id,email,name FROM users WHERE id=$1',
      [payload.id]
    );

    if (r.rowCount === 0)
      return res.status(401).json({ error: 'invalid_user' });

    req.user = r.rows[0];

    next();

  } catch (err) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

/* ===============================
   AUTH ROUTES
================================ */

// SIGNUP
app.post('/auth/signup', async (req, res) => {

  const { email, password, name, phone } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'email_password_required' });

  const existing = await query(
    'SELECT id FROM users WHERE email=$1',
    [email]
  );

  if (existing.rowCount > 0)
    return res.status(400).json({ error: 'user_exists' });

  const hash = await bcrypt.hash(password, 10);
  const id = uuidv4();

  await query(
    `INSERT INTO users(id,email,password_hash,name,phone)
     VALUES($1,$2,$3,$4,$5)`,
    [id, email, hash, name || null, phone || null]
  );

  const accessToken = jwt.sign({ id }, ACCESS_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ id }, REFRESH_SECRET, { expiresIn: '30d' });

  const exp = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

  await query(
    'INSERT INTO refresh_tokens(token,user_id,expires_at) VALUES($1,$2,$3)',
    [refreshToken, id, exp]
  );

  res.json({
    accessToken,
    refreshToken,
    user: { id, email, name }
  });
});


// LOGIN ✅
app.post('/auth/login', async (req, res) => {

  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'email_password_required' });

  const r = await query(
    'SELECT * FROM users WHERE email=$1',
    [email]
  );

  if (r.rowCount === 0)
    return res.status(401).json({ error: 'invalid_credentials' });

  const user = r.rows[0];

  const validPassword =
    await bcrypt.compare(password, user.password_hash);

  if (!validPassword)
    return res.status(401).json({ error: 'invalid_credentials' });

  const accessToken = jwt.sign(
    { id: user.id },
    ACCESS_SECRET,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { id: user.id },
    REFRESH_SECRET,
    { expiresIn: '30d' }
  );

  const exp = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

  await query(
    'INSERT INTO refresh_tokens(token,user_id,expires_at) VALUES($1,$2,$3)',
    [refreshToken, user.id, exp]
  );

  res.json({
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      email: user.email,
      name: user.name
    }
  });
});

/* ===============================
   PROTECTED TEST ROUTE 🔐
================================ */

app.get('/me', authMiddleware, async (req, res) => {
  res.json({
    message: "Authenticated user",
    user: req.user
  });
});

/* ===============================
   LISTINGS
================================ */

app.post('/listings', authMiddleware, async (req, res) => {

  const { title, description, price_cents, currency } = req.body;

  const id = uuidv4();

  await query(
    `INSERT INTO listings
     VALUES($1,$2,$3,$4,$5,$6,$7)`,
    [
      id,
      req.user.id,
      title,
      description,
      price_cents || 0,
      currency || 'BRL',
      'active'
    ]
  );

  const r = await query(
    'SELECT * FROM listings WHERE id=$1',
    [id]
  );

  res.json(r.rows[0]);
});

app.get('/listings', async (_, res) => {
  const r = await query(
    'SELECT * FROM listings WHERE status=$1',
    ['active']
  );
  res.json(r.rows);
});

/* ===============================
   CURRENT USER (TEST AUTH)
================================ */

app.get('/me', authMiddleware, async (req, res) => {
  res.json({
    message: 'Usuário autenticado ✅',
    user: req.user
  });
});

/* ===============================
   HEALTH CHECK
================================ */

app.get('/_health', (_, res) =>
  res.json({ ok: true, now: new Date() })
);

/* ===============================
   START SERVER
================================ */

async function startServer() {
  try {
    console.log("Preparing database...");
    await createTable();

    app.listen(PORT, () => {
      console.log(`Escrow backend running on port ${PORT}`);
    });

  } catch (err) {
    console.error("Startup error:", err);
    process.exit(1);
  }
}

startServer();
