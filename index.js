// Escrow backend with Postgres persistence and refresh tokens (demo)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});
async function createTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  console.log("Users table ready");
}

createTable();


const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'access_secret_dev';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'refresh_secret_dev';

async function query(text, params) {
  const client = await pool.connect();
  try {
    const res = await client.query(text, params);
    return res;
  } finally {
    client.release();
  }
}

// helpers
async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({error:'no auth'});
  const token = auth.replace('Bearer ','');
  try {
    const payload = jwt.verify(token, ACCESS_SECRET);
    const r = await query('SELECT id, email, name FROM users WHERE id=$1', [payload.id]);
    if (r.rowCount === 0) return res.status(401).json({error:'invalid user'});
    req.user = r.rows[0];
    next();
  } catch(e) {
    return res.status(401).json({error:'invalid token'});
  }
}

// auth
app.post('/auth/signup', async (req,res) => {
  const {email, password, name, phone} = req.body;
  if (!email || !password) return res.status(400).json({error:'email_password_required'});
  const existing = await query('SELECT id FROM users WHERE email=$1', [email]);
  if (existing.rowCount > 0) return res.status(400).json({error:'user_exists'});
  const hash = await bcrypt.hash(password, 10);
  const id = uuidv4();
  await query('INSERT INTO users(id,email,password_hash,name,phone) VALUES($1,$2,$3,$4,$5)', [id,email,hash,name||null,phone||null]);
  const accessToken = jwt.sign({id}, ACCESS_SECRET, {expiresIn: '15m'});
  const refreshToken = jwt.sign({id}, REFRESH_SECRET, {expiresIn: '30d'});
  // store refresh token
  const exp = new Date(Date.now() + 30*24*60*60*1000);
  await query('INSERT INTO refresh_tokens(token,user_id,expires_at) VALUES($1,$2,$3)', [refreshToken,id,exp]);
  res.json({accessToken, refreshToken, user:{id,email,name}});
});

app.post('/auth/login', async (req,res) => {
  const {email, password} = req.body;
  if (!email || !password) return res.status(400).json({error:'email_password_required'});
  const r = await query('SELECT id,password_hash,email,name FROM users WHERE email=$1', [email]);
  if (r.rowCount === 0) return res.status(401).json({error:'invalid_credentials'});
  const user = r.rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({error:'invalid_credentials'});
  const accessToken = jwt.sign({id: user.id}, ACCESS_SECRET, {expiresIn: '15m'});
  const refreshToken = jwt.sign({id: user.id}, REFRESH_SECRET, {expiresIn: '30d'});
  const exp = new Date(Date.now() + 30*24*60*60*1000);
  await query('INSERT INTO refresh_tokens(token,user_id,expires_at) VALUES($1,$2,$3)', [refreshToken,user.id,exp]);
  res.json({accessToken, refreshToken, user:{id:user.id,email:user.email,name:user.name}});
});

// refresh
app.post('/auth/refresh', async (req,res) => {
  const {refreshToken} = req.body;
  if (!refreshToken) return res.status(400).json({error:'refresh_required'});
  try {
    const payload = jwt.verify(refreshToken, REFRESH_SECRET);
    // check token exists in DB
    const r = await query('SELECT token FROM refresh_tokens WHERE token=$1', [refreshToken]);
    if (r.rowCount === 0) return res.status(401).json({error:'invalid_refresh'});
    const accessToken = jwt.sign({id: payload.id}, ACCESS_SECRET, {expiresIn: '15m'});
    res.json({accessToken});
  } catch(e) {
    return res.status(401).json({error:'invalid_refresh'});
  }
});

app.post('/auth/logout', async (req,res) => {
  const {refreshToken} = req.body;
  if (!refreshToken) return res.status(400).json({error:'refresh_required'});
  await query('DELETE FROM refresh_tokens WHERE token=$1', [refreshToken]);
  res.json({success:true});
});

// listings
app.post('/listings', authMiddleware, async (req,res) => {
  const {title, description, price_cents, currency} = req.body;
  const id = uuidv4();
  await query('INSERT INTO listings(id,user_id,title,description,price_cents,currency,status) VALUES($1,$2,$3,$4,$5,$6,$7)', [id, req.user.id, title, description, price_cents||0, currency||'BRL','active']);
  const r = await query('SELECT * FROM listings WHERE id=$1', [id]);
  res.json(r.rows[0]);
});

app.get('/listings', async (req,res) => {
  const r = await query('SELECT * FROM listings WHERE status=$1', ['active']);
  res.json(r.rows);
});

app.get('/listings/:id', async (req,res) => {
  const r = await query('SELECT * FROM listings WHERE id=$1', [req.params.id]);
  if (r.rowCount===0) return res.status(404).json({error:'not_found'});
  res.json(r.rows[0]);
});

// escrows
app.post('/escrow/initiate', authMiddleware, async (req,res) => {
  const {listingId} = req.body;
  const r = await query('SELECT * FROM listings WHERE id=$1', [listingId]);
  if (r.rowCount===0) return res.status(404).json({error:'listing_not_found'});
  const listing = r.rows[0];
  if (listing.user_id === req.user.id) return res.status(400).json({error:'cannot_buy_own'});
  const id = uuidv4();
  await query('INSERT INTO escrows(id,listing_id,buyer_id,seller_id,amount_cents,currency,status) VALUES($1,$2,$3,$4,$5,$6,$7)', [id, listing.id, req.user.id, listing.user_id, listing.price_cents, listing.currency, 'pending']);
  const e = (await query('SELECT * FROM escrows WHERE id=$1', [id])).rows[0];
  res.json(e);
});

app.post('/escrow/fund', authMiddleware, async (req,res) => {
  const {escrowId} = req.body;
  const r = await query('SELECT * FROM escrows WHERE id=$1', [escrowId]);
  if (r.rowCount===0) return res.status(404).json({error:'escrow_not_found'});
  const escrow = r.rows[0];
  if (escrow.buyer_id !== req.user.id) return res.status(403).json({error:'not_buyer'});
  const holdId = 'HOLD_' + uuidv4();
  const now = new Date();
  await query('UPDATE escrows SET gateway_hold_id=$1, status=$2, funded_at=$3 WHERE id=$4', [holdId, 'funded', now, escrowId]);
  const txId = uuidv4();
  await query('INSERT INTO transactions(id,escrow_id,type,amount_cents,provider_tx_id) VALUES($1,$2,$3,$4,$5)', [txId, escrowId, 'hold', escrow.amount_cents, holdId]);
  const updated = (await query('SELECT * FROM escrows WHERE id=$1', [escrowId])).rows[0];
  res.json({success:true, escrow: updated});
});

app.post('/escrow/confirm-delivery', authMiddleware, async (req,res) => {
  const {escrowId} = req.body;
  const r = await query('SELECT * FROM escrows WHERE id=$1', [escrowId]);
  if (r.rowCount===0) return res.status(404).json({error:'escrow_not_found'});
  const escrow = r.rows[0];
  if (escrow.buyer_id !== req.user.id) return res.status(403).json({error:'not_buyer'});
  await query('UPDATE escrows SET buyer_confirmed=true WHERE id=$1', [escrowId]);
  const nowEscrow = (await query('SELECT * FROM escrows WHERE id=$1', [escrowId])).rows[0];
  if (nowEscrow.seller_confirmed && nowEscrow.status === 'funded') {
    const releaseId = 'RELEASE_' + uuidv4();
    await query('UPDATE escrows SET status=$1, released_at=$2 WHERE id=$3', ['released', new Date(), escrowId]);
    await query('INSERT INTO transactions(id,escrow_id,type,amount_cents,provider_tx_id) VALUES($1,$2,$3,$4,$5)', [uuidv4(), escrowId, 'release', nowEscrow.amount_cents, releaseId]);
  }
  res.json({success:true});
});

app.post('/escrow/confirm-release', authMiddleware, async (req,res) => {
  const {escrowId} = req.body;
  const r = await query('SELECT * FROM escrows WHERE id=$1', [escrowId]);
  if (r.rowCount===0) return res.status(404).json({error:'escrow_not_found'});
  const escrow = r.rows[0];
  if (escrow.seller_id !== req.user.id) return res.status(403).json({error:'not_seller'});
  await query('UPDATE escrows SET seller_confirmed=true WHERE id=$1', [escrowId]);
  const nowEscrow = (await query('SELECT * FROM escrows WHERE id=$1', [escrowId])).rows[0];
  if (nowEscrow.buyer_confirmed && nowEscrow.status === 'funded') {
    const releaseId = 'RELEASE_' + uuidv4();
    await query('UPDATE escrows SET status=$1, released_at=$2 WHERE id=$3', ['released', new Date(), escrowId]);
    await query('INSERT INTO transactions(id,escrow_id,type,amount_cents,provider_tx_id) VALUES($1,$2,$3,$4,$5)', [uuidv4(), escrowId, 'release', nowEscrow.amount_cents, releaseId]);
  }
  res.json({success:true});
});

app.post('/escrow/dispute', authMiddleware, async (req,res) => {
  const {escrowId, reason, evidence} = req.body;
  const r = await query('SELECT * FROM escrows WHERE id=$1', [escrowId]);
  if (r.rowCount===0) return res.status(404).json({error:'escrow_not_found'});
  const dId = uuidv4();
  await query('INSERT INTO disputes(id,escrow_id,opened_by,reason,evidence,status) VALUES($1,$2,$3,$4,$5,$6)', [dId, escrowId, req.user.id, reason||'', evidence||null, 'open']);
  await query('UPDATE escrows SET status=$1 WHERE id=$2', ['dispute', escrowId]);
  const d = (await query('SELECT * FROM disputes WHERE id=$1', [dId])).rows[0];
  res.json({success:true, dispute: d});
});

// admin resolve (no auth for demo)
app.post('/admin/resolve', async (req,res) => {
  const {disputeId, action} = req.body;
  const d = (await query('SELECT * FROM disputes WHERE id=$1', [disputeId])).rows[0];
  if (!d) return res.status(404).json({error:'not_found'});
  const escrow = (await query('SELECT * FROM escrows WHERE id=$1', [d.escrow_id])).rows[0];
  if (!escrow) return res.status(404).json({error:'escrow_not_found'});
  if (action === 'refund') {
    await query('UPDATE escrows SET status=$1, refunded_at=$2 WHERE id=$3', ['refunded', new Date(), escrow.id]);
    await query('INSERT INTO transactions(id,escrow_id,type,amount_cents,provider_tx_id) VALUES($1,$2,$3,$4,$5)', [uuidv4(), escrow.id, 'refund', escrow.amount_cents, 'REFUND_'+uuidv4()]);
    await query('UPDATE disputes SET status=$1, resolution=$2 WHERE id=$3', ['resolved','refund', disputeId]);
  } else {
    await query('UPDATE escrows SET status=$1, released_at=$2 WHERE id=$3', ['released', new Date(), escrow.id]);
    await query('INSERT INTO transactions(id,escrow_id,type,amount_cents,provider_tx_id) VALUES($1,$2,$3,$4,$5)', [uuidv4(), escrow.id, 'release', escrow.amount_cents, 'RELEASE_'+uuidv4()]);
    await query('UPDATE disputes SET status=$1, resolution=$2 WHERE id=$3', ['resolved','release', disputeId]);
  }
  res.json({success:true});
});

app.get('/escrows', authMiddleware, async (req,res) => {
  const r = await query('SELECT * FROM escrows WHERE buyer_id=$1 OR seller_id=$1', [req.user.id]);
  res.json(r.rows);
});

app.get('/_health', (req,res) => res.json({ok:true, now: new Date()}));

app.listen(PORT, () => console.log('Escrow backend running on port', PORT));
