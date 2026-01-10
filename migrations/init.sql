-- init.sql - schema for escrow demo
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  phone TEXT,
  kyc_status TEXT DEFAULT 'none',
  created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS listings (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  title TEXT,
  description TEXT,
  price_cents INT,
  currency TEXT DEFAULT 'BRL',
  status TEXT DEFAULT 'active',
  created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS escrows (
  id UUID PRIMARY KEY,
  listing_id UUID REFERENCES listings(id),
  buyer_id UUID REFERENCES users(id),
  seller_id UUID REFERENCES users(id),
  amount_cents INT,
  currency TEXT,
  gateway_hold_id TEXT,
  status TEXT,
  buyer_confirmed BOOLEAN DEFAULT false,
  seller_confirmed BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT now(),
  funded_at TIMESTAMP,
  released_at TIMESTAMP,
  refunded_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
  id UUID PRIMARY KEY,
  escrow_id UUID REFERENCES escrows(id),
  type TEXT,
  amount_cents INT,
  provider_tx_id TEXT,
  created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS disputes (
  id UUID PRIMARY KEY,
  escrow_id UUID REFERENCES escrows(id),
  opened_by UUID REFERENCES users(id),
  reason TEXT,
  evidence JSONB,
  status TEXT,
  resolution TEXT,
  created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token TEXT PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT now()
);
