Escrow Backend (Postgres + Refresh Tokens) - Demo
------------------------------------------------
This backend demo now uses Postgres for persistence and implements JWT access tokens + refresh tokens stored in the DB.

Setup:
1. Create a Postgres database (local or Docker). Example using psql:
   CREATE DATABASE escrow_demo;
2. Copy `.env.example` to `.env` and fill `DATABASE_URL`, `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`.
3. Install dependencies:
   npm install
4. Run migrations:
   npm run migrate
5. Start server:
   npm start

Notes:
- Access tokens expire in 15 minutes; refresh tokens last 30 days.
- This is still a demo: no production hardening, no rate limiting, and secrets stored in .env.
