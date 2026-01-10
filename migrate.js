// Simple migration runner. Run with: node migrate.js
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const sql = fs.readFileSync(path.join(__dirname, 'migrations', 'init.sql')).toString();
const pool = new Pool({connectionString: process.env.DATABASE_URL});

(async () => {
  try {
    const client = await pool.connect();
    await client.query(sql);
    console.log('Migrations applied');
    client.release();
    process.exit(0);
  } catch (e) {
    console.error('Migration error', e);
    process.exit(1);
  }
})();
