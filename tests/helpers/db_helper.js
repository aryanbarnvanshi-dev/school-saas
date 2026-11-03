/**
 * School SaaS E2E Test Suite - Database Fixtures & Helper
 * Loads environment variables and provides pool helpers for test verification & cleanup.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const util = require('util');
const { Pool } = require('pg');

const scryptAsync = util.promisify(crypto.scrypt);

// Load environment variables from project root .env if not already loaded
const envFilePath = path.join(__dirname, '..', '..', '.env');
if (fs.existsSync(envFilePath)) {
  const envContent = fs.readFileSync(envFilePath, 'utf8');
  envContent.split(/\r?\n/).forEach((line) => {
    line = line.trim();
    if (!line || line.startsWith('#')) return;
    const eqIdx = line.indexOf('=');
    if (eqIdx !== -1) {
      const key = line.substring(0, eqIdx).trim();
      const val = line.substring(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
      if (!process.env[key]) {
        process.env[key] = val;
      }
    }
  });
}

const DATABASE_URL = process.env.DATABASE_URL;

let testPool = null;

function getDbPool() {
  if (!testPool && DATABASE_URL) {
    testPool = new Pool({
      connectionString: DATABASE_URL,
      ssl: { rejectUnauthorized: true },
      max: 3,
      idleTimeoutMillis: 10000,
    });
  }
  return testPool;
}

async function query(sql, params = []) {
  const p = getDbPool();
  if (!p) throw new Error('DATABASE_URL not configured for tests.');
  return await p.query(sql, params);
}

async function closeDbPool() {
  if (testPool) {
    await testPool.end();
    testPool = null;
  }
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = await scryptAsync(password, salt, 64);
  return `scrypt:${salt}:${derivedKey.toString('hex')}`;
}

// Known fixtures in Neon DB
const FIXTURES = {
  SUPER_ADMIN: {
    username: 'superadmin',
    email: 'aryanbarnvanshi@gmail.com',
    password: process.env.SUPER_ADMIN_PASSWORD || 'SuperAdmin@2026',
    role: 'super_admin',
  },
  TENANTS: {
    DPS: {
      id: '9f025e7d-a42c-4c8e-8ea6-c9a8d9c02442',
      name: 'Delhi Public School',
      slug: 'dps-delhi',
    },
    RKM: {
      id: 'a49a7378-aedc-4153-bba8-594a612b473a',
      name: 'R K MISSION PUBLIC SCHOOL',
      slug: 'rkmps',
    },
    ST_XAVIER: {
      id: 'e898fee3-547c-49ad-b08a-d536054d7413',
      name: 'St. Xavier International',
      slug: 'stxavier',
    },
  },
  TEST_ADMIN_DPS: {
    username: 'dps_admin_test',
    email: 'dps_admin_test@campusdesk.site',
    password: 'TestAdmin@2026',
    role: 'admin',
    tenant_id: '9f025e7d-a42c-4c8e-8ea6-c9a8d9c02442',
  },
  TEST_ADMIN_RKM: {
    username: 'rkm_admin_test',
    email: 'rkm_admin_test@campusdesk.site',
    password: 'TestAdmin@2026',
    role: 'admin',
    tenant_id: 'a49a7378-aedc-4153-bba8-594a612b473a',
  },
};

/**
 * Ensure deterministic test admin users exist in DB for multi-tenant isolation testing
 */
async function ensureTestUsers() {
  const testUsers = [FIXTURES.TEST_ADMIN_DPS, FIXTURES.TEST_ADMIN_RKM];

  for (const u of testUsers) {
    const existing = await query(
      'SELECT id FROM cms_users WHERE LOWER(email) = $1 OR LOWER(username) = $2 LIMIT 1',
      [u.email.toLowerCase(), u.username.toLowerCase()]
    );

    const hashed = await hashPassword(u.password);
    if (existing.rows.length === 0) {
      await query(
        `INSERT INTO cms_users (tenant_id, username, email, password_hash, role, is_active, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())`,
        [u.tenant_id, u.username, u.email, hashed, u.role]
      );
    } else {
      // Ensure password hash is fresh and active
      await query(
        `UPDATE cms_users SET password_hash = $1, tenant_id = $2, role = $3, is_active = true WHERE id = $4`,
        [hashed, u.tenant_id, u.role, existing.rows[0].id]
      );
    }
  }
}

module.exports = {
  getDbPool,
  query,
  closeDbPool,
  hashPassword,
  FIXTURES,
  ensureTestUsers,
};
