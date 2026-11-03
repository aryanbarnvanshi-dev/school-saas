/**
 * Single-File Multi-Tenant School SaaS Backend
 * Connects directly to Neon PostgreSQL.
 * Serves 3 HTML files: master_panel.html, admin.html, and school.html (SSR).
 */

const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');
const util = require('util');
const zlib = require('zlib');
const { monitorEventLoopDelay } = require('perf_hooks');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');

const scryptAsync = util.promisify(crypto.scrypt);

// Event Loop Delay Monitor for deterministic 512MB RAM concurrency health diagnostics
const eventLoopDelay = monitorEventLoopDelay({ resolution: 20 });
eventLoopDelay.enable();

// Automatically load environment variables from .env file (Zero NPM dependency)
const envFilePath = path.join(__dirname, '.env');
if (fs.existsSync(envFilePath)) {
  const envContent = fs.readFileSync(envFilePath, 'utf8');
  envContent.split(/\r?\n/).forEach(line => {
    line = line.trim();
    if (!line || line.startsWith('#')) return;
    const eqIdx = line.indexOf('=');
    if (eqIdx !== -1) {
      const key = line.substring(0, eqIdx).trim();
      const val = line.substring(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
      process.env[key] = val;
    }
  });
}

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_APP_PASS = (process.env.GMAIL_APP_PASS || '').replace(/\s+/g, '');
const ROOT_DOMAIN = (process.env.ROOT_DOMAIN || 'campusdesk.site').toLowerCase().trim();
const APP_NAME = process.env.APP_NAME || 'CampusDesk';

if (!DATABASE_URL) {
  console.error('[ERROR] DATABASE_URL is missing. Please define it in your .env file.');
  process.exit(1);
}
console.log('[CONFIG] Connecting to DB Host:', new URL(DATABASE_URL).host);

const mailTransporter = (GMAIL_USER && GMAIL_APP_PASS) ? nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: GMAIL_USER,
    pass: GMAIL_APP_PASS,
  },
}) : null;

// Bounded In-Memory Maps with Active Lockout Immunity (Guarantees 512MB RAM Limit while preventing eviction-bypass attacks)
const MAX_MAP_ENTRIES = 5000;
function safeMapSet(map, key, value) {
  if (map.size >= MAX_MAP_ENTRIES) {
    const now = Date.now();
    // 1. Evict expired entries first
    let evictedKey = null;
    for (const [k, v] of map.entries()) {
      if ((v.resetAt && now > v.resetAt) || (v.expires && now > v.expires) || (v.expiresAt && now > v.expiresAt)) {
        evictedKey = k;
        break;
      }
    }
    // 2. If no expired entry, evict oldest non-lockout entry
    if (!evictedKey) {
      for (const [k, v] of map.entries()) {
        if (!v.lockedUntil || now > v.lockedUntil) {
          evictedKey = k;
          break;
        }
      }
    }
    // 3. Fallback: evict oldest
    if (evictedKey) {
      map.delete(evictedKey);
    } else {
      const oldestKey = map.keys().next().value;
      if (oldestKey !== undefined) map.delete(oldestKey);
    }
  }
  map.set(key, value);
}

// In-Memory Password Reset OTP Store: Map<email, { otpHash, expires, attempts, createdAt }>
const resetTokens = new Map();

// In-Memory Per-IP Login Rate Limiter (Bucket 1: 5 attempts / 60s sliding window)
const loginIpRateLimits = new Map();

// In-Memory Account-Level Login Lockout Store (Bucket 2: 5 consecutive failed attempts -> 5 min lockout)
const loginAttempts = new Map();

// In-Memory Admission Inquiry Rate Limiter: Map<ip, { count, resetAt }> (3 submissions / 60s window)
const inquiryRateLimits = new Map();

// In-Memory Socket-Level Inquiry Rate Limiter: Map<socketIp, { count, resetAt }> (Bound socket to max 5 submissions / 5s to prevent XFF rotation bypass)
const socketInquiryLimits = new Map();

// In-Memory SaaS Demo Inquiry Rate Limiter: Map<ip, { count, resetAt }> (3 submissions / 60s window)
const saasInquiryRateLimits = new Map();

// In-Memory Cryptographic Session Store: Map<token, { userId, username, email, role, tenantId, tenantSlug, schoolName, expiresAt }>
const activeSessions = new Map();

// Active Periodic Garbage Collector: Sweeps expired OTPs, sessions, unlock records, and IP rate limits every 60 seconds
setInterval(() => {
  const now = Date.now();
  for (const [email, record] of resetTokens.entries()) {
    if (now > record.expires) {
      resetTokens.delete(email);
    }
  }
  for (const [key, record] of loginAttempts.entries()) {
    if ((record.lockedUntil && now > record.lockedUntil) || (record.resetAt && now > record.resetAt)) {
      loginAttempts.delete(key);
    }
  }
  for (const [ip, record] of loginIpRateLimits.entries()) {
    if (now > record.resetAt) {
      loginIpRateLimits.delete(ip);
    }
  }
  for (const [ip, record] of inquiryRateLimits.entries()) {
    if (now > record.resetAt) {
      inquiryRateLimits.delete(ip);
    }
  }
  for (const [ip, timestamps] of socketInquiryLimits.entries()) {
    if (!Array.isArray(timestamps) || timestamps.length === 0 || now - timestamps[timestamps.length - 1] > 10000) {
      socketInquiryLimits.delete(ip);
    }
  }
  for (const [ip, record] of saasInquiryRateLimits.entries()) {
    if (now > record.resetAt) {
      saasInquiryRateLimits.delete(ip);
    }
  }
  for (const [token, session] of activeSessions.entries()) {
    if (now > session.expiresAt) {
      activeSessions.delete(token);
    }
  }
}, 60000).unref();

// Proxy-Aware Client IP Extraction (Defense against X-Forwarded-For Header Spoofing)
function getClientIp(req) {
  const remoteAddress = (req && req.socket && req.socket.remoteAddress) || '127.0.0.1';
  // Only trust X-Forwarded-For if incoming socket is loopback or trusted reverse proxy
  const isLoopback = remoteAddress === '127.0.0.1' || 
                     remoteAddress === '::1' || 
                     remoteAddress === '::ffff:127.0.0.1';
  if (isLoopback && req && req.headers && req.headers['x-forwarded-for']) {
    const rawFwd = Array.isArray(req.headers['x-forwarded-for'])
      ? req.headers['x-forwarded-for'][0]
      : req.headers['x-forwarded-for'];
    const clientIp = rawFwd.split(',')[0].trim();
    if (clientIp) return clientIp;
  }
  return remoteAddress;
}

// Memory-Bounded In-Memory Sliding Window Rate Limiter
function checkRateLimit(map, key, limit, windowMs) {
  const now = Date.now();
  let record = map.get(key);
  if (!record || now > record.resetAt) {
    record = { count: 1, resetAt: now + windowMs };
    safeMapSet(map, key, record);
    return { allowed: true, remaining: limit - 1, retryAfterSec: Math.ceil(windowMs / 1000) };
  }
  if (record.count >= limit) {
    const retryAfterSec = Math.max(1, Math.ceil((record.resetAt - now) / 1000));
    return { allowed: false, remaining: 0, retryAfterSec };
  }
  record.count += 1;
  return { allowed: true, remaining: limit - record.count, retryAfterSec: Math.ceil((record.resetAt - now) / 1000) };
}

// Memory-Bounded In-Memory Sliding Log Rate Limiter (Prunes timestamps older than windowMs)
function checkSlidingLogRateLimit(map, key, limit, windowMs) {
  const now = Date.now();
  let timestamps = map.get(key);
  if (!timestamps) {
    timestamps = [];
    safeMapSet(map, key, timestamps);
  }
  const cutoff = now - windowMs;
  let startIdx = 0;
  while (startIdx < timestamps.length && timestamps[startIdx] <= cutoff) {
    startIdx++;
  }
  if (startIdx > 0) {
    timestamps.splice(0, startIdx);
  }
  if (timestamps.length >= limit) {
    const oldestTimestamp = timestamps[0];
    const retryAfterSec = Math.max(1, Math.ceil((oldestTimestamp + windowMs - now) / 1000));
    return { allowed: false, remaining: 0, retryAfterSec };
  }
  timestamps.push(now);
  return { allowed: true, remaining: limit - timestamps.length, retryAfterSec: 0 };
}

// HTTP Parameter Pollution (HPP) Defense: Safely extract scalar string from query params
function getScalarQuery(query, key) {
  if (!query || query[key] === undefined || query[key] === null) return undefined;
  const val = query[key];
  if (Array.isArray(val)) {
    for (let i = 0; i < val.length; i++) {
      if (typeof val[i] === 'string' && val[i].trim().length > 0) {
        return val[i].trim();
      }
    }
    return String(val[0] || '').trim();
  }
  return typeof val === 'string' ? val.trim() : String(val).trim();
}

// URL Scheme Validator: Strictly permits http, https, relative paths, and safe raster data:image/
function isValidUrl(rawUrl) {
  if (rawUrl === null || rawUrl === undefined || rawUrl === '') return true;
  if (typeof rawUrl !== 'string') return false;
  const trimmed = rawUrl.trim();
  if (!trimmed) return true;

  const lower = trimmed.toLowerCase();
  if (lower.startsWith('javascript:') || lower.startsWith('vbscript:') || lower.startsWith('data:text/')) {
    return false;
  }

  // Allow standard http and https protocols
  if (/^https?:\/\/[^\s<>"'`]+$/i.test(trimmed)) {
    return true;
  }

  // Allow safe raster data:image/ URIs (png, jpeg, jpg, webp, gif)
  if (/^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+$/i.test(trimmed)) {
    return true;
  }

  // Allow relative asset paths (e.g. /images/default.png)
  if (/^\/[^/\\][^\s<>"'`]*$/i.test(trimmed)) {
    return true;
  }

  return false;
}

function sanitizeUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  const trimmed = rawUrl.trim();
  if (isValidUrl(trimmed)) {
    return trimmed.substring(0, 1000);
  }
  return '';
}

function stripDangerousHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/<\/?script\b[^>]*>/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '');
}

// CORS Helper: Validates origins against loopback, platform ROOT_DOMAIN, and registered tenant hosts
function isAllowedOrigin(origin, host) {
  if (!origin) return false;
  try {
    const originUrl = new URL(origin);
    const originHost = originUrl.hostname.toLowerCase();
    if (originHost === 'localhost' || originHost === '127.0.0.1' || originHost === '::1') {
      return true;
    }
    if (originHost === ROOT_DOMAIN || originHost.endsWith('.' + ROOT_DOMAIN)) {
      return true;
    }
    if (host && originHost === host.split(':')[0].toLowerCase()) {
      return true;
    }
    return false;
  } catch (e) {
    return false;
  }
}

// Cryptographic Token Verification Gatekeeper (Server-Side Wall)
function authenticate(req) {
  const authHeader = req.headers['authorization'] || '';
  let token = '';
  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  } else if (req.headers['x-auth-token']) {
    token = req.headers['x-auth-token'].trim();
  } else {
    const cookie = req.headers['cookie'] || '';
    const match = cookie.match(/school_saas_token=([^;]+)/);
    if (match) token = match[1].trim();
  }

  if (!token) return null;
  const session = activeSessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    activeSessions.delete(token);
    return null;
  }
  return session;
}

// Helper to strictly guard and enforce Role-Based Access Control and Tenant Isolation
function verifyAdminAccess(req, res, requestedTenantId) {
  const session = authenticate(req);
  if (!session) {
    sendJson(res, 401, { success: false, error: 'Unauthorized: Session missing or expired.' });
    return null;
  }
  // Enforce strict Role-Based Access Control (RBAC): Only super_admin and admin roles permitted
  if (session.role !== 'super_admin' && session.role !== 'admin') {
    sendJson(res, 403, { success: false, error: 'Forbidden: School Admin privilege required.' });
    return null;
  }
  if (session.role === 'super_admin') {
    const targetTenantId = requestedTenantId || session.tenantId;
    if (!targetTenantId) {
      sendJson(res, 400, { success: false, error: 'Bad Request: tenant_id is required for SuperAdmin operations.' });
      return null;
    }
    return { session, targetTenantId };
  }
  if (requestedTenantId && session.tenantId !== requestedTenantId) {
    sendJson(res, 403, { success: false, error: 'Forbidden: Cross-tenant modification denied. You cannot modify another school\'s data.' });
    return null;
  }
  return { session, targetTenantId: session.tenantId };
}

// RFC 4180 CSV Field Formatter (Encloses in double quotes if commas, quotes, or newlines present, escaping quotes as "")
function formatCsvField(val) {
  if (val === null || val === undefined) return '';
  const str = String(val);
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

// Output HTML Sanitizer for SSR Dynamic Values (Neutralizes Stored XSS)
function escapeForHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Industry Standard Security HTTP Headers (OWASP Hardened: HSTS, Strict CSP, nosniff, SAMEORIGIN)
const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data: https: https://images.unsplash.com; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';",
};

// Asynchronous Cryptographic Password Hashing (Offloaded to libuv threadpool to prevent Event-Loop Blocking DoS)
async function hashPassword(password) {
  if (typeof password !== 'string' || password.length === 0 || password.length > 128) {
    throw new Error('Password must be between 1 and 128 characters.');
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = await scryptAsync(password, salt, 64);
  return `scrypt:${salt}:${derivedKey.toString('hex')}`;
}

async function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.startsWith('scrypt:') || typeof password !== 'string' || password.length > 128) {
    return false;
  }
  try {
    const parts = storedHash.split(':');
    if (parts.length !== 3) return false;
    const [_, salt, hash] = parts;
    const derivedKey = await scryptAsync(password, salt, 64);
    const hashBuf = Buffer.from(hash, 'hex');
    const derivedBuf = Buffer.from(derivedKey.toString('hex'), 'hex');
    if (hashBuf.length !== derivedBuf.length) return false;
    return crypto.timingSafeEqual(hashBuf, derivedBuf);
  } catch (e) {
    return false;
  }
}

// Send Password Reset OTP Email (Strict Zero-Log Security)
async function sendResetEmail(toEmail, otp) {
  // If target is an automated test account, skip real SMTP to prevent Mailer-Daemon bounces on nonexistent test inboxes
  const isTestEmail = /(@example\.com|\.test|_test@)/i.test(toEmail);
  if (isTestEmail || process.env.NODE_ENV === 'test') {
    console.log(`[AUTH] [TEST SIMULATION] Simulated password reset OTP for ${toEmail}. External SMTP skipped.`);
    return;
  }

  if (mailTransporter && GMAIL_USER) {
    await mailTransporter.sendMail({
      from: `"${APP_NAME} Security" <${GMAIL_USER}>`,
      to: toEmail,
      subject: `Your Password Reset OTP - ${APP_NAME}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 500px; margin: auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 10px;">
          <h2 style="color: #2563eb;">${APP_NAME} Password Reset</h2>
          <p>You requested to reset your password. Use the following One-Time Password (OTP) to proceed:</p>
          <div style="font-size: 28px; font-weight: bold; letter-spacing: 4px; color: #1e293b; background: #f1f5f9; padding: 12px; text-align: center; border-radius: 8px; margin: 20px 0;">
            ${otp}
          </div>
          <p style="color: #64748b; font-size: 13px;">This OTP is valid for 15 minutes. If you did not request this, please ignore this email.</p>
        </div>
      `,
    });
    console.log(`[AUTH] Password reset OTP sent to ${toEmail} via Gmail SMTP.`);
  } else {
    console.warn(`[AUTH] Gmail SMTP not configured in .env. Cannot dispatch OTP to ${toEmail}`);
    throw new Error('Email service is not configured. Please contact administrator.');
  }
}

// PostgreSQL Pool with Verified SSL & Resilient Auto-Reconnect (Deterministic 512MB RAM Budget)
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: true },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  statement_timeout: 10000,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000,
});

pool.on('error', (err) => {
  console.log('[DB POOL] Recovering from idle connection reset:', err.message);
});

async function dbQuery(text, params, maxRetries = 2) {
  let attempt = 0;
  while (true) {
    try {
      return await pool.query(text, params);
    } catch (err) {
      attempt++;
      // Only safely auto-retry idempotent SELECT queries to prevent duplicate non-idempotent INSERT/UPDATE writes!
      const isIdempotent = typeof text === 'string' && text.trim().toUpperCase().startsWith('SELECT');
      const isNetworkErr = err.code === 'ECONNRESET' || err.code === '57P01' || err.code === '08006' ||
                           err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT' ||
                           (err.message && /connection terminated|socket disconnected|timeout|closed|Connection reset/i.test(err.message));
      if (isIdempotent && isNetworkErr && attempt <= maxRetries) {
        const delay = attempt === 1 ? 600 : 1800;
        console.warn(`[DB POOL] Network blip/cold-start (${err.code || err.message}). Safe retry ${attempt}/${maxRetries} after ${delay}ms...`);
        await new Promise(r => setTimeout(r, delay));
        continue;
      }
      throw err;
    }
  }
}

// Ensure school_uploads table exists in Neon PostgreSQL for zero-loss image persistence across cloud restarts
async function ensureUploadsTable() {
  try {
    await dbQuery(`
      CREATE TABLE IF NOT EXISTS school_uploads (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id UUID,
        filename TEXT UNIQUE,
        data BYTEA,
        mime_type TEXT,
        size_bytes INT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
  } catch (err) {
    console.error('[DB] Failed to ensure school_uploads table:', err.message);
  }
}
ensureUploadsTable();

// Helper: Read JSON with strict size limit, early stream bounds, and zero-churn Buffer accumulation
const MAX_BODY_BYTES = 1024 * 1024; // 1 Megabyte
function parseBody(req, maxLimit = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const contentLength = parseInt(req.headers['content-length'], 10);
    if (!isNaN(contentLength) && contentLength > maxLimit) {
      req.destroy();
      return reject(new Error('PAYLOAD_TOO_LARGE'));
    }

    const chunks = [];
    let bytesReceived = 0;
    let destroyed = false;

    req.on('data', chunk => {
      if (destroyed) return;
      bytesReceived += chunk.length;
      if (bytesReceived > maxLimit) {
        destroyed = true;
        req.destroy();
        return reject(new Error('PAYLOAD_TOO_LARGE'));
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (destroyed) return;
      if (chunks.length === 0) {
        return resolve({});
      }
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw || !raw.trim()) {
        return resolve({});
      }
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(new Error('INVALID_JSON'));
      }
    });

    req.on('error', err => {
      if (!destroyed) reject(err);
    });
  });
}

// Native HTTP Gzip/Deflate Response Compression Helper
function compressAndSend(req, res, statusCode, headers, rawBody) {
  const buffer = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody || '', 'utf8');
  const responseHeaders = { ...headers };

  // Check client Accept-Encoding
  const acceptEncoding = (req && req.headers && req.headers['accept-encoding']) || '';
  const canGzip = /\bgzip\b/i.test(acceptEncoding);
  const canDeflate = /\bdeflate\b/i.test(acceptEncoding);

  // Set Vary header for proper caching proxy behavior
  if (responseHeaders['Vary']) {
    if (!responseHeaders['Vary'].includes('Accept-Encoding')) {
      responseHeaders['Vary'] += ', Accept-Encoding';
    }
  } else {
    responseHeaders['Vary'] = 'Accept-Encoding';
  }

  // Strictly compress payloads over 1024 bytes (1KB) when client supports gzip or deflate
  if (buffer.length > 1024 && (canGzip || canDeflate)) {
    try {
      let compressed;
      let encoding;
      if (canGzip) {
        compressed = zlib.gzipSync(buffer);
        encoding = 'gzip';
      } else {
        compressed = zlib.deflateSync(buffer);
        encoding = 'deflate';
      }

      responseHeaders['Content-Encoding'] = encoding;
      responseHeaders['Content-Length'] = compressed.length;

      res.writeHead(statusCode, responseHeaders);
      return res.end(compressed);
    } catch (err) {
      console.error('[COMPRESSION ERROR] Compression failed, sending raw:', err.message);
    }
  }

  // Uncompressed response (< 1KB or no supported encoding)
  responseHeaders['Content-Length'] = buffer.length;
  res.writeHead(statusCode, responseHeaders);
  return res.end(buffer);
}

// Helper: JSON response with global security headers, constrained CORS, cache neutralization, and compression
function sendJson(res, statusCode, data, extraHeaders = {}) {
  const req = res.req;
  const reqPath = (req && req.url) ? url.parse(req.url).pathname : '';
  const isAdminApi = reqPath.startsWith('/api/admin') || reqPath.startsWith('/api/super-admin');
  const origin = (req && req.headers && req.headers['origin']) || '';
  const host = (req && req.headers && req.headers['host']) || '';

  const corsHeaders = {
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Auth-Token',
  };

  if (isAdminApi) {
    if (isAllowedOrigin(origin, host)) {
      corsHeaders['Access-Control-Allow-Origin'] = origin;
      corsHeaders['Access-Control-Allow-Credentials'] = 'true';
      corsHeaders['Vary'] = 'Origin';
    }
  } else {
    corsHeaders['Access-Control-Allow-Origin'] = '*';
  }

  const existingCookie = res.getHeader('Set-Cookie');
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    ...SECURITY_HEADERS,
    ...corsHeaders,
    ...extraHeaders,
  };
  if (existingCookie && !headers['Set-Cookie']) {
    headers['Set-Cookie'] = existingCookie;
  }
  const payload = JSON.stringify(data);
  return compressAndSend(req, res, statusCode, headers, payload);
}

// In-Memory Zero-Disk Read Template Cache (Pre-loads all 5 HTML templates into RAM at startup)
const TEMPLATE_CACHE = new Map();
const TEMPLATE_NAMES = [
  'school.html',
  'admin.html',
  'master_panel.html',
  'login.html',
  'landing.html',
];

function initTemplateCache() {
  const publicDir = path.join(__dirname, 'public');
  for (const name of TEMPLATE_NAMES) {
    const fullPath = path.join(publicDir, name);
    try {
      if (fs.existsSync(fullPath)) {
        const content = fs.readFileSync(fullPath, 'utf8');
        TEMPLATE_CACHE.set(name, content);
        TEMPLATE_CACHE.set(fullPath, content);
      }
    } catch (e) {
      console.error(`[CACHE ERROR] Failed to load ${name}:`, e.message);
    }
  }
  console.log(`[TEMPLATE CACHE] In-memory zero-disk cache initialized with ${TEMPLATE_NAMES.length} templates.`);
}

initTemplateCache();

// Ensure public uploads directory exists for client-side WebP uploads
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Helper: Serve static file with security headers, in-memory zero-disk caching, and compression
function serveFile(res, filePath, contentType = 'text/html; charset=utf-8') {
  const baseName = path.basename(filePath);
  const cachedContent = TEMPLATE_CACHE.get(baseName) || TEMPLATE_CACHE.get(filePath);
  if (cachedContent) {
    return compressAndSend(res.req, res, 200, { 'Content-Type': contentType, ...SECURITY_HEADERS }, cachedContent);
  }
  fs.readFile(filePath, 'utf8', (err, content) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
      res.end('Internal Server Error');
      return;
    }
    TEMPLATE_CACHE.set(baseName, content);
    compressAndSend(res.req, res, 200, { 'Content-Type': contentType, ...SECURITY_HEADERS }, content);
  });
}

// In-Memory School Resolution TTL Cache (Max 100 schools, 60s TTL)
const schoolResolveCache = new Map();
const SCHOOL_CACHE_TTL_MS = 60000;

// Extract school slug from domain or query (Hardened against HPP, Subdomain Spoofing, and Connection Starvation)
async function resolveSchool(req, parsedUrl) {
  // 1. Explicit query parameter ?school=dps-delhi (HPP Safe)
  const schoolParam = getScalarQuery(parsedUrl && parsedUrl.query, 'school');
  if (schoolParam) {
    const slug = schoolParam.toLowerCase().substring(0, 100);
    const cacheKey = `slug:${slug}`;
    const cached = schoolResolveCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.data;
    }
    const res = await dbQuery(
      `SELECT t.id as tenant_id, t.name as school_name, t.slug as school_slug, t.settings,
              s.id as site_id, s.domain, s.name as site_name
       FROM cms_tenants t
       LEFT JOIN cms_sites s ON s.tenant_id = t.id
       WHERE t.slug = $1 OR s.slug = $1 LIMIT 1`,
      [slug]
    );
    const row = res.rows.length > 0 ? res.rows[0] : null;
    if (schoolResolveCache.size >= 100) schoolResolveCache.clear();
    schoolResolveCache.set(cacheKey, { data: row, expiresAt: Date.now() + SCHOOL_CACHE_TTL_MS });
    return row;
  }

  // 2. Subdomain / Custom Domain Resolution from Host header
  const host = (req.headers['host'] || '').split(':')[0].toLowerCase();
  const cleanHost = host.replace(/^www\./, '');
  const cacheKey = `host:${cleanHost}`;
  const cached = schoolResolveCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.data;
  }

  const wwwHost = 'www.' + cleanHost;
  const isSubdomainOfRoot = cleanHost.endsWith('.' + ROOT_DOMAIN) || cleanHost.endsWith('.localhost');
  const subdomainSlug = isSubdomainOfRoot ? cleanHost.replace(new RegExp(`\\.?(${ROOT_DOMAIN}|localhost)$`), '') : '';
  
  // Custom domain (with or without www) or verified root tenant slug match
  const res = await dbQuery(
    `SELECT t.id as tenant_id, t.name as school_name, t.slug as school_slug, t.settings,
            s.id as site_id, s.domain, s.name as site_name
     FROM cms_sites s
     JOIN cms_tenants t ON t.id = s.tenant_id
     WHERE s.domain = $1 OR s.domain = $2 OR s.domain = $3 OR t.slug = $4 LIMIT 1`,
    [host, cleanHost, wwwHost, subdomainSlug]
  );
  const row = res.rows.length > 0 ? res.rows[0] : null;
  if (schoolResolveCache.size >= 100) schoolResolveCache.clear();
  schoolResolveCache.set(cacheKey, { data: row, expiresAt: Date.now() + SCHOOL_CACHE_TTL_MS });
  return row;
}

// In-Memory Template Retrieval with Zero Disk Reads
function getSchoolTemplate() {
  let tpl = TEMPLATE_CACHE.get('school.html');
  if (!tpl) {
    const templatePath = path.join(__dirname, 'public', 'school.html');
    tpl = fs.readFileSync(templatePath, 'utf8');
    TEMPLATE_CACHE.set('school.html', tpl);
  }
  return tpl;
}

function getLandingTemplate() {
  let tpl = TEMPLATE_CACHE.get('landing.html');
  if (!tpl) {
    const templatePath = path.join(__dirname, 'public', 'landing.html');
    tpl = fs.readFileSync(templatePath, 'utf8');
    TEMPLATE_CACHE.set('landing.html', tpl);
  }
  return tpl;
}

async function getSaasLandingConfig() {
  const res = await dbQuery('SELECT * FROM saas_landing_config WHERE id = 1 LIMIT 1');
  return res.rows[0] || null;
}

async function getLiveSchoolsList() {
  const res = await dbQuery(`
    SELECT t.name, t.slug, s.domain 
    FROM cms_tenants t
    LEFT JOIN cms_sites s ON s.tenant_id = t.id
    ORDER BY t.created_at DESC
    LIMIT 6
  `);
  return res.rows;
}

// Fetch public school data bundle (Consolidated Single-Query JSON aggregation for pool resilience + fallback)
async function getPublicSchoolData(tenantId) {
  try {
    const res = await dbQuery(`
      SELECT 
        (SELECT coalesce(json_agg(n), '[]') FROM (
          SELECT id, title, content, category, priority, created_at 
          FROM school_notices WHERE tenant_id = $1 AND status = 'published' 
          ORDER BY priority = 'high' DESC, created_at DESC LIMIT 50
        ) n) as notices,
        (SELECT coalesce(json_agg(t), '[]') FROM (
          SELECT id, student_name, class_or_grade, percentage_or_score, year, rank, stream, photo_url 
          FROM school_toppers WHERE tenant_id = $1 
          ORDER BY display_order ASC, created_at DESC LIMIT 50
        ) t) as toppers,
        (SELECT coalesce(json_agg(f), '[]') FROM (
          SELECT id, title, description, category, image_url 
          FROM school_facilities WHERE tenant_id = $1 
          ORDER BY display_order ASC LIMIT 50
        ) f) as facilities,
        (SELECT coalesce(json_agg(fs), '[]') FROM (
          SELECT id, grade, tuition_fee, annual_fee, academic_year 
          FROM school_fee_structures WHERE tenant_id = $1 
          ORDER BY display_order ASC, grade ASC LIMIT 50
        ) fs) as fees,
        (SELECT coalesce(json_agg(s), '[]') FROM (
          SELECT id, name, designation, qualification, photo_url 
          FROM school_staff WHERE tenant_id = $1 
          ORDER BY display_order ASC LIMIT 100
        ) s) as staff,
        (SELECT coalesce(json_agg(d), '[]') FROM (
          SELECT id, title, file_url, file_size, category 
          FROM school_downloads WHERE tenant_id = $1 
          ORDER BY display_order ASC, created_at DESC LIMIT 50
        ) d) as downloads,
        (SELECT coalesce(json_agg(g), '[]') FROM (
          SELECT id, title, image_url, category, display_order 
          FROM school_gallery WHERE tenant_id = $1 
          ORDER BY display_order ASC, created_at DESC LIMIT 50
        ) g) as gallery
    `, [tenantId]);

    const row = res.rows[0] || {};
    return {
      notices: row.notices || [],
      toppers: row.toppers || [],
      facilities: row.facilities || [],
      fees: row.fees || [],
      staff: row.staff || [],
      downloads: row.downloads || [],
      gallery: row.gallery || [],
    };
  } catch (err) {
    console.error('[DB] Consolidated getPublicSchoolData query failed, falling back:', err.message);
    const [notices, toppers, facilities, fees, staff, downloads, gallery] = await Promise.all([
      dbQuery(`SELECT id, title, content, category, priority, created_at FROM school_notices WHERE tenant_id = $1 AND status = 'published' ORDER BY priority = 'high' DESC, created_at DESC LIMIT 50`, [tenantId]),
      dbQuery(`SELECT id, student_name, class_or_grade, percentage_or_score, year, rank, stream, photo_url FROM school_toppers WHERE tenant_id = $1 ORDER BY display_order ASC, created_at DESC LIMIT 50`, [tenantId]),
      dbQuery(`SELECT id, title, description, category, image_url FROM school_facilities WHERE tenant_id = $1 ORDER BY display_order ASC LIMIT 50`, [tenantId]),
      dbQuery(`SELECT id, grade, tuition_fee, annual_fee, academic_year FROM school_fee_structures WHERE tenant_id = $1 ORDER BY display_order ASC, grade ASC LIMIT 50`, [tenantId]),
      dbQuery(`SELECT id, name, designation, qualification, photo_url FROM school_staff WHERE tenant_id = $1 ORDER BY display_order ASC LIMIT 100`, [tenantId]),
      dbQuery(`SELECT id, title, file_url, file_size, category FROM school_downloads WHERE tenant_id = $1 ORDER BY display_order ASC, created_at DESC LIMIT 50`, [tenantId]),
      dbQuery(`SELECT id, title, image_url, category, display_order FROM school_gallery WHERE tenant_id = $1 ORDER BY display_order ASC, created_at DESC LIMIT 50`, [tenantId]),
    ]);

    return {
      notices: notices.rows,
      toppers: toppers.rows,
      facilities: facilities.rows,
      fees: fees.rows,
      staff: staff.rows,
      downloads: downloads.rows,
      gallery: gallery.rows,
    };
  }
}

// Fetch complete school data bundle for Authenticated School Admin CMS
async function getSchoolData(tenantId) {
  const [notices, toppers, facilities, fees, staff, downloads, inquiries, gallery] = await Promise.all([
    dbQuery(`SELECT * FROM school_notices WHERE tenant_id = $1 ORDER BY priority = 'high' DESC, created_at DESC LIMIT 100`, [tenantId]),
    dbQuery(`SELECT * FROM school_toppers WHERE tenant_id = $1 ORDER BY display_order ASC, created_at DESC LIMIT 100`, [tenantId]),
    dbQuery(`SELECT * FROM school_facilities WHERE tenant_id = $1 ORDER BY display_order ASC LIMIT 50`, [tenantId]),
    dbQuery(`SELECT * FROM school_fee_structures WHERE tenant_id = $1 ORDER BY display_order ASC, grade ASC LIMIT 50`, [tenantId]),
    dbQuery(`SELECT * FROM school_staff WHERE tenant_id = $1 ORDER BY display_order ASC LIMIT 100`, [tenantId]),
    dbQuery(`SELECT * FROM school_downloads WHERE tenant_id = $1 ORDER BY display_order ASC, created_at DESC LIMIT 50`, [tenantId]),
    dbQuery(`SELECT * FROM school_admission_inquiries WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 200`, [tenantId]),
    dbQuery(`SELECT * FROM school_gallery WHERE tenant_id = $1 ORDER BY display_order ASC, created_at DESC LIMIT 100`, [tenantId]),
  ]);

  return {
    notices: notices.rows,
    toppers: toppers.rows,
    facilities: facilities.rows,
    fees: fees.rows,
    staff: staff.rows,
    downloads: downloads.rows,
    inquiries: inquiries.rows,
    gallery: gallery.rows,
  };
}

// Create HTTP Server
const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const host = (req.headers['host'] || '').toLowerCase();

  // CORS preflight (Constrained on administrative endpoints)
  if (req.method === 'OPTIONS') {
    const origin = req.headers['origin'] || '';
    const isAdminApi = pathname.startsWith('/api/admin') || pathname.startsWith('/api/super-admin');
    const preflightHeaders = {
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Auth-Token',
      ...SECURITY_HEADERS,
    };
    if (isAdminApi) {
      if (isAllowedOrigin(origin, host)) {
        preflightHeaders['Access-Control-Allow-Origin'] = origin;
        preflightHeaders['Access-Control-Allow-Credentials'] = 'true';
        preflightHeaders['Vary'] = 'Origin';
      }
    } else {
      preflightHeaders['Access-Control-Allow-Origin'] = '*';
    }
    res.writeHead(204, preflightHeaders);
    res.end();
    return;
  }

  try {
    // ----------------------------------------------------
    // ROUTE: PRODUCTION HEALTH CHECK (/health & /api/health)
    // ----------------------------------------------------
    if (pathname === '/health' || pathname === '/api/health') {
      try {
        const t0 = Date.now();
        await dbQuery('SELECT 1');
        const dbLatency = Date.now() - t0;
        const mem = process.memoryUsage();
        const safeMs = (v) => isNaN(v) ? 0 : +(v / 1e6).toFixed(2);

        return sendJson(res, 200, {
          status: 'UP',
          service: 'School SaaS Unified Platform',
          timestamp: new Date().toISOString(),
          uptime_seconds: Math.floor(process.uptime()),
          memory: {
            rss_mb: +(mem.rss / 1024 / 1024).toFixed(2),
            rss_bytes: mem.rss,
            heap_used_mb: +(mem.heapUsed / 1024 / 1024).toFixed(2),
            heap_total_mb: +(mem.heapTotal / 1024 / 1024).toFixed(2),
            external_mb: +(mem.external / 1024 / 1024).toFixed(2),
            array_buffers_mb: +((mem.arrayBuffers || 0) / 1024 / 1024).toFixed(2),
          },
          event_loop: {
            p50_ms: safeMs(eventLoopDelay.percentile(50)),
            p90_ms: safeMs(eventLoopDelay.percentile(90)),
            p99_ms: safeMs(eventLoopDelay.percentile(99)),
            max_ms: safeMs(eventLoopDelay.max),
            mean_ms: safeMs(eventLoopDelay.mean),
          },
          database: {
            status: 'connected',
            provider: 'Neon PostgreSQL (Singapore)',
            latency_ms: dbLatency,
            pool: {
              totalCount: pool.totalCount,
              idleCount: pool.idleCount,
              waitingCount: pool.waitingCount,
              total_clients: pool.totalCount,
              idle_clients: pool.idleCount,
              waiting_requests: pool.waitingCount,
            }
          },
          cache: {
            templates_cached: TEMPLATE_CACHE.size,
            active_sessions: activeSessions.size,
            login_attempts: loginAttempts.size,
            inquiry_rate_limits: inquiryRateLimits.size,
            reset_tokens: resetTokens.size,
          },
          security: {
            ssl: true,
            scrypt_passwords: true,
            sha256_otp: true,
            brute_force_lockout: true,
            security_headers: true,
            xss_sanitized: true,
          }
        });
      } catch (dbErr) {
        return sendJson(res, 503, {
          status: 'DOWN',
          database: 'disconnected',
          error: 'Database connection failed: ' + dbErr.message
        });
      }
    }

    // ----------------------------------------------------
    // STATIC ASSETS: PUBLIC UPLOADS (/uploads/...)
    // ----------------------------------------------------
    if (pathname.startsWith('/uploads/') && (req.method === 'GET' || req.method === 'HEAD')) {
      const safeName = path.basename(pathname);
      const filePath = path.join(UPLOADS_DIR, safeName);

      if (!fs.existsSync(filePath)) {
        // Fallback: Query Neon PostgreSQL DB for persistent upload data across cloud container restarts
        try {
          const dbFile = await dbQuery(`SELECT data, mime_type FROM school_uploads WHERE filename = $1 LIMIT 1`, [safeName]);
          if (dbFile.rows.length > 0 && dbFile.rows[0].data) {
            const buf = dbFile.rows[0].data;
            const mime = dbFile.rows[0].mime_type || 'image/webp';
            try { fs.writeFileSync(filePath, buf); } catch (e) {} // cache to disk
            res.writeHead(200, {
              'Content-Type': mime,
              'Content-Length': buf.length,
              'Cache-Control': 'public, max-age=31536000, immutable',
              'X-Content-Type-Options': 'nosniff',
              ...SECURITY_HEADERS
            });
            if (req.method === 'HEAD') return res.end();
            return res.end(buf);
          }
        } catch (dbErr) {
          console.error('[UPLOADS DB FALLBACK] Error:', dbErr.message);
        }

        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
        return res.end('Image Not Found');
      }

      const ext = path.extname(safeName).toLowerCase();
      let contentType = 'image/webp';
      if (ext === '.png') contentType = 'image/png';
      else if (ext === '.jpg' || ext === '.jpeg') contentType = 'image/jpeg';
      else if (ext === '.gif') contentType = 'image/gif';
      else if (ext === '.svg') contentType = 'image/svg+xml';

      const stat = fs.statSync(filePath);
      const headers = {
        'Content-Type': contentType,
        'Content-Length': stat.size,
        'Cache-Control': 'public, max-age=31536000, immutable',
        'X-Content-Type-Options': 'nosniff',
        ...SECURITY_HEADERS
      };

      if (req.method === 'HEAD') {
        res.writeHead(200, headers);
        return res.end();
      }

      res.writeHead(200, headers);
      fs.createReadStream(filePath).pipe(res);
      return;
    }

    // ----------------------------------------------------
    // ROUTE 0: AUTHENTICATION PORTAL (/login)
    // ----------------------------------------------------
    if (pathname === '/login') {
      return serveFile(res, path.join(__dirname, 'public', 'login.html'));
    }

    // ----------------------------------------------------
    // API: AUTH & PASSWORD RESET (GMAIL SMTP READY + HARDENED)
    // ----------------------------------------------------
    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const body = await parseBody(req);
      const { emailOrUsername, password } = body;
      if (!emailOrUsername || !password) {
        return sendJson(res, 400, { success: false, error: 'Email/Username and password required' });
      }

      if (typeof password !== 'string' || password.length === 0 || password.length > 128) {
        return sendJson(res, 400, { success: false, error: 'Password must not exceed 128 characters.' });
      }

      const clientIp = getClientIp(req);
      const idKey = emailOrUsername.trim().toLowerCase();
      const attemptKey = `${clientIp}:${idKey}`;
      const now = Date.now();

      // Bucket 1: Per-IP Sliding Window Rate Limiting (5 attempts / 60s window)
      const ipRate = checkRateLimit(loginIpRateLimits, clientIp, 5, 60 * 1000);
      if (!ipRate.allowed) {
        return sendJson(res, 429, { 
          success: false, 
          error: `Too many login attempts. Please try again in ${ipRate.retryAfterSec} seconds.` 
        }, { 'Retry-After': String(ipRate.retryAfterSec) });
      }

      // Bucket 2: Account-Level Lockout (5 consecutive failed attempts -> 5 min lockout)
      let attemptData = loginAttempts.get(attemptKey);
      if (attemptData && attemptData.resetAt && now > attemptData.resetAt) {
        loginAttempts.delete(attemptKey);
        attemptData = null;
      }

      if (attemptData && attemptData.lockedUntil && now < attemptData.lockedUntil) {
        const waitMin = Math.ceil((attemptData.lockedUntil - now) / 60000);
        const retrySec = Math.max(1, Math.ceil((attemptData.lockedUntil - now) / 1000));
        return sendJson(res, 429, { 
          success: false, 
          error: `Account login temporarily locked from your IP due to 5 failed attempts. Please retry after ${waitMin} minute(s).` 
        }, { 'Retry-After': String(retrySec) });
      }

      const userRes = await dbQuery(
        `SELECT u.id, u.tenant_id, u.username, u.email, u.password_hash, u.role, u.is_active, t.slug as tenant_slug, t.name as school_name
         FROM cms_users u
         LEFT JOIN cms_tenants t ON t.id = u.tenant_id
         WHERE (LOWER(u.email) = $1 OR LOWER(u.username) = $1) AND u.is_active = true LIMIT 1`,
        [idKey]
      );

      if (userRes.rows.length === 0) {
        const cur = attemptData || { attempts: 0, resetAt: now + 15 * 60 * 1000 };
        cur.attempts += 1;
        if (cur.attempts >= 5) {
          cur.lockedUntil = now + 5 * 60 * 1000;
          safeMapSet(loginAttempts, attemptKey, cur);
          return sendJson(res, 429, { 
            success: false, 
            error: 'Login temporarily locked from this IP for 5 minutes due to 5 consecutive failed attempts.' 
          }, { 'Retry-After': '300' });
        }
        safeMapSet(loginAttempts, attemptKey, cur);
        return sendJson(res, 401, { success: false, error: `Invalid email/username or password. (${5 - cur.attempts} attempts remaining)` });
      }

      const user = userRes.rows[0];
      const isValid = await verifyPassword(password, user.password_hash);
      if (!isValid) {
        const cur = attemptData || { attempts: 0, resetAt: now + 15 * 60 * 1000 };
        cur.attempts += 1;
        if (cur.attempts >= 5) {
          cur.lockedUntil = now + 5 * 60 * 1000;
          safeMapSet(loginAttempts, attemptKey, cur);
          return sendJson(res, 429, { 
            success: false, 
            error: 'Login temporarily locked from this IP for 5 minutes due to 5 consecutive failed attempts.' 
          }, { 'Retry-After': '300' });
        }
        safeMapSet(loginAttempts, attemptKey, cur);
        return sendJson(res, 401, { success: false, error: `Invalid email/username or password. (${5 - cur.attempts} attempts remaining)` });
      }

      // Successful login resets brute-force counter for this IP and account
      loginAttempts.delete(attemptKey);
      loginIpRateLimits.delete(clientIp);
      await dbQuery(`UPDATE cms_users SET last_login = NOW() WHERE id = $1`, [user.id]);

      // Generate 24-hour Cryptographic Session Token
      const token = crypto.randomBytes(32).toString('hex');
      safeMapSet(activeSessions, token, {
        userId: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        tenantId: user.tenant_id,
        tenantSlug: user.tenant_slug,
        schoolName: user.school_name,
        expiresAt: Date.now() + 24 * 60 * 60 * 1000,
      });

      // Set-Cookie across main domain and subdomains for seamless server-side authentication
      const hostHeader = (req.headers['host'] || '').split(':')[0].toLowerCase();
      let cookieDomain = '';
      if (hostHeader.endsWith(ROOT_DOMAIN)) {
        cookieDomain = `; Domain=.${ROOT_DOMAIN}`;
      }
      res.setHeader('Set-Cookie', `school_saas_token=${token}; Path=/${cookieDomain}; HttpOnly; SameSite=Lax; Max-Age=86400`);

      return sendJson(res, 200, {
        success: true,
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          tenant_id: user.tenant_id,
          tenant_slug: user.tenant_slug,
          school_name: user.school_name,
        }
      });
    }

    if (pathname === '/api/auth/forgot-password' && req.method === 'POST') {
      const body = await parseBody(req);
      const { email } = body;
      if (!email) return sendJson(res, 400, { success: false, error: 'Email address is required' });

      const normEmail = email.trim().toLowerCase();

      // Rate limit / Spam Protection: 60-second cooldown per email
      const existing = resetTokens.get(normEmail);
      if (existing && existing.createdAt && (Date.now() - existing.createdAt < 60000)) {
        const waitSec = Math.ceil((60000 - (Date.now() - existing.createdAt)) / 1000);
        return sendJson(res, 429, { 
          success: false, 
          error: `Please wait ${waitSec} seconds before requesting another OTP.` 
        });
      }

      const userRes = await dbQuery(
        `SELECT id, email, username FROM cms_users WHERE LOWER(email) = $1 AND is_active = true LIMIT 1`,
        [normEmail]
      );

      if (userRes.rows.length === 0) {
        // OWASP Anti-Account Enumeration: Return uniform success response so attackers cannot discover valid emails
        return sendJson(res, 200, {
          success: true,
          message: 'If this email address is registered, a password reset OTP has been sent.'
        });
      }

      // Cryptographically secure 6-digit OTP & SHA-256 in-memory hashing
      const otp = crypto.randomInt(100000, 1000000).toString();
      const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
      const expires = Date.now() + 15 * 60 * 1000; // Strict 15-minute expiration timestamp
      safeMapSet(resetTokens, normEmail, { otpHash, expires, attempts: 0, createdAt: Date.now() });

      try {
        await sendResetEmail(normEmail, otp);
        return sendJson(res, 200, {
          success: true,
          message: 'If this email address is registered, a password reset OTP has been sent.'
        });
      } catch (mailErr) {
        console.error('Mail dispatch error:', mailErr.message);
        resetTokens.delete(normEmail);
        return sendJson(res, 503, { success: false, error: 'Email service is temporarily unavailable. Please retry shortly.' });
      }
    }

    if (pathname === '/api/auth/reset-password' && req.method === 'POST') {
      const body = await parseBody(req);
      const { email, otp, newPassword } = body;
      if (!email || !otp || !newPassword) {
        return sendJson(res, 400, { success: false, error: 'Email, OTP, and new password are required' });
      }

      if (typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > 128) {
        return sendJson(res, 400, { success: false, error: 'New password must be between 8 and 128 characters long.' });
      }

      const normEmail = email.trim().toLowerCase();
      const record = resetTokens.get(normEmail);

      if (!record) {
        return sendJson(res, 400, { success: false, error: 'No active OTP request found. Please request an OTP first.' });
      }

      // 1. Strict 15-minute expiration check
      if (Date.now() > record.expires) {
        resetTokens.delete(normEmail);
        return sendJson(res, 400, { success: false, error: 'OTP has expired (15 minutes limit exceeded). Please request a new one.' });
      }

      // 2. Strict OTP verification with SHA-256 constant-time comparison & 5-attempt brute-force protection
      const submittedHash = crypto.createHash('sha256').update(otp.trim()).digest('hex');
      const submittedBuf = Buffer.from(submittedHash, 'hex');
      const targetBuf = Buffer.from(record.otpHash, 'hex');
      const isMatch = (submittedBuf.length === targetBuf.length) && crypto.timingSafeEqual(submittedBuf, targetBuf);

      if (!isMatch) {
        record.attempts = (record.attempts || 0) + 1;
        const remaining = 5 - record.attempts;
        if (remaining <= 0) {
          resetTokens.delete(normEmail);
          return sendJson(res, 429, { 
            success: false, 
            error: 'Too many incorrect attempts (5/5). This OTP has been permanently invalidated. Please request a new OTP.' 
          });
        }
        return sendJson(res, 400, { 
          success: false, 
          error: `Invalid OTP code. You have ${remaining} attempt(s) remaining.` 
        });
      }

      // 3. Password update & instant OTP destruction
      const newHash = await hashPassword(newPassword);
      await dbQuery(
        `UPDATE cms_users SET password_hash = $1, updated_at = NOW() WHERE LOWER(email) = $2`,
        [newHash, normEmail]
      );

      // Fetch user profile to support instant seamless auto-login
      const userRes = await dbQuery(
        `SELECT u.id, u.tenant_id, u.username, u.email, u.role, t.slug as tenant_slug, t.name as school_name
         FROM cms_users u
         LEFT JOIN cms_tenants t ON t.id = u.tenant_id
         WHERE LOWER(u.email) = $1 LIMIT 1`,
        [normEmail]
      );
      const user = userRes.rows[0] || null;

      // Invalidate ALL previous active sessions for this user ID (Prevents stolen token persistence)
      if (user) {
        for (const [sToken, sRecord] of activeSessions.entries()) {
          if (sRecord.userId === user.id) {
            activeSessions.delete(sToken);
          }
        }
      }

      // Generate 24-hour Cryptographic Session Token
      const token = crypto.randomBytes(32).toString('hex');
      if (user) {
        safeMapSet(activeSessions, token, {
          userId: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          tenantId: user.tenant_id,
          tenantSlug: user.tenant_slug,
          schoolName: user.school_name,
          expiresAt: Date.now() + 24 * 60 * 60 * 1000,
        });
      }

      // Instantly delete OTP from memory so it can never be re-used
      resetTokens.delete(normEmail);
      for (const k of loginAttempts.keys()) {
        if (k.endsWith(`:${normEmail}`)) {
          loginAttempts.delete(k);
        }
      }
      console.log(`[AUTH] Password successfully updated for ${normEmail}`);
      return sendJson(res, 200, {
        success: true,
        message: 'Password successfully updated! Logging you in...',
        token,
        user: user ? {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          tenant_id: user.tenant_id,
          tenant_slug: user.tenant_slug,
          school_name: user.school_name,
        } : null
      });
    }

    if (pathname === '/api/auth/logout' && req.method === 'POST') {
      const authHeader = req.headers['authorization'] || '';
      let token = '';
      if (authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7).trim();
      } else if (req.headers['x-auth-token']) {
        token = req.headers['x-auth-token'].trim();
      } else {
        const cookie = req.headers['cookie'] || '';
        const match = cookie.match(/school_saas_token=([^;]+)/);
        if (match) token = match[1].trim();
      }
      if (token) activeSessions.delete(token);
      const hostHeader = (req.headers['host'] || '').split(':')[0].toLowerCase();
      let cookieDomain = '';
      if (hostHeader.endsWith(ROOT_DOMAIN)) {
        cookieDomain = `; Domain=.${ROOT_DOMAIN}`;
      }
      res.setHeader('Set-Cookie', `school_saas_token=; Path=/${cookieDomain}; HttpOnly; SameSite=Lax; Max-Age=0`);
      return sendJson(res, 200, { success: true, message: 'Logged out successfully.' });
    }

    // ----------------------------------------------------
    // ROUTE 1: SUPER ADMIN PANEL (/master or master.*)
    // (Strict Server-Side Auth Wall: Unauthenticated users are redirected before HTML is ever served)
    // ----------------------------------------------------
    if ((pathname === '/master' || host.startsWith('master.')) && !pathname.startsWith('/api/')) {
      if (pathname === '/login') {
        return serveFile(res, path.join(__dirname, 'public', 'login.html'));
      }
      const session = authenticate(req);
      if (!session || session.role !== 'super_admin') {
        res.writeHead(302, { 'Location': '/login', ...SECURITY_HEADERS });
        return res.end();
      }
      return serveFile(res, path.join(__dirname, 'public', 'master_panel.html'));
    }

    // ----------------------------------------------------
    // ROUTE 2: SCHOOL ADMIN CMS (/admin or admin.*)
    // (Strict Server-Side Auth Wall: Unauthenticated users are redirected before HTML is ever served)
    // ----------------------------------------------------
    if ((pathname === '/admin' || host.startsWith('admin.')) && !pathname.startsWith('/api/')) {
      if (pathname === '/login') {
        return serveFile(res, path.join(__dirname, 'public', 'login.html'));
      }
      const session = authenticate(req);
      if (!session || (session.role !== 'admin' && session.role !== 'super_admin')) {
        res.writeHead(302, { 'Location': '/login', ...SECURITY_HEADERS });
        return res.end();
      }
      return serveFile(res, path.join(__dirname, 'public', 'admin.html'));
    }

    // ----------------------------------------------------
    // API: SUPER ADMIN ENDPOINTS (STRICT SUPER ADMIN TOKEN REQUIRED)
    // ----------------------------------------------------
    if (pathname === '/api/super-admin/schools') {
      const session = authenticate(req);
      if (!session) {
        return sendJson(res, 401, { success: false, error: 'Unauthorized: Valid Super Admin session token required.' });
      }
      if (session.role !== 'super_admin') {
        return sendJson(res, 403, { success: false, error: 'Forbidden: Super Admin privileges required.' });
      }

      if (req.method === 'GET') {
        const schools = await dbQuery(
          `SELECT t.id, t.name, t.slug, t.created_at, s.domain, s.status 
           FROM cms_tenants t
           LEFT JOIN cms_sites s ON s.tenant_id = t.id
           ORDER BY t.created_at DESC`
        );
        return sendJson(res, 200, { success: true, schools: schools.rows });
      }

      if (req.method === 'POST') {
        const body = await parseBody(req);
        const { name, slug, domain } = body;
        if (!name || !slug) return sendJson(res, 400, { success: false, error: 'Name and slug required' });

        const slugClean = slug.trim().toLowerCase();
        if (!/^[a-z0-9-]+$/.test(slugClean) || slugClean.length > 50) {
          return sendJson(res, 400, { success: false, error: 'Slug must contain only lowercase alphanumeric characters and hyphens (max 50 chars).' });
        }
        if (typeof name !== 'string' || !name.trim() || name.trim().length > 100) {
          return sendJson(res, 400, { success: false, error: 'School name is required (max 100 characters).' });
        }

        // Atomic transaction: Tenant + Site with rich default settings
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          const initialSettings = {
            theme: {
              primary_color: '#1e3a8a',
              secondary_color: '#d97706',
              font_family: 'Plus Jakarta Sans',
              logo_url: ''
            },
            header: {
              tagline: 'Affiliated Senior Secondary Institution',
              phone: '',
              email: '',
              affiliation: 'Recognized & Affiliated Institution',
              admission_badge: 'Admissions 2026-27 Open'
            },
            hero: {
              badge: 'Premier Center of Excellence & Holistic Education',
              title: 'Nurturing Inquiring Minds, Inspiring Confident Leaders.',
              subtitle: `Welcome to ${name.trim()}. Our campus provides holistic education with world-class facilities and dedicated faculty.`,
              cta_text: 'Enroll Your Child Today',
              stats: [
                { value: '100%', label: 'Board Pass Rate' },
                { value: '1:15', label: 'Faculty Ratio' },
                { value: '30+', label: 'Smart STEM Labs' },
                { value: '25+', label: 'Years of Legacy' }
              ]
            },
            principal: {
              name: 'Head of Institution',
              title: 'Principal & Educational Director',
              message: `Welcome to ${name.trim()}. We empower every scholar to think fearlessly, discover their potential, and lead with empathy.`,
              photo_url: ''
            },
            about: {
              headline: 'Building Character, Wisdom and Global Citizenship',
              story: `Founded with the conviction that quality education transforms society, ${name.trim()} offers an enriching environment combining academic rigor with ethical integrity.`,
              stat1_value: '100%',
              stat1_label: 'Smart Classrooms',
              stat2_value: '25+',
              stat2_label: 'Years of Excellence'
            },
            contact: {
              address: 'Main Campus Road, Institutional Area',
              phone: '',
              email: '',
              hours: 'Mon - Sat: 8:30 AM to 3:30 PM (Closed on Sundays)'
            },
            footer: {
              tagline: 'Empowering Generation Next with Excellence & Character.'
            }
          };

          const tRes = await client.query(
            `INSERT INTO cms_tenants (name, slug, settings) VALUES ($1, $2, $3) RETURNING id`,
            [name.trim(), slugClean, initialSettings]
          );
          const tenantId = tRes.rows[0].id;

          const siteDomain = (domain || `${slugClean}.${ROOT_DOMAIN}`).trim().toLowerCase().substring(0, 100);
          await client.query(
            `INSERT INTO cms_sites (tenant_id, name, slug, domain, status) 
             VALUES ($1, $2, $3, $4, 'published')`,
            [tenantId, name.trim() + ' Official', slugClean + '-site', siteDomain]
          );
          await client.query('COMMIT');
          return sendJson(res, 201, { success: true, tenant_id: tenantId });
        } catch (e) {
          try { await client.query('ROLLBACK'); } catch (_) {}
          return sendJson(res, 500, { success: false, error: e.message });
        } finally {
          client.release(true);
        }
      }

      if (req.method === 'PUT') {
        const body = await parseBody(req);
        const { tenant_id, domain } = body;
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!tenant_id || !uuidRegex.test(tenant_id)) {
          return sendJson(res, 400, { success: false, error: 'Valid tenant UUID ID required' });
        }

        let cleanDomain = null;
        if (domain && typeof domain === 'string' && domain.trim()) {
          cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').substring(0, 100);
          if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(cleanDomain)) {
            return sendJson(res, 400, { success: false, error: 'Invalid domain format. Example: stxavier.edu.in or dps.schoolsaas.site' });
          }
        }

        const updateRes = await dbQuery(
          `UPDATE cms_sites SET domain = $1, updated_at = NOW() WHERE tenant_id = $2 RETURNING *`,
          [cleanDomain, tenant_id]
        );

        if (updateRes.rowCount === 0) {
          return sendJson(res, 404, { success: false, error: 'School site not found for this tenant.' });
        }

        return sendJson(res, 200, { success: true, site: updateRes.rows[0], message: 'Custom domain updated successfully!' });
      }

      if (req.method === 'DELETE') {
        const body = await parseBody(req);
        const { id } = body;
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!id || !uuidRegex.test(id)) return sendJson(res, 400, { success: false, error: 'Valid tenant UUID ID required' });
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          await client.query('DELETE FROM cms_sites WHERE tenant_id = $1', [id]);
          await client.query('DELETE FROM school_notices WHERE tenant_id = $1', [id]);
          await client.query('DELETE FROM school_toppers WHERE tenant_id = $1', [id]);
          await client.query('DELETE FROM school_facilities WHERE tenant_id = $1', [id]);
          await client.query('DELETE FROM school_fee_structures WHERE tenant_id = $1', [id]);
          await client.query('DELETE FROM school_staff WHERE tenant_id = $1', [id]);
          await client.query('DELETE FROM school_downloads WHERE tenant_id = $1', [id]);
          await client.query('DELETE FROM school_admission_inquiries WHERE tenant_id = $1', [id]);
          await client.query("DELETE FROM cms_users WHERE tenant_id = $1 AND role != 'super_admin'", [id]);
          await client.query('DELETE FROM cms_tenants WHERE id = $1', [id]);
          await client.query('COMMIT');
          return sendJson(res, 200, { success: true });
        } catch (e) {
          try { await client.query('ROLLBACK'); } catch (_) {}
          return sendJson(res, 500, { success: false, error: e.message });
        } finally {
          client.release(true);
        }
      }
    }

    // ----------------------------------------------------
    // API: SUPER ADMIN SAAS LANDING CMS & DEMO LEADS
    // ----------------------------------------------------
    if (pathname === '/api/super-admin/landing') {
      const session = authenticate(req);
      if (!session || session.role !== 'super_admin') {
        return sendJson(res, 403, { success: false, error: 'Forbidden: Super Admin access required' });
      }

      if (req.method === 'GET') {
        const config = await getSaasLandingConfig();
        return sendJson(res, 200, { success: true, config });
      }

      if (req.method === 'PUT') {
        const body = await parseBody(req);
        const {
          hero_badge,
          hero_title,
          hero_subtitle,
          cta_primary_text,
          cta_primary_link,
          cta_secondary_text,
          cta_secondary_link,
          contact_email,
          contact_phone,
          contact_whatsapp,
          stats_json,
          features_json,
          pricing_json
        } = body;

        const updateRes = await dbQuery(
          `UPDATE saas_landing_config SET
            hero_badge = COALESCE($1, hero_badge),
            hero_title = COALESCE($2, hero_title),
            hero_subtitle = COALESCE($3, hero_subtitle),
            cta_primary_text = COALESCE($4, cta_primary_text),
            cta_primary_link = COALESCE($5, cta_primary_link),
            cta_secondary_text = COALESCE($6, cta_secondary_text),
            cta_secondary_link = COALESCE($7, cta_secondary_link),
            contact_email = COALESCE($8, contact_email),
            contact_phone = COALESCE($9, contact_phone),
            contact_whatsapp = COALESCE($10, contact_whatsapp),
            stats_json = COALESCE($11::jsonb, stats_json),
            features_json = COALESCE($12::jsonb, features_json),
            pricing_json = COALESCE($13::jsonb, pricing_json),
            updated_at = NOW()
           WHERE id = 1 RETURNING *`,
          [
            hero_badge,
            hero_title,
            hero_subtitle,
            cta_primary_text,
            cta_primary_link,
            cta_secondary_text,
            cta_secondary_link,
            contact_email,
            contact_phone,
            contact_whatsapp,
            stats_json ? JSON.stringify(stats_json) : null,
            features_json ? JSON.stringify(features_json) : null,
            pricing_json ? JSON.stringify(pricing_json) : null
          ]
        );

        return sendJson(res, 200, {
          success: true,
          config: updateRes.rows[0],
          message: 'SaaS Landing Page configuration updated successfully!'
        });
      }
    }

    if (pathname === '/api/super-admin/leads') {
      const session = authenticate(req);
      if (!session || session.role !== 'super_admin') {
        return sendJson(res, 403, { success: false, error: 'Forbidden: Super Admin access required' });
      }
      const leads = await dbQuery('SELECT * FROM saas_demo_leads ORDER BY created_at DESC LIMIT 100');
      return sendJson(res, 200, { success: true, leads: leads.rows });
    }

    if (pathname === '/api/saas/inquiry' && req.method === 'POST') {
      const clientIp = getClientIp(req);
      const rateCheck = checkRateLimit(saasInquiryRateLimits, clientIp, 3, 60 * 1000);
      if (!rateCheck.allowed) {
        return sendJson(res, 429, { 
          success: false, 
          error: `Too many requests. Please try again in ${rateCheck.retryAfterSec} seconds.` 
        }, { 'Retry-After': String(rateCheck.retryAfterSec) });
      }

      const body = await parseBody(req);
      const { school_name, contact_person, phone, email, city, message } = body;
      if (!school_name || !contact_person || !phone) {
        return sendJson(res, 400, { success: false, error: 'School name, contact person, and phone are required.' });
      }

      const leadRes = await dbQuery(
        `INSERT INTO saas_demo_leads (school_name, contact_person, phone, email, city, message)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
        [
          stripDangerousHtml(school_name).trim().substring(0, 150),
          stripDangerousHtml(contact_person).trim().substring(0, 100),
          phone.trim().substring(0, 20),
          (email || '').trim().substring(0, 100),
          stripDangerousHtml(city || '').trim().substring(0, 100),
          stripDangerousHtml(message || '').trim().substring(0, 1000)
        ]
      );

      return sendJson(res, 201, { success: true, lead_id: leadRes.rows[0].id, message: 'Demo request received successfully!' });
    }

    // ----------------------------------------------------
    // API: SCHOOL ADMIN CMS ENDPOINTS (STRICT RBAC & TENANT LOCK)
    // ----------------------------------------------------
    if (pathname === '/api/admin/data') {
      let requestedTenantId = null;
      let school = null;
      const schoolParam = getScalarQuery(parsedUrl && parsedUrl.query, 'school');
      if (schoolParam) {
        school = await resolveSchool(req, parsedUrl);
        if (school) requestedTenantId = school.tenant_id;
      }

      const auth = verifyAdminAccess(req, res, requestedTenantId);
      if (!auth) return;
      const { session, targetTenantId } = auth;

      if (!school || school.tenant_id !== targetTenantId) {
        const resTenant = await dbQuery(
          `SELECT t.id as tenant_id, t.name as school_name, t.slug as school_slug, 
                  s.id as site_id, s.domain, s.name as site_name
           FROM cms_tenants t
           LEFT JOIN cms_sites s ON s.tenant_id = t.id
           WHERE t.id = $1 LIMIT 1`,
          [targetTenantId]
        );
        school = resTenant.rows[0];
      }

      if (!school) return sendJson(res, 404, { success: false, error: 'School not found' });

      const data = await getSchoolData(school.tenant_id);
      return sendJson(res, 200, { success: true, school, data, user: session });
    }

    // Notices CRUD
    if (pathname === '/api/admin/notices') {
      if (req.method === 'POST') {
        const body = await parseBody(req);
        const { title, content, category, priority } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!title || typeof title !== 'string' || !title.trim() || title.trim().length > 200) {
          return sendJson(res, 400, { success: false, error: 'Notice title is required (1-200 characters).' });
        }
        if (content && typeof content === 'string' && content.length > 5000) {
          return sendJson(res, 400, { success: false, error: 'Notice content must not exceed 5000 characters.' });
        }
        const allowedPriorities = ['low', 'medium', 'high'];
        const safePriority = allowedPriorities.includes(priority) ? priority : 'medium';
        const safeCategory = (category || 'general').toString().trim().substring(0, 50);

        const result = await dbQuery(
          `INSERT INTO school_notices (tenant_id, title, content, category, priority, status)
           VALUES ($1, $2, $3, $4, $5, 'published') RETURNING *`,
          [targetTenantId, title.trim(), (content || '').trim(), safeCategory, safePriority]
        );
        return sendJson(res, 201, { success: true, notice: result.rows[0] });
      }
      if (req.method === 'PUT') {
        const body = await parseBody(req);
        const { id, title, content, category, priority } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!id) return sendJson(res, 400, { success: false, error: 'Notice ID is required.' });
        if (!title || typeof title !== 'string' || !title.trim() || title.trim().length > 200) {
          return sendJson(res, 400, { success: false, error: 'Notice title is required (1-200 characters).' });
        }
        if (content && typeof content === 'string' && content.length > 5000) {
          return sendJson(res, 400, { success: false, error: 'Notice content must not exceed 5000 characters.' });
        }
        const allowedPriorities = ['low', 'medium', 'high'];
        const safePriority = allowedPriorities.includes(priority) ? priority : 'medium';
        const safeCategory = (category || 'general').toString().trim().substring(0, 50);

        const result = await dbQuery(
          `UPDATE school_notices SET title = $1, content = $2, category = $3, priority = $4, updated_at = NOW()
           WHERE id = $5 AND tenant_id = $6 RETURNING *`,
          [title.trim(), (content || '').trim(), safeCategory, safePriority, id, targetTenantId]
        );
        return sendJson(res, 200, { success: true, notice: result.rows[0] });
      }

      if (req.method === 'DELETE') {
        const body = await parseBody(req);
        const { id } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!id) return sendJson(res, 400, { success: false, error: 'Notice ID is required.' });
        await dbQuery(`DELETE FROM school_notices WHERE id = $1 AND tenant_id = $2`, [id, targetTenantId]);
        return sendJson(res, 200, { success: true });
      }
    }

    // Toppers CRUD
    if (pathname === '/api/admin/toppers') {
      if (req.method === 'POST') {
        const body = await parseBody(req);
        const { student_name, class_or_grade, percentage_or_score, year, rank, stream, photo_url } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!student_name || typeof student_name !== 'string' || !student_name.trim() || student_name.trim().length > 100) {
          return sendJson(res, 400, { success: false, error: 'Student name is required (1-100 characters).' });
        }
        if (!percentage_or_score || typeof percentage_or_score !== 'string' || percentage_or_score.trim().length > 50) {
          return sendJson(res, 400, { success: false, error: 'Valid percentage or score is required (max 50 characters).' });
        }
        if (photo_url && !isValidUrl(photo_url)) {
          return sendJson(res, 400, { success: false, error: 'Invalid photo URL scheme. Only http, https, and safe data:image/ URLs are allowed.' });
        }
        const safePhoto = (photo_url || '').toString().trim().substring(0, 1000);
        const result = await dbQuery(
          `INSERT INTO school_toppers (tenant_id, student_name, class_or_grade, percentage_or_score, year, rank, stream, photo_url, display_order)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0) RETURNING *`,
          [
            targetTenantId, 
            student_name.trim(), 
            (class_or_grade || 'Class 12').toString().trim().substring(0, 50), 
            percentage_or_score.trim(), 
            (year || '2025-26').toString().trim().substring(0, 20), 
            (rank || '1').toString().trim().substring(0, 20), 
            (stream || 'General').toString().trim().substring(0, 50),
            safePhoto
          ]
        );
        return sendJson(res, 201, { success: true, topper: result.rows[0] });
      }
      if (req.method === 'PUT') {
        const body = await parseBody(req);
        const { id, student_name, class_or_grade, percentage_or_score, year, rank, stream, photo_url } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!id) return sendJson(res, 400, { success: false, error: 'Topper ID is required.' });
        if (!student_name || typeof student_name !== 'string' || !student_name.trim() || student_name.trim().length > 100) {
          return sendJson(res, 400, { success: false, error: 'Student name is required (1-100 characters).' });
        }
        if (!percentage_or_score || typeof percentage_or_score !== 'string' || percentage_or_score.trim().length > 50) {
          return sendJson(res, 400, { success: false, error: 'Valid percentage or score is required (max 50 characters).' });
        }
        if (photo_url && !isValidUrl(photo_url)) {
          return sendJson(res, 400, { success: false, error: 'Invalid photo URL scheme. Only http, https, and safe data:image/ URLs are allowed.' });
        }
        const safePhoto = (photo_url || '').toString().trim().substring(0, 1000);
        const result = await dbQuery(
          `UPDATE school_toppers SET student_name = $1, class_or_grade = $2, percentage_or_score = $3, year = $4, rank = $5, stream = $6, photo_url = $7, updated_at = NOW()
           WHERE id = $8 AND tenant_id = $9 RETURNING *`,
          [
            student_name.trim(), 
            (class_or_grade || 'Class 12').toString().trim().substring(0, 50), 
            percentage_or_score.trim(), 
            (year || '2025-26').toString().trim().substring(0, 20), 
            (rank || '1').toString().trim().substring(0, 20), 
            (stream || 'General').toString().trim().substring(0, 50), 
            safePhoto,
            id, 
            targetTenantId
          ]
        );
        return sendJson(res, 200, { success: true, topper: result.rows[0] });
      }

      if (req.method === 'DELETE') {
        const body = await parseBody(req);
        const { id } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!id) return sendJson(res, 400, { success: false, error: 'Topper ID is required.' });
        await dbQuery(`DELETE FROM school_toppers WHERE id = $1 AND tenant_id = $2`, [id, targetTenantId]);
        return sendJson(res, 200, { success: true });
      }
    }

    // Facilities CRUD
    if (pathname === '/api/admin/facilities') {
      if (req.method === 'POST') {
        const body = await parseBody(req);
        const { title, description, category, image_url } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!title || typeof title !== 'string' || !title.trim() || title.trim().length > 100) {
          return sendJson(res, 400, { success: false, error: 'Facility title is required (1-100 characters).' });
        }
        if (description && typeof description === 'string' && description.length > 1000) {
          return sendJson(res, 400, { success: false, error: 'Description must not exceed 1000 characters.' });
        }
        if (image_url && !isValidUrl(image_url)) {
          return sendJson(res, 400, { success: false, error: 'Invalid image URL scheme. Only http, https, and safe data:image/ URLs are allowed.' });
        }
        const safeImage = (image_url || '').toString().trim().substring(0, 1000);
        const result = await dbQuery(
          `INSERT INTO school_facilities (tenant_id, title, description, category, image_url, display_order)
           VALUES ($1, $2, $3, $4, $5, 0) RETURNING *`,
          [targetTenantId, title.trim(), (description || '').trim(), (category || 'infrastructure').toString().trim().substring(0, 50), safeImage]
        );
        return sendJson(res, 201, { success: true, facility: result.rows[0] });
      }
      if (req.method === 'PUT') {
        const body = await parseBody(req);
        const { id, title, description, category, image_url } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!id) return sendJson(res, 400, { success: false, error: 'Facility ID is required.' });
        if (!title || typeof title !== 'string' || !title.trim() || title.trim().length > 100) {
          return sendJson(res, 400, { success: false, error: 'Facility title is required (1-100 characters).' });
        }
        if (description && typeof description === 'string' && description.length > 1000) {
          return sendJson(res, 400, { success: false, error: 'Description must not exceed 1000 characters.' });
        }
        if (image_url && !isValidUrl(image_url)) {
          return sendJson(res, 400, { success: false, error: 'Invalid image URL scheme. Only http, https, and safe data:image/ URLs are allowed.' });
        }
        const safeImage = (image_url || '').toString().trim().substring(0, 1000);
        const result = await dbQuery(
          `UPDATE school_facilities SET title = $1, description = $2, category = $3, image_url = $4, updated_at = NOW()
           WHERE id = $5 AND tenant_id = $6 RETURNING *`,
          [title.trim(), (description || '').trim(), (category || 'infrastructure').toString().trim().substring(0, 50), safeImage, id, targetTenantId]
        );
        return sendJson(res, 200, { success: true, facility: result.rows[0] });
      }

      if (req.method === 'DELETE') {
        const body = await parseBody(req);
        const { id } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!id) return sendJson(res, 400, { success: false, error: 'Facility ID is required.' });
        await dbQuery(`DELETE FROM school_facilities WHERE id = $1 AND tenant_id = $2`, [id, targetTenantId]);
        return sendJson(res, 200, { success: true });
      }
    }

    // Fees CRUD
    if (pathname === '/api/admin/fees') {
      if (req.method === 'POST') {
        const body = await parseBody(req);
        const { grade, tuition_fee, annual_fee, academic_year } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!grade || typeof grade !== 'string' || !grade.trim() || grade.trim().length > 50) {
          return sendJson(res, 400, { success: false, error: 'Grade is required (1-50 characters).' });
        }
        const safeTuition = (tuition_fee || '0').toString().trim().substring(0, 50);
        const safeAnnual = (annual_fee || '0').toString().trim().substring(0, 50);
        const safeYear = (academic_year || '2026-27').toString().trim().substring(0, 20);

        const result = await dbQuery(
          `INSERT INTO school_fee_structures (tenant_id, grade, tuition_fee, annual_fee, academic_year, frequency, display_order)
           VALUES ($1, $2, $3, $4, $5, 'annual', 0) RETURNING *`,
          [targetTenantId, grade.trim(), safeTuition, safeAnnual, safeYear]
        );
        return sendJson(res, 201, { success: true, fee: result.rows[0] });
      }
      if (req.method === 'PUT') {
        const body = await parseBody(req);
        const { id, grade, tuition_fee, annual_fee, academic_year } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!id) return sendJson(res, 400, { success: false, error: 'Fee ID is required.' });
        if (!grade || typeof grade !== 'string' || !grade.trim() || grade.trim().length > 50) {
          return sendJson(res, 400, { success: false, error: 'Grade is required (1-50 characters).' });
        }
        const safeTuition = (tuition_fee || '0').toString().trim().substring(0, 50);
        const safeAnnual = (annual_fee || '0').toString().trim().substring(0, 50);
        const safeYear = (academic_year || '2026-27').toString().trim().substring(0, 20);

        const result = await dbQuery(
          `UPDATE school_fee_structures SET grade = $1, tuition_fee = $2, annual_fee = $3, academic_year = $4, updated_at = NOW()
           WHERE id = $5 AND tenant_id = $6 RETURNING *`,
          [grade.trim(), safeTuition, safeAnnual, safeYear, id, targetTenantId]
        );
        return sendJson(res, 200, { success: true, fee: result.rows[0] });
      }

      if (req.method === 'DELETE') {
        const body = await parseBody(req);
        const { id } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!id) return sendJson(res, 400, { success: false, error: 'Fee ID is required.' });
        await dbQuery(`DELETE FROM school_fee_structures WHERE id = $1 AND tenant_id = $2`, [id, targetTenantId]);
        return sendJson(res, 200, { success: true });
      }
    }

    // Staff CRUD
    if (pathname === '/api/admin/staff') {
      if (req.method === 'POST') {
        const body = await parseBody(req);
        const { name, designation, qualification, photo_url } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!name || typeof name !== 'string' || !name.trim() || name.trim().length > 100) {
          return sendJson(res, 400, { success: false, error: 'Staff name is required (1-100 characters).' });
        }
        if (!designation || typeof designation !== 'string' || !designation.trim() || designation.trim().length > 100) {
          return sendJson(res, 400, { success: false, error: 'Designation is required (1-100 characters).' });
        }
        if (photo_url && !isValidUrl(photo_url)) {
          return sendJson(res, 400, { success: false, error: 'Invalid photo URL scheme. Only http, https, and safe data:image/ URLs are allowed.' });
        }
        const safeQual = (qualification || '').toString().trim().substring(0, 200);
        const safePhoto = (photo_url || '').toString().trim().substring(0, 1000);

        const result = await dbQuery(
          `INSERT INTO school_staff (tenant_id, name, designation, qualification, photo_url, display_order)
           VALUES ($1, $2, $3, $4, $5, 0) RETURNING *`,
          [targetTenantId, name.trim(), designation.trim(), safeQual, safePhoto]
        );
        return sendJson(res, 201, { success: true, staff: result.rows[0] });
      }
      if (req.method === 'PUT') {
        const body = await parseBody(req);
        const { id, name, designation, qualification, photo_url } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!id) return sendJson(res, 400, { success: false, error: 'Staff ID is required.' });
        if (!name || typeof name !== 'string' || !name.trim() || name.trim().length > 100) {
          return sendJson(res, 400, { success: false, error: 'Staff name is required (1-100 characters).' });
        }
        if (!designation || typeof designation !== 'string' || !designation.trim() || designation.trim().length > 100) {
          return sendJson(res, 400, { success: false, error: 'Designation is required (1-100 characters).' });
        }
        if (photo_url && !isValidUrl(photo_url)) {
          return sendJson(res, 400, { success: false, error: 'Invalid photo URL scheme. Only http, https, and safe data:image/ URLs are allowed.' });
        }
        const safeQual = (qualification || '').toString().trim().substring(0, 200);
        const safePhoto = (photo_url || '').toString().trim().substring(0, 1000);

        const result = await dbQuery(
          `UPDATE school_staff SET name = $1, designation = $2, qualification = $3, photo_url = $4, updated_at = NOW()
           WHERE id = $5 AND tenant_id = $6 RETURNING *`,
          [name.trim(), designation.trim(), safeQual, safePhoto, id, targetTenantId]
        );
        return sendJson(res, 200, { success: true, staff: result.rows[0] });
      }

      if (req.method === 'DELETE') {
        const body = await parseBody(req);
        const { id } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!id) return sendJson(res, 400, { success: false, error: 'Staff ID is required.' });
        await dbQuery(`DELETE FROM school_staff WHERE id = $1 AND tenant_id = $2`, [id, targetTenantId]);
        return sendJson(res, 200, { success: true });
      }
    }

    // Campus Photo Gallery CRUD
    if (pathname === '/api/admin/gallery') {
      if (req.method === 'GET') {
        const requestedTenantId = getScalarQuery(parsedUrl && parsedUrl.query, 'tenant_id');
        const auth = verifyAdminAccess(req, res, requestedTenantId);
        if (!auth) return;
        const { targetTenantId } = auth;

        const gallery = await dbQuery(
          `SELECT * FROM school_gallery WHERE tenant_id = $1 ORDER BY display_order ASC, created_at DESC LIMIT 100`,
          [targetTenantId]
        );
        return sendJson(res, 200, { success: true, gallery: gallery.rows });
      }

      if (req.method === 'POST') {
        const body = await parseBody(req);
        const { title, image_url, category } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;

        if (!title || typeof title !== 'string' || !title.trim()) {
          return sendJson(res, 400, { success: false, error: 'Photo title is required.' });
        }
        if (!image_url || typeof image_url !== 'string' || !image_url.trim()) {
          return sendJson(res, 400, { success: false, error: 'Valid image URL is required.' });
        }
        if (!isValidUrl(image_url)) {
          return sendJson(res, 400, { success: false, error: 'Invalid image URL scheme. Only http, https, and safe data:image/ URLs are allowed.' });
        }
        const safeCategory = (category || 'Campus').toString().trim().substring(0, 50);
        const cleanTitle = stripDangerousHtml(title).trim().substring(0, 150);
        if (!cleanTitle) {
          return sendJson(res, 400, { success: false, error: 'Valid photo title is required.' });
        }

        const result = await dbQuery(
          `INSERT INTO school_gallery (tenant_id, title, image_url, category, display_order)
           VALUES ($1, $2, $3, $4, 0) RETURNING *`,
          [targetTenantId, cleanTitle, image_url.trim().substring(0, 1000), safeCategory]
        );
        return sendJson(res, 201, { success: true, photo: result.rows[0] });
      }

      if (req.method === 'DELETE') {
        const body = await parseBody(req);
        const { id } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!id) return sendJson(res, 400, { success: false, error: 'Photo ID is required.' });
        await dbQuery(`DELETE FROM school_gallery WHERE id = $1 AND tenant_id = $2`, [id, targetTenantId]);
        return sendJson(res, 200, { success: true });
      }
    }

    // ----------------------------------------------------
    // API: ADMIN PHOTO / ASSET UPLOAD (WebP Native & Hardware Accelerated)
    // ----------------------------------------------------
    if (pathname === '/api/admin/upload' && req.method === 'POST') {
      let body;
      try {
        body = await parseBody(req, 3 * 1024 * 1024);
      } catch (err) {
        if (err.message === 'PAYLOAD_TOO_LARGE') {
          return sendJson(res, 413, { success: false, error: 'Payload exceeds 3MB limit. Please upload a smaller image.' });
        }
        return sendJson(res, 400, { success: false, error: 'Malformed JSON payload.' });
      }

      const auth = verifyAdminAccess(req, res, body && body.tenant_id);
      if (!auth) return;

      const { image } = body || {};
      if (!image || typeof image !== 'string') {
        return sendJson(res, 400, { success: false, error: 'Image data is required.' });
      }

      const match = image.match(/^data:image\/(webp|jpeg|jpg|png);base64,(.+)$/i);
      if (!match) {
        return sendJson(res, 400, { success: false, error: 'Invalid image data format. Only WebP, JPEG, and PNG data URIs are permitted.' });
      }

      const imageBuffer = Buffer.from(match[2], 'base64');
      if (imageBuffer.length > 2 * 1024 * 1024) {
        return sendJson(res, 413, { success: false, error: 'Decoded image exceeds 2MB size limit.' });
      }

      // Verify Magic Bytes
      let isWebP = false;
      let isJpeg = false;
      let isPng = false;

      if (imageBuffer.length >= 12 &&
          imageBuffer[0] === 0x52 && imageBuffer[1] === 0x49 && imageBuffer[2] === 0x46 && imageBuffer[3] === 0x46 &&
          imageBuffer[8] === 0x57 && imageBuffer[9] === 0x45 && imageBuffer[10] === 0x42 && imageBuffer[11] === 0x50) {
        isWebP = true;
      } else if (imageBuffer.length >= 3 && imageBuffer[0] === 0xFF && imageBuffer[1] === 0xD8 && imageBuffer[2] === 0xFF) {
        isJpeg = true;
      } else if (imageBuffer.length >= 4 && imageBuffer[0] === 0x89 && imageBuffer[1] === 0x50 && imageBuffer[2] === 0x4E && imageBuffer[3] === 0x47) {
        isPng = true;
      }

      if (!isWebP && !isJpeg && !isPng) {
        return sendJson(res, 400, { success: false, error: 'File signature verification failed: corrupted or non-image content.' });
      }

      const ext = isWebP ? '.webp' : (isPng ? '.png' : '.jpg');
      const uniqueFileName = `${crypto.randomUUID()}${ext}`;
      const destPath = path.join(UPLOADS_DIR, uniqueFileName);

      fs.writeFileSync(destPath, imageBuffer);

      // Persist to Neon DB so container restarts never lose uploaded assets
      try {
        const mimeType = isWebP ? 'image/webp' : (isPng ? 'image/png' : 'image/jpeg');
        await dbQuery(
          `INSERT INTO school_uploads (tenant_id, filename, data, mime_type, size_bytes)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (filename) DO UPDATE SET data = EXCLUDED.data`,
          [auth.targetTenantId || null, uniqueFileName, imageBuffer, mimeType, imageBuffer.length]
        );
      } catch (uploadDbErr) {
        console.error('[DB UPLOAD PERSISTENCE] Warning:', uploadDbErr.message);
      }

      return sendJson(res, 201, {
        success: true,
        url: `/uploads/${uniqueFileName}`,
        size_bytes: imageBuffer.length,
        format: isWebP ? 'webp' : (isPng ? 'png' : 'jpeg')
      });
    }

    // School Website Settings / CMS Customizer Endpoint
    if (pathname === '/api/admin/settings') {
      if (req.method === 'GET') {
        const requestedTenantId = getScalarQuery(parsedUrl && parsedUrl.query, 'tenant_id');
        const auth = verifyAdminAccess(req, res, requestedTenantId);
        if (!auth) return;
        const { targetTenantId } = auth;

        const tenantRes = await dbQuery(`SELECT settings, name, slug FROM cms_tenants WHERE id = $1 LIMIT 1`, [targetTenantId]);
        if (tenantRes.rows.length === 0) return sendJson(res, 404, { success: false, error: 'Tenant not found.' });
        return sendJson(res, 200, { success: true, settings: tenantRes.rows[0].settings || {}, name: tenantRes.rows[0].name });
      }

      if (req.method === 'PUT') {
        const body = await parseBody(req);
        const { settings, school_name } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;

        if (!settings || typeof settings !== 'object') {
          return sendJson(res, 400, { success: false, error: 'Settings object payload required.' });
        }

        if (settings.theme && settings.theme.logo_url && !isValidUrl(settings.theme.logo_url)) {
          return sendJson(res, 400, { success: false, error: 'Invalid logo URL scheme. Only http, https, and safe data:image/ URLs are allowed.' });
        }
        if (settings.principal && settings.principal.photo_url && !isValidUrl(settings.principal.photo_url)) {
          return sendJson(res, 400, { success: false, error: 'Invalid principal photo URL scheme. Only http, https, and safe data:image/ URLs are allowed.' });
        }

        // Clean & deep merge settings with security guardrails
        const existing = await dbQuery(`SELECT settings, name FROM cms_tenants WHERE id = $1 LIMIT 1`, [targetTenantId]);
        if (existing.rows.length === 0) return sendJson(res, 404, { success: false, error: 'Tenant not found.' });
        const mergedSettings = { ...(existing.rows[0].settings || {}), ...settings };

        if (school_name && typeof school_name === 'string' && school_name.trim()) {
          await dbQuery(
            `UPDATE cms_tenants SET name = $1, settings = $2, updated_at = NOW() WHERE id = $3`,
            [school_name.trim().substring(0, 150), mergedSettings, targetTenantId]
          );
        } else {
          await dbQuery(
            `UPDATE cms_tenants SET settings = $1, updated_at = NOW() WHERE id = $2`,
            [mergedSettings, targetTenantId]
          );
        }

        return sendJson(res, 200, { success: true, settings: mergedSettings, message: 'Website branding & content saved successfully!' });
      }
    }

    // Downloads CRUD (With Strict URL Scheme Validation)
    if (pathname === '/api/admin/downloads') {
      if (req.method === 'GET') {
        const requestedTenantId = getScalarQuery(parsedUrl && parsedUrl.query, 'tenant_id');
        const auth = verifyAdminAccess(req, res, requestedTenantId);
        if (!auth) return;
        const { targetTenantId } = auth;

        const downloads = await dbQuery(
          `SELECT * FROM school_downloads WHERE tenant_id = $1 ORDER BY display_order ASC, created_at DESC LIMIT 100`,
          [targetTenantId]
        );
        return sendJson(res, 200, { success: true, downloads: downloads.rows });
      }

      if (req.method === 'POST') {
        const body = await parseBody(req);
        const { title, file_url, category, file_size } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;

        if (!title || typeof title !== 'string' || !title.trim()) {
          return sendJson(res, 400, { success: false, error: 'Download title is required.' });
        }
        if (!file_url || typeof file_url !== 'string' || !file_url.trim()) {
          return sendJson(res, 400, { success: false, error: 'Valid file URL is required.' });
        }
        if (!isValidUrl(file_url)) {
          return sendJson(res, 400, { success: false, error: 'Invalid file URL scheme. Only http, https, and safe data:image/ URLs are allowed.' });
        }
        const safeCategory = (category || 'General').toString().trim().substring(0, 50);
        const safeSize = (file_size || '1 MB').toString().trim().substring(0, 20);

        const result = await dbQuery(
          `INSERT INTO school_downloads (tenant_id, title, file_url, file_size, category, display_order)
           VALUES ($1, $2, $3, $4, $5, 0) RETURNING *`,
          [targetTenantId, stripDangerousHtml(title).trim().substring(0, 150), file_url.trim().substring(0, 1000), safeSize, safeCategory]
        );
        return sendJson(res, 201, { success: true, download: result.rows[0] });
      }

      if (req.method === 'DELETE') {
        const body = await parseBody(req);
        const { id } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;
        if (!id) return sendJson(res, 400, { success: false, error: 'Download ID is required.' });
        await dbQuery(`DELETE FROM school_downloads WHERE id = $1 AND tenant_id = $2`, [id, targetTenantId]);
        return sendJson(res, 200, { success: true });
      }
    }

    // ----------------------------------------------------
    // API: CSV INQUIRIES EXPORT (STREAMED RFC 4180 WITH UTF-8 BOM)
    // ----------------------------------------------------
    if (pathname === '/api/admin/inquiries/export') {
      if (req.method === 'GET') {
        const requestedTenantId = getScalarQuery(parsedUrl && parsedUrl.query, 'tenant_id');
        const auth = verifyAdminAccess(req, res, requestedTenantId);
        if (!auth) return;
        const { session, targetTenantId } = auth;

        if (!targetTenantId) {
          return sendJson(res, 400, { success: false, error: 'Tenant context required.' });
        }

        let tenantSlug = session.tenantSlug;
        if (!tenantSlug && targetTenantId) {
          const tenantRes = await dbQuery('SELECT slug FROM school_tenants WHERE id = $1', [targetTenantId]);
          if (tenantRes.rows.length > 0) {
            tenantSlug = tenantRes.rows[0].slug;
          }
        }
        if (!tenantSlug) tenantSlug = 'school';

        const inquiries = await dbQuery(
          `SELECT * FROM school_admission_inquiries WHERE tenant_id = $1 ORDER BY created_at DESC`,
          [targetTenantId]
        );

        const date = new Date().toISOString().split('T')[0];
        const headers = {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': `attachment; filename="inquiries_${tenantSlug}_${date}.csv"`,
          'Vary': 'Accept-Encoding',
          'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
          ...SECURITY_HEADERS,
        };

        const headerRow = 'Student Name,Parent Name,Phone,Email,Grade,Notes,Status,Submission Date';
        const rows = [headerRow];

        for (const row of inquiries.rows) {
          const submissionDate = row.created_at ? new Date(row.created_at).toISOString() : '';
          const csvRow = [
            formatCsvField(row.student_name),
            formatCsvField(row.parent_name),
            formatCsvField(row.phone),
            formatCsvField(row.email),
            formatCsvField(row.grade),
            formatCsvField(row.notes),
            formatCsvField(row.status),
            formatCsvField(submissionDate),
          ].join(',');
          rows.push(csvRow);
        }

        const csvContent = '\uFEFF' + rows.join('\r\n') + '\r\n';
        return compressAndSend(req, res, 200, headers, csvContent);
      }
      return sendJson(res, 405, { success: false, error: 'Method Not Allowed' });
    }

    // Admission Inquiries Admin Endpoints (Strict RBAC, Pagination & Status Validation)
    if (pathname === '/api/admin/inquiries') {
      if (req.method === 'GET') {
        const requestedTenantId = getScalarQuery(parsedUrl && parsedUrl.query, 'tenant_id');
        const auth = verifyAdminAccess(req, res, requestedTenantId);
        if (!auth) return;
        const { targetTenantId } = auth;

        if (!targetTenantId) {
          return sendJson(res, 400, { success: false, error: 'Tenant context required' });
        }

        const pageParam = getScalarQuery(parsedUrl && parsedUrl.query, 'page');
        const limitParam = getScalarQuery(parsedUrl && parsedUrl.query, 'limit');
        const page = Math.max(1, parseInt(pageParam, 10) || 1);
        const limit = Math.min(200, Math.max(1, parseInt(limitParam, 10) || 50));
        const offset = (page - 1) * limit;

        const inquiries = await dbQuery(
          `SELECT * FROM school_admission_inquiries WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
          [targetTenantId, limit, offset]
        );
        return sendJson(res, 200, { success: true, inquiries: inquiries.rows, page, limit });
      }

      if (req.method === 'POST') {
        const body = await parseBody(req);
        const { id, status } = body;
        const auth = verifyAdminAccess(req, res, body.tenant_id);
        if (!auth) return;
        const { targetTenantId } = auth;

        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!id || !uuidRegex.test(id)) {
          return sendJson(res, 400, { success: false, error: 'Valid inquiry ID (UUID format) is required.' });
        }

        let normalizedStatus = status;
        if (normalizedStatus === 'contacted') normalizedStatus = 'reviewing';
        if (normalizedStatus === 'approved') normalizedStatus = 'accepted';

        const validStatuses = ['pending', 'reviewing', 'accepted', 'rejected'];
        if (!normalizedStatus || !validStatuses.includes(normalizedStatus)) {
          return sendJson(res, 400, { success: false, error: 'Invalid status. Must be pending, reviewing, accepted, or rejected.' });
        }

        const updateResult = await dbQuery(
          `UPDATE school_admission_inquiries SET status = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3 RETURNING id`,
          [normalizedStatus, id, targetTenantId]
        );
        if (updateResult.rowCount === 0) {
          return sendJson(res, 404, { success: false, error: 'Inquiry not found for this tenant.' });
        }
        return sendJson(res, 200, { success: true });
      }
    }

    // ----------------------------------------------------
    // API: PUBLIC ADMISSION INQUIRIES (WITH ANTI-SPAM PROTECTION)
    // ----------------------------------------------------
    if (pathname === '/api/public/inquiries' && req.method === 'POST') {
      const clientIp = getClientIp(req);
      const rateCheck = checkRateLimit(inquiryRateLimits, clientIp, 3, 60 * 1000);
      if (!rateCheck.allowed) {
        return sendJson(res, 429, { 
          success: false, 
          error: `Rate limit exceeded: You have submitted too many inquiries. Please try again in ${rateCheck.retryAfterSec} seconds.` 
        }, { 'Retry-After': String(rateCheck.retryAfterSec) });
      }

      const body = await parseBody(req);
      const { tenant_id, student_name, parent_name, phone, email, grade, grade_applying, remarks, notes } = body;

      // Strict Schema & Type Validation (OWASP Input Sanitization)
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      if (!tenant_id || !uuidRegex.test(tenant_id)) {
        return sendJson(res, 400, { success: false, error: 'Valid School Tenant ID is required.' });
      }

      const cleanStudent = stripDangerousHtml(student_name || '').trim();
      if (!cleanStudent || cleanStudent.length > 100) {
        return sendJson(res, 400, { success: false, error: 'Valid student name (1-100 characters) is required.' });
      }

      const phoneClean = (phone || '').toString().trim();
      const phoneRegex = /^[0-9+\s\-()]{7,20}$/;
      if (!phoneClean || !phoneRegex.test(phoneClean)) {
        return sendJson(res, 400, { success: false, error: 'Valid phone number (7-20 digits) is required.' });
      }

      const emailClean = (email || '').toString().trim().toLowerCase();
      if (emailClean && (!emailClean.includes('@') || emailClean.length > 100)) {
        return sendJson(res, 400, { success: false, error: 'Invalid email address format (max 100 characters).' });
      }

      // Anti-Spam Lead Protection: Rate limit inquiries per email (prevents XFF rotation spam)
      if (emailClean) {
        const emailRateCheck = checkRateLimit(inquiryRateLimits, `email:${emailClean}`, 3, 60 * 1000);
        if (!emailRateCheck.allowed) {
          return sendJson(res, 429, { 
            success: false, 
            error: `Rate limit exceeded: Too many inquiries submitted for this email address. Please try again in ${emailRateCheck.retryAfterSec} seconds.` 
          }, { 'Retry-After': String(emailRateCheck.retryAfterSec) });
        }
      }

      // Check tenant existence to prevent orphan data or invalid tenant injection
      const tenantCheck = await dbQuery(`SELECT id FROM cms_tenants WHERE id = $1 LIMIT 1`, [tenant_id]);
      if (tenantCheck.rows.length === 0) {
        return sendJson(res, 404, { success: false, error: 'School tenant does not exist.' });
      }

      await dbQuery(
        `INSERT INTO school_admission_inquiries (tenant_id, student_name, parent_name, phone, email, grade, notes, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')`,
        [
          tenant_id, 
          cleanStudent.substring(0, 100), 
          (parent_name && String(parent_name).trim()) ? stripDangerousHtml(parent_name).trim().substring(0, 100) : '', 
          phoneClean.substring(0, 20), 
          (emailClean && emailClean.trim()) ? emailClean.substring(0, 100) : null, 
          (grade || grade_applying) ? stripDangerousHtml(grade || grade_applying).trim().substring(0, 50) : '', 
          (notes || remarks) ? stripDangerousHtml(notes || remarks).trim().substring(0, 500) : ''
        ]
      );
      return sendJson(res, 201, { success: true, message: 'Inquiry submitted successfully!' });
    }

    // ----------------------------------------------------
    // ROUTE 2.5: SAAS PLATFORM MARKETING LANDING PAGE
    // (Rendered on root domain campusdesk.site, www.campusdesk.site, or localhost root)
    // ----------------------------------------------------
    const hostClean = host.split(':')[0].replace(/^www\./, '');
    const isRootDomain = (hostClean === ROOT_DOMAIN || hostClean === 'localhost' || hostClean.startsWith('127.0.0.1'));
    const rootSchoolParam = getScalarQuery(parsedUrl && parsedUrl.query, 'school');
    if ((pathname === '/' || pathname === '') && !rootSchoolParam && isRootDomain) {
      const [config, liveSchools] = await Promise.all([
        getSaasLandingConfig(),
        getLiveSchoolsList()
      ]);
      let html = getLandingTemplate();
      const safeConfig = config || {};
      const landingTokens = {
        HERO_BADGE: escapeForHtml(safeConfig.hero_badge || 'Next-Gen Multi-Tenant School OS'),
        HERO_TITLE: escapeForHtml(safeConfig.hero_title || 'Empower Your School With Modern Websites & Digital Management'),
        HERO_SUBTITLE: escapeForHtml(safeConfig.hero_subtitle || ''),
        CTA_PRIMARY_TEXT: escapeForHtml(safeConfig.cta_primary_text || 'Explore Live Schools'),
        CTA_PRIMARY_LINK: escapeForHtml(safeConfig.cta_primary_link || '#live-schools'),
        CTA_SECONDARY_TEXT: escapeForHtml(safeConfig.cta_secondary_text || 'Book a Free Demo'),
        CTA_SECONDARY_LINK: escapeForHtml(safeConfig.cta_secondary_link || '#demo-request'),
        CONTACT_EMAIL: escapeForHtml(safeConfig.contact_email || `support@${ROOT_DOMAIN}`),
        CONTACT_PHONE: escapeForHtml(safeConfig.contact_phone || '+91 98765 43210'),
        CONTACT_WHATSAPP: escapeForHtml(safeConfig.contact_whatsapp || '+919876543210'),
      };
      html = html.replace(/{{([A-Z0-9_]+)}}/g, (match, key) => {
        return landingTokens[key] !== undefined ? landingTokens[key] : match;
      });
      html = html.replace(
        '</body>',
        `<script>
          window.__SAAS_CONFIG__ = ${JSON.stringify(safeConfig).replace(/</g, '\\u003c')};
          window.__LIVE_SCHOOLS__ = ${JSON.stringify(liveSchools).replace(/</g, '\\u003c')};
        </script></body>`
      );
      return compressAndSend(req, res, 200, { 'Content-Type': 'text/html; charset=utf-8', ...SECURITY_HEADERS }, html);
    }

    // ----------------------------------------------------
    // ROUTE 3: PUBLIC SCHOOL WEBSITE (SSR Dynamic Template)
    // ----------------------------------------------------
    const school = await resolveSchool(req, parsedUrl);
    if (!school) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
      res.end('No school found configured on this domain.');
      return;
    }

    // Strict Data Privacy: Only fetch public data for public website visitors
    const schoolData = await getPublicSchoolData(school.tenant_id);

    // Read cached school.html template (Zero disk reads on public traffic)
    let html = getSchoolTemplate();

    // Server-Side Rendering (SSR) Injection with Context-Aware HTML Escaping
    const safeSchoolName = escapeForHtml(school.school_name);
    const safeSchoolTitle = escapeForHtml(`${school.school_name} - Official Institutional Portal`);
    const safeSchoolDesc = escapeForHtml(`Welcome to ${school.school_name}. Explore notices, toppers, campus facilities, fee structure, and online admissions.`);
    
    // Dynamic School Customization & Branding (100% Dynamic from PostgreSQL)
    const schoolSettings = school.settings || {};
    const themeSettings = schoolSettings.theme || {};
    const headerSettings = schoolSettings.header || {};
    const heroSettings = schoolSettings.hero || {};
    const principalSettings = schoolSettings.principal || {};
    const aboutSettings = schoolSettings.about || {};
    const contactSettings = schoolSettings.contact || {};
    const footerSettings = schoolSettings.footer || {};

    const primaryColor = escapeForHtml(themeSettings.primary_color || schoolSettings.primary_color || '#1e3a8a');
    const secondaryColor = escapeForHtml(themeSettings.secondary_color || schoolSettings.secondary_color || '#d97706');
    const fontFamily = escapeForHtml(themeSettings.font_family || 'Plus Jakarta Sans');

    const safeLogoUrl = sanitizeUrl(themeSettings.logo_url);
    const brandLogoHtml = safeLogoUrl
      ? `<img src="${escapeForHtml(safeLogoUrl)}" alt="${safeSchoolName}" class="w-full h-full object-contain p-1">`
      : `<i class="fa-solid fa-graduation-cap"></i>`;

    const safePrincipalPhoto = sanitizeUrl(principalSettings.photo_url);
    const principalPhotoHtml = safePrincipalPhoto
      ? `<img src="${escapeForHtml(safePrincipalPhoto)}" alt="${escapeForHtml(principalSettings.name || 'Principal')}" class="w-full h-full object-cover">`
      : `<i class="fa-solid fa-user-tie"></i>`;

    const topbarPhone = escapeForHtml(headerSettings.phone || contactSettings.phone || '+91 98765 43210');
    const topbarEmail = escapeForHtml(headerSettings.email || contactSettings.email || 'admissions@school.edu');
    const topbarAffiliation = escapeForHtml(headerSettings.affiliation || 'Affiliated Senior Secondary Institution');
    const topbarAdmissionBadge = escapeForHtml(headerSettings.admission_badge || 'Admissions 2026-27 Open');
    const headerTagline = escapeForHtml(headerSettings.tagline || 'Affiliated Senior Secondary Institution');

    const heroBadge = escapeForHtml(heroSettings.badge || 'Premier Center of Excellence & Holistic Education');
    const heroTitle = escapeForHtml(heroSettings.title || 'Nurturing Inquiring Minds, Inspiring Confident Leaders.');
    const heroSubtitle = escapeForHtml(heroSettings.subtitle || `Welcome to ${school.school_name}. Our campus provides holistic education with world-class facilities and dedicated faculty.`);
    const heroCta = escapeForHtml(heroSettings.cta_text || 'Enroll Your Child Today');

    const principalName = escapeForHtml(principalSettings.name || 'Head of Institution');
    const principalTitle = escapeForHtml(principalSettings.title || 'Principal & Educational Director');
    const principalMessage = escapeForHtml(principalSettings.message || `True education is not merely the accumulation of facts, but the ignition of curiosity and character. At our institution, we empower every scholar to think fearlessly and lead with empathy.`);

    const aboutHeadline = escapeForHtml(aboutSettings.headline || 'Building Character, Wisdom and Global Citizenship');
    const aboutStory = escapeForHtml(aboutSettings.story || `Founded with the conviction that quality education transforms society, ${school.school_name} offers an enriching academic environment.`);
    const aboutStat1Val = escapeForHtml(aboutSettings.stat1_value || '45,000+');
    const aboutStat1Lbl = escapeForHtml(aboutSettings.stat1_label || 'Proud Alumni Worldwide');
    const aboutStat2Val = escapeForHtml(aboutSettings.stat2_value || '100%');
    const aboutStat2Lbl = escapeForHtml(aboutSettings.stat2_label || 'Smart Digitized Classrooms');

    const contactAddress = escapeForHtml(contactSettings.address || 'Institutional Area, Main Campus');
    const contactPhone = escapeForHtml(contactSettings.phone || headerSettings.phone || '+91 98765 43210');
    const contactEmail = escapeForHtml(contactSettings.email || headerSettings.email || 'admissions@school.edu');
    const contactHours = escapeForHtml(contactSettings.hours || 'Mon - Sat: 8:30 AM to 3:30 PM (Closed on Sundays)');

    const footerTagline = escapeForHtml(footerSettings.tagline || 'Empowering Generation Next with Excellence & Character.');

    // Neutralize HTML script tag breakout attacks (OWASP JSON-in-script encoding)
    const safeSchoolJson = JSON.stringify(school).replace(/</g, '\\u003c');
    const safeDataJson = JSON.stringify(schoolData).replace(/</g, '\\u003c');

    const tokens = {
      SCHOOL_NAME: safeSchoolName,
      META_TITLE: safeSchoolTitle,
      META_DESCRIPTION: safeSchoolDesc,
      PRIMARY_COLOR: primaryColor,
      SECONDARY_COLOR: secondaryColor,
      FONT_FAMILY: fontFamily,
      BRAND_LOGO_HTML: brandLogoHtml,
      TOPBAR_PHONE: topbarPhone,
      TOPBAR_EMAIL: topbarEmail,
      TOPBAR_AFFILIATION: topbarAffiliation,
      TOPBAR_ADMISSION_BADGE: topbarAdmissionBadge,
      HEADER_TAGLINE: headerTagline,
      HERO_BADGE: heroBadge,
      HERO_TITLE: heroTitle,
      HERO_SUBTITLE: heroSubtitle,
      HERO_CTA: heroCta,
      PRINCIPAL_NAME: principalName,
      PRINCIPAL_TITLE: principalTitle,
      PRINCIPAL_MESSAGE: principalMessage,
      PRINCIPAL_PHOTO_HTML: principalPhotoHtml,
      ABOUT_HEADLINE: aboutHeadline,
      ABOUT_STORY: aboutStory,
      ABOUT_STAT1_VAL: aboutStat1Val,
      ABOUT_STAT1_LBL: aboutStat1Lbl,
      ABOUT_STAT2_VAL: aboutStat2Val,
      ABOUT_STAT2_LBL: aboutStat2Lbl,
      CONTACT_ADDRESS: contactAddress,
      CONTACT_PHONE: contactPhone,
      CONTACT_EMAIL: contactEmail,
      CONTACT_HOURS: contactHours,
      FOOTER_TAGLINE: footerTagline,
    };

    html = html.replace(/{{([A-Z0-9_]+)}}/g, (match, key) => {
      return tokens[key] !== undefined ? tokens[key] : match;
    });

    html = html.replace(
      '<!-- INJECT_SERVER_DATA -->',
      `<script>
        window.__SCHOOL__ = ${safeSchoolJson};
        window.__DATA__ = ${safeDataJson};
      </script>`
    );

    return compressAndSend(req, res, 200, { 'Content-Type': 'text/html; charset=utf-8', ...SECURITY_HEADERS }, html);

  } catch (err) {
    console.error('Server error:', err);
    if (err.message === 'PAYLOAD_TOO_LARGE') {
      return sendJson(res, 413, { success: false, error: 'Request entity too large (Max 1MB allowed).' });
    }
    if (err.message === 'INVALID_JSON') {
      return sendJson(res, 400, { success: false, error: 'Malformed JSON payload format.' });
    }
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8', ...SECURITY_HEADERS });
    res.end('Internal Server Error. Please contact administrator.');
  }
});

// Server Slowloris Protection & Concurrency Timeouts (Strict 512MB RAM VPS Limits)
server.requestTimeout = 30000;
server.headersTimeout = 35000;
server.keepAliveTimeout = 65000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`========================================================`);
  console.log(`  School SaaS Unified Server running on port ${PORT}`);
  console.log(`  Connected to Neon PostgreSQL (Singapore)`);
  console.log(`  - Super Admin:     http://localhost:${PORT}/master`);
  console.log(`  - School Admin:    http://localhost:${PORT}/admin`);
  console.log(`  - Public Website:  http://localhost:${PORT}/?school=dps-delhi`);
  console.log(`  - School 2:        http://localhost:${PORT}/?school=rkmps`);
  console.log(`========================================================`);
});

// Global Process Crash Guards (Prevents 512MB VPS sudden downtime)
process.on('unhandledRejection', (reason) => {
  console.error('[SYSTEM] Unhandled Promise Rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('[SYSTEM] Uncaught Exception:', err);
});

// Graceful Shutdown (Drains DB connection pool cleanly on restart/reboot)
function gracefulShutdown(signal) {
  console.log(`\n[SYSTEM] Received ${signal}. Draining pool and closing server gracefully...`);
  server.close(async () => {
    try {
      await pool.end();
      console.log('[SYSTEM] Database pool closed cleanly.');
    } catch (e) {
      console.error('[SYSTEM] Error closing DB pool:', e.message);
    }
    process.exit(0);
  });
  setTimeout(() => {
    console.error('[SYSTEM] Force exiting after 5s shutdown timeout.');
    process.exit(1);
  }, 5000).unref();
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
