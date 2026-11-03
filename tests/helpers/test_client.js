/**
 * School SaaS E2E Test Suite - HTTP Test Client Helper
 * Opaque-box HTTP client for executing black-box network tests against server.js
 */

const http = require('http');
const zlib = require('zlib');
const { URL } = require('url');

const DEFAULT_BASE_URL = process.env.TEST_BASE_URL || 'http://127.0.0.1:3000';

class TestClient {
  constructor(baseUrl = DEFAULT_BASE_URL) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.defaultHeaders = {};
  }

  /**
   * Execute an HTTP request against the server
   * @param {Object} opts Request options
   * @returns {Promise<Object>} Response object { status, headers, body, rawBody, json, durationMs }
   */
  async request(opts) {
    const method = (opts.method || 'GET').toUpperCase();
    let reqPath = opts.path || '/';
    if (opts.query) {
      const q = typeof opts.query === 'string' ? opts.query : new URLSearchParams(opts.query).toString();
      reqPath += (reqPath.includes('?') ? '&' : '?') + q;
    }

    const targetUrl = new URL(reqPath, this.baseUrl);
    const headers = { ...this.defaultHeaders, ...(opts.headers || {}) };

    if (opts.token) {
      headers['Authorization'] = `Bearer ${opts.token}`;
    }
    if (opts.ip) {
      headers['X-Forwarded-For'] = opts.ip;
    }
    if (opts.host) {
      headers['Host'] = opts.host;
    }

    let payload = null;
    if (opts.json !== undefined) {
      payload = JSON.stringify(opts.json);
      headers['Content-Type'] = headers['Content-Type'] || 'application/json';
      headers['Content-Length'] = Buffer.byteLength(payload);
    } else if (opts.body !== undefined) {
      payload = opts.body;
      if (typeof payload === 'string') {
        headers['Content-Length'] = Buffer.byteLength(payload);
      } else if (Buffer.isBuffer(payload)) {
        headers['Content-Length'] = payload.length;
      }
    }

    const requestOptions = {
      hostname: targetUrl.hostname,
      port: targetUrl.port || 80,
      path: targetUrl.pathname + targetUrl.search,
      method,
      headers,
      timeout: opts.timeout || 30000,
      ...(opts.agent !== undefined ? { agent: opts.agent } : {}),
    };

    const startTime = Date.now();

    return new Promise((resolve, reject) => {
      const req = http.request(requestOptions, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const durationMs = Date.now() - startTime;
          const rawBody = Buffer.concat(chunks);
          const encoding = res.headers['content-encoding'];

          let bodyBuffer = rawBody;
          if (encoding === 'gzip') {
            try {
              bodyBuffer = zlib.gunzipSync(rawBody);
            } catch (err) {
              // Keep raw buffer if gunzip fails
            }
          } else if (encoding === 'deflate') {
            try {
              bodyBuffer = zlib.inflateSync(rawBody);
            } catch (err) {
              // Keep raw buffer if inflate fails
            }
          }

          const bodyString = bodyBuffer.toString('utf8');
          let parsedJson = null;
          const contentType = res.headers['content-type'] || '';
          if (contentType.includes('application/json')) {
            try {
              parsedJson = JSON.parse(bodyString);
            } catch (e) {
              parsedJson = null;
            }
          }

          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: bodyString,
            rawBody,
            decompressedBuffer: bodyBuffer,
            json: parsedJson,
            durationMs,
          });
        });
      });

      req.on('timeout', () => {
        req.destroy(new Error(`Request timed out after ${opts.timeout || 15000}ms`));
      });

      req.on('error', (err) => {
        reject(err);
      });

      if (payload) {
        req.write(payload);
      }
      req.end();
    });
  }

  get(path, opts = {}) {
    return this.request({ ...opts, method: 'GET', path });
  }

  post(path, json, opts = {}) {
    return this.request({ ...opts, method: 'POST', path, json });
  }

  put(path, json, opts = {}) {
    return this.request({ ...opts, method: 'PUT', path, json });
  }

  delete(path, json, opts = {}) {
    return this.request({ ...opts, method: 'DELETE', path, json });
  }

  /**
   * Convenience helper to authenticate and obtain token
   */
  async login(emailOrUsername, password, ip = null) {
    const opts = {
      path: '/api/auth/login',
      json: { emailOrUsername, password }
    };
    if (ip) opts.ip = ip;
    const res = await this.post('/api/auth/login', { emailOrUsername, password }, ip ? { ip } : {});
    return res;
  }
}

module.exports = {
  TestClient,
  defaultClient: new TestClient(),
};
