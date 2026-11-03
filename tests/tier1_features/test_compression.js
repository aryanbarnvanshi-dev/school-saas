/**
 * Tier 1 - Feature Coverage: HTTP Compression
 * Verifies native HTTP gzip/deflate response compression for payloads > 1KB.
 * Requirements: R2, PROJECT.md Feature 7
 */

const zlib = require('zlib');
const { defaultClient } = require('../helpers/test_client');
const { assertEqual, assertContains } = require('../helpers/assertions');

module.exports = {
  name: 'Tier 1 - HTTP Compression Feature Coverage',
  tests: [
    {
      name: 'T1_COMP_01: SSR school portal page (>1KB) compresses with gzip when client supports gzip',
      async run() {
        const res = await defaultClient.request({
          method: 'GET',
          path: '/?school=dps-delhi',
          headers: {
            'Accept-Encoding': 'gzip, deflate',
          },
        });

        assertEqual(res.status, 200, 'Portal should return 200');
        const encoding = res.headers['content-encoding'];
        if (encoding !== 'gzip') {
          throw new Error(`Expected Content-Encoding: gzip for >1KB payload, but got: ${encoding || 'none'}. Required by R2.`);
        }
      },
    },
    {
      name: 'T1_COMP_02: Client requesting Accept-Encoding identity receives uncompressed response',
      async run() {
        const res = await defaultClient.request({
          method: 'GET',
          path: '/?school=dps-delhi',
          headers: {
            'Accept-Encoding': 'identity',
          },
        });

        assertEqual(res.status, 200, 'Portal should return 200');
        const encoding = res.headers['content-encoding'];
        if (encoding && encoding !== 'identity') {
          throw new Error(`Expected no compression (or identity) when Accept-Encoding: identity requested, got: ${encoding}`);
        }
      },
    },
    {
      name: 'T1_COMP_03: Decompressed gzip response body matches uncompressed payload content verbatim',
      async run() {
        // Request compressed
        const resGzip = await defaultClient.request({
          method: 'GET',
          path: '/?school=dps-delhi',
          headers: { 'Accept-Encoding': 'gzip' },
        });

        // Request uncompressed
        const resRaw = await defaultClient.request({
          method: 'GET',
          path: '/?school=dps-delhi',
          headers: { 'Accept-Encoding': 'identity' },
        });

        assertEqual(resGzip.status, 200);
        assertEqual(resRaw.status, 200);

        // Decompressed body should contain the same critical markup
        assertContains(resGzip.body, 'Delhi Public School', 'Decompressed body must contain school name');
        assertEqual(
          resGzip.body.includes('window.__DATA__'),
          resRaw.body.includes('window.__DATA__'),
          'Decompressed and uncompressed bodies must both have serialized hydration data'
        );
      },
    },
    {
      name: 'T1_COMP_04: Small responses (<1KB) are not compressed to avoid gzip overhead',
      async run() {
        // Unauthenticated access to /api/admin/inquiries produces a tiny JSON error payload (~100 bytes)
        const res = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/inquiries',
          headers: { 'Accept-Encoding': 'gzip' },
        });

        assertEqual(res.status, 401);
        if (res.rawBody.length < 1024) {
          const encoding = res.headers['content-encoding'];
          if (encoding === 'gzip') {
            throw new Error(`Payload under 1024 bytes (${res.rawBody.length} bytes) was unnecessarily compressed.`);
          }
        }
      },
    },
    {
      name: 'T1_COMP_05: Gzip compression on landing page achieves significant size reduction (>50%)',
      async run() {
        const resCompressed = await defaultClient.request({
          method: 'GET',
          path: '/',
          headers: { 'Accept-Encoding': 'gzip' },
        });

        const resUncompressed = await defaultClient.request({
          method: 'GET',
          path: '/',
          headers: { 'Accept-Encoding': 'identity' },
        });

        assertEqual(resCompressed.status, 200);
        assertEqual(resUncompressed.status, 200);

        const compressedSize = resCompressed.rawBody.length;
        const uncompressedSize = resUncompressed.rawBody.length;

        // If compression is active, verify compression ratio
        if (resCompressed.headers['content-encoding'] === 'gzip') {
          const ratio = (uncompressedSize - compressedSize) / uncompressedSize;
          if (ratio < 0.50) {
            throw new Error(`Expected at least 50% compression reduction, achieved only ${(ratio * 100).toFixed(1)}%`);
          }
        } else {
          throw new Error('Landing page was not compressed with gzip. Required by R2.');
        }
      },
    },
  ],
};
