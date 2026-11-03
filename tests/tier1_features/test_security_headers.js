/**
 * Tier 1 - Feature Coverage: Security Headers
 * Verifies OWASP-grade security headers on all HTTP endpoints (API & HTML).
 * Requirements: R1, PROJECT.md Feature 2
 */

const { defaultClient } = require('../helpers/test_client');
const { assertEqual, assertHeader, assertContains } = require('../helpers/assertions');

module.exports = {
  name: 'Tier 1 - Security Headers Feature Coverage',
  tests: [
    {
      name: 'T1_SEC_01: X-Content-Type-Options nosniff is set on HTML and API endpoints',
      async run() {
        const resHtml = await defaultClient.get('/?school=dps-delhi');
        assertHeader(resHtml.headers, 'x-content-type-options', 'nosniff', 'HTML endpoint missing X-Content-Type-Options');

        const resApi = await defaultClient.get('/health');
        assertHeader(resApi.headers, 'x-content-type-options', 'nosniff', 'API endpoint missing X-Content-Type-Options');
      },
    },
    {
      name: 'T1_SEC_02: X-Frame-Options is set to prevent clickjacking',
      async run() {
        const res = await defaultClient.get('/');
        const frameOpt = (res.headers['x-frame-options'] || '').toUpperCase();
        if (frameOpt !== 'SAMEORIGIN' && frameOpt !== 'DENY') {
          throw new Error(`Expected X-Frame-Options to be SAMEORIGIN or DENY, got: ${frameOpt}`);
        }
      },
    },
    {
      name: 'T1_SEC_03: Content-Security-Policy header defines required restrictions',
      async run() {
        const res = await defaultClient.get('/?school=dps-delhi');
        const csp = res.headers['content-security-policy'] || '';
        if (!csp) {
          throw new Error('Content-Security-Policy header is missing on portal response');
        }
        assertContains(csp, "default-src", 'CSP should contain default-src');
        assertContains(csp, "script-src", 'CSP should contain script-src');
        assertContains(csp, "style-src", 'CSP should contain style-src');
      },
    },
    {
      name: 'T1_SEC_04: Referrer-Policy and Permissions-Policy headers are present',
      async run() {
        const res = await defaultClient.get('/health');
        assertHeader(res.headers, 'referrer-policy', 'strict-origin-when-cross-origin', 'Referrer-Policy should be strict-origin-when-cross-origin');
        assertContains(res.headers['permissions-policy'] || '', 'camera=()', 'Permissions-Policy should restrict camera access');
      },
    },
    {
      name: 'T1_SEC_05: Strict-Transport-Security (HSTS) header is enforced for HTTPS security',
      async run() {
        const res = await defaultClient.get('/health');
        const hsts = res.headers['strict-transport-security'];
        if (!hsts) {
          throw new Error('Strict-Transport-Security (HSTS) header is missing from response. Required by R1.');
        }
        assertContains(hsts.toLowerCase(), 'max-age', 'HSTS header must include max-age directive');
      },
    },
    {
      name: 'T1_SEC_06: API responses include Cache-Control no-store to prevent sensitive data caching',
      async run() {
        const res = await defaultClient.get('/health');
        const cacheControl = res.headers['cache-control'] || '';
        assertContains(cacheControl, 'no-store', 'API response must include Cache-Control: no-store');
      },
    },
  ],
};
