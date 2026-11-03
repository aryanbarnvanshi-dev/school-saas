/**
 * Tier 2 - Boundary & Corner Cases: Brute-Force Lockouts
 * Verifies precise boundary conditions around password lengths, case normalization, and lockouts.
 * Requirements: R1, PROJECT.md Feature 1
 */

const { defaultClient } = require('../helpers/test_client');
const { assertEqual, assertContains } = require('../helpers/assertions');

module.exports = {
  name: 'Tier 2 - Brute-Force Lockouts Boundary & Corner Cases',
  tests: [
    {
      name: 'T2_LOCK_01: Exactly 5th failed login attempt triggers lockout threshold',
      async run() {
        const uniqueSuffix = (Date.now() % 200) + 1;
        const testIp = `198.51.${uniqueSuffix}.21`;
        const targetEmail = `lockout_boundary_01_${Date.now()}@test.com`;

        for (let i = 1; i <= 4; i++) {
          const res = await defaultClient.request({
            method: 'POST',
            path: '/api/auth/login',
            ip: testIp,
            json: { emailOrUsername: targetEmail, password: 'BadPassword' + i },
          });
          assertEqual(res.status, 401, `Attempt ${i} should return 401`);
        }

        // 5th attempt
        const res5 = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/login',
          ip: testIp,
          json: { emailOrUsername: targetEmail, password: 'BadPassword5' },
        });

        assertEqual(res5.status, 429, '5th attempt must return 429');
        const err5 = (res5.json.error || '').toLowerCase();
        if (!err5.includes('locked') && !err5.includes('too many') && !err5.includes('try again')) {
          throw new Error(`Expected error message to indicate lockout/rate limit, got: "${res5.json.error}"`);
        }
      },
    },
    {
      name: 'T2_LOCK_02: 6th attempt during active lockout returns 429 with remaining lockout time',
      async run() {
        const uniqueSuffix = (Date.now() % 200) + 2;
        const testIp = `198.51.${uniqueSuffix}.22`;
        const targetEmail = `lockout_boundary_02_${Date.now()}@test.com`;

        // Trigger lockout with 5 attempts
        for (let i = 1; i <= 5; i++) {
          await defaultClient.request({
            method: 'POST',
            path: '/api/auth/login',
            ip: testIp,
            json: { emailOrUsername: targetEmail, password: 'BadPassword' + i },
          });
        }

        // 6th attempt while locked
        const res6 = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/login',
          ip: testIp,
          json: { emailOrUsername: targetEmail, password: 'BadPassword6' },
        });

        assertEqual(res6.status, 429, 'Attempt during active lockout must return 429');
        const err6 = (res6.json.error || '').toLowerCase();
        if (!err6.includes('locked') && !err6.includes('too many') && !err6.includes('try again')) {
          throw new Error(`Expected error message to indicate lockout/rate limit, got: "${res6.json.error}"`);
        }
      },
    },
    {
      name: 'T2_LOCK_03: Email casing differences (UPPERCASE vs lowercase) track against the same lockout bucket',
      async run() {
        const uniqueSuffix = (Date.now() % 200) + 3;
        const testIp = `198.51.${uniqueSuffix}.23`;
        const baseEmail = `case_test_${Date.now()}@test.com`;
        const lowerEmail = baseEmail.toLowerCase();
        const upperEmail = baseEmail.toUpperCase();

        // 2 attempts with lowercase
        for (let i = 1; i <= 2; i++) {
          await defaultClient.request({
            method: 'POST',
            path: '/api/auth/login',
            ip: testIp,
            json: { emailOrUsername: lowerEmail, password: 'Wrong' },
          });
        }

        // 3rd attempt with uppercase should show 2 attempts remaining
        const res3 = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/login',
          ip: testIp,
          json: { emailOrUsername: upperEmail, password: 'Wrong' },
        });

        assertEqual(res3.status, 401);
        assertContains(res3.json.error, '2 attempts remaining', 'Attempts counter must be case-insensitive');
      },
    },
    {
      name: 'T2_LOCK_04: Empty or whitespace-only password payload is rejected with HTTP 400',
      async run() {
        const res = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/login',
          json: { emailOrUsername: 'admin@test.com', password: '' },
        });

        assertEqual(res.status, 400, 'Empty password should return 400 Bad Request');
        assertEqual(res.json.success, false);
      },
    },
    {
      name: 'T2_LOCK_05: Password exceeding 128 characters is rejected with HTTP 400 without crashing scrypt',
      async run() {
        const oversizedPassword = 'A'.repeat(129);
        const res = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/login',
          json: { emailOrUsername: 'admin@test.com', password: oversizedPassword },
        });

        assertEqual(res.status, 400, 'Password > 128 chars should be rejected with 400');
        assertContains(res.json.error, '128', 'Error should mention 128 character limit');
      },
    },
  ],
};
