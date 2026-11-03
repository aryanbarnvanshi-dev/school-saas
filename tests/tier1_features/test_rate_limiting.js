/**
 * Tier 1 - Feature Coverage: Rate Limiting
 * Verifies memory-bounded rate limiting across authentication, inquiries, and OTP requests.
 * Requirements: R1, PROJECT.md Feature 1
 */

const { defaultClient } = require('../helpers/test_client');
const { assertEqual, assertContains } = require('../helpers/assertions');
const { FIXTURES } = require('../helpers/db_helper');

module.exports = {
  name: 'Tier 1 - Rate Limiting Feature Coverage',
  tests: [
    {
      name: 'T1_RATE_01: Login returns 401 with remaining attempts on failed credentials',
      async run() {
        const testIp = `198.51.${Date.now() % 200}.11`;
        const res = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/login',
          ip: testIp,
          json: { emailOrUsername: `nonexistent_${Date.now()}@test.com`, password: 'WrongPassword123' },
        });

        assertEqual(res.status, 401, 'Status should be 401 Unauthorized');
        assertEqual(res.json.success, false, 'Success field should be false');
        assertContains(res.json.error, 'attempts remaining', 'Error message should indicate remaining attempts');
      },
    },
    {
      name: 'T1_RATE_02: Login triggers HTTP 429 on 5 consecutive failed attempts',
      async run() {
        const testIp = `198.51.${Date.now() % 200}.12`;
        const targetUser = `lockout_user_${Date.now()}@test.com`;

        // 4 failed attempts
        for (let i = 1; i <= 4; i++) {
          const res = await defaultClient.request({
            method: 'POST',
            path: '/api/auth/login',
            ip: testIp,
            json: { emailOrUsername: targetUser, password: 'WrongPassword' + i },
          });
          assertEqual(res.status, 401, `Attempt ${i} should return 401`);
        }

        // 5th failed attempt triggers 429 lockout
        const res5 = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/login',
          ip: testIp,
          json: { emailOrUsername: targetUser, password: 'WrongPassword5' },
        });

        assertEqual(res5.status, 429, '5th failed attempt should trigger HTTP 429 Too Many Requests');
        assertEqual(res5.json.success, false, 'Response success should be false');
        const err5 = (res5.json.error || '').toLowerCase();
        if (!err5.includes('locked') && !err5.includes('too many') && !err5.includes('try again')) {
          throw new Error(`Expected error message to indicate lockout/rate limit, got: "${res5.json.error}"`);
        }
      },
    },
    {
      name: 'T1_RATE_03: Login rate limit resets upon successful authentication',
      async run() {
        const testIp = `198.51.${Date.now() % 200}.13`;
        // 2 failed attempts
        for (let i = 1; i <= 2; i++) {
          await defaultClient.request({
            method: 'POST',
            path: '/api/auth/login',
            ip: testIp,
            json: { emailOrUsername: 'superadmin', password: 'IncorrectPassword' },
          });
        }

        // Successful authentication
        const successRes = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/login',
          ip: testIp,
          json: { emailOrUsername: 'superadmin', password: process.env.SUPER_ADMIN_PASSWORD || 'SuperAdmin@2026' },
        });

        assertEqual(successRes.status, 200, 'SuperAdmin login should succeed with 200');
        assertEqual(successRes.json.success, true, 'Login response success should be true');

        // Subsequent failure should have full 4 attempts remaining (counter was reset)
        const postFailRes = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/login',
          ip: testIp,
          json: { emailOrUsername: 'superadmin', password: 'WrongPasswordAgain' },
        });
        assertEqual(postFailRes.status, 401, 'Should return 401');
        assertContains(postFailRes.json.error, '4 attempts remaining', 'Counter should have reset after successful login');
      },
    },
    {
      name: 'T1_RATE_04: Public admission inquiry endpoint triggers HTTP 429 when rate limit exceeded',
      async run() {
        const testIp = `198.51.${Date.now() % 200}.14`;
        const dpsTenantId = '9f025e7d-a42c-4c8e-8ea6-c9a8d9c02442';

        const inquiryData = {
          tenant_id: dpsTenantId,
          student_name: 'Rate Limit Test Student',
          parent_name: 'Rate Limit Test Parent',
          phone: '+91 9876543210',
          email: 'ratelimit@example.com',
          grade: 'Grade 5',
          notes: 'Testing inquiry submission rate limiting',
        };

        // Submit inquiries up to the limit
        let triggered429 = false;
        for (let i = 1; i <= 7; i++) {
          const res = await defaultClient.request({
            method: 'POST',
            path: '/api/public/inquiries',
            ip: testIp,
            json: inquiryData,
          });

          if (res.status === 429) {
            triggered429 = true;
            assertEqual(res.json.success, false, 'Rate limited inquiry response success should be false');
            assertContains(res.json.error.toLowerCase(), 'limit', 'Error should mention rate limit exceeded');
            break;
          }
        }

        assertEqual(triggered429, true, 'Inquiry submissions should trigger HTTP 429 within 7 requests');
      },
    },
    {
      name: 'T1_RATE_05: Password reset OTP request enforces spam cooldown (HTTP 429 on rapid requests)',
      async run() {
        const testIp = '198.51.100.15';
        const targetEmail = FIXTURES.TEST_ADMIN_RKM.email;

        // First OTP request
        const res1 = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/forgot-password',
          ip: testIp,
          json: { email: targetEmail },
        });
        assertEqual(res1.status, 200, 'First forgot-password request should return 200');

        // Immediate second OTP request (within 60-second cooldown)
        const res2 = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/forgot-password',
          ip: testIp,
          json: { email: targetEmail },
        });

        assertEqual(res2.status, 429, 'Immediate duplicate OTP request should return HTTP 429');
        assertEqual(res2.json.success, false, 'Success should be false on rate limited OTP request');
        assertContains(res2.json.error.toLowerCase(), 'wait', 'Error should instruct user to wait');
      },
    },
    {
      name: 'T1_RATE_06: Password reset OTP brute-force lockout invalidates OTP after 5 wrong attempts',
      async run() {
        const testIp = '198.51.100.16';
        const targetEmail = FIXTURES.TEST_ADMIN_DPS.email;

        // Trigger OTP request
        const reqRes = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/forgot-password',
          ip: testIp,
          json: { email: targetEmail },
        });
        assertEqual(reqRes.status, 200);

        // Submit 4 incorrect OTPs
        for (let i = 1; i <= 4; i++) {
          const res = await defaultClient.request({
            method: 'POST',
            path: '/api/auth/reset-password',
            ip: testIp,
            json: { email: targetEmail, otp: '00000' + i, newPassword: 'NewSecurePassword123!' },
          });
          assertEqual(res.status, 400, `Incorrect OTP attempt ${i} should return 400`);
        }

        // 5th incorrect OTP should permanently invalidate token and return 429
        const res5 = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/reset-password',
          ip: testIp,
          json: { email: targetEmail, otp: '999999', newPassword: 'NewSecurePassword123!' },
        });

        assertEqual(res5.status, 429, '5th incorrect OTP should return HTTP 429');
        assertContains(res5.json.error.toLowerCase(), 'invalidated', 'Error message should state OTP is invalidated');
      },
    },
  ],
};
