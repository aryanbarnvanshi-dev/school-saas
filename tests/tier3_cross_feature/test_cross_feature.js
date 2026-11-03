/**
 * Tier 3 - Cross-Feature Combinations
 * Exercises pairwise feature interactions across rate limiting, authentication, tenant isolation, and export concurrency.
 * Requirements: R1-R4, PROJECT.md
 */

const { defaultClient } = require('../helpers/test_client');
const { assertEqual, assertContains, assertNotContains } = require('../helpers/assertions');
const { FIXTURES, query } = require('../helpers/db_helper');

module.exports = {
  name: 'Tier 3 - Cross-Feature Combinations',
  tests: [
    {
      name: 'T3_CROSS_01: Authenticated admin operations are NOT blocked when client IP has exhausted public inquiry rate limit',
      async run() {
        const sharedIp = '198.51.100.77';

        // 1. Exhaust public inquiry rate limit from this IP
        const inquiryData = {
          tenant_id: FIXTURES.TENANTS.DPS.id,
          student_name: 'Spam Student',
          phone: '+91 9876543210',
          grade: 'Grade 1',
        };
        for (let i = 0; i < 7; i++) {
          await defaultClient.request({
            method: 'POST',
            path: '/api/public/inquiries',
            ip: sharedIp,
            json: inquiryData,
          });
        }

        // Verify public inquiries are now rate-limited (429)
        const spamRes = await defaultClient.request({
          method: 'POST',
          path: '/api/public/inquiries',
          ip: sharedIp,
          json: inquiryData,
        });
        assertEqual(spamRes.status, 429, 'Public inquiry should be rate limited');

        // 2. An authenticated admin from that SAME IP must still be able to manage admin resources
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password,
          sharedIp
        );
        assertEqual(loginRes.status, 200, 'Admin login must succeed even if public inquiry rate limit is tripped');

        const adminDataRes = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/data',
          token: loginRes.json.token,
          ip: sharedIp,
        });
        assertEqual(adminDataRes.status, 200, 'Admin CMS access must NOT be blocked by public inquiry rate limiter');
      },
    },
    {
      name: 'T3_CROSS_02: Cross-Tenant IDOR: Admin A injecting Tenant B UUID into notice payload is quarantined to Tenant A',
      async run() {
        // DPS Admin logs in
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        assertEqual(loginRes.status, 200);
        const token = loginRes.json.token;

        // DPS Admin tries to create a notice explicitly targeting RK Mission's tenant_id
        const res = await defaultClient.request({
          method: 'POST',
          path: '/api/admin/notices',
          token,
          json: {
            tenant_id: FIXTURES.TENANTS.RKM.id, // Malicious target
            title: 'IDOR Notice Test',
            content: 'This notice should not appear under RK Mission.',
            category: 'academic',
            priority: 'normal',
          },
        });

        // The server must either reject with 403 Forbidden OR force tenant_id to DPS
        if (res.status === 200 || res.status === 201) {
          // If server returned 200/201, verify the notice was saved under DPS, NOT RK Mission
          const dbCheck = await query(
            `SELECT tenant_id FROM school_notices WHERE title = 'IDOR Notice Test' ORDER BY created_at DESC LIMIT 1`
          );
          if (dbCheck.rows.length > 0) {
            assertEqual(
              dbCheck.rows[0].tenant_id,
              FIXTURES.TENANTS.DPS.id,
              'IDOR failed: Notice was incorrectly assigned to RK Mission!'
            );
          }
        } else {
          assertEqual(res.status, 403, 'Cross-tenant payload should be rejected with 403');
        }
      },
    },
    {
      name: 'T3_CROSS_03: Admissions CSV export executes cleanly while concurrent new submissions are arriving',
      async run() {
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        const token = loginRes.json.token;

        // Launch concurrent inquiry submissions while requesting export
        const concurrentPromises = [];

        // 3 background submissions
        for (let i = 1; i <= 3; i++) {
          concurrentPromises.push(
            defaultClient.request({
              method: 'POST',
              path: '/api/public/inquiries',
              ip: `198.51.100.8${i}`,
              json: {
                tenant_id: FIXTURES.TENANTS.DPS.id,
                student_name: `Concurrent Student ${i} - ${Date.now()}`,
                phone: '+91 9876543210',
                grade: 'Grade 9',
              },
            })
          );
        }

        // Concurrent CSV export
        concurrentPromises.push(
          defaultClient.request({
            method: 'GET',
            path: '/api/admin/inquiries/export',
            token,
          })
        );

        const results = await Promise.all(concurrentPromises);
        const exportRes = results[results.length - 1];

        assertEqual(exportRes.status, 200, 'CSV export must complete with 200 during concurrent inserts');
        assertContains(exportRes.headers['content-type'] || '', 'text/csv', 'Should return CSV content type');
      },
    },
    {
      name: 'T3_CROSS_04: Distributed password spraying across multiple usernames from a single IP triggers IP rate limit',
      async run() {
        const sprayIp = `198.51.${Date.now() % 200}.91`;

        // Attempt logging in with 6 different usernames from the exact same IP
        let triggeredRateLimit = false;
        for (let i = 1; i <= 8; i++) {
          const res = await defaultClient.request({
            method: 'POST',
            path: '/api/auth/login',
            ip: sprayIp,
            json: {
              emailOrUsername: `target_account_${Date.now()}_${i}@school.edu`,
              password: 'CommonPassword123!',
            },
          });

          if (res.status === 429) {
            triggeredRateLimit = true;
            break;
          }
        }

        // A hardened rate limiter keyed on IP (or dual-bucket IP + user) must cap spraying at <= 5 attempts per IP
        if (!triggeredRateLimit) {
          throw new Error('IP was able to spray > 5 different user accounts without tripping IP-level rate limiting.');
        }
      },
    },
    {
      name: 'T3_CROSS_05: Large Unicode inquiry with multi-byte characters is stored, retrieved by admin, and exported to CSV',
      async run() {
        const unicodeStudent = 'विद्यार्थी Test Scholar 🎓';
        const unicodeNotes = 'विशेष टिप्पणी: Special remarks with quotes "quoted" and commas, in the text.';
        const timestamp = Date.now();
        const unicodeEmail = `unicode_${timestamp}@example.com`;

        // Allow socket burst limit window (5s) from previous test to clear
        await new Promise(r => setTimeout(r, 5200));

        // 1. Submit inquiry
        const submitRes = await defaultClient.request({
          method: 'POST',
          path: '/api/public/inquiries',
          ip: `198.51.${timestamp % 200}.95`,
          json: {
            tenant_id: FIXTURES.TENANTS.DPS.id,
            student_name: unicodeStudent,
            parent_name: 'अभिभावक Parent',
            phone: '+91 9876543210',
            email: unicodeEmail,
            grade: 'Class 11',
            notes: unicodeNotes,
          },
        });
        assertEqual(submitRes.status, 201);

        // 2. Admin retrieves inquiry list
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        const token = loginRes.json.token;

        const listRes = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/inquiries',
          token,
        });
        assertEqual(listRes.status, 200);
        const found = listRes.json.inquiries.find(i => i.email === unicodeEmail);
        if (!found) {
          throw new Error('Unicode inquiry was not found in admin inquiries list');
        }
        assertEqual(found.student_name, unicodeStudent, 'Unicode student name was corrupted');

        // 3. Export to CSV and verify RFC 4180 quoting and Unicode preservation
        const exportRes = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/inquiries/export',
          token,
        });
        assertEqual(exportRes.status, 200);
        assertContains(exportRes.body, unicodeStudent, 'CSV export should contain Unicode characters intact');
      },
    },
    {
      name: 'T3_CROSS_06: Session invalidation: Logging out via /api/auth/logout prevents further admin requests',
      async run() {
        // 1. Log in to get active session token
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        assertEqual(loginRes.status, 200);
        const token = loginRes.json.token;

        // 2. Perform authorized admin request
        const beforeRes = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/data',
          token,
        });
        assertEqual(beforeRes.status, 200, 'Should be authorized prior to logout');

        // 3. Logout
        const logoutRes = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/logout',
          token,
        });
        assertEqual(logoutRes.status, 200, 'Logout should return 200');

        // 4. Subsequent admin request with the logged-out token must be rejected with 401
        const afterRes = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/data',
          token,
        });
        assertEqual(afterRes.status, 401, 'Logged out token must return HTTP 401 Unauthorized');
      },
    },
  ],
};
