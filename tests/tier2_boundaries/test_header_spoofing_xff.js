/**
 * Tier 2 - Boundary & Corner Cases: Header Spoofing & IP Resolution
 * Verifies resistance against client-side header spoofing (X-Forwarded-For, Host).
 * Requirements: R1, PROJECT.md Feature 1 & 4
 */

const { defaultClient } = require('../helpers/test_client');
const { assertEqual, assertContains } = require('../helpers/assertions');

module.exports = {
  name: 'Tier 2 - Header Spoofing & IP Resolution Boundary Cases',
  tests: [
    {
      name: 'T2_XFF_01: Single attacker cannot evade inquiry rate limit by spoofing random XFF headers on loopback socket',
      async run() {
        const dpsTenantId = '9f025e7d-a42c-4c8e-8ea6-c9a8d9c02442';
        const inquiryData = {
          tenant_id: dpsTenantId,
          student_name: 'XFF Test Student',
          phone: '+91 9876543210',
          email: 'xff_test@example.com',
          grade: 'Grade 3',
        };

        // When spoofing rotating X-Forwarded-For from the same socket connection,
        // a hardened server should enforce rate limits and not allow infinite requests
        let attemptsAllowed = 0;
        for (let i = 1; i <= 10; i++) {
          const fakeIp = `203.0.113.${i}`;
          const res = await defaultClient.request({
            method: 'POST',
            path: '/api/public/inquiries',
            ip: fakeIp,
            json: inquiryData,
          });
          if (res.status === 201) {
            attemptsAllowed++;
          }
        }

        // If server blindly trusts XFF, it allowed all 10.
        // Hardened server should bound socket or validate proxy, capping allowed submissions.
        if (attemptsAllowed > 5) {
          throw new Error(`Server blindly trusted rotating X-Forwarded-For headers, allowing ${attemptsAllowed}/10 requests without rate limit enforcement.`);
        }
      },
    },
    {
      name: 'T2_XFF_02: Multi-hop X-Forwarded-For chain is parsed safely without server crash',
      async run() {
        const multiHopXff = '198.51.100.99, 10.0.0.1, 172.16.0.1';
        const res = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/login',
          headers: {
            'X-Forwarded-For': multiHopXff,
          },
          json: { emailOrUsername: 'multi_hop_user@test.com', password: 'TestPassword123' },
        });

        assertEqual(res.status, 401, 'Should return 401 without crashing on multi-hop XFF');
        assertEqual(res.json.success, false);
      },
    },
    {
      name: 'T2_XFF_03: Malformed X-Forwarded-For string containing SQL or control characters is handled safely',
      async run() {
        const malformedXff = "'; DROP TABLE cms_users; -- <script>";
        const res = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/login',
          headers: {
            'X-Forwarded-For': malformedXff,
          },
          json: { emailOrUsername: 'malformed_ip_user@test.com', password: 'TestPassword123' },
        });

        assertEqual(res.status, 401, 'Malformed XFF must not cause 500 or SQL injection');
      },
    },
    {
      name: 'T2_XFF_04: IPv6 formatted client addresses in X-Forwarded-For are handled safely',
      async run() {
        const ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334';
        const res = await defaultClient.request({
          method: 'POST',
          path: '/api/auth/login',
          headers: {
            'X-Forwarded-For': ipv6,
          },
          json: { emailOrUsername: 'ipv6_user@test.com', password: 'TestPassword123' },
        });

        assertEqual(res.status, 401, 'IPv6 address in XFF must be handled without error');
      },
    },
    {
      name: 'T2_XFF_05: Malicious Host header spoofing (e.g. evil.com) returns 404 and does not match arbitrary tenants',
      async run() {
        const res = await defaultClient.request({
          method: 'GET',
          path: '/',
          host: 'evil.attacker.com',
        });

        assertEqual(res.status, 404, 'Unmapped foreign Host header must return 404 Not Found');
        assertContains(res.body.toLowerCase(), 'no school found', 'Response should indicate school not found');
      },
    },
  ],
};
