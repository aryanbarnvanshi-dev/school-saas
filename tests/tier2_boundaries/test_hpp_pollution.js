/**
 * Tier 2 - Boundary & Corner Cases: HTTP Parameter Pollution (HPP) & Type Confusion
 * Verifies resistance against duplicate query parameters and prototype pollution attacks.
 * Requirements: R1, PROJECT.md Feature 4
 */

const { defaultClient } = require('../helpers/test_client');
const { assertEqual, assertContains } = require('../helpers/assertions');
const { FIXTURES } = require('../helpers/db_helper');

module.exports = {
  name: 'Tier 2 - HTTP Parameter Pollution & Type Confusion Boundary Cases',
  tests: [
    {
      name: 'T2_HPP_01: Duplicate school parameter (?school=dps-delhi&school=rkmps) does not cause 500 error or database crash',
      async run() {
        const res = await defaultClient.request({
          method: 'GET',
          path: '/?school=dps-delhi&school=rkmps',
        });

        if (res.status === 500) {
          throw new Error('Server threw HTTP 500 on HPP query (?school=a&school=b). Array type was passed to scalar SQL parameter.');
        }

        // Server should either select the first/last valid scalar slug or safely return 404
        if (res.status !== 200 && res.status !== 404) {
          throw new Error(`Expected HTTP 200 or 404 for HPP query, got: ${res.status}`);
        }
      },
    },
    {
      name: 'T2_HPP_02: Array pollution on tenant_id parameter in admin endpoints (?tenant_id=a&tenant_id=b) is safely handled',
      async run() {
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        assertEqual(loginRes.status, 200);

        const res = await defaultClient.request({
          method: 'GET',
          path: `/api/admin/inquiries?tenant_id=${FIXTURES.TENANTS.DPS.id}&tenant_id=${FIXTURES.TENANTS.RKM.id}`,
          token: loginRes.json.token,
        });

        // Must not crash with 500
        if (res.status === 500) {
          throw new Error('Admin inquiries endpoint crashed with 500 on duplicate tenant_id array parameter.');
        }
      },
    },
    {
      name: 'T2_HPP_03: Non-numeric and array values in page/limit parameters default to safe integers',
      async run() {
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        assertEqual(loginRes.status, 200);

        const res = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/inquiries?page=abc&limit=xyz',
          token: loginRes.json.token,
        });

        assertEqual(res.status, 200, 'Invalid pagination values should default to valid page/limit without error');
        assertEqual(typeof res.json.page, 'number', 'Page should be a valid number');
        assertEqual(typeof res.json.limit, 'number', 'Limit should be a valid number');
      },
    },
    {
      name: 'T2_HPP_04: Prototype pollution payload in JSON body does not modify Object.prototype',
      async run() {
        const pollutionPayload = JSON.parse('{"__proto__": {"pollutedKey": "PWNED_01"}, "constructor": {"prototype": {"pollutedKey2": "PWNED_02"}}}');
        
        await defaultClient.request({
          method: 'POST',
          path: '/api/auth/login',
          json: {
            emailOrUsername: 'test@example.com',
            password: 'Password123',
            ...pollutionPayload,
          },
        });

        const testObj = {};
        assertEqual(testObj.pollutedKey, undefined, 'Object.prototype was polluted with pollutedKey!');
        assertEqual(testObj.pollutedKey2, undefined, 'Object.prototype was polluted with pollutedKey2!');
      },
    },
    {
      name: 'T2_HPP_05: Empty parameter value (?school=) renders landing page or 404 without crashing',
      async run() {
        const res = await defaultClient.request({
          method: 'GET',
          path: '/?school=',
        });

        if (res.status === 500) {
          throw new Error('Server threw 500 on empty school parameter (?school=).');
        }
        if (res.status !== 200 && res.status !== 404) {
          throw new Error(`Expected HTTP 200 or 404 on ?school=, got: ${res.status}`);
        }
      },
    },
  ],
};
