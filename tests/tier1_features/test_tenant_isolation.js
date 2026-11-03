/**
 * Tier 1 - Feature Coverage: Tenant Isolation & RBAC
 * Verifies tamper-proof row-level isolation between schools.
 * Requirements: R1, PROJECT.md Feature 4
 */

const { defaultClient } = require('../helpers/test_client');
const { assertEqual, assertContains } = require('../helpers/assertions');
const { FIXTURES } = require('../helpers/db_helper');

module.exports = {
  name: 'Tier 1 - Tenant Isolation Feature Coverage',
  tests: [
    {
      name: 'T1_ISO_01: Unauthenticated requests to /api/admin/inquiries return HTTP 401',
      async run() {
        const res = await defaultClient.get('/api/admin/inquiries');
        assertEqual(res.status, 401, 'Unauthenticated admin endpoint must return 401');
        assertEqual(res.json.success, false, 'Response success should be false');
        assertContains(res.json.error.toLowerCase(), 'unauthorized', 'Error should state unauthorized');
      },
    },
    {
      name: 'T1_ISO_02: DPS Admin requesting RK Mission inquiries returns HTTP 403 Forbidden',
      async run() {
        // Log in as DPS Admin
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        assertEqual(loginRes.status, 200, 'DPS Admin login should succeed');
        const token = loginRes.json.token;

        // Attempt to read RK Mission inquiries
        const rkmTenantId = FIXTURES.TENANTS.RKM.id;
        const res = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/inquiries',
          query: { tenant_id: rkmTenantId },
          token,
        });

        assertEqual(res.status, 403, 'Cross-tenant inquiry read must return HTTP 403 Forbidden');
        assertEqual(res.json.success, false, 'Success should be false');
        assertContains(res.json.error.toLowerCase(), 'cross-tenant', 'Error should explain cross-tenant denial');
      },
    },
    {
      name: 'T1_ISO_03: DPS Admin attempting to update an inquiry belonging to RK Mission returns HTTP 403',
      async run() {
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        const token = loginRes.json.token;

        const fakeRkmInquiryId = '11111111-2222-3333-4444-555555555555';
        const res = await defaultClient.request({
          method: 'POST',
          path: '/api/admin/inquiries',
          token,
          json: {
            id: fakeRkmInquiryId,
            status: 'approved',
            tenant_id: FIXTURES.TENANTS.RKM.id,
          },
        });

        assertEqual(res.status, 403, 'Cross-tenant inquiry update must return HTTP 403 Forbidden');
        assertEqual(res.json.success, false, 'Success should be false');
      },
    },
    {
      name: 'T1_ISO_04: DPS Admin attempting to create notice under RK Mission tenant returns HTTP 403',
      async run() {
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        const token = loginRes.json.token;

        const res = await defaultClient.request({
          method: 'POST',
          path: '/api/admin/notices',
          token,
          json: {
            title: 'Malicious Cross-Tenant Notice',
            content: 'Notice content',
            category: 'general',
            priority: 'normal',
            tenant_id: FIXTURES.TENANTS.RKM.id,
          },
        });

        assertEqual(res.status, 403, 'Cross-tenant notice creation must return HTTP 403 Forbidden');
        assertEqual(res.json.success, false, 'Success should be false');
      },
    },
    {
      name: 'T1_ISO_05: DPS Admin attempting to modify RK Mission settings returns HTTP 403',
      async run() {
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        const token = loginRes.json.token;

        const res = await defaultClient.request({
          method: 'PUT',
          path: '/api/admin/settings',
          token,
          json: {
            tenant_id: FIXTURES.TENANTS.RKM.id,
            settings: {
              theme: { primary_color: '#ff0000' },
            },
          },
        });

        assertEqual(res.status, 403, 'Cross-tenant settings modification must return HTTP 403 Forbidden');
        assertEqual(res.json.success, false, 'Success should be false');
      },
    },
    {
      name: 'T1_ISO_06: DPS Admin querying /api/admin/data receives exclusively DPS data',
      async run() {
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        const token = loginRes.json.token;

        const res = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/data',
          token,
        });

        assertEqual(res.status, 200, 'Admin data endpoint should return 200');
        assertEqual(res.json.success, true, 'Admin data response should succeed');
        assertEqual(res.json.school.tenant_id, FIXTURES.TENANTS.DPS.id, 'Returned tenant ID must match DPS');
        assertEqual(res.json.school.school_slug, FIXTURES.TENANTS.DPS.slug, 'Returned slug must match DPS');
      },
    },
  ],
};
