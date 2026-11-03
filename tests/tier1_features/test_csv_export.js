/**
 * Tier 1 - Feature Coverage: 1-Click Admissions CSV Export
 * Verifies RFC 4180 compliant CSV generation, UTF-8 BOM, streaming headers, and tenant isolation.
 * Requirements: R4, PROJECT.md Feature 12 & CSV Export Contract
 */

const { defaultClient } = require('../helpers/test_client');
const { assertEqual, assertContains, assertNotContains } = require('../helpers/assertions');
const { FIXTURES, query } = require('../helpers/db_helper');

module.exports = {
  name: 'Tier 1 - Admissions CSV Export Feature Coverage',
  tests: [
    {
      name: 'T1_CSV_01: Unauthenticated request to /api/admin/inquiries/export returns HTTP 401',
      async run() {
        const res = await defaultClient.get('/api/admin/inquiries/export');
        assertEqual(res.status, 401, 'Unauthenticated CSV export should return 401');
      },
    },
    {
      name: 'T1_CSV_02: Authenticated export returns HTTP 200 with text/csv content-type and attachment disposition',
      async run() {
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        assertEqual(loginRes.status, 200);
        const token = loginRes.json.token;

        const res = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/inquiries/export',
          token,
        });

        assertEqual(res.status, 200, 'Export endpoint should return 200');
        const ct = res.headers['content-type'] || '';
        assertContains(ct.toLowerCase(), 'text/csv', 'Content-Type must be text/csv');

        const cd = res.headers['content-disposition'] || '';
        assertContains(cd.toLowerCase(), 'attachment', 'Content-Disposition should indicate attachment download');
      },
    },
    {
      name: 'T1_CSV_03: Exported CSV starts with UTF-8 BOM (\\uFEFF) for Excel compatibility',
      async run() {
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        const token = loginRes.json.token;

        const res = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/inquiries/export',
          token,
        });

        assertEqual(res.status, 200);
        const hasBom = res.body.charCodeAt(0) === 0xFEFF || res.rawBody[0] === 0xEF && res.rawBody[1] === 0xBB && res.rawBody[2] === 0xBF;
        if (!hasBom) {
          throw new Error('CSV export is missing the UTF-8 BOM (\\uFEFF) required for Excel compatibility.');
        }
      },
    },
    {
      name: 'T1_CSV_04: Header row contains all required columns per RFC 4180 specification',
      async run() {
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        const token = loginRes.json.token;

        const res = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/inquiries/export',
          token,
        });

        assertEqual(res.status, 200);
        const lines = res.body.replace(/^\uFEFF/, '').trim().split(/\r?\n/);
        const headerLine = lines[0] || '';

        const requiredCols = [
          'Student Name',
          'Parent Name',
          'Phone',
          'Email',
          'Grade',
          'Notes',
          'Status',
          'Submission Date',
        ];

        for (const col of requiredCols) {
          assertContains(headerLine, col, `CSV header missing required column: ${col}`);
        }
      },
    },
    {
      name: 'T1_CSV_05: Export strictly filters inquiries by tenant without leaking other schools data',
      async run() {
        // Seed unique inquiry for RK Mission
        const rkmUniqueStudent = 'RKM_Exclusive_Student_' + Date.now();
        await query(
          `INSERT INTO school_admission_inquiries (tenant_id, student_name, parent_name, phone, email, grade, notes, status)
           VALUES ($1, $2, 'Parent RKM', '+91 9999988888', 'rkm@test.com', 'Grade 8', 'Exclusive RKM note', 'pending')`,
          [FIXTURES.TENANTS.RKM.id, rkmUniqueStudent]
        );

        // DPS Admin exports CSV
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        const token = loginRes.json.token;

        const res = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/inquiries/export',
          token,
        });

        assertEqual(res.status, 200);
        assertNotContains(
          res.body,
          rkmUniqueStudent,
          'DPS CSV export must NOT contain student inquiries belonging to RK Mission'
        );
      },
    },
  ],
};
