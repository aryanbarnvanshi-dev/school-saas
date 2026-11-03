/**
 * Tier 4 - Real-World Workload Scenarios
 * Executes realistic multi-step end-to-end user journeys simulating production operations.
 * Requirements: R1-R4, PROJECT.md
 */

const { defaultClient } = require('../helpers/test_client');
const { assertEqual, assertContains, assertNotContains } = require('../helpers/assertions');
const { FIXTURES, query } = require('../helpers/db_helper');

module.exports = {
  name: 'Tier 4 - Real-World Workload Scenarios',
  tests: [
    {
      name: 'T4_WORK_01: End-to-End Admissions Lead Journey (Capture -> Storage -> Admin Update -> CSV Export -> Tenant Verification)',
      async run() {
        const timestamp = Date.now();
        const testStudentName = `Admissions Journey Student ${timestamp}`;
        const testParentName = `Parent ${timestamp}`;
        const testEmail = `lead_${timestamp}@family.org`;
        const testPhone = '+91 9123456789';
        const dpsTenantId = FIXTURES.TENANTS.DPS.id;

        // Step 1: Public Lead Submission
        const submitRes = await defaultClient.request({
          method: 'POST',
          path: '/api/public/inquiries',
          agent: false,
          ip: `198.51.100.${timestamp % 200 + 10}`,
          json: {
            tenant_id: dpsTenantId,
            student_name: testStudentName,
            parent_name: testParentName,
            email: testEmail,
            phone: testPhone,
            grade: 'Grade 9',
            notes: 'Interested in STEM curriculum and transportation facility.',
          },
        });
        assertEqual(submitRes.status, 201, 'Public inquiry submission must return 201 Created');

        // Step 2: Database Storage Verification
        const dbRes = await query(
          `SELECT id, tenant_id, status FROM school_admission_inquiries WHERE email = $1 LIMIT 1`,
          [testEmail]
        );
        assertEqual(dbRes.rows.length, 1, 'Inquiry must be persisted in database');
        const inquiryRecord = dbRes.rows[0];
        assertEqual(inquiryRecord.tenant_id, dpsTenantId, 'Persisted inquiry must belong to DPS tenant');
        assertEqual(inquiryRecord.status, 'pending', 'Initial status must be pending');

        // Step 3: DPS Admin Authentication & Inquiry Fetch
        const dpsLogin = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        assertEqual(dpsLogin.status, 200, 'DPS Admin login must succeed');
        const dpsToken = dpsLogin.json.token;

        const listRes = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/inquiries',
          token: dpsToken,
        });
        assertEqual(listRes.status, 200);
        const listedInquiry = listRes.json.inquiries.find(i => i.id === inquiryRecord.id);
        if (!listedInquiry) {
          throw new Error('New inquiry not found in DPS Admin inquiries list');
        }
        assertEqual(listedInquiry.student_name, testStudentName);

        // Step 4: Admin Updates Status to 'rejected'
        const updateRes = await defaultClient.request({
          method: 'POST',
          path: '/api/admin/inquiries',
          token: dpsToken,
          json: {
            id: inquiryRecord.id,
            status: 'rejected',
            tenant_id: dpsTenantId,
          },
        });
        assertEqual(updateRes.status, 200, 'Status update must return 200 OK');

        // Step 5: DPS Admin Exports CSV and Verifies Updated Status
        const exportRes = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/inquiries/export',
          token: dpsToken,
        });
        assertEqual(exportRes.status, 200, 'CSV export should return 200');
        assertContains(exportRes.body, testStudentName, 'CSV export must contain student name');
        assertContains(exportRes.body, 'rejected', 'CSV export must reflect updated rejected status');

        // Step 6: Tenant Isolation Check - RK Mission Admin cannot view or export this inquiry
        const rkmLogin = await defaultClient.login(
          FIXTURES.TEST_ADMIN_RKM.email,
          FIXTURES.TEST_ADMIN_RKM.password
        );
        assertEqual(rkmLogin.status, 200);
        const rkmToken = rkmLogin.json.token;

        const rkmListRes = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/inquiries',
          token: rkmToken,
        });
        assertEqual(rkmListRes.status, 200);
        const leakedInquiry = rkmListRes.json.inquiries.find(i => i.id === inquiryRecord.id);
        assertEqual(leakedInquiry, undefined, 'DPS inquiry must NEVER appear in RK Mission inquiry list');

        const rkmExportRes = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/inquiries/export',
          token: rkmToken,
        });
        assertEqual(rkmExportRes.status, 200);
        assertNotContains(rkmExportRes.body, testStudentName, 'DPS inquiry must NEVER leak into RK Mission CSV export');
      },
    },
    {
      name: 'T4_WORK_02: Multi-Tenant Concurrent SSR Theming & Hydration Isolation (DPS, RK Mission, St. Xavier)',
      async run() {
        // Fetch all 3 portals in parallel
        const [dpsRes, rkmRes, stxRes] = await Promise.all([
          defaultClient.get('/?school=dps-delhi'),
          defaultClient.get('/?school=rkmps'),
          defaultClient.get('/?school=stxavier'),
        ]);

        assertEqual(dpsRes.status, 200, 'DPS portal should return 200');
        assertEqual(rkmRes.status, 200, 'RK Mission portal should return 200');
        assertEqual(stxRes.status, 200, 'St. Xavier portal should return 200');

        // Verify DPS content & theming
        assertContains(dpsRes.body, 'Delhi Public School');
        assertContains(dpsRes.body, 'dps-delhi');

        // Verify RK Mission content & theming
        assertContains(rkmRes.body, 'R K MISSION PUBLIC SCHOOL');
        assertContains(rkmRes.body, 'rkmps');

        // Verify St. Xavier content & theming
        assertContains(stxRes.body, 'St. Xavier');
        assertContains(stxRes.body, 'stxavier');

        // Cross-contamination checks
        assertNotContains(rkmRes.body, 'Delhi Public School', 'RK Mission must not contain DPS school name');
        assertNotContains(stxRes.body, 'Delhi Public School', 'St. Xavier must not contain DPS school name');
      },
    },
    {
      name: 'T4_WORK_03: SuperAdmin Multi-Tenant Oversight vs School Admin RBAC Separation',
      async run() {
        // 1. SuperAdmin login
        const saLogin = await defaultClient.login(
          FIXTURES.SUPER_ADMIN.username,
          FIXTURES.SUPER_ADMIN.password
        );
        assertEqual(saLogin.status, 200, 'SuperAdmin login must succeed');
        const saToken = saLogin.json.token;

        // SuperAdmin can view all schools
        const schoolsRes = await defaultClient.request({
          method: 'GET',
          path: '/api/super-admin/schools',
          token: saToken,
        });
        assertEqual(schoolsRes.status, 200, 'SuperAdmin should access schools list');
        assertEqual(schoolsRes.json.success, true);
        if (!Array.isArray(schoolsRes.json.schools) || schoolsRes.json.schools.length < 3) {
          throw new Error('Expected at least 3 schools in SuperAdmin schools list');
        }

        // 2. School Admin (DPS) login
        const dpsLogin = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        assertEqual(dpsLogin.status, 200);
        const dpsToken = dpsLogin.json.token;

        // School Admin attempting SuperAdmin endpoints must be rejected with 403 Forbidden
        const forbiddenGetRes = await defaultClient.request({
          method: 'GET',
          path: '/api/super-admin/schools',
          token: dpsToken,
        });
        assertEqual(forbiddenGetRes.status, 403, 'School Admin must be denied access to SuperAdmin schools list with 403');

        const forbiddenPostRes = await defaultClient.request({
          method: 'POST',
          path: '/api/super-admin/schools',
          token: dpsToken,
          json: { name: 'Illegal School Creation', slug: 'illegal-slug' },
        });
        assertEqual(forbiddenPostRes.status, 403, 'School Admin must be denied creation of schools with 403');
      },
    },
    {
      name: 'T4_WORK_04: Concurrency Load & Resident Memory (RSS) Budget Invariant Check (<250MB Peak Load)',
      async run() {
        // Step 1: Check baseline memory via /health
        const healthInitial = await defaultClient.get('/health');
        assertEqual(healthInitial.status, 200);
        const initialRss = healthInitial.json.memory.rss_mb;

        // Step 2: Fire burst of 20 concurrent requests
        const burstPromises = [];
        for (let i = 0; i < 20; i++) {
          const path = i % 3 === 0 ? '/?school=dps-delhi' : i % 3 === 1 ? '/?school=rkmps' : '/health';
          burstPromises.push(defaultClient.get(path));
        }

        const responses = await Promise.all(burstPromises);
        const successCount = responses.filter(r => r.status === 200).length;
        if (successCount < 18) {
          throw new Error(`Expected at least 18/20 concurrent requests to succeed, got ${successCount}`);
        }

        // Step 3: Check post-load memory
        const healthPost = await defaultClient.get('/health');
        assertEqual(healthPost.status, 200);
        const postRss = healthPost.json.memory.rss_mb;

        // Verify strict 512MB RAM compliance: RSS peak must stay well below 250MB
        if (postRss > 250) {
          throw new Error(`Node.js resident memory RSS (${postRss}MB) exceeded 250MB peak load budget! Required by R2.`);
        }
      },
    },
  ],
};
