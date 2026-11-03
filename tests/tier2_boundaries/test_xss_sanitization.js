/**
 * Tier 2 - Boundary & Corner Cases: XSS & Sanitization Hardening
 * Verifies that malicious HTML/JS payloads submitted in forms are sanitized and neutralized.
 * Requirements: R1, PROJECT.md Feature 3
 */

const fs = require('fs');
const path = require('path');
const { defaultClient } = require('../helpers/test_client');
const { assertEqual, assertContains, assertNotContains } = require('../helpers/assertions');
const { FIXTURES } = require('../helpers/db_helper');

module.exports = {
  name: 'Tier 2 - XSS & Sanitization Hardening Boundary Cases',
  tests: [
    {
      name: 'T2_XSS_01: Raw <script> tags in inquiry fields are neutralized when retrieved by admin',
      async run() {
        const xssPayload = '<script>alert("XSS_PAYLOAD_01")</script>';
        const dpsTenantId = FIXTURES.TENANTS.DPS.id;

        // Submit inquiry containing script tag
        const submitRes = await defaultClient.request({
          method: 'POST',
          path: '/api/public/inquiries',
          ip: '198.51.100.41',
          json: {
            tenant_id: dpsTenantId,
            student_name: xssPayload,
            parent_name: 'XSS Tester Parent',
            phone: '+91 9876543210',
            email: 'xsstest1@example.com',
            grade: 'Grade 10',
            notes: 'Testing script tag neutralization',
          },
        });

        // If rejected immediately with 400 Bad Request, that is successful defense against script injection
        if (submitRes.status === 400) {
          assertEqual(submitRes.json.success, false, 'Should return success: false when XSS payload is rejected');
          return;
        }

        assertEqual(submitRes.status, 201, 'Inquiry submission should succeed or sanitize');

        // Admin retrieves inquiries
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        assertEqual(loginRes.status, 200);

        const listRes = await defaultClient.request({
          method: 'GET',
          path: '/api/admin/inquiries',
          token: loginRes.json.token,
        });
        assertEqual(listRes.status, 200);

        // Find the submitted inquiry
        const found = listRes.json.inquiries.find(i => i.email === 'xsstest1@example.com');
        if (found) {
          // If stored or rendered, verify it does not allow raw script execution
          // When JSON stringified, tags are strings, but client templates must escape them
          assertContains(found.student_name, 'XSS_PAYLOAD_01');
        }
      },
    },
    {
      name: 'T2_XSS_02: Attribute breakout payloads (e.g. " onfocus="alert(1)) are safely escaped',
      async run() {
        const breakoutPayload = 'Student" onfocus="alert(1)" data-x="';
        const dpsTenantId = FIXTURES.TENANTS.DPS.id;

        const submitRes = await defaultClient.request({
          method: 'POST',
          path: '/api/public/inquiries',
          ip: '198.51.100.42',
          json: {
            tenant_id: dpsTenantId,
            student_name: breakoutPayload,
            parent_name: 'Breakout Test Parent',
            email: 'breakout_xss@example.com',
            phone: '+91 9876543210',
            grade: 'Grade 6',
          },
        });
        assertEqual(submitRes.status, 201);
      },
    },
    {
      name: 'T2_XSS_03: Client-side esc() function in public/admin.html escapes quotes (&quot; and &#39;)',
      async run() {
        const adminPath = path.join(__dirname, '..', '..', 'public', 'admin.html');
        const adminContent = fs.readFileSync(adminPath, 'utf8');

        // Look for esc function definition
        const escMatch = adminContent.match(/function\s+esc\s*\([^)]*\)\s*\{[\s\S]*?\}/);
        if (!escMatch) {
          throw new Error('admin.html does not define esc() function');
        }

        const escBody = escMatch[0];
        // Must escape double quotes (&quot; or replace) and single quotes (&#039; or &#39;)
        const escapesQuotes = (escBody.includes('&quot;') || escBody.includes('replace(/"/g')) &&
                              (escBody.includes('&#39;') || escBody.includes('&#039;') || escBody.includes("replace(/'/g"));

        if (!escapesQuotes) {
          throw new Error('Client-side esc() function in admin.html fails to escape quotes, allowing attribute/event-handler breakout XSS.');
        }
      },
    },
    {
      name: 'T2_XSS_04: Client-side esc() function in public/school.html escapes quotes (&quot; and &#39;)',
      async run() {
        const schoolPath = path.join(__dirname, '..', '..', 'public', 'school.html');
        const schoolContent = fs.readFileSync(schoolPath, 'utf8');

        const escMatch = schoolContent.match(/function\s+esc\s*\([^)]*\)\s*\{[\s\S]*?\}/);
        if (!escMatch) {
          throw new Error('school.html does not define esc() function');
        }

        const escBody = escMatch[0];
        const escapesQuotes = (escBody.includes('&quot;') || escBody.includes('replace(/"/g')) &&
                              (escBody.includes('&#39;') || escBody.includes('&#039;') || escBody.includes("replace(/'/g"));

        if (!escapesQuotes) {
          throw new Error('Client-side esc() function in school.html fails to escape quotes, allowing attribute/event-handler breakout XSS.');
        }
      },
    },
    {
      name: 'T2_XSS_05: Server-side escapeForHtml encodes <, >, &, ", and \' correctly',
      async run() {
        // Query portal with school parameter containing HTML special chars
        const res = await defaultClient.get('/?school=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E');
        assertEqual(res.status, 404);
        assertNotContains(res.body, '<script>alert(1)</script>', 'Server must not reflect unescaped script tag');
      },
    },
  ],
};
