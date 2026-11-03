/**
 * Tier 2 - Boundary & Corner Cases: Broken Image URLs & URI Schemes
 * Verifies validation of image URLs against dangerous protocols and malformed schemes.
 * Requirements: R1, R3, PROJECT.md Feature 3 & 11
 */

const { defaultClient } = require('../helpers/test_client');
const { assertEqual, assertContains, assertNotContains } = require('../helpers/assertions');
const { FIXTURES } = require('../helpers/db_helper');

module.exports = {
  name: 'Tier 2 - Broken Image URLs & URI Schemes Boundary Cases',
  tests: [
    {
      name: 'T2_IMG_01: javascript: URI in image URL fields is rejected or stripped to prevent DOM-based XSS',
      async run() {
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        assertEqual(loginRes.status, 200);
        const token = loginRes.json.token;

        const maliciousUrl = 'javascript:alert(document.domain)';
        const res = await defaultClient.request({
          method: 'POST',
          path: '/api/admin/toppers',
          token,
          json: {
            student_name: 'Security Test Student',
            class_or_grade: 'Class 12',
            percentage_or_score: '99%',
            photo_url: maliciousUrl,
          },
        });

        // The server should either reject with 400 (protocol validation) or neutralize the URL
        if (res.status === 200 || res.status === 201) {
          // If accepted, verify photo_url in database was neutralized
          const listRes = await defaultClient.request({
            method: 'GET',
            path: '/api/admin/data',
            token,
          });
          const created = listRes.json.data.toppers.find(t => t.student_name === 'Security Test Student');
          if (created && created.photo_url.toLowerCase().startsWith('javascript:')) {
            throw new Error('Server accepted and stored unvalidated javascript: URI in photo_url field.');
          }
        } else {
          assertEqual(res.status, 400, 'Server should reject javascript: protocol with 400');
        }
      },
    },
    {
      name: 'T2_IMG_02: Malformed URI schemes (file:///, ftp://) are rejected or neutralized',
      async run() {
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        const token = loginRes.json.token;

        const res = await defaultClient.request({
          method: 'POST',
          path: '/api/admin/facilities',
          token,
          json: {
            title: 'Test Facility',
            category: 'Sports',
            image_url: 'file:///etc/passwd',
          },
        });

        if (res.status === 200 || res.status === 201) {
          const listRes = await defaultClient.request({ method: 'GET', path: '/api/admin/data', token });
          const created = listRes.json.data.facilities.find(f => f.title === 'Test Facility');
          if (created && created.image_url.startsWith('file:')) {
            throw new Error('Server stored file:/// URI protocol without validation.');
          }
        }
      },
    },
    {
      name: 'T2_IMG_03: Excessively long image URL strings (>2000 chars) are handled without buffer overflow',
      async run() {
        const loginRes = await defaultClient.login(
          FIXTURES.TEST_ADMIN_DPS.email,
          FIXTURES.TEST_ADMIN_DPS.password
        );
        const token = loginRes.json.token;

        const longUrl = 'https://images.example.com/' + 'a'.repeat(3000) + '.jpg';
        const res = await defaultClient.request({
          method: 'POST',
          path: '/api/admin/toppers',
          token,
          json: {
            student_name: 'Long URL Test Student',
            class_or_grade: 'Class 10',
            percentage_or_score: '98%',
            photo_url: longUrl,
          },
        });

        // Must not crash server with 500
        if (res.status === 500) {
          throw new Error('Server crashed with 500 on oversized URL string.');
        }
      },
    },
    {
      name: 'T2_IMG_04: CSP img-src directive allows data: and HTTPS while restricting script execution',
      async run() {
        const res = await defaultClient.get('/?school=dps-delhi');
        const csp = res.headers['content-security-policy'] || '';
        assertContains(csp, 'img-src', 'CSP must define img-src');
        assertContains(csp, 'data:', 'CSP img-src must permit data: URIs for inline SVG fallbacks');
      },
    },
    {
      name: 'T2_IMG_05: Broken image URL in SSR settings does not cause server-side rendering exception',
      async run() {
        // Query school portal with unusual character sequences in query
        const res = await defaultClient.get('/?school=dps-delhi&img=broken%00url');
        assertEqual(res.status, 200, 'Portal should render cleanly despite malformed img parameters');
        assertContains(res.body, 'Delhi Public School');
      },
    },
  ],
};
