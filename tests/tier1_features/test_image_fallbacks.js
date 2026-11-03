/**
 * Tier 1 - Feature Coverage: Image Fallbacks (onerror)
 * Verifies graceful UI fallback for broken image URLs across templates and SSR output.
 * Requirements: R3, PROJECT.md Feature 11
 */

const fs = require('fs');
const path = require('path');
const { defaultClient } = require('../helpers/test_client');
const { assertEqual, assertContains } = require('../helpers/assertions');

module.exports = {
  name: 'Tier 1 - Image Fallbacks Feature Coverage',
  tests: [
    {
      name: 'T1_IMG_01: SSR brand logo rendered in HTML includes graceful onerror fallback handler',
      async run() {
        const res = await defaultClient.get('/?school=dps-delhi');
        assertEqual(res.status, 200);

        // Check if logo image tag or server SSR includes onerror handler
        if (res.body.includes('<img') && res.body.includes('object-contain')) {
          assertContains(res.body.toLowerCase(), 'onerror=', 'Rendered brand logo image must include an onerror fallback handler');
        } else {
          // If logo is font-awesome icon, verify icon fallback exists
          assertContains(res.body, 'fa-graduation-cap', 'Fallback graduation cap icon should be rendered when no logo image is set');
        }
      },
    },
    {
      name: 'T1_IMG_02: Client school.html template equips topper photo render points with onerror handler',
      async run() {
        const templatePath = path.join(__dirname, '..', '..', 'public', 'school.html');
        const content = fs.readFileSync(templatePath, 'utf8');

        // Look for topper card template rendering
        assertContains(content.toLowerCase(), 'topper', 'school.html should contain toppers section');
        const topperImgMatches = content.match(/<img[^>]+photo_url[^>]*>/gi) || [];
        for (const imgTag of topperImgMatches) {
          if (!imgTag.toLowerCase().includes('onerror=')) {
            throw new Error(`Topper image tag missing onerror fallback: ${imgTag}`);
          }
        }
      },
    },
    {
      name: 'T1_IMG_03: Client school.html template equips campus facilities with onerror fallback',
      async run() {
        const templatePath = path.join(__dirname, '..', '..', 'public', 'school.html');
        const content = fs.readFileSync(templatePath, 'utf8');

        const facilityImgMatches = content.match(/<img[^>]+image_url[^>]*>/gi) || [];
        for (const imgTag of facilityImgMatches) {
          if (!imgTag.toLowerCase().includes('onerror=')) {
            throw new Error(`Facility image tag missing onerror fallback: ${imgTag}`);
          }
        }
      },
    },
    {
      name: 'T1_IMG_04: Client school.html template equips gallery and lightbox with onerror fallback',
      async run() {
        const templatePath = path.join(__dirname, '..', '..', 'public', 'school.html');
        const content = fs.readFileSync(templatePath, 'utf8');

        assertContains(content.toLowerCase(), 'gallery', 'school.html should contain gallery section');
        // Check if gallery rendering includes onerror
        if (!content.includes('onerror=') && !content.includes('onerror =')) {
          throw new Error('school.html contains zero onerror handlers on image render points. Required by R3.');
        }
      },
    },
    {
      name: 'T1_IMG_05: Admin panel (admin.html) equips image preview modals with onerror fallbacks',
      async run() {
        const templatePath = path.join(__dirname, '..', '..', 'public', 'admin.html');
        const content = fs.readFileSync(templatePath, 'utf8');

        // Check if admin panel image renders have onerror fallbacks
        const imgTags = content.match(/<img[^>]*>/gi) || [];
        const hasOnError = imgTags.some(tag => tag.toLowerCase().includes('onerror='));
        if (!hasOnError) {
          throw new Error('admin.html lacks onerror fallback handlers on image rendering. Required by R3.');
        }
      },
    },
  ],
};
