/**
 * Tier 1 - Feature Coverage: SSR Template Serving & Multi-Tenant Theming
 * Verifies dynamic template caching, placeholder interpolation, and branding hydration.
 * Requirements: R3, PROJECT.md Feature 10
 */

const { defaultClient } = require('../helpers/test_client');
const { assertEqual, assertContains } = require('../helpers/assertions');

module.exports = {
  name: 'Tier 1 - SSR Template Serving & Multi-Tenant Theming Feature Coverage',
  tests: [
    {
      name: 'T1_SSR_01: Resolving DPS Delhi renders distinctive school name and hydration state',
      async run() {
        const res = await defaultClient.get('/?school=dps-delhi');
        assertEqual(res.status, 200, 'DPS portal should return 200');
        assertContains(res.body, 'Delhi Public School', 'Should render DPS school name');
        assertContains(res.body, 'window.__SCHOOL__', 'Should inject school hydration payload');
        assertContains(res.body, 'window.__DATA__', 'Should inject school data bundle');
      },
    },
    {
      name: 'T1_SSR_02: Resolving RK Mission renders distinctive theme and institutional branding',
      async run() {
        const res = await defaultClient.get('/?school=rkmps');
        assertEqual(res.status, 200, 'RK Mission portal should return 200');
        assertContains(res.body, 'R K MISSION PUBLIC SCHOOL', 'Should render RK Mission school name');
        assertContains(res.body, 'window.__SCHOOL__', 'Should inject school hydration payload');
      },
    },
    {
      name: 'T1_SSR_03: Resolving St. Xavier International renders distinctive portal content',
      async run() {
        const res = await defaultClient.get('/?school=stxavier');
        assertEqual(res.status, 200, 'St. Xavier portal should return 200');
        assertContains(res.body, 'St. Xavier', 'Should render St. Xavier school name');
        assertContains(res.body, 'window.__SCHOOL__', 'Should inject school hydration payload');
      },
    },
    {
      name: 'T1_SSR_04: Unknown school slug query returns HTTP 404 Not Found',
      async run() {
        const res = await defaultClient.get('/?school=unknown-slug-invalid-999');
        assertEqual(res.status, 404, 'Unknown school should return HTTP 404');
        assertContains(res.body.toLowerCase(), 'no school found', 'Body should state no school found');
      },
    },
    {
      name: 'T1_SSR_05: SaaS Marketing Landing Page renders on root domain with live schools list',
      async run() {
        const res = await defaultClient.get('/');
        assertEqual(res.status, 200, 'Landing page should return 200');
        assertContains(res.body, 'window.__SAAS_CONFIG__', 'Should inject SaaS config payload');
        assertContains(res.body, 'window.__LIVE_SCHOOLS__', 'Should inject live schools list');
      },
    },
  ],
};
