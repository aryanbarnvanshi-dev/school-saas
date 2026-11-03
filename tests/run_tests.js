#!/usr/bin/env node
/**
 * School SaaS E2E Test Suite - Automated Test Runner
 * Deterministic test runner for Tiers 1-4.
 *
 * Usage:
 *   node tests/run_tests.js                     # Run all tiers (Tiers 1-4)
 *   node tests/run_tests.js --tier=1           # Run Tier 1 Feature Coverage
 *   node tests/run_tests.js --tier=2           # Run Tier 2 Boundary Cases
 *   node tests/run_tests.js --tier=3           # Run Tier 3 Cross-Feature
 *   node tests/run_tests.js --tier=4           # Run Tier 4 Real-World Workloads
 *   node tests/run_tests.js path/to/test.js    # Run a specific test file
 */

const fs = require('fs');
const path = require('path');
const { ensureTestUsers, closeDbPool } = require('./helpers/db_helper');

// Parse CLI flags
const args = process.argv.slice(2);
let tierFilter = null;
let fileFilter = null;
let grepFilter = null;

for (const arg of args) {
  if (arg.startsWith('--tier=')) {
    tierFilter = arg.split('=')[1].trim();
  } else if (arg.startsWith('--grep=')) {
    grepFilter = arg.split('=')[1].trim().toLowerCase();
  } else if (arg.endsWith('.js')) {
    fileFilter = path.resolve(arg);
  }
}

// All test suite paths
const TEST_SUITES = [
  // Tier 1: Feature Coverage
  { tier: '1', file: path.join(__dirname, 'tier1_features', 'test_rate_limiting.js') },
  { tier: '1', file: path.join(__dirname, 'tier1_features', 'test_security_headers.js') },
  { tier: '1', file: path.join(__dirname, 'tier1_features', 'test_tenant_isolation.js') },
  { tier: '1', file: path.join(__dirname, 'tier1_features', 'test_compression.js') },
  { tier: '1', file: path.join(__dirname, 'tier1_features', 'test_ssr_theming.js') },
  { tier: '1', file: path.join(__dirname, 'tier1_features', 'test_image_fallbacks.js') },
  { tier: '1', file: path.join(__dirname, 'tier1_features', 'test_csv_export.js') },

  // Tier 2: Boundary & Corner Cases
  { tier: '2', file: path.join(__dirname, 'tier2_boundaries', 'test_brute_force_lockouts.js') },
  { tier: '2', file: path.join(__dirname, 'tier2_boundaries', 'test_header_spoofing_xff.js') },
  { tier: '2', file: path.join(__dirname, 'tier2_boundaries', 'test_xss_sanitization.js') },
  { tier: '2', file: path.join(__dirname, 'tier2_boundaries', 'test_hpp_pollution.js') },
  { tier: '2', file: path.join(__dirname, 'tier2_boundaries', 'test_broken_image_urls.js') },

  // Tier 3: Cross-Feature Combinations
  { tier: '3', file: path.join(__dirname, 'tier3_cross_feature', 'test_cross_feature.js') },

  // Tier 4: Real-World Workloads
  { tier: '4', file: path.join(__dirname, 'tier4_workloads', 'test_real_world_workloads.js') },
];

async function main() {
  console.log('================================================================');
  console.log('       School SaaS E2E Test Suite Runner (Tiers 1-4)           ');
  console.log('================================================================\n');

  // Step 1: Ensure DB fixtures exist
  try {
    process.stdout.write('[SETUP] Checking and provisioning deterministic test fixtures in DB... ');
    await ensureTestUsers();
    console.log('DONE\n');
  } catch (err) {
    console.log('WARNING: DB test fixture setup skipped/failed:', err.message, '\n');
  }

  // Filter suites
  let suitesToRun = TEST_SUITES;
  if (fileFilter) {
    suitesToRun = suitesToRun.filter(s => path.resolve(s.file) === fileFilter);
    if (suitesToRun.length === 0 && fs.existsSync(fileFilter)) {
      suitesToRun = [{ tier: 'custom', file: fileFilter }];
    }
  } else if (tierFilter) {
    const normTier = tierFilter.replace(/^tier/i, '');
    suitesToRun = suitesToRun.filter(s => s.tier === normTier);
  }

  if (suitesToRun.length === 0) {
    console.error('[ERROR] No test suites matched the given filter.');
    process.exit(1);
  }

  let totalTests = 0;
  let passedTests = 0;
  let failedTests = 0;
  const failures = [];
  const suiteResults = [];

  const overallStartTime = Date.now();

  for (const suiteDef of suitesToRun) {
    if (!fs.existsSync(suiteDef.file)) {
      console.warn(`[WARN] Suite file not found: ${suiteDef.file}`);
      continue;
    }

    const suite = require(suiteDef.file);
    console.log(`----------------------------------------------------------------`);
    console.log(`[SUITE] ${suite.name || path.basename(suiteDef.file)}`);
    console.log(`----------------------------------------------------------------`);

    let suitePassed = 0;
    let suiteFailed = 0;

    for (const test of (suite.tests || [])) {
      if (grepFilter && !test.name.toLowerCase().includes(grepFilter)) {
        continue;
      }

      totalTests++;
      const testStart = Date.now();
      try {
        await test.run();
        const duration = Date.now() - testStart;
        console.log(`  [PASS] ${test.name} (${duration}ms)`);
        passedTests++;
        suitePassed++;
      } catch (err) {
        const duration = Date.now() - testStart;
        console.log(`  [FAIL] ${test.name} (${duration}ms)`);
        console.log(`         Error: ${err.message}`);
        failedTests++;
        suiteFailed++;
        failures.push({
          suite: suite.name,
          test: test.name,
          error: err.message,
          stack: err.stack,
        });
      }
    }

    suiteResults.push({
      name: suite.name,
      total: suitePassed + suiteFailed,
      passed: suitePassed,
      failed: suiteFailed,
    });
    console.log('');
  }

  const overallDuration = ((Date.now() - overallStartTime) / 1000).toFixed(2);

  // Close DB pool
  await closeDbPool();

  console.log('================================================================');
  console.log('                      TEST RUN SUMMARY                          ');
  console.log('================================================================');
  console.log(`Total Test Suites Executed: ${suiteResults.length}`);
  console.log(`Total Test Cases Executed:   ${totalTests}`);
  console.log(`Passed:                      ${passedTests}`);
  console.log(`Failed:                      ${failedTests}`);
  console.log(`Total Execution Time:        ${overallDuration}s\n`);

  if (failures.length > 0) {
    console.log('----------------------------------------------------------------');
    console.log('                     FAILURE DETAILS                            ');
    console.log('----------------------------------------------------------------');
    failures.forEach((f, idx) => {
      console.log(`\n${idx + 1}) [${f.suite}] ${f.test}`);
      console.log(`   ${f.error}`);
    });
    console.log('\n================================================================');
    console.log(`RESULT: FAILED (${failedTests} failures need implementation fixes)`);
    console.log('================================================================');
    process.exit(1);
  } else {
    console.log('================================================================');
    console.log('RESULT: 100% PASSED');
    console.log('================================================================');
    process.exit(0);
  }
}

main().catch(async (err) => {
  console.error('[FATAL RUNNER ERROR]:', err);
  await closeDbPool();
  process.exit(1);
});
