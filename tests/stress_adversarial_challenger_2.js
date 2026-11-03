/**
 * Challenger 2: Adversarial Concurrency & Memory Budget Verification Harness
 * Empirical stress test for 512MB RAM budget, event loop latency, gzip compression, and CSV streaming.
 */

const http = require('http');
const zlib = require('zlib');
const path = require('path');
const { defaultClient } = require('./helpers/test_client');
const { FIXTURES, query, closeDbPool, ensureTestUsers } = require('./helpers/db_helper');
const { assertEqual, assertContains, assertNotContains } = require('./helpers/assertions');

// Minimal RFC 4180 CSV parser for empirical validation
function parseRfc4180Csv(csvString) {
  // Strip BOM if present
  let cleanCsv = csvString;
  if (cleanCsv.charCodeAt(0) === 0xFEFF) {
    cleanCsv = cleanCsv.slice(1);
  }

  const rows = [];
  let currentRow = [];
  let currentField = '';
  let inQuotes = false;
  let i = 0;

  while (i < cleanCsv.length) {
    const char = cleanCsv[i];
    const nextChar = cleanCsv[i + 1];

    if (inQuotes) {
      if (char === '"' && nextChar === '"') {
        currentField += '"';
        i += 2;
      } else if (char === '"') {
        inQuotes = false;
        i++;
      } else {
        currentField += char;
        i++;
      }
    } else {
      if (char === '"') {
        inQuotes = true;
        i++;
      } else if (char === ',') {
        currentRow.push(currentField);
        currentField = '';
        i++;
      } else if (char === '\r' && nextChar === '\n') {
        currentRow.push(currentField);
        rows.push(currentRow);
        currentRow = [];
        currentField = '';
        i += 2;
      } else if (char === '\n') {
        currentRow.push(currentField);
        rows.push(currentRow);
        currentRow = [];
        currentField = '';
        i++;
      } else {
        currentField += char;
        i++;
      }
  if (currentField.length > 0 || currentRow.length > 0) {
    currentRow.push(currentField);
    rows.push(currentRow);
  }
  return rows;
}

async function safeQuery(sql, params = [], retries = 3) {
  for (let a = 1; a <= retries; a++) {
    try {
      return await query(sql, params);
    } catch (err) {
      if (a === retries) throw err;
      console.log(`[WARN] safeQuery retry ${a}/${retries} after error: ${err.message}`);
      await new Promise(r => setTimeout(r, 1000 * a));
    }
  }
}

async function runAdversarialChallenge() {
  console.log('================================================================');
  console.log('   CHALLENGER 2: ADVERSARIAL CONCURRENCY & MEMORY BUDGET TEST   ');
  console.log('================================================================\n');

  try {
    await ensureTestUsers();
  } catch (err) {
    console.log('[WARN] ensureTestUsers skipped/failed:', err.message);
  }

  const metrics = {
    idleRssMb: 0,
    peakRssMb: 0,
    postLoadRssMb: 0,
    eventLoopP50: 0,
    eventLoopP99: 0,
    poolTotal: 0,
    poolIdle: 0,
    poolWaiting: 0,
    compressionRatios: {},
    csvTestsPassed: 0,
    concurrencyErrors: 0,
  };

  let allPassed = true;

  // =========================================================================
  // SECTION 1: MEMORY & EVENT LOOP CONCURRENCY STRESS
  // =========================================================================
  console.log('>>> [SECTION 1] MEMORY & EVENT LOOP CONCURRENCY STRESS');

  // Step 1.1: Idle Baseline
  console.log('--- Step 1.1: Idle Memory & Event Loop Baseline ---');
  await new Promise(r => setTimeout(r, 2000)); // Allow idle settling
  const healthRes1 = await defaultClient.get('/health');
  assertEqual(healthRes1.status, 200, 'Health endpoint should return 200');
  
  metrics.idleRssMb = healthRes1.json.memory.rss_mb;
  metrics.eventLoopP50 = healthRes1.json.event_loop.p50_ms;
  metrics.eventLoopP99 = healthRes1.json.event_loop.p99_ms;
  metrics.poolTotal = healthRes1.json.database.pool.totalCount;
  metrics.poolIdle = healthRes1.json.database.pool.idleCount;
  metrics.poolWaiting = healthRes1.json.database.pool.waitingCount;

  console.log(`  - Idle RSS:              ${metrics.idleRssMb.toFixed(2)} MB (Budget: strictly < 100 MB)`);
  console.log(`  - Heap Used:             ${healthRes1.json.memory.heap_used_mb.toFixed(2)} MB`);
  console.log(`  - Event Loop Lag (p50):  ${metrics.eventLoopP50.toFixed(2)} ms`);
  console.log(`  - Event Loop Lag (p99):  ${metrics.eventLoopP99.toFixed(2)} ms`);
  console.log(`  - DB Pool Total:         ${metrics.poolTotal}`);
  console.log(`  - DB Pool Idle:          ${metrics.poolIdle}`);
  console.log(`  - DB Pool Waiting:       ${metrics.poolWaiting}`);

  if (metrics.idleRssMb >= 100) {
    console.error(`  [FAIL] Idle RSS ${metrics.idleRssMb}MB exceeds strict 100MB limit!`);
    allPassed = false;
  } else {
    console.log(`  [PASS] Idle RSS is strictly < 100 MB.`);
  }

  if (metrics.poolWaiting > 0) {
    console.error(`  [FAIL] DB pool has waiting requests at idle: ${metrics.poolWaiting}`);
    allPassed = false;
  }

  // Step 1.2: Concurrency Burst (50 concurrent requests: 25 SSR + 25 Health)
  console.log('\n--- Step 1.2: Concurrency Spike (50 simultaneous requests) ---');
  const burstStart = Date.now();
  const burstReqs = [];
  for (let i = 0; i < 50; i++) {
    const isSsr = i % 2 === 0;
    const path = isSsr ? '/?school=dps-delhi' : '/health';
    burstReqs.push(defaultClient.request({
      method: 'GET',
      path,
      timeout: 30000,
      headers: { 'Accept-Encoding': 'gzip, deflate' }
    }));
  }

  const burstResults = await Promise.all(burstReqs);
  const burstDuration = Date.now() - burstStart;
  const burstFailures = burstResults.filter(r => r.status !== 200);
  console.log(`  - Executed 50 concurrent requests in ${burstDuration} ms`);
  console.log(`  - Successful: ${50 - burstFailures.length} / 50`);
  if (burstFailures.length > 0) {
    console.error(`  [FAIL] ${burstFailures.length} requests failed during concurrency spike!`);
    allPassed = false;
  } else {
    console.log(`  [PASS] 100% of concurrent requests returned HTTP 200.`);
  }

  // Step 1.3: Sustained Concurrency Spike (100 requests in 5 waves of 20)
  console.log('\n--- Step 1.3: Sustained Load (100 requests across 5 waves) ---');
  let maxRssObserved = metrics.idleRssMb;
  for (let wave = 1; wave <= 5; wave++) {
    const waveReqs = [];
    for (let j = 0; j < 20; j++) {
      const tenantIdx = j % 3;
      const targetSlug = tenantIdx === 0 ? 'dps-delhi' : (tenantIdx === 1 ? 'rkmps' : 'stxavier');
      const wavePath = j % 4 === 0 ? '/health' : `/?school=${targetSlug}`;
      waveReqs.push(defaultClient.request({
        method: 'GET',
        path: wavePath,
        timeout: 30000,
        headers: { 'Accept-Encoding': 'gzip, deflate' }
      }));
    }
    const waveRes = await Promise.all(waveReqs);
    const waveFails = waveRes.filter(r => r.status !== 200);
    if (waveFails.length > 0) {
      metrics.concurrencyErrors += waveFails.length;
    }

    const midHealth = await defaultClient.get('/health');
    const waveRss = midHealth.json.memory.rss_mb;
    if (waveRss > maxRssObserved) maxRssObserved = waveRss;
    process.stdout.write(`  - Wave ${wave}/5: 20 reqs done, current RSS: ${waveRss.toFixed(2)} MB, pool: total=${midHealth.json.database.pool.totalCount}, waiting=${midHealth.json.database.pool.waitingCount}\n`);
  }

  metrics.peakRssMb = maxRssObserved;
  console.log(`  - Peak RSS Under Concurrency Spikes: ${metrics.peakRssMb.toFixed(2)} MB (Budget: strictly < 250 MB)`);
  if (metrics.peakRssMb >= 250) {
    console.error(`  [FAIL] Peak RSS ${metrics.peakRssMb}MB exceeded 250MB concurrency spike budget!`);
    allPassed = false;
  } else {
    console.log(`  [PASS] Peak RSS complies with < 250MB limit under concurrency spikes.`);
  }

  // Step 1.4: Pool Starvation & Recovery Verification
  console.log('\n--- Step 1.4: DB Pool Release & Starvation Invariant ---');
  await new Promise(r => setTimeout(r, 1000));
  const postHealth = await defaultClient.get('/health');
  metrics.postLoadRssMb = postHealth.json.memory.rss_mb;
  const postPool = postHealth.json.database.pool;
  console.log(`  - Post-load Pool State: total=${postPool.totalCount}, idle=${postPool.idleCount}, waiting=${postPool.waitingCount}`);
  console.log(`  - Event Loop Lag (p50=${postHealth.json.event_loop.p50_ms.toFixed(2)}ms, max=${postHealth.json.event_loop.max_ms.toFixed(2)}ms)`);

  if (postPool.totalCount > 10) {
    console.error(`  [FAIL] Connection pool exceeded max 10 clients: totalCount=${postPool.totalCount}`);
    allPassed = false;
  } else {
    console.log(`  [PASS] Connection pool respect max 10 bound (actual: ${postPool.totalCount}/10).`);
  }

  if (postPool.waitingCount !== 0) {
    console.error(`  [FAIL] Connection pool starvation: ${postPool.waitingCount} requests waiting!`);
    allPassed = false;
  } else {
    console.log(`  [PASS] Zero pool starvation. Connections released cleanly.`);
  }

  // =========================================================================
  // SECTION 2: COMPRESSION & PAYLOAD STRESS
  // =========================================================================
  console.log('\n>>> [SECTION 2] COMPRESSION & PAYLOAD STRESS');

  const compressionTargets = [
    { name: 'DPS School Portal (SSR)', path: '/?school=dps-delhi' },
    { name: 'RK Mission Portal (SSR)', path: '/?school=rkmps' },
    { name: 'St. Xavier Portal (SSR)', path: '/?school=stxavier' },
    { name: 'SaaS Platform Landing Page', path: '/' },
  ];

  for (const target of compressionTargets) {
    // 2.1: Request with gzip
    const gzippedRes = await defaultClient.request({
      method: 'GET',
      path: target.path,
      headers: { 'Accept-Encoding': 'gzip, deflate' }
    });
    assertEqual(gzippedRes.status, 200, `${target.name} should return 200`);

    // 2.2: Request uncompressed (identity)
    const rawRes = await defaultClient.request({
      method: 'GET',
      path: target.path,
      headers: { 'Accept-Encoding': 'identity' }
    });
    assertEqual(rawRes.status, 200, `${target.name} (identity) should return 200`);

    const rawSize = rawRes.rawBody.length;
    const compressedSize = gzippedRes.rawBody.length;
    const encoding = gzippedRes.headers['content-encoding'];
    const ratio = ((rawSize - compressedSize) / rawSize) * 100;
    metrics.compressionRatios[target.name] = ratio;

    console.log(`--- ${target.name} ---`);
    console.log(`  - Uncompressed size:   ${rawSize} bytes (${(rawSize / 1024).toFixed(2)} KB)`);
    console.log(`  - Gzipped wire size:   ${compressedSize} bytes (${(compressedSize / 1024).toFixed(2)} KB)`);
    console.log(`  - Content-Encoding:    ${encoding || 'none'}`);
    console.log(`  - Compression Ratio:   ${ratio.toFixed(2)}% reduction (Target: > 70%)`);

    if (rawSize > 1024) {
      if (encoding !== 'gzip') {
        console.error(`  [FAIL] Expected Content-Encoding: gzip for > 1KB payload, got: ${encoding || 'none'}`);
        allPassed = false;
      } else {
        console.log(`  [PASS] Content-Encoding: gzip present.`);
      }

      if (ratio < 70) {
        console.error(`  [FAIL] Compression ratio ${ratio.toFixed(2)}% is below required 70%!`);
        allPassed = false;
      } else {
        console.log(`  [PASS] Compression ratio ${ratio.toFixed(2)}% strictly exceeds 70% threshold.`);
      }
    }

    // Decompression byte-for-byte fidelity check
    const decompressed = zlib.gunzipSync(gzippedRes.rawBody);
    if (!decompressed.equals(rawRes.rawBody)) {
      console.error(`  [FAIL] Decompressed payload does not match identity payload byte-for-byte!`);
      allPassed = false;
    } else {
      console.log(`  [PASS] Decompressed payload matches identity payload with 100% byte fidelity.`);
    }
  }

  // 2.3: Uncompressed small responses (< 1KB)
  console.log('\n--- Small Responses (< 1KB) Non-Compression Verification ---');
  const smallEndpoints = [
    { name: '/health JSON metrics', path: '/health', expectedStatus: 200 },
    { name: '404 Unknown Tenant', path: '/?school=non-existent-tenant-xyz', expectedStatus: 404 },
    { name: '401 Unauthorized API', path: '/api/admin/inquiries', expectedStatus: 401 },
  ];

  for (const small of smallEndpoints) {
    const res = await defaultClient.request({
      method: 'GET',
      path: small.path,
      headers: { 'Accept-Encoding': 'gzip, deflate' }
    });
    assertEqual(res.status, small.expectedStatus, `${small.name} should return ${small.expectedStatus}`);
    const size = res.rawBody.length;
    const encoding = res.headers['content-encoding'];
    console.log(`  - ${small.name}: ${size} bytes, Content-Encoding: ${encoding || 'none (uncompressed)'}`);

    if (size < 1024) {
      if (encoding) {
        console.error(`  [FAIL] Payload < 1024 bytes (${size} bytes) should remain uncompressed, but got ${encoding}!`);
        allPassed = false;
      } else {
        console.log(`  [PASS] Correctly bypassed compression for < 1KB payload.`);
      }
    }
  }

  // =========================================================================
  // SECTION 3: ADMISSIONS & CSV EXPORT STRESS
  // =========================================================================
  console.log('\n>>> [SECTION 3] ADMISSIONS & CSV EXPORT STRESS');

  // Step 3.1: Seed adversarial inquiries with commas, double quotes, newlines, and Unicode
  console.log('--- Step 3.1: Seeding Adversarial Inquiries for RFC 4180 Testing ---');
  const dpsTenantId = FIXTURES.TENANTS.DPS.id;
  const timestamp = Date.now();
  const adversarialInquiries = [
    {
      student: `Smith, John Jr. ${timestamp}`,
      parent: `O'Connor, Mary "Mom"`,
      phone: '+91 98765 43210',
      email: `smith.jr.${timestamp}@test.com`,
      grade: 'Grade 10',
      notes: `Notes with "quoted text", commas, and\r\nnewlines on multiple\nlines!`,
      status: 'pending'
    },
    {
      student: `विद्यार्थी आर्यन ${timestamp} 🎓`,
      parent: `अभिभावक शर्मा`,
      phone: '+91 91234 56789',
      email: `aryan.unicode.${timestamp}@test.com`,
      grade: 'Grade 11 - Science',
      notes: `Multilingual note: नमस्ते! Über-Schüler & 中文测试`,
      status: 'reviewing'
    }
  ];

  for (const inq of adversarialInquiries) {
    await query(
      `INSERT INTO school_admission_inquiries (tenant_id, student_name, parent_name, phone, email, grade, notes, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [dpsTenantId, inq.student, inq.parent, inq.phone, inq.email, inq.grade, inq.notes, inq.status]
    );
  }
  console.log(`  - Seeded 2 adversarial test inquiries into DPS PostgreSQL database.`);

  // Step 3.2: Authenticated CSV Export Retrieval
  console.log('\n--- Step 3.2: Exporting CSV & Validating RFC 4180 & UTF-8 BOM ---');
  const loginRes = await defaultClient.login(
    FIXTURES.TEST_ADMIN_DPS.email,
    FIXTURES.TEST_ADMIN_DPS.password
  );
  assertEqual(loginRes.status, 200, 'DPS Admin login should succeed');
  const dpsToken = loginRes.json.token;

  const exportRes = await defaultClient.request({
    method: 'GET',
    path: '/api/admin/inquiries/export',
    token: dpsToken,
    headers: { 'Accept-Encoding': 'gzip, deflate' }
  });
  assertEqual(exportRes.status, 200, 'CSV export should return 200');

  const ct = exportRes.headers['content-type'] || '';
  const cd = exportRes.headers['content-disposition'] || '';
  console.log(`  - Content-Type:        ${ct}`);
  console.log(`  - Content-Disposition: ${cd}`);
  assertContains(ct.toLowerCase(), 'text/csv', 'Content-Type must be text/csv');
  assertContains(cd.toLowerCase(), 'attachment', 'Content-Disposition must be attachment');

  // Verify UTF-8 BOM (\uFEFF)
  // BOM can be checked in raw decompressed buffer or rawBody if uncompressed
  const csvBuffer = exportRes.decompressedBuffer;
  const hasBom = (csvBuffer[0] === 0xEF && csvBuffer[1] === 0xBB && csvBuffer[2] === 0xBF) ||
                 exportRes.body.charCodeAt(0) === 0xFEFF;
  console.log(`  - UTF-8 BOM Detected:  ${hasBom ? 'YES (0xEF, 0xBB, 0xBF)' : 'NO'}`);
  if (!hasBom) {
    console.error(`  [FAIL] Export missing UTF-8 BOM (\\uFEFF) required for Excel!`);
    allPassed = false;
  } else {
    console.log(`  [PASS] UTF-8 BOM present at offset 0.`);
    metrics.csvTestsPassed++;
  }

  // Parse CSV with RFC 4180 parser
  const parsedRows = parseRfc4180Csv(exportRes.body);
  console.log(`  - Total Rows Parsed:   ${parsedRows.length}`);
  const headerRow = parsedRows[0];
  console.log(`  - Header Columns:      ${headerRow ? headerRow.join(' | ') : 'EMPTY'}`);

  const expectedHeaders = ['Student Name', 'Parent Name', 'Phone', 'Email', 'Grade', 'Notes', 'Status', 'Submission Date'];
  assertEqual(headerRow.length, expectedHeaders.length, `Header column count should be ${expectedHeaders.length}`);
  for (let c = 0; c < expectedHeaders.length; c++) {
    assertEqual(headerRow[c], expectedHeaders[c], `Column ${c} should be "${expectedHeaders[c]}"`);
  }
  console.log(`  [PASS] Header columns strictly match RFC 4180 specification.`);
  metrics.csvTestsPassed++;

  // Step 3.3: Verify Field Escaping of Seeded Adversarial Data
  console.log('\n--- Step 3.3: Adversarial Data Escaping & Integrity Check ---');
  let foundComplexStudent = false;
  let foundUnicodeStudent = false;

  for (const row of parsedRows) {
    const student = row[0];
    const parent = row[1];
    const notes = row[5];
    const status = row[6];

    if (student && student.includes('Smith, John Jr.')) {
      foundComplexStudent = true;
      console.log(`  - Validated Complex Row:`);
      console.log(`    * Student: "${student}" (commas handled correctly)`);
      console.log(`    * Parent:  "${parent}" (quotes handled correctly)`);
      console.log(`    * Notes:   "${notes.replace(/\r?\n/g, '\\n')}" (multiline newlines handled correctly)`);
      assertEqual(parent, `O'Connor, Mary "Mom"`, 'Quotes in field must be unescaped correctly');
      assertContains(notes, 'quoted text', 'Quoted notes must match');
      assertContains(notes, '\n', 'Multiline newline must be preserved');
    }

    if (student && student.includes('विद्यार्थी आर्यन')) {
      foundUnicodeStudent = true;
      console.log(`  - Validated Unicode Row:`);
      console.log(`    * Student: "${student}" (Devanagari + Emoji preserved)`);
      console.log(`    * Parent:  "${parent}"`);
      console.log(`    * Status:  "${status}"`);
      console.log(`    * Notes:   "${notes}"`);
      assertContains(student, '🎓', 'Emoji in student name must be preserved');
      assertContains(notes, 'नमस्ते', 'Devanagari text in notes must be preserved');
      assertContains(notes, '中文测试', 'CJK characters in notes must be preserved');
    }
  }

  if (!foundComplexStudent || !foundUnicodeStudent) {
    console.error(`  [FAIL] Failed to locate seeded adversarial inquiry rows in exported CSV!`);
    allPassed = false;
  } else {
    console.log(`  [PASS] RFC 4180 escaping and UTF-8 multi-byte characters verified with 100% integrity.`);
    metrics.csvTestsPassed++;
  }

  // Step 3.4: Concurrent Inquiries While Running CSV Export (High Stress)
  console.log('\n--- Step 3.4: High-Concurrency Inquiries During Concurrent CSV Export ---');
  // Log in RK Mission admin for cross-tenant concurrent export
  const rkmLogin = await defaultClient.login(
    FIXTURES.TEST_ADMIN_RKM.email,
    FIXTURES.TEST_ADMIN_RKM.password
  );
  assertEqual(rkmLogin.status, 200);
  const rkmToken = rkmLogin.json.token;

  // We will run:
  // - 10 concurrent public inquiry submissions (with distinct IPs)
  // - 5 concurrent CSV exports for DPS
  // - 5 concurrent CSV exports for RK Mission
  const concurrentStressTasks = [];
  const insertedStudents = [];

  for (let i = 1; i <= 10; i++) {
    const sName = `Stress Lead #${i} - ${timestamp}`;
    insertedStudents.push(sName);
    concurrentStressTasks.push(
      defaultClient.request({
        method: 'POST',
        path: '/api/public/inquiries',
        ip: `198.51.100.${100 + i}`,
        json: {
          tenant_id: dpsTenantId,
          student_name: sName,
          parent_name: `Parent of #${i}`,
          phone: `+91 998877665${i % 10}`,
          grade: `Grade ${i % 12 + 1}`,
          notes: `Concurrent inquiry payload ${i}`,
        }
      }).then(res => ({ type: 'inquiry', id: i, res }))
    );
  }

  for (let d = 1; d <= 5; d++) {
    concurrentStressTasks.push(
      defaultClient.request({
        method: 'GET',
        path: '/api/admin/inquiries/export',
        token: dpsToken,
      }).then(res => ({ type: 'dps_export', id: d, res }))
    );
  }

  for (let r = 1; r <= 5; r++) {
    concurrentStressTasks.push(
      defaultClient.request({
        method: 'GET',
        path: '/api/admin/inquiries/export',
        token: rkmToken,
      }).then(res => ({ type: 'rkm_export', id: r, res }))
    );
  }

  const stressStart = Date.now();
  const stressResults = await Promise.all(concurrentStressTasks);
  const stressDuration = Date.now() - stressStart;

  console.log(`  - Completed 20 concurrent operations (10 inserts + 10 exports) in ${stressDuration} ms`);

  let inquiriesSucceeded = 0;
  let dpsExportsSucceeded = 0;
  let rkmExportsSucceeded = 0;

  for (const outcome of stressResults) {
    if (outcome.type === 'inquiry') {
      if (outcome.res.status === 201) inquiriesSucceeded++;
      else console.error(`    [FAIL] Inquiry #${outcome.id} failed with status ${outcome.res.status}`);
    } else if (outcome.type === 'dps_export') {
      if (outcome.res.status === 200 && outcome.res.body.startsWith('\uFEFF')) {
        dpsExportsSucceeded++;
      } else {
        console.error(`    [FAIL] DPS Export #${outcome.id} failed or missing BOM: status=${outcome.res.status}`);
      }
    } else if (outcome.type === 'rkm_export') {
      if (outcome.res.status === 200 && outcome.res.body.startsWith('\uFEFF')) {
        // Verify no DPS students leaked into RKM export
        let leaked = false;
        for (const sName of insertedStudents) {
          if (outcome.res.body.includes(sName)) leaked = true;
        }
        if (!leaked) {
          rkmExportsSucceeded++;
        } else {
          console.error(`    [FAIL] RKM Export #${outcome.id} leaked DPS students!`);
        }
      } else {
        console.error(`    [FAIL] RKM Export #${outcome.id} failed: status=${outcome.res.status}`);
      }
    }
  }

  console.log(`  - Concurrent Inquiries Succeeded: ${inquiriesSucceeded} / 10`);
  console.log(`  - Concurrent DPS Exports Succeeded: ${dpsExportsSucceeded} / 5`);
  console.log(`  - Concurrent RKM Exports Succeeded: ${rkmExportsSucceeded} / 5 (Zero cross-tenant leakage)`);

  if (inquiriesSucceeded === 10 && dpsExportsSucceeded === 5 && rkmExportsSucceeded === 5) {
    console.log(`  [PASS] 100% of concurrent inquiries and CSV exports completed cleanly without contention.`);
    metrics.csvTestsPassed++;
  } else {
    console.error(`  [FAIL] Concurrency stress test had failures.`);
    allPassed = false;
  }

  // Final Health & Pool Check
  const finalHealth = await defaultClient.get('/health');
  console.log('\n--- Final System State ---');
  console.log(`  - Final Server RSS:      ${finalHealth.json.memory.rss_mb.toFixed(2)} MB`);
  console.log(`  - Final Pool Clients:    ${finalHealth.json.database.pool.totalCount} (idle: ${finalHealth.json.database.pool.idleCount}, waiting: ${finalHealth.json.database.pool.waitingCount})`);
  console.log(`  - Final Event Loop Lag:  p50=${finalHealth.json.event_loop.p50_ms.toFixed(2)}ms, p99=${finalHealth.json.event_loop.p99_ms.toFixed(2)}ms`);

  await closeDbPool();

  console.log('\n================================================================');
  console.log(`FINAL VERDICT: ${allPassed ? 'APPROVE' : 'CHALLENGE_FAILED'}`);
  console.log('================================================================');

  if (!allPassed) {
    process.exit(1);
  }
}

runAdversarialChallenge().catch(err => {
  console.error('[UNCAUGHT TEST RUNNER ERROR]:', err);
  process.exit(1);
});
