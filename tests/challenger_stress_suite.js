/**
 * Challenger 1: Empirical Adversarial Stress & Security Test Suite
 * Stress-tests:
 * 1. Rate Limiting & Header Spoofing (Login bursts, Inquiry bursts, Rotated XFF)
 * 2. Adversarial Injections & Parameter Attacks (HPP, XSS, Dangerous URIs)
 * 3. Multi-Tenant IDOR Probing (Cross-tenant reads, updates, deletes, settings)
 */

const http = require('http');
const { FIXTURES } = require('./helpers/db_helper');

const BASE_HOST = '127.0.0.1';
const BASE_PORT = 3000;

function httpRequest({ method = 'GET', path, headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const reqHeaders = { ...headers };
    let payload = null;
    if (body !== null) {
      payload = typeof body === 'string' ? body : JSON.stringify(body);
      reqHeaders['Content-Type'] = reqHeaders['Content-Type'] || 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(payload);
    }
    const req = http.request({
      hostname: BASE_HOST,
      port: BASE_PORT,
      path,
      method,
      headers: reqHeaders,
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(data);
        } catch (_) {}
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: data,
          json,
        });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function loginUser(email, password, ip = '127.0.0.1') {
  const res = await httpRequest({
    method: 'POST',
    path: '/api/auth/login',
    headers: { 'X-Forwarded-For': ip },
    body: { emailOrUsername: email, password },
  });
  if (res.status === 200 && res.json && res.json.token) {
    return res.json.token;
  }
  return null;
}

async function runAdversarialSuite() {
  console.log('================================================================');
  console.log('       Challenger 1: Adversarial Stress & Verification Suite    ');
  console.log('================================================================\n');

  const findings = [];
  const results = {
    total: 0,
    passed: 0,
    failed: 0,
  };

  function record(testName, passed, detail) {
    results.total++;
    if (passed) {
      results.passed++;
      console.log(`  [PASS] ${testName}`);
    } else {
      results.failed++;
      console.log(`  [FAIL] ${testName}`);
      console.log(`         Details: ${detail}`);
      findings.push({ testName, detail });
    }
  }

  // -------------------------------------------------------------------------
  // SECTION 1: Adversarial Rate Limiting & Header Spoofing
  // -------------------------------------------------------------------------
  console.log('--- SECTION 1: Rate Limiting & Header Spoofing ---');

  // Test 1.1: Single IP normal login lockout (Must return 429 after 5 failed attempts)
  {
    const singleIp = `198.51.99.${Date.now() % 200}`;
    const targetUser = `single_ip_user_${Date.now()}@example.com`;
    let got429 = false;
    for (let i = 1; i <= 6; i++) {
      const res = await httpRequest({
        method: 'POST',
        path: '/api/auth/login',
        headers: { 'X-Forwarded-For': singleIp },
        body: { emailOrUsername: targetUser, password: 'WrongPassword' + i },
      });
      if (i <= 4 && res.status !== 401) {
        record('1.1 Standard Login Rate Limit: 1-4 failed attempts return 401', false, `Attempt ${i} returned HTTP ${res.status}`);
        break;
      }
      if (i >= 5 && res.status === 429) {
        got429 = true;
      }
    }
    record('1.1 Standard Login Rate Limit: 5th/6th failed attempt returns HTTP 429', got429, `Lockout 429 was ${got429 ? 'observed' : 'NOT observed'}`);
  }

  // Test 1.2: Rotated XFF burst on login (Adversary attempting to bypass login rate limit)
  {
    const targetUser = `rot_xff_user_${Date.now()}@example.com`;
    let lockouts = 0;
    let allowedFails = 0;
    for (let i = 1; i <= 10; i++) {
      const rotatedIp = `198.51.88.${i}`;
      const res = await httpRequest({
        method: 'POST',
        path: '/api/auth/login',
        headers: { 'X-Forwarded-For': rotatedIp },
        body: { emailOrUsername: targetUser, password: 'WrongPassword' + i },
      });
      if (res.status === 429) lockouts++;
      if (res.status === 401) allowedFails++;
    }
    // If the rate limiter keys only on IP or IP+user, rotated XFF allows all 10 failed attempts
    const resistant = lockouts > 0;
    record('1.2 Rotated X-Forwarded-For on Login: Enforces rate limit against credential stuffing', resistant,
      `Rotated XFF allowed ${allowedFails}/10 attempts with 0 lockouts. Rate limit is bypassable via rotated XFF header.`);
  }

  // Test 1.3: Standard inquiry rate limit (Must return 429 after 3 inquiries per minute from same IP)
  {
    const singleIp = `198.51.77.${Date.now() % 200}`;
    let inquiry429 = false;
    for (let i = 1; i <= 5; i++) {
      const res = await httpRequest({
        method: 'POST',
        path: '/api/public/inquiries',
        headers: { 'X-Forwarded-For': singleIp },
        body: {
          tenant_id: FIXTURES.TENANT_DPS_ID,
          student_name: 'Inquiry Rate Student ' + i,
          phone: '+91 9876543210',
          email: `single_ip_lead_${i}@example.com`,
          grade: 'Grade 1',
        },
      });
      if (res.status === 429) {
        inquiry429 = true;
        break;
      }
    }
    record('1.3 Standard Inquiry Rate Limit: Returns 429 within 5 submissions from single IP', inquiry429,
      `Inquiry 429 was ${inquiry429 ? 'observed' : 'NOT observed'}`);
  }

  // Test 1.4: Rotated XFF burst on public inquiries (Adversary attempting spam submission)
  {
    let createdCount = 0;
    let rateLimitedCount = 0;
    for (let i = 1; i <= 10; i++) {
      const fakeIp = `203.0.113.${100 + i}`;
      const res = await httpRequest({
        method: 'POST',
        path: '/api/public/inquiries',
        headers: { 'X-Forwarded-For': fakeIp },
        body: {
          tenant_id: FIXTURES.TENANT_DPS_ID,
          student_name: 'Rotated XFF Student ' + i,
          phone: '+91 9876543210',
          email: `rot_lead_${Date.now()}_${i}@example.com`,
          grade: 'Grade 2',
        },
      });
      if (res.status === 201) createdCount++;
      if (res.status === 429) rateLimitedCount++;
    }
    const xffInquiryCapped = rateLimitedCount > 0;
    record('1.4 Rotated X-Forwarded-For on Inquiries: Caps rapid spam burst from single connection', xffInquiryCapped,
      `Rotated XFF permitted ${createdCount}/10 inquiries to be created with 0 rate limit lockouts.`);
  }

  // -------------------------------------------------------------------------
  // SECTION 2: Adversarial Injection & Parameter Attacks
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 2: Adversarial Injection & Parameter Attacks ---');

  // Test 2.1: HTTP Parameter Pollution (HPP) on school query
  {
    const res = await httpRequest({
      method: 'GET',
      path: '/?school=dps-delhi&school=rkmps',
    });
    const noCrash = res.status !== 500 && res.status !== 502;
    record('2.1 HPP on Public School Portal: ?school=a&school=b does not trigger 500 crash', noCrash,
      `Status: HTTP ${res.status}`);
  }

  // Test 2.2: Array pollution on tenant_id query param
  {
    const res = await httpRequest({
      method: 'GET',
      path: `/?school[]=${FIXTURES.TENANT_DPS_SLUG}`,
    });
    const noCrash = res.status !== 500 && res.status !== 502;
    record('2.2 Array Parameter Pollution: ?school[]=slug handled safely without crash', noCrash,
      `Status: HTTP ${res.status}`);
  }

  // Test 2.3: Stored XSS in public inquiry fields
  {
    const scriptPayload = "<script>alert('xss')</script>";
    const eventPayload = "<img src=x onerror=alert('xss')>";
    const res = await httpRequest({
      method: 'POST',
      path: '/api/public/inquiries',
      headers: { 'X-Forwarded-For': `198.51.66.${Date.now() % 200}` },
      body: {
        tenant_id: FIXTURES.TENANT_DPS_ID,
        student_name: 'XSS Student ' + scriptPayload,
        parent_name: 'XSS Parent ' + eventPayload,
        phone: '+91 9876543210',
        email: `xss_test_${Date.now()}@example.com`,
        grade: 'Grade 3',
        notes: 'Notes payload ' + scriptPayload,
      },
    });

    let safeHandling = false;
    if (res.status === 400) {
      safeHandling = true; // Rejected upfront
    } else if (res.status === 201) {
      // Stored - check how it is retrieved by admin
      const dpsToken = await loginUser(FIXTURES.TEST_ADMIN_DPS.email, FIXTURES.TEST_ADMIN_DPS.password, '127.0.0.1');
      if (dpsToken) {
        const getRes = await httpRequest({
          method: 'GET',
          path: '/api/admin/inquiries?limit=5',
          headers: { 'Authorization': `Bearer ${dpsToken}` },
        });
        if (getRes.status === 200 && getRes.json && getRes.json.inquiries) {
          const match = getRes.json.inquiries.find(inq => (inq.student_name || '').includes('XSS Student'));
          if (match) {
            // Verify <script> tag is stripped or escaped
            const rawScriptPreserved = (match.student_name || '').includes('<script>');
            safeHandling = !rawScriptPreserved;
          }
        }
      }
    }
    record('2.3 Stored XSS Handling in Inquiries: Script tags neutralized / stripped', safeHandling,
      `Status: HTTP ${res.status}`);
  }

  // Test 2.4: Dangerous URI scheme rejection: javascript: in file download creation
  {
    const dpsToken = await loginUser(FIXTURES.TEST_ADMIN_DPS.email, FIXTURES.TEST_ADMIN_DPS.password, '127.0.0.1');
    let rejected = false;
    if (dpsToken) {
      const res = await httpRequest({
        method: 'POST',
        path: '/api/admin/downloads',
        headers: { 'Authorization': `Bearer ${dpsToken}` },
        body: {
          tenant_id: FIXTURES.TENANT_DPS_ID,
          title: 'Malicious Download',
          file_url: 'javascript:alert(document.cookie)',
          category: 'Academics',
          file_size: '100 KB',
        },
      });
      rejected = res.status === 400;
    }
    record('2.4 Dangerous URI Schemes: javascript: URL in downloads rejected with HTTP 400', rejected,
      `Download creation with javascript: returned status: HTTP ${rejected ? '400' : 'not 400'}`);
  }

  // Test 2.5: Dangerous URI scheme rejection: data:text/html in downloads
  {
    const dpsToken = await loginUser(FIXTURES.TEST_ADMIN_DPS.email, FIXTURES.TEST_ADMIN_DPS.password, '127.0.0.1');
    let rejected = false;
    if (dpsToken) {
      const res = await httpRequest({
        method: 'POST',
        path: '/api/admin/downloads',
        headers: { 'Authorization': `Bearer ${dpsToken}` },
        body: {
          tenant_id: FIXTURES.TENANT_DPS_ID,
          title: 'HTML Data URI',
          file_url: 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
          category: 'Academics',
          file_size: '100 KB',
        },
      });
      rejected = res.status === 400;
    }
    record('2.5 Dangerous URI Schemes: data:text/html URI in downloads rejected with HTTP 400', rejected,
      `Download creation with data:text/html returned status: HTTP ${rejected ? '400' : 'not 400'}`);
  }

  // -------------------------------------------------------------------------
  // SECTION 3: Multi-Tenant IDOR Probing
  // -------------------------------------------------------------------------
  console.log('\n--- SECTION 3: Multi-Tenant IDOR Probing ---');

  const dpsToken = await loginUser(FIXTURES.TEST_ADMIN_DPS.email, FIXTURES.TEST_ADMIN_DPS.password, '127.0.0.1');
  const rkmToken = await loginUser(FIXTURES.TEST_ADMIN_RKM.email, FIXTURES.TEST_ADMIN_RKM.password, '127.0.0.1');

  if (!dpsToken || !rkmToken) {
    console.error('[ERROR] Could not authenticate test admins for IDOR probing.');
    return;
  }

  // Test 3.1: Cross-tenant inquiry read (DPS admin querying RK Mission inquiries)
  {
    const res = await httpRequest({
      method: 'GET',
      path: `/api/admin/inquiries?tenant_id=${FIXTURES.TENANT_RKM_ID}`,
      headers: { 'Authorization': `Bearer ${dpsToken}` },
    });
    const forbidden = res.status === 403;
    record('3.1 Cross-Tenant Read: DPS Admin querying RK Mission inquiries returns HTTP 403', forbidden,
      `Expected HTTP 403, got HTTP ${res.status}: ${res.body}`);
  }

  // Test 3.2: Cross-tenant data bundle read (DPS admin querying RK Mission data)
  {
    const res = await httpRequest({
      method: 'GET',
      path: `/api/admin/data?tenant_id=${FIXTURES.TENANT_RKM_ID}`,
      headers: { 'Authorization': `Bearer ${dpsToken}` },
    });
    const forbidden = res.status === 403;
    record('3.2 Cross-Tenant Read: DPS Admin querying RK Mission /api/admin/data returns HTTP 403', forbidden,
      `Expected HTTP 403, got HTTP ${res.status}`);
  }

  // Test 3.3: Cross-tenant notice creation (DPS admin injecting RK Mission tenant_id)
  {
    const res = await httpRequest({
      method: 'POST',
      path: '/api/admin/notices',
      headers: { 'Authorization': `Bearer ${dpsToken}` },
      body: {
        tenant_id: FIXTURES.TENANT_RKM_ID,
        title: 'IDOR Injected Notice',
        content: 'Cross-tenant attack attempt',
        category: 'Urgent',
        priority: 'high',
      },
    });
    const forbidden = res.status === 403;
    record('3.3 Cross-Tenant Write: DPS Admin creating notice for RK Mission returns HTTP 403', forbidden,
      `Expected HTTP 403, got HTTP ${res.status}`);
  }

  // Test 3.4: Cross-tenant settings update (DPS admin modifying RK Mission settings)
  {
    const res = await httpRequest({
      method: 'PUT',
      path: '/api/admin/settings',
      headers: { 'Authorization': `Bearer ${dpsToken}` },
      body: {
        tenant_id: FIXTURES.TENANT_RKM_ID,
        school_name: 'DPS Hacked RK Mission',
        settings: { motto: 'Attacked' },
      },
    });
    const forbidden = res.status === 403;
    record('3.4 Cross-Tenant Update: DPS Admin modifying RK Mission settings returns HTTP 403', forbidden,
      `Expected HTTP 403, got HTTP ${res.status}`);
  }

  // Test 3.5: Cross-tenant CSV export (DPS admin attempting to export RK Mission leads)
  {
    const res = await httpRequest({
      method: 'GET',
      path: `/api/admin/inquiries/export?tenant_id=${FIXTURES.TENANT_RKM_ID}`,
      headers: { 'Authorization': `Bearer ${dpsToken}` },
    });
    const forbidden = res.status === 403;
    record('3.5 Cross-Tenant Export: DPS Admin exporting RK Mission inquiries returns HTTP 403', forbidden,
      `Expected HTTP 403, got HTTP ${res.status}`);
  }

  // -------------------------------------------------------------------------
  // SUMMARY
  // -------------------------------------------------------------------------
  console.log('\n================================================================');
  console.log('                 ADVERSARIAL SUITE SUMMARY                      ');
  console.log('================================================================');
  console.log(`Total Adversarial Tests: ${results.total}`);
  console.log(`Passed:                  ${results.passed}`);
  console.log(`Failed / Bypass Found:   ${results.failed}\n`);

  if (findings.length > 0) {
    console.log('Confirmed Vulnerabilities / Adversarial Findings:');
    findings.forEach((f, idx) => {
      console.log(`\n${idx + 1}) ${f.testName}`);
      console.log(`   ${f.detail}`);
    });
  }
}

runAdversarialSuite().catch(console.error);
