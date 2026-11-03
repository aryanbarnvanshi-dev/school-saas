const http = require('http');

async function sendLogin(xff, email, password) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ emailOrUsername: email, password: password });
    const req = http.request({
      hostname: '127.0.0.1',
      port: 3000,
      path: '/api/auth/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'X-Forwarded-For': xff,
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function main() {
  console.log('Testing 10 failed logins with rotating X-Forwarded-For for the SAME target account:');
  const targetEmail = 'probe_target_' + Date.now() + '@example.com';
  for (let i = 1; i <= 10; i++) {
    const fakeIp = `198.51.100.${i}`;
    const res = await sendLogin(fakeIp, targetEmail, 'WrongPassword' + i);
    console.log(`Attempt ${i} [XFF: ${fakeIp}] -> HTTP ${res.status}: ${res.body}`);
  }
}

main().catch(console.error);
