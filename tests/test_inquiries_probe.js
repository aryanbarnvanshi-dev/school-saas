const http = require('http');

async function sendInquiry(xff, email) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      tenant_id: '9f025e7d-a42c-4c8e-8ea6-c9a8d9c02442',
      student_name: 'Burst Test Student',
      phone: '+91 9876543210',
      email: email,
      grade: 'Grade 1'
    });
    const req = http.request({
      hostname: '127.0.0.1',
      port: 3000,
      path: '/api/public/inquiries',
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
  console.log('Testing 10 public inquiries with rotated X-Forwarded-For and distinct email per request:');
  for (let i = 1; i <= 10; i++) {
    const fakeIp = `203.0.113.${i}`;
    const email = `burst_lead_${Date.now()}_${i}@example.com`;
    const res = await sendInquiry(fakeIp, email);
    console.log(`Inquiry ${i} [XFF: ${fakeIp}] -> HTTP ${res.status}: ${res.body}`);
  }
}

main().catch(console.error);
