#!/usr/bin/env node
// Verifies the live site sends the expected security headers. Usage: node security/check-headers.mjs https://wellkeptsite.com/
const url = process.argv[2] || 'https://wellkeptsite.com/';
const REQUIRED = ['strict-transport-security', 'x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy'];
const res = await fetch(url, { redirect: 'follow' });
const missing = REQUIRED.filter(h => !res.headers.has(h));
for (const h of REQUIRED) console.log(`${missing.includes(h) ? '✖' : '✔'} ${h}${res.headers.get(h) ? ': ' + res.headers.get(h) : ''}`);
const csp = res.headers.get('content-security-policy') || res.headers.get('content-security-policy-report-only');
console.log(`${csp ? '✔' : '✖'} content-security-policy${res.headers.has('content-security-policy') ? '' : ' (report-only)'}`);
if (missing.length) process.exit(1);
