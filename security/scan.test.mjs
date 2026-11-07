// Measures the scanner: every planted leak must be caught (recall), clean text must pass (false positives).
// Run: node --test security/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanText } from './scan.mjs';

// All values below are fake and generated for testing. leak-scan:ignore applies only to real files.
const b64 = s => Buffer.from(s).toString('base64');
const LEAKS = {
  'aws-access-key': 'const k = "AKIA' + 'IOSFODNN7EXAMPLQ";',
  'github-token': 'token: ghp_' + 'a'.repeat(20) + 'B'.repeat(16),
  'stripe-secret': 'STRIPE=sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc',
  'google-api-key': 'key=AIza' + 'SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY',
  'slack-token': 'xoxb-' + '123456789012-abcdefABCDEF',
  'anthropic-key': 'sk-ant-' + 'api03-abcdefghijklmnopqrstuvwx',
  'private-key': '-----BEGIN RSA ' + 'PRIVATE KEY-----',
  'jwt': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
  'db-url-with-password': 'postgres://admin:' + 'hunter2pass@db.example.com/prod',
  'generic-secret-assignment': 'password = "' + 'Tr0ub4dor&3horse' + '"',
  'credit-card': 'card 4242 4242 4242 4242',
  'us-ssn': 'SSN 123-45-6789',
  'jp-my-number': 'マイナンバー: 1234 5678 9018',
};

const EVASIONS = {
  'base64-encoded stripe key': [b64('sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc'), 'stripe-secret'],
  'full-width aws key': ['ＡＫＩＡ' + 'IOSFODNN7EXAMPLQ', 'aws-access-key'],
  'card with dashes': ['4111-1111-1111-1111', 'credit-card'],
};

const CLEAN = [
  'Call us at (512) 555-0142 for a free audit.',
  '<meta name="google-site-verification" content="ggxXaxfzzloDc5hGSqMJa2dQzt55KuIgk-AsVXQqCrg" />',
  'Order #1234567890123 shipped',              // fails Luhn
  'password: "your-password-here"',            // placeholder
  'const apiKey = process.env.API_KEY;',
  'Use pk_live_ publishable keys only in the browser.',
  'font-family: "Hiragino Sans", Arial; color:#5B4FE8;',
  'マイナンバー: 1234 5678 9012',               // bad check digit
  'https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap',
];

for (const [rule, text] of Object.entries(LEAKS)) {
  test(`detects ${rule}`, () => assert.ok(scanText(text).some(f => f.rule === rule), `missed: ${text}`));
}
for (const [name, [text, rule]] of Object.entries(EVASIONS)) {
  test(`detects evasion: ${name}`, () => assert.ok(scanText(text).some(f => f.rule === rule)));
}
for (const text of CLEAN) {
  test(`no false positive: ${text.slice(0, 40)}`, () => assert.deepEqual(scanText(text), []));
}
test('ignore marker suppresses a line', () => assert.deepEqual(scanText('SSN 123-45-6789 // leak-scan:ignore'), []));
