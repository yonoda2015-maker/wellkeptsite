#!/usr/bin/env node
// WellKept Site leak scanner: finds secrets and personal data before they are pushed.
// Usage: node security/scan.mjs [paths...]   (default: all git-tracked files)
//        node security/scan.mjs --staged     (only staged files, for pre-commit)
// Exit code 1 when any finding is reported.
import { readFileSync, existsSync, statSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { extname } from 'node:path';

export const RULES = [
  { id: 'aws-access-key', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: 'github-token', re: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b/g },
  { id: 'stripe-secret', re: /\b(sk|rk)_live_[A-Za-z0-9]{16,}\b/g },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_\-]{35}\b/g },
  { id: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { id: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g },
  { id: 'openai-key', re: /\bsk-(proj-)?[A-Za-z0-9]{32,}\b/g },
  { id: 'private-key', re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY( BLOCK)?-----/g },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { id: 'db-url-with-password', re: /\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis):\/\/[^\s:@\/"']+:[^\s@\/"']+@/g },
  { id: 'generic-secret-assignment',
    re: /\b(api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token)\b["']?\s*[:=]\s*["']([^"'\s]{12,})["']/gi,
    check: m => !/^(your|example|changeme|xxx|<|\$\{|process\.env)/i.test(m[2]) },
  { id: 'credit-card', re: /\b(?:\d[ -]?){13,19}\b/g, check: m => luhn(m[0].replace(/\D/g, '')) && m[0].replace(/\D/g, '').length >= 13 },
  { id: 'us-ssn', re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  { id: 'jp-my-number', re: /(マイナンバー|個人番号|my ?number)[^\d]{0,10}(\d{4}[ -]?\d{4}[ -]?\d{4})/gi, check: m => myNumberValid(m[2].replace(/\D/g, '')) },
];

// Files that must never be committed, whatever their content.
export const FORBIDDEN_FILES = [/(^|\/)\.env(\.|$)(?!example)/, /\.(pem|key|p12|pfx)$/, /(^|\/)id_(rsa|ed25519|ecdsa)$/, /\.sql(\.gz)?$/, /(^|\/)\.vercel\//];

const BINARY = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.woff', '.woff2', '.pdf', '.zip']);
const IGNORE_LINE = 'leak-scan:ignore';

export function luhn(d) {
  let s = 0;
  for (let i = 0; i < d.length; i++) {
    let n = +d[d.length - 1 - i];
    if (i % 2) { n *= 2; if (n > 9) n -= 9; }
    s += n;
  }
  return s % 10 === 0 && !/^(\d)\1+$/.test(d);
}

export function myNumberValid(d) {
  if (d.length !== 12) return false;
  const p = d.slice(0, 11).split('').reverse().map(Number);
  const sum = p.reduce((a, n, i) => a + n * (i < 6 ? i + 2 : i - 4), 0);
  const r = sum % 11;
  return (r <= 1 ? 0 : 11 - r) === +d[11];
}

// Base64 blobs can hide secrets; decode and rescan them once.
function decodedVariants(text) {
  const out = [];
  for (const m of text.matchAll(/[A-Za-z0-9+\/]{24,}={0,2}/g)) {
    try {
      const s = Buffer.from(m[0], 'base64').toString('utf8');
      if (/^[\x20-\x7e\s]+$/.test(s)) out.push(s);
    } catch {}
  }
  return out;
}

export function scanText(text, file = '<text>') {
  const findings = [];
  const lines = text.split('\n');
  lines.forEach((line, i) => {
    if (line.includes(IGNORE_LINE)) return;
    const variants = [line, line.normalize('NFKC'), ...decodedVariants(line)];
    const seen = new Set();
    for (const v of variants) {
      for (const r of RULES) {
        for (const m of v.matchAll(r.re)) {
          if (r.check && !r.check(m)) continue;
          const key = r.id + m.index;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({ file, line: i + 1, rule: r.id, match: redact(m[0]), encoded: v !== line });
        }
      }
    }
  });
  return findings;
}

function redact(s) { return s.length <= 8 ? '****' : s.slice(0, 4) + '…' + s.slice(-2); }

function listFiles(args) {
  if (args.includes('--staged')) return execSync('git diff --cached --name-only --diff-filter=ACM', { encoding: 'utf8' }).split('\n').filter(Boolean);
  const paths = args.filter(a => !a.startsWith('--'));
  if (paths.length) return paths;
  return execSync('git ls-files', { encoding: 'utf8' }).split('\n').filter(Boolean);
}

export function scanFiles(files) {
  const findings = [];
  for (const f of files) {
    if (FORBIDDEN_FILES.some(re => re.test(f))) findings.push({ file: f, line: 0, rule: 'forbidden-file', match: f });
    if (f === 'security/scan.test.mjs' || f === '.claude/hooks/leak-guard.test.mjs') continue; // deliberate fake leaks
    if (!existsSync(f) || statSync(f).isDirectory() || BINARY.has(extname(f).toLowerCase()) || f.endsWith('package-lock.json')) continue;
    findings.push(...scanText(readFileSync(f, 'utf8'), f));
  }
  return findings;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const findings = scanFiles(listFiles(process.argv.slice(2)));
  for (const f of findings) console.log(`${f.file}:${f.line}  [${f.rule}]  ${f.match}${f.encoded ? '  (encoded)' : ''}`);
  if (findings.length) {
    console.error(`\n✖ ${findings.length} possible leak(s). Remove them, or add "${IGNORE_LINE}" on the line if it is a deliberate fake.`);
    process.exit(1);
  }
  console.log('✔ No leaks found.');
}
