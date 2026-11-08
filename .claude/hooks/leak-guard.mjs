#!/usr/bin/env node
// Claude Code PreToolUse hook: stops Claude from writing secrets/personal data into files,
// reading secret files, or sending them out through shell commands. Exit 2 = block.
import { scanText, FORBIDDEN_FILES } from '../../security/scan.mjs';

const input = JSON.parse(await new Promise(r => { let d = ''; process.stdin.on('data', c => d += c); process.stdin.on('end', () => r(d)); }));
const { tool_name: tool, tool_input: t = {} } = input;
const block = msg => { console.error(`leak-guard: ${msg}`); process.exit(2); };
const path = t.file_path || t.notebook_path || '';
const secretFile = p => FORBIDDEN_FILES.some(re => re.test(p.replace(/^.*?\/(?=[^/]*$)/, '')) || re.test(p));

if (['Read', 'Write', 'Edit', 'NotebookEdit'].includes(tool) && path && secretFile(path))
  block(`access to secret file ${path} is not allowed`);

if (['Write', 'Edit', 'NotebookEdit'].includes(tool) && !path.endsWith('security/scan.test.mjs')) {
  const text = [t.content, t.new_string, t.new_source, ...(t.edits || []).map(e => e.new_string)].filter(Boolean).join('\n');
  const hits = scanText(text, path);
  if (hits.length) block(`refusing to write ${hits.map(h => h.rule).join(', ')} into ${path}`);
}

if (tool === 'Bash') {
  const cmd = t.command || '';
  if (/(^|[\s;&|(])(cat|less|more|head|tail|grep|sed|awk|cp|scp|base64|xxd|strings)\b[^|;&]*(\.env\b|\.pem\b|id_rsa|id_ed25519|\.vercel\/)/.test(cmd))
    block('reading or copying secret files from the shell is not allowed');
  if (/(^|[\s;&|(])(env|printenv|set)\s*($|[|;&>])|echo\s+["']?\$\{?[A-Z_]*(TOKEN|SECRET|KEY|PASSWORD|POSTGRES_URL)/.test(cmd))
    block('printing environment secrets is not allowed');
  if (/\b(curl|wget|nc|ncat)\b[\s\S]*(\.env|\$\{?[A-Z_]*(TOKEN|SECRET|KEY|PASSWORD))/.test(cmd))
    block('sending secrets over the network is not allowed');
  const hits = scanText(cmd);
  if (hits.length) block(`command contains ${hits.map(h => h.rule).join(', ')}`);
}
process.exit(0);
