#!/usr/bin/env node
/**
 * Pre-publication scan: every blob reachable from any ref, every commit's author, committer and
 * message, and the working tree. Exits 1 on any finding.
 *
 *   node scripts/release_scan.mjs [--patterns <file>]
 *
 * Built-in patterns cover credential formats and home-directory paths. Personal identifiers
 * (names, user names, private project names) belong in an untracked patterns file, one regular
 * expression per line, default `.release-scan.local`. Author and committer fields equal to the
 * publishing identity (`--allow-identity "Name <email>"`, default the repository's git user.name and
 * user.email) are not scanned; every other identity is. `--allow-email <address>` accepts an address.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const BUILTIN = [
  ['Anthropic key', /sk-ant-[A-Za-z0-9_-]{10,}/],
  ['OpenAI key', /\bsk-(?:proj-)?[A-Za-z0-9]{20,}/],
  ['GitHub token', /\b(?:gh[opsur]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/],
  ['AWS key id', /\bAKIA[0-9A-Z]{16}\b/],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ['private key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['bearer token', /\bBearer\s+[A-Za-z0-9._~+/-]{20,}/],
  ['Windows home path', /[A-Za-z]:[\\/]+Users[\\/]+(?!Public\b)[^\\/\s"'`]+/i],
  ['POSIX home path', /(?:^|[\s"'`(])\/(?:home|Users)\/[^/\s"'`]+/],
  ['email address', /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/],
];
// Addresses that are public by design.
const ALLOWED_EMAILS = new Set(['noreply@github.com']);

function git(args, input) {
  const r = spawnSync('git', ['-C', ROOT, ...args], { maxBuffer: 1 << 30, input });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${r.stderr}`);
  return r.stdout;
}
const argv = process.argv.slice(2);
const option = name => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
for (const address of argv.flatMap((v, i) => v === '--allow-email' ? [argv[i + 1]] : [])) ALLOWED_EMAILS.add(address.toLowerCase());
const patternFile = option('--patterns') || join(ROOT, '.release-scan.local');
// Default: the repository's configured identity, which is what new commits are authored as.
const configured = key => spawnSync('git', ['-C', ROOT, 'config', key], { encoding: 'utf8' }).stdout.trim();
const ALLOWED_IDENTITY = option('--allow-identity') || `${configured('user.name')} <${configured('user.email')}>`;
const patterns = [...BUILTIN];
if (existsSync(patternFile)) {
  for (const line of readFileSync(patternFile, 'utf8').split(/\r?\n/))
    if (line.trim() && !line.startsWith('#')) patterns.push([`local pattern ${line.trim()}`, new RegExp(line.trim(), 'i')]);
} else console.log(`note: no local patterns file at ${patternFile}; personal identifiers are not checked`);

const findings = [];
function scan(where, text) {
  for (const [label, re] of patterns) {
    const global = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    for (const m of text.matchAll(global)) {
      if (label === 'email address' && ALLOWED_EMAILS.has(m[0].toLowerCase())) continue;
      if (label === 'email address' && /@(?:example\.(?:com|org)|users\.noreply\.github\.com)$/i.test(m[0])) continue;
      findings.push(`${where}: ${label}: ${m[0].slice(0, 80)}`);
    }
  }
}

const hasHistory = spawnSync('git', ['-C', ROOT, 'rev-parse', '--verify', 'HEAD'], { encoding: 'utf8' }).status === 0;
let blobs = 0, commits = 0;
if (hasHistory) {
  // Commit metadata: author, committer and the full message of every commit on every ref.
  const log = git(['log', '--all', '--format=%H%x00%an <%ae>%x00%cn <%ce>%x00%B%x01']).toString('utf8');
  for (const entry of log.split('\x01').filter(e => e.trim())) {
    const [hash, author, committer, message] = entry.trim().split('\x00');
    commits++;
    // The publishing identity is public by design; anything else in these fields is scanned.
    if (author !== ALLOWED_IDENTITY) scan(`commit ${hash.slice(0, 12)} author`, author);
    if (committer !== ALLOWED_IDENTITY) scan(`commit ${hash.slice(0, 12)} committer`, committer);
    scan(`commit ${hash.slice(0, 12)} message`, message || '');
  }
  // Every blob reachable from any ref, including ones later deleted.
  const objects = git(['rev-list', '--all', '--objects']).toString('utf8').split('\n').filter(Boolean);
  const names = new Map(objects.map(l => [l.slice(0, 40), l.slice(41)]));
  const types = git(['cat-file', '--batch-check=%(objectname) %(objecttype)'], [...names.keys()].join('\n') + '\n')
    .toString('utf8').split('\n').filter(Boolean).map(l => l.split(' '));
  for (const [hash, type] of types) {
    if (type !== 'blob') continue;
    blobs++;
    scan(`blob ${hash.slice(0, 12)} (${names.get(hash) || '?'})`, git(['cat-file', 'blob', hash]).toString('utf8'));
    scan(`path of blob ${hash.slice(0, 12)}`, names.get(hash) || '');
  }
}
// Working tree, excluding .git and the local patterns file itself.
let files = 0;
(function walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (name === '.git' || path === resolve(patternFile)) continue;
    const s = statSync(path);
    if (s.isDirectory()) walk(path);
    else { files++; scan(`file ${relative(ROOT, path)}`, readFileSync(path, 'utf8')); }
  }
})(ROOT);

console.log(`scanned ${commits} commits, ${blobs} blobs, ${files} working-tree files with ${patterns.length} patterns`);
if (findings.length) {
  console.log(findings.join('\n'));
  console.log(`\nFAIL: ${findings.length} finding(s)`);
  process.exitCode = 1;
} else console.log('PASS: no findings');
