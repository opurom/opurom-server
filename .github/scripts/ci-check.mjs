#!/usr/bin/env node
// CI check dispatcher: one check per parallel matrix job.
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, extname, relative } from 'node:path';

const ROOT = process.cwd();
const name = process.argv[2];
const TEXT_EXT = new Set(['.md', '.rs', '.js', '.mjs', '.cjs', '.json', '.yml', '.yaml', '.toml', '.opu', '.sql', '.sh', '.ts', '.txt', '.opuir.json', '.wxml', '.wxss', '.axml', '.acss', '.qml', '.qss', '.ttml', '.ttss', '.swan', '.ksml', '.css', '.html', '.gitignore']);
const CJK = /[\u3400-\u9FFF\uF900-\uFAFF\u3000-\u303F\uFF00-\uFFEF]/;

function tracked() {
  const r = spawnSync('git', ['ls-files', '-z'], { cwd: ROOT, encoding: 'utf8' });
  return (r.stdout || '').split('\0').filter(Boolean);
}
function run(cmd, args) {
  const r = spawnSync(cmd, args, { cwd: ROOT, encoding: 'utf8' });
  process.stdout.write(r.stdout || '');
  process.stderr.write(r.stderr || '');
  if (r.status !== 0) process.exit(r.status || 1);
}
function walk(dir, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (['.git', 'target', 'node_modules', '.DS_Store'].includes(e.name)) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.isFile()) out.push(p);
  }
  return out;
}

function isBrokenDocTarget(f, target) {
  if (/^(https?:|mailto:|#)/.test(target)) return false;
  const clean = target.replace(/^<|>$/g, '').replace(/#.*$/, '');
  if (!clean || clean.includes('*')) return false;
  // Sibling repositories are published separately, so a path that leaves this
  // repository is checked on GitHub, not on disk.
  if (clean.startsWith('..')) return false;
  return !existsSync(join(ROOT, f, '..', clean));
}

if (name === 'rust-test') {
  if (!existsSync(join(ROOT, 'Cargo.toml'))) { console.log('rust-test: SKIP (no Cargo.toml)'); process.exit(0); }
  run('cargo', ['test', '--all-targets']);
} else if (name === 'rust-fmt') {
  if (!existsSync(join(ROOT, 'Cargo.toml'))) { console.log('rust-fmt: SKIP (no Cargo.toml)'); process.exit(0); }
  // rustfmt output changes between releases, so the check only requires that
  // the tree is parseable and formatted by the pinned toolchain in CI. The
  // authoritative formatting gate is `cargo fmt` run before each commit.
  const r = spawnSync('cargo', ['fmt', '--all', '--', '--check'], { cwd: ROOT, encoding: 'utf8' });
  if (r.status === 0) { console.log('rust-fmt: OK'); process.exit(0); }
  console.log('rust-fmt: drift detected');
  console.log((r.stdout || '').split('\n').slice(0, 40).join('\n'));
  console.log('run `cargo fmt --all` in this repository to apply the pinned toolchain formatting');
  process.exit(1);
} else if (name === 'node-test') {
  const pkg = join(ROOT, 'package.json');
  if (!existsSync(pkg)) { console.log('node-test: SKIP (no package.json)'); process.exit(0); }
  const scripts = JSON.parse(readFileSync(pkg, 'utf8')).scripts || {};
  if (scripts.test) run('npm', ['test']);
  else if (existsSync(join(ROOT, 'test'))) run('node', ['--test']);
  else console.log('node-test: SKIP (no test script)');
} else if (name === 'node-syntax') {
  const files = walk(ROOT).filter(f => ['.js', '.mjs', '.cjs'].includes(extname(f)));
  for (const f of files) run('node', ['--check', relative(ROOT, f)]);
  console.log(`node-syntax: OK (${files.length} files)`);
} else if (name === 'validate') {
  if (existsSync(join(ROOT, 'scripts', 'validate.mjs'))) run('node', ['scripts/validate.mjs']);
  else console.log('validate: SKIP');

} else {
  console.error(`unknown check: ${name}`);
  process.exit(2);
}
