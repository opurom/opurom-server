#!/usr/bin/env node
// Release notes in two modes.
//
// Fleet mode (default): stdin carries [{"repo","subjects":[...]}] — the
// grouped commit subjects the evaluate job collected for every product
// repository. Each repository becomes a section.
//
// Repo mode: --repo-only <tag> [prev-tag] — collect the subjects of THIS
// repository from local git log between the two tags and emit the same
// three-bucket body without a repository heading. The sub-repository
// release workflow uses this mode.
import { execFileSync } from 'node:child_process';

const sentence = (s) => {
  const first = s.split(/\s+/)[0] || '';
  return /^[a-z]/.test(s) && !/[._/]/.test(first) ? s[0].toUpperCase() + s.slice(1) : s;
};

const group = (subjects, repo) => {
  const buckets = { Features: [], Changes: [], Fixes: [] };
  for (const raw of subjects) {
    // entries arrive as {sha, message} (fleet) or plain strings (repo mode)
    const sha = typeof raw === 'object' ? raw.sha : '';
    let s = typeof raw === 'object' ? raw.message : raw;
    s = s.split('\n')[0].trim();
    if (!s) continue;
    const m = /^([a-z]+)\(([^)]+)\):\s*(.+)$/.exec(s) || /^([a-z]+):\s*(.+)$/.exec(s);
    if (!m) { buckets.Changes.push(`- ${sentence(s)}${linkFor(repo, sha)}`); continue; }
    const type = m[1];
    const subject = m[3] ?? m[2];
    const scope = m[3] === undefined ? '' : m[2];
    const head = type === 'feat' ? 'Features' : type === 'fix' ? 'Fixes' : 'Changes';
    const body = scope ? `${sentence(subject)} in ${scope}` : sentence(subject);
    buckets[head].push(`- ${body}${linkFor(repo, sha)}`);
  }
  return buckets;
};

const linkFor = (repo, sha) =>
  sha ? ` ([${repo}@${sha.slice(0, 7)}](https://github.com/opurom/${repo}/commit/${sha}))` : '';

function collectSubjects(tag, prev) {
  const range = prev ? `${prev}..${tag}` : tag;
  const out = execFileSync('git', ['log', '--format=%s', range], { encoding: 'utf8' });
  return out.split('\n').map((s) => s.trim()).filter(Boolean);
}

function prevTagOf(tag) {
  const tags = execFileSync('git', ['tag', '--sort=-v:refname'], { encoding: 'utf8' })
    .split('\n').map((s) => s.trim()).filter(Boolean);
  const i = tags.indexOf(tag);
  return i >= 0 && tags[i + 1] ? tags[i + 1] : '';
}

if (process.argv.includes('--repo-only')) {
  const i = process.argv.indexOf('--repo-only');
  const tag = process.argv[i + 1];
  if (!tag) { console.error('usage: node release-notes.mjs --repo-only <tag> [prev-tag]'); process.exit(1); }
  const prev = process.argv[i + 2] || prevTagOf(tag);
  const b = group(collectSubjects(tag, prev), '');  // repo mode: no per-entry links
  const parts = [];
  for (const h of ['Features', 'Changes', 'Fixes']) {
    if (b[h].length) parts.push(`### ${h}\n${b[h].join('\n')}`);
  }
  parts.push(`**Full Changelog**: https://github.com/opurom/${process.env.GITHUB_REPOSITORY || 'opurom/opurom-release'}/compare/${prev || ''}...${tag}`);
  process.stdout.write(parts.join('\n\n') + '\n');
  process.exit(0);
}

process.stdin.setEncoding('utf8');
let input = '';
process.stdin.on('data', (c) => { input += c; });
process.stdin.on('end', () => {
  const fleet = JSON.parse(input);
  // Aggregate across repositories into the three standard buckets; each
  // entry links to its source commit.
  const b = { Features: [], Changes: [], Fixes: [] };
  for (const { repo, subjects } of fleet) {
    const grouped = group(subjects, repo);
    for (const h of ['Features', 'Changes', 'Fixes']) {
      b[h].push(...grouped[h]);
    }
  }
  const parts = [];
  for (const h of ['Features', 'Changes', 'Fixes']) {
    if (b[h].length) parts.push(`### ${h}\n\n${b[h].join('\n')}`);
  }
  if (!parts.length) parts.push('No eligible changes since the previous train.');
  process.stdout.write(parts.join('\n\n') + '\n');
});
