#!/usr/bin/env node
// Shared version arithmetic for all OPUROM repositories.
// Tags are lightweight, sequential per repository: v0.0.0001, v0.0.0002 ...
// v0.0.9999 is followed by v0.1.0000 (four-digit patch, middle component rolls).
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';

export const FIRST_TAG = 'v0.0.0001';

export function parseTag(tag) {
  const m = /^v(\d+)\.(\d+)\.(\d{4})$/.exec(String(tag || '').trim());
  if (!m) throw new Error(`invalid version tag: ${tag}`);
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

export function formatTag({ major, minor, patch }) {
  return `v${major}.${minor}.${String(patch).padStart(4, '0')}`;
}

export function nextTag(tag) {
  if (!tag) return FIRST_TAG;
  const v = parseTag(tag);
  if (v.patch >= 9999) return formatTag({ major: v.major, minor: v.minor + 1, patch: 0 });
  return formatTag({ major: v.major, minor: v.minor, patch: v.patch + 1 });
}

export function tagRank(tag) {
  const v = parseTag(tag);
  return ((v.major * 10000 + v.minor) * 10000) + v.patch;
}

export function isVersionTag(tag) {
  return /^v\d+\.\d+\.\d{4}$/.test(String(tag || '').trim());
}

export function git(dir, args) {
  const r = spawnSync('git', args, { cwd: dir, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')} in ${dir}: ${(r.stderr || '').trim()}`);
  return (r.stdout || '').trim();
}

export function commitsOldestFirst(dir) {
  return git(dir, ['log', '--reverse', '--format=%H']).split('\n').filter(Boolean);
}

export function existingTags(dir) {
  return git(dir, ['tag', '--list']).split('\n').filter(isVersionTag);
}

// Assign one lightweight version tag per commit, oldest first. Missing tags
// are created; existing correct tags are left alone. Returns the newest tag.
export function tagCommits(dir) {
  const commits = commitsOldestFirst(dir);
  if (!commits.length) throw new Error(`no commits in ${dir}`);
  const tags = existingTags(dir);
  const byTag = new Map(tags.map(t => [git(dir, ['rev-list', '-n', '1', t]), t]));
  let expected = FIRST_TAG;
  const created = [];
  for (const sha of commits) {
    const current = byTag.get(sha);
    if (!current) {
      git(dir, ['tag', expected, sha]);
      byTag.set(sha, expected);
      created.push(expected);
    } else {
      expected = current;
    }
    expected = nextTag(expected);
  }
  return { newest: byTag.get(commits[commits.length - 1]), created, count: commits.length };
}

export function reposAt(root) {
  return readdirSync(root, { withFileTypes: true })
    .filter(e => e.isDirectory() && e.name.startsWith('opurom-') && existsSync(resolve(root, e.name, '.git')))
    .map(e => e.name)
    .sort();
}
