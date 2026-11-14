#!/usr/bin/env node
// Shared SemVer 2.0 version arithmetic for all OPUROM repositories.
//
// Tag format: vMAJOR.MINOR.PATCH[-STAGE.N]
//   STAGE = alpha | beta | rc (pre-release), or absent (final release)
//   N starts at 1 with no leading zeros.
//
// Sequence: v0.1.0-alpha.1, v0.1.0-alpha.2 ... v0.1.0-beta.1 ...
// v0.1.0-rc.1 ... v0.1.0, then v0.1.1, v0.2.0, v1.0.0.
// Stage promotion is an explicit human decision (see promoteStage), never an
// automatic side effect of nextTag, so iteration numbers never jump a stage.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';

export const FIRST_TAG = 'v0.1.0-alpha.1';
export const STAGES = ['alpha', 'beta', 'rc'];
const STAGE_RANK = { alpha: 0, beta: 1, rc: 2, final: 3 };

// SemVer 2.0 shape: no leading zeros in any numeric field.
const TAG_RE = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(alpha|beta|rc)\.([1-9]\d*))?$/;

export function parseTag(tag) {
  const m = TAG_RE.exec(String(tag || '').trim());
  if (!m) throw new Error(`invalid SemVer version tag: ${tag}`);
  return {
    major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]),
    stage: m[4] || null, iteration: m[5] ? Number(m[5]) : null,
  };
}

export function formatTag(v) {
  const base = `v${v.major}.${v.minor}.${v.patch}`;
  return v.stage ? `${base}-${v.stage}.${v.iteration}` : base;
}

// Next tag in the SAME stage. Final releases bump the patch component.
export function nextTag(tag) {
  if (!tag) return FIRST_TAG;
  const v = parseTag(tag);
  if (v.stage) return formatTag({ ...v, iteration: v.iteration + 1 });
  return formatTag({ ...v, patch: v.patch + 1 });
}

// Explicit stage promotion, resetting the iteration to 1.
export function promoteStage(tag, stage) {
  if (!STAGES.includes(stage)) throw new Error(`unknown stage: ${stage}`);
  const v = parseTag(tag);
  return formatTag({ ...v, stage, iteration: 1 });
}

// Explicit final release, dropping the prerelease suffix.
export function finalizeVersion(tag) {
  const v = parseTag(tag);
  return formatTag({ ...v, stage: null, iteration: null });
}

// Comparable integer: numeric fields dominate, then stage, then iteration.
// A final release sorts AFTER every prerelease of the same numeric version.
export function tagRank(tag) {
  const v = parseTag(tag);
  const rank = v.stage ? STAGE_RANK[v.stage] : STAGE_RANK.final;
  const iter = v.stage ? v.iteration : 0;
  return (((v.major * 1_000_000 + v.minor) * 1_000_000 + v.patch) * 10 + rank) * 1_000_000 + iter;
}

export function isVersionTag(tag) {
  return TAG_RE.test(String(tag || '').trim());
}

export function isPrerelease(tag) {
  return Boolean(parseTag(tag).stage);
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

// Read the version series a specific commit declares, looking at the version
// file as it existed at that commit (so historical commits resolve to the
// series in force when they landed). Returns null when the commit predates any
// version file.
function seriesAtCommit(dir, sha) {
  const tryRead = (file, parse) => {
    const r = spawnSync('git', ['show', `${sha}:${file}`], { cwd: dir, encoding: 'utf8' });
    if (r.status !== 0) return null;
    return parse(r.stdout);
  };
  const cargoOf = (text) => {
    const m = /^\s*version\s*=\s*"(\d+\.\d+\.\d+)"\s*$/m.exec(text);
    return m ? m[1] : null;
  };
  const pkgOf = (text) => {
    try { const v = JSON.parse(text).version; return typeof v === 'string' ? v : null; } catch { return null; }
  };
  const raw = tryRead('Cargo.toml', cargoOf) ?? tryRead('package.json', pkgOf) ?? tryRead('VERSION', (t) => t.trim());
  if (!raw) return null;
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(raw);
  return m ? { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) } : null;
}

// Assign one lightweight SemVer tag per commit, oldest first. Each commit is
// tagged inside the series its version file declared at that commit: a series
// change (0.1.0 -> 0.2.0) restarts the alpha counter at 1 without touching the
// previous series' tags. Existing correct tags are left alone; only missing
// ones are created. Returns the newest tag.
export function tagCommits(dir) {
  const commits = commitsOldestFirst(dir);
  if (!commits.length) throw new Error(`no commits in ${dir}`);
  const tags = existingTags(dir);
  const byTag = new Map(tags.map(t => [git(dir, ['rev-list', '-n', '1', t]), t]));
  const created = [];
  let counter = 0; // alpha iteration within the current series
  let seriesKey = null;
  for (const sha of commits) {
    const series = seriesAtCommit(dir, sha) ?? { major: 0, minor: 1, patch: 0 };
    const key = `${series.major}.${series.minor}.${series.patch}`;
    if (key !== seriesKey) { seriesKey = key; counter = 0; }
    counter += 1;
    const expected = `v${key}-alpha.${counter}`;
    const current = byTag.get(sha);
    if (!current) {
      git(dir, ['tag', expected, sha]);
      byTag.set(sha, expected);
      created.push(expected);
    }
    // If a commit already carries a tag, trust it and keep counting from the
    // series position rather than renumbering existing history.
  }
  return { newest: byTag.get(commits[commits.length - 1]), created, count: commits.length };
}

export function reposAt(root) {
  return readdirSync(root, { withFileTypes: true })
    .filter(e => e.isDirectory() && e.name.startsWith('opurom-') && existsSync(resolve(root, e.name, '.git')))
    .map(e => e.name)
    .sort();
}

// The release series for a repository, read from the version file it already
// ships. Precedence: Cargo.toml `version`, then package.json `version`, then a
// plain `VERSION` file for repos with neither (e.g. a pure-data repo). Editing
// the file is how a maintainer promotes the series (0.1.0 -> 0.2.0); CI then
// tags the next alpha of that series on the following commit.
export function readReleaseSeries(dir) {
  const fromCargo = () => {
    const file = resolve(dir, 'Cargo.toml');
    if (!existsSync(file)) return null;
    const m = /^\s*version\s*=\s*"([^"]+)"/m.exec(readFileSync(file, 'utf8'));
    return m ? m[1] : null;
  };
  const fromPkg = () => {
    const file = resolve(dir, 'package.json');
    if (!existsSync(file)) return null;
    const v = JSON.parse(readFileSync(file, 'utf8')).version;
    return typeof v === 'string' ? v : null;
  };
  const fromVersionFile = () => {
    const file = resolve(dir, 'VERSION');
    if (!existsSync(file)) return null;
    return readFileSync(file, 'utf8').trim();
  };
  const raw = fromCargo() ?? fromPkg() ?? fromVersionFile();
  if (!raw) throw new Error(`no version found in ${dir} (Cargo.toml, package.json or VERSION)`);
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(raw);
  if (!m) throw new Error(`version must be MAJOR.MINOR.PATCH, got ${JSON.stringify(raw)}`);
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

// Next alpha tag for the series declared in VERSION, given the tags already in
// the repo: the iteration continues from the highest existing alpha of the SAME
// series, so promoting VERSION to a new series restarts at alpha.1 without
// touching tag numbers of the previous series.
export function nextTagForSeries(existingTagsList, { major, minor, patch }) {
  const prefix = `v${major}.${minor}.${patch}-alpha.`;
  let max = 0;
  for (const t of existingTagsList) {
    if (typeof t === 'string' && t.startsWith(prefix)) {
      const n = Number(t.slice(prefix.length));
      if (Number.isInteger(n) && n > max) max = n;
    }
  }
  return `v${major}.${minor}.${patch}-alpha.${max + 1}`;
}
