#!/usr/bin/env node
// Print the next lightweight version tag for this repository. Existing tags
// arrive on stdin; the current release series is read from the repo's version
// file (Cargo.toml, package.json or VERSION). Promoting that file to a new
// series restarts the alpha counter at 1 for the new series only, so a 0.2.0
// repository is tagged v0.2.0-alpha.1, v0.2.0-alpha.2, ... while its earlier
// v0.1.0-alpha.* tags are left untouched.
import { nextTagForSeries, readReleaseSeries } from './version.mjs';

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', c => { input += c; });
process.stdin.on('end', () => {
  const tags = input.split(/\s+/).filter(Boolean);
  const series = readReleaseSeries(process.cwd());
  process.stdout.write(nextTagForSeries(tags, series) + '\n');
});
