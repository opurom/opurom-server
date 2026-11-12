#!/usr/bin/env node
// Print the next lightweight version tag given all existing tags on stdin.
import { nextTag, parseTag, tagRank, isVersionTag } from './version.mjs';

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', c => { input += c; });
process.stdin.on('end', () => {
  const tags = input.split(/\s+/).filter(isVersionTag);
  let latest = null;
  for (const t of tags) if (!latest || tagRank(t) > tagRank(latest)) latest = t;
  const next = nextTag(latest);
  parseTag(next);
  process.stdout.write(next + '\n');
});
