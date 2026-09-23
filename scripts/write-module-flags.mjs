/**
 * Tell Node what each build directory is.
 *
 * The package is `"type": "module"`, so every .js file under it is ESM unless
 * something says otherwise — and `dist/cjs` is emphatically not. Without this,
 * a CommonJS consumer like Inventory's server requires dist/cjs/index.js, Node
 * reads the nearest package.json, sees "module", and refuses it with
 * ERR_REQUIRE_ESM. The build looks fine; the failure is at the consumer.
 *
 * A one-line package.json in each directory is the documented way to scope the
 * module type, and it is why a bundler is not needed here: `tsc` twice plus
 * these two files is the whole dual build.
 *
 * Run from `npm run build`. Safe to re-run.
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

/** @type {[string, string][]} */
const flags = [
  ['dist/esm', 'module'],
  ['dist/cjs', 'commonjs'],
];

for (const [dir, type] of flags) {
  const target = join(root, dir);
  mkdirSync(target, { recursive: true });
  writeFileSync(join(target, 'package.json'), `${JSON.stringify({ type }, null, 2)}\n`);
  process.stdout.write(`wrote ${dir}/package.json ("type": "${type}")\n`);
}
