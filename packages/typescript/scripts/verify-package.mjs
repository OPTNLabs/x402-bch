import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = process.cwd();
const packageJson = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));

for (const [subpath, conditions] of Object.entries(packageJson.exports)) {
  const importTarget = resolve(root, conditions.import);
  const typeTarget = resolve(root, conditions.types);
  if (!existsSync(importTarget) || !existsSync(typeTarget)) {
    throw new Error(`missing build output for ${subpath}`);
  }
  const imported = await import(importTarget);
  if (typeof imported !== 'object' || imported === null) {
    throw new Error(`invalid ESM export for ${subpath}`);
  }
}

console.log(`verified ${Object.keys(packageJson.exports).length} public export paths`);
