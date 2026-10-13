import { access } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const inventory = JSON.parse(await (await import('node:fs/promises')).readFile(join(root, 'spec/api-manifest.json'), 'utf8'));
const languages = ['typescript', 'rust', 'go', 'java', 'python', 'cpp'];
if (inventory.schemaVersion !== 1 || inventory.contractVersion !== 'x402-bch-sdk-1') throw new Error('API inventory header mismatch');
for (const language of languages) {
  const entry = inventory.packages?.[language];
  if (!entry || !Array.isArray(entry.required) || !Array.isArray(entry.roles) || entry.roles.length !== 5) throw new Error(`${language}: invalid API inventory entry`);
  for (const relativePath of entry.required) {
    try { await access(join(root, entry.root, relativePath)); }
    catch { throw new Error(`${language}: missing public API path ${relativePath}`); }
  }
}
console.log(`API inventory: ${languages.length} package surfaces and five roles validated`);
