import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const manifestPath = join(root, 'spec/feature-manifest.json');
const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));

const requiredLanguages = ['typescript', 'rust', 'go', 'java', 'python', 'cpp'];
const allowedStatuses = new Set(['complete', 'partial', 'missing', 'runtime-only']);
const allowedEvidence = new Set(['source', 'fixture', 'mocknet', 'provider', 'mempool', 'confirmed', 'runtime']);

if (manifest.schemaVersion !== 1) throw new Error('feature manifest schemaVersion must be 1');
if (manifest.contractVersion !== 'x402-bch-sdk-1') throw new Error('feature manifest contractVersion mismatch');
if (JSON.stringify(manifest.languages) !== JSON.stringify(requiredLanguages)) {
  throw new Error('feature manifest languages must list the six supported SDKs in canonical order');
}
if (!Array.isArray(manifest.features) || manifest.features.length === 0) {
  throw new Error('feature manifest must contain features');
}

const ids = new Set();
for (const feature of manifest.features) {
  if (!feature || typeof feature !== 'object') throw new Error('feature manifest contains a non-object feature');
  if (!/^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$/.test(feature.id)) {
    throw new Error(`invalid feature id: ${feature.id}`);
  }
  if (ids.has(feature.id)) throw new Error(`duplicate feature id: ${feature.id}`);
  ids.add(feature.id);
  if (typeof feature.title !== 'string' || feature.title.length === 0) {
    throw new Error(`${feature.id}: title is required`);
  }
  if (!Array.isArray(feature.roles) || feature.roles.length === 0) {
    throw new Error(`${feature.id}: roles are required`);
  }
  if (!Array.isArray(feature.fixtures)) throw new Error(`${feature.id}: fixtures must be an array`);
  if (!Array.isArray(feature.requiredEvidence) || feature.requiredEvidence.length === 0) {
    throw new Error(`${feature.id}: requiredEvidence is required`);
  }
  for (const evidence of feature.requiredEvidence) {
    if (!allowedEvidence.has(evidence)) throw new Error(`${feature.id}: unsupported evidence state ${evidence}`);
  }
  if (!feature.coverage || typeof feature.coverage !== 'object') {
    throw new Error(`${feature.id}: coverage is required`);
  }
  for (const language of requiredLanguages) {
    const status = feature.coverage[language];
    if (!allowedStatuses.has(status)) throw new Error(`${feature.id}: invalid ${language} status ${status}`);
  }
}

const gaps = manifest.features.flatMap((feature) =>
  requiredLanguages
    .filter((language) => feature.coverage[language] !== 'complete' && feature.coverage[language] !== 'runtime-only')
    .map((language) => `${feature.id}:${language}:${feature.coverage[language]}`),
);

console.log(`feature manifest: ${manifest.features.length} features, ${gaps.length} non-complete language obligations`);
if (gaps.length > 0) {
  console.log(gaps.map((gap) => `  - ${gap}`).join('\n'));
}

if (process.env.X402_STRICT_PARITY === '1' && gaps.length > 0) {
  throw new Error(`strict feature parity is incomplete (${gaps.length} obligations remain)`);
}
