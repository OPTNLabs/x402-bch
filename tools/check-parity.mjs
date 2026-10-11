import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const fixtureRelativePath = 'spec/conformance/v1/payment-requirements.json';
const packageFixtures = [
  ['TypeScript', 'packages/typescript'],
  ['Rust', 'packages/rust'],
  ['Go', 'packages/go'],
  ['Java', 'packages/java'],
  ['Python', 'packages/python'],
  ['C++', 'packages/cpp'],
];

const canonicalPath = join(root, packageFixtures[0][1], fixtureRelativePath);
const canonicalText = await readFile(canonicalPath, 'utf8');
const fixture = JSON.parse(canonicalText);

if (fixture.version !== 1 || !Array.isArray(fixture.cases) || fixture.cases.length < 1) {
  throw new Error('invalid conformance fixture');
}
for (const testCase of fixture.cases) {
  const { requirements, expected } = testCase;
  if (requirements.x402Version !== 2) throw new Error(`${testCase.name}: x402 version`);
  if (requirements.scheme !== 'exact') throw new Error(`${testCase.name}: scheme`);
  if (!/^\d+$/.test(requirements.amount)) throw new Error(`${testCase.name}: amount`);
  if (
    requirements.extra?.requestHash !== undefined &&
    !/^[0-9a-f]{64}$/.test(requirements.extra.requestHash)
  ) {
    throw new Error(`${testCase.name}: requestHash`);
  }
  if (expected.requestHashBytes !== undefined && expected.requestHashBytes !== 32) {
    throw new Error(`${testCase.name}: requestHashBytes`);
  }
}

for (const [language, packagePath] of packageFixtures.slice(1)) {
  const packageFixturePath = join(root, packagePath, fixtureRelativePath);
  const packageText = await readFile(packageFixturePath, 'utf8');
  if (packageText !== canonicalText) {
    throw new Error(`${language} fixture differs from the TypeScript fixture`);
  }
}
console.log(
  `conformance fixtures: ${fixture.cases.length} cases validated across ${packageFixtures.length} packages`,
);

function commandAvailable(command) {
  try {
    execFileSync('which', [command], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function run(command, args, cwd) {
  execFileSync(command, args, { cwd, stdio: 'inherit' });
}

run('npm', ['run', 'test:conformance'], join(root, 'packages/typescript'));
run('python3', ['tests/run_conformance.py'], join(root, 'packages/python'));
run('make', ['test'], join(root, 'packages/java'));

const cppBuild = mkdtempSync(join(tmpdir(), 'x402-bch-cpp-'));
try {
  run('cmake', ['-S', join(root, 'packages/cpp'), '-B', cppBuild], root);
  run('cmake', ['--build', cppBuild], root);
  run('ctest', ['--test-dir', cppBuild, '--output-on-failure'], root);
} finally {
  rmSync(cppBuild, { recursive: true, force: true });
}

if (commandAvailable('go')) {
  run('go', ['test', './...'], join(root, 'packages/go'));
} else {
  console.warn('go toolchain unavailable; Go conformance test not run');
}

if (commandAvailable('cargo')) {
  run(
    'cargo',
    ['test', '--manifest-path', 'Cargo.toml', '--locked', '-p', 'x402-chain-bch', '--lib'],
    join(root, 'packages/rust'),
  );
} else {
  console.warn('cargo toolchain unavailable; Rust conformance test not run');
}
