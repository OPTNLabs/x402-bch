import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

const fixture = JSON.parse(
  await readFile(
    new URL('../spec/conformance/v1/payment-requirements.json', import.meta.url),
    'utf8',
  ),
);

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
console.log(`conformance fixtures: ${fixture.cases.length} cases validated`);

const root = new URL('..', import.meta.url).pathname;
execFileSync('python3', [join(root, 'packages/python/test_conformance.py')], { stdio: 'inherit' });
const temp = mkdtempSync(join(tmpdir(), 'x402-bch-parity-'));
try {
  const javaDir = join(root, 'packages/java');
  execFileSync('javac', ['-d', temp, join(javaDir, 'ConformanceTest.java')], { stdio: 'inherit' });
  execFileSync('java', ['-cp', temp, 'ConformanceTest'], { stdio: 'inherit' });
  const cppBinary = join(temp, 'conformance_test');
  execFileSync(
    'g++',
    ['-std=c++17', join(root, 'packages/cpp/conformance_test.cpp'), '-o', cppBinary],
    { stdio: 'inherit' },
  );
  execFileSync(cppBinary, [], { stdio: 'inherit' });
} finally {
  rmSync(temp, { recursive: true, force: true });
}
if (existsSync('/usr/bin/go') || existsSync(`${process.env.PATH?.split(':')[0]}/go`)) {
  execFileSync('go', ['test', './...'], { cwd: join(root, 'packages/go'), stdio: 'inherit' });
} else {
  console.warn('go toolchain unavailable; Go conformance test not run');
}
