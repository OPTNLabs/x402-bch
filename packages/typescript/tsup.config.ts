import { defineConfig } from 'tsup';

const baseConfig = {
  entry: {
    index: 'packages/typescript/src/index.ts',
    'exact/client/index': 'packages/typescript/src/exact/client/index.ts',
    'exact/server/index': 'packages/typescript/src/exact/server/index.ts',
    'exact/facilitator/index': 'packages/typescript/src/exact/facilitator/index.ts',
  },
  dts: { resolve: true },
  sourcemap: true,
  target: 'es2020',
};

export default defineConfig({
  ...baseConfig,
  format: 'esm',
  outDir: 'packages/typescript/dist/esm',
  clean: true,
});
