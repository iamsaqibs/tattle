import { defineConfig } from 'tsup';

// Two self-contained ESM bundles. The preload is loaded into EVERY node process
// the tool spawns, so it must not depend on shared chunks (splitting: false) and
// must not carry a shebang.
export default defineConfig([
  {
    entry: { cli: 'src/cli.ts' },
    format: ['esm'],
    target: 'node18',
    platform: 'node',
    clean: true,
    splitting: false,
    sourcemap: false,
    banner: { js: '#!/usr/bin/env node' },
    external: ['@resvg/resvg-js'],
  },
  {
    entry: { preload: 'src/preload.ts' },
    format: ['esm'],
    target: 'node18',
    platform: 'node',
    clean: false,
    splitting: false,
    sourcemap: false,
  },
]);
