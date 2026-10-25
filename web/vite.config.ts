import { defineConfig } from 'vitest/config';
import { fileURLToPath, URL } from 'node:url';

// The published `libsodium-wrappers-sumo` ESM build has a broken relative import
// (./libsodium-sumo.mjs is not shipped in its own dist). Its CommonJS build
// resolves `libsodium-sumo` correctly, so we point the bundler and the test
// runner at that file. Types are hand-written in src/libsodium.d.ts.
const sumoCjs = fileURLToPath(
  new URL('./node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js', import.meta.url),
);

export default defineConfig({
  // brand/brand.json lives outside web/, so the dev server must be allowed to
  // read one level up. Production builds inline it.
  server: { fs: { allow: ['..'] } },
  resolve: {
    alias: { 'libsodium-wrappers-sumo': sumoCjs },
  },
  build: {
    target: 'es2022',
    outDir: 'dist',
    sourcemap: true,
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    testTimeout: 60_000,
  },
});
