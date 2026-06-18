import { defineConfig } from 'vitest/config';

// Tests run in plain Node (real WebCrypto); WebAuthn, location/document and IndexedDB are faked per-suite,
// so no jsdom is needed. Coverage is measured against the TS sources, not the built dist.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    setupFiles: ['./test/setup.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // index.ts is a pure re-export barrel and _types.ts is type-only — neither has executable lines.
      exclude: ['src/index.ts', 'src/_types.ts'],
      reporter: ['text', 'html', 'lcov'],
      thresholds: { lines: 90, functions: 90, statements: 90, branches: 85 },
    },
  },
});
