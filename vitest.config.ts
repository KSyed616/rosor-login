import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    // live.test.ts talks to a real TeamDeck provider. Excluded by default so a
    // clean checkout passes without one running; opt in with
    // `npx vitest run tests/login/live.test.ts` when a provider is up.
    exclude: ['tests/live.test.ts', '**/node_modules/**'],
  },
});
