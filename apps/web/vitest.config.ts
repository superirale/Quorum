/**
 * A second test runner, for the one package that needs one.
 *
 * Every other package in this repo tests with `node --test`, and that is not a
 * preference this file overrides lightly. The reason is narrow: Node strips
 * TypeScript types, it does not *transform* syntax, and JSX is a transform. A
 * `.tsx` component cannot be imported by `node --test` at all, so the four
 * screens M5 added had no runner and went four milestones untested.
 *
 * Vitest is the smallest thing that fixes that here, because `@vitejs/plugin-react`
 * was already a dependency: the tests compile through the same pipeline as the
 * app, so a component that passes a test is a component the browser gets.
 *
 * `jsdom` rather than a real browser because none of these claims are about
 * rendering. They are about what the screen *says* — which word is next to a
 * task, whether a caveat is present, whether a button exists — and those are
 * decided by the DOM, not by pixels.
 */

import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    include: ['test/**/*.test.ts', 'test/**/*.test.tsx'],
    setupFiles: ['test/setup.ts'],
    restoreMocks: true,
  },
})
