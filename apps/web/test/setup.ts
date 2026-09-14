/**
 * Unmount between tests.
 *
 * Testing Library registers this itself when a runner exposes `afterEach` as a
 * global, and this project does not — `globals: true` would put `describe` and
 * `it` in scope without an import, which is the opposite of how every other
 * test file in this repo reads. So the hook is registered here instead.
 *
 * Without it each render is appended to the same document and `getByText`
 * starts finding the previous test's screen, which fails as an ambiguous match
 * if you are lucky and passes against the wrong DOM if you are not.
 */

import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

afterEach(cleanup)
