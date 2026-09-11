/**
 * Write `schemas/` from the Zod definitions.
 *
 * Committing generated files is usually a smell. Here it is the point: the JSON
 * Schema is what a Go relay, a Rust agent or a Python test harness validates
 * against, and none of them can run Zod. Generated at install time it would
 * exist only inside TypeScript's world — precisely the world it is meant to
 * escape. Committed, protocol drift shows up in review as a diff on a schema
 * file rather than as a surprise for someone else's implementation.
 *
 * Run: pnpm --filter @quorum/protocol schemas
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { generate, serialize } from './schemas.ts'
import { PROTOCOL_VERSION } from '../src/version.ts'

const outDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'schemas')
mkdirSync(outDir, { recursive: true })

console.log(`generating JSON Schema for Quorum v${PROTOCOL_VERSION}`)

let changed = 0
for (const [name, value] of Object.entries(generate())) {
  const path = join(outDir, name)
  const next = serialize(value)
  let previous: string | undefined
  try {
    previous = readFileSync(path, 'utf8')
  } catch {
    /* new file */
  }
  if (previous !== next) {
    writeFileSync(path, next)
    changed++
    console.log(`  written   ${name}`)
  } else {
    console.log(`  unchanged ${name}`)
  }
}

console.log(changed === 0 ? 'up to date' : `${changed} file(s) changed`)
