import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test, describe } from 'node:test'
import { fileURLToPath } from 'node:url'

import { generate, serialize } from '../scripts/schemas.ts'
import { BODY_SCHEMAS } from '../src/bodies/index.ts'
import { QUORUM_KINDS, kindName } from '../src/kinds.ts'

const schemaDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'schemas')

describe('committed JSON Schema', () => {
  test('matches the Zod definitions', () => {
    // The failure this prevents: someone edits a body schema, ships it, and the
    // Go relay keeps validating against last week's rules with no error
    // anywhere. Run `pnpm --filter @quorum/protocol schemas` to fix.
    for (const [name, value] of Object.entries(generate())) {
      const onDisk = readFileSync(join(schemaDir, name), 'utf8')
      assert.equal(onDisk, serialize(value), `${name} is stale`)
    }
  })

  test('every Quorum kind appears in the index', () => {
    const index = JSON.parse(readFileSync(join(schemaDir, 'index.json'), 'utf8'))
    for (const kind of QUORUM_KINDS) {
      assert.ok(index.kinds[String(kind)], `kind ${kind} missing from index.json`)
      assert.equal(index.kinds[String(kind)].name, kindName(kind))
    }
  })

  test('every kind with a body schema has a schema file', () => {
    const index = JSON.parse(readFileSync(join(schemaDir, 'index.json'), 'utf8'))
    for (const kind of Object.keys(BODY_SCHEMAS)) {
      const file = index.kinds[kind]?.body
      assert.ok(file, `kind ${kind} has a Zod body but no file in index.json`)
      assert.doesNotThrow(() => readFileSync(join(schemaDir, file), 'utf8'))
    }
  })

  test('defaulted fields are optional in the published schema', () => {
    // `io: 'input'` in the generator. Getting this wrong would mark every
    // defaulted field as required and reject valid events from implementations
    // that omitted them — a spec bug that only bites other languages.
    const approval = JSON.parse(
      readFileSync(join(schemaDir, 'body-8102-approval-request.json'), 'utf8'),
    )
    assert.ok(!approval.required.includes('required'), '`required` has a default of 1')
    assert.equal(approval.properties.required.default, 1)
  })
})
