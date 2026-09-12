import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { applyEdits, bool, flag, flagAll, int, pairs, parseArgs, parseValue } from '../src/args.ts'

describe('parseArgs', () => {
  it('separates command words from flags', () => {
    const args = parseArgs(['workspace', 'create', 'payments', '--as', 'ada'])
    assert.deepEqual(args.words, ['workspace', 'create', 'payments'])
    assert.equal(flag(args, 'as'), 'ada')
  })

  it('accepts --flag=value and --flag value alike', () => {
    assert.equal(flag(parseArgs(['--group=ops']), 'group'), 'ops')
    assert.equal(flag(parseArgs(['--group', 'ops']), 'group'), 'ops')
  })

  it('keeps every occurrence of a repeated flag', () => {
    const args = parseArgs(['grant', 'bot', 'action:deploy', '--scope', 'env=prod', '--scope', 'region=eu'])
    assert.deepEqual(flagAll(args, 'scope'), ['env=prod', 'region=eu'])
  })

  it('does not swallow the next flag as a value', () => {
    // `--reason --set x=1` is a missing reason, not a reason of "--set". Worth
    // pinning: the other reading silently drops the edit.
    const args = parseArgs(['approve', 'a91f', '--reason', '--set', 'replicas=3'])
    assert.equal(flag(args, 'reason'), '')
    assert.deepEqual(flagAll(args, 'set'), ['replicas=3'])
  })

  it('treats a valueless flag as true', () => {
    assert.equal(bool(parseArgs(['inbox', '--all']), 'all'), true)
    assert.equal(bool(parseArgs(['inbox']), 'all'), false)
  })

  it('passes everything after -- through as words', () => {
    const args = parseArgs(['say', '--', '--not-a-flag'])
    assert.deepEqual(args.words, ['say', '--not-a-flag'])
  })

  it('refuses a non-integer where a number is required', () => {
    assert.throws(() => int(parseArgs(['--max-uses', 'lots']), 'max-uses'), /whole number/)
  })
})

describe('pairs', () => {
  it('parses values as JSON so numbers stay numbers', () => {
    // The whole reason this is not a string map. A scope of {replicas: "3"}
    // does not match an action asking for {replicas: 3}, and a digest over
    // `"3"` is not a digest over `3`.
    assert.deepEqual(pairs(['replicas=3'], '--set'), { replicas: 3 })
    assert.deepEqual(pairs(['on=true'], '--set'), { on: true })
    assert.deepEqual(pairs(['env=production'], '--scope'), { env: 'production' })
  })

  it('leaves things that only look like numbers alone', () => {
    assert.deepEqual(pairs(['version=1.4.2'], '--set'), { version: '1.4.2' })
  })

  it('keeps = inside the value', () => {
    assert.deepEqual(pairs(['q=a=b'], '--set'), { q: 'a=b' })
  })

  it('rejects a pair with no key', () => {
    assert.throws(() => pairs(['=3'], '--set'), /key=value/)
    assert.throws(() => pairs(['nope'], '--set'), /key=value/)
  })

  it('parses a quoted number back to a string', () => {
    assert.deepEqual(parseValue('"3"'), '3')
  })
})

describe('applyEdits', () => {
  const proposed = { service: 'api', version: '1.4.2', env: 'production', replicas: 30 }

  it('returns the input untouched when there is nothing to edit', () => {
    assert.equal(applyEdits(proposed, {}), proposed)
  })

  it('copies rather than mutating', () => {
    const edited = applyEdits(proposed, { replicas: 3 })
    assert.deepEqual(edited, { ...proposed, replicas: 3 })
    // The chain records both digests and an auditor compares them, so the
    // original has to survive intact.
    assert.equal(proposed.replicas, 30)
  })

  it('reaches nested keys', () => {
    const nested = { limits: { cpu: 1, memory: 512 } }
    assert.deepEqual(applyEdits(nested, { 'limits.cpu': 4 }), { limits: { cpu: 4, memory: 512 } })
  })

  it('refuses to invent a field the agent never proposed', () => {
    // An approver adding an argument the agent did not ask about is either a
    // typo or a way past the agent's own validation. Neither should go through
    // quietly.
    assert.throws(() => applyEdits(proposed, { force: true }), /has no "force"/)
  })

  it('refuses to edit a payload that is not an object', () => {
    assert.throws(() => applyEdits('a string', { x: 1 }), /object payload/)
  })

  it('refuses a path through a non-object', () => {
    assert.throws(() => applyEdits(proposed, { 'service.name': 'x' }), /not an object/)
  })
})
