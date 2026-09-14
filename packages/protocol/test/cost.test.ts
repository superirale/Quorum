/**
 * Budget arithmetic, and the two ways an overspend hides.
 *
 * The addition is trivial and is not what these tests are about. What they pin
 * is the shape of the comparison: that a budget stated in tokens is measured
 * against both halves of a spend, that an unstated ceiling is not a ceiling of
 * zero, and that a stated ceiling of zero is.
 */

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import { addCost, checkBudget, describeBudget, tokensSpent } from '../src/index.ts'

describe('adding up a cost', () => {
  test('sums each dimension', () => {
    assert.deepEqual(
      addCost({ tokens_in: 100, tokens_out: 20, usd: 0.5 }, { tokens_in: 5, usd: 0.25, msat: 40 }),
      { tokens_in: 105, tokens_out: 20, usd: 0.75, msat: 40 },
    )
  })

  test('an absent dimension stays absent rather than becoming zero', () => {
    // `{}` is "nobody said" and `{usd: 0}` is "it was free". A thread priced in
    // tokens should not acquire a usd total that reads as having been costed.
    assert.deepEqual(addCost({ tokens_in: 10 }, { tokens_out: 3 }), {
      tokens_in: 10,
      tokens_out: 3,
    })
    assert.deepEqual(addCost(undefined, undefined), {})
  })

  test('a reported zero is kept, because somebody reported it', () => {
    assert.deepEqual(addCost({ usd: 0 }, undefined), { usd: 0 })
  })
})

describe('a budget in tokens', () => {
  test('counts both halves of the spend', () => {
    // The failure this exists for: 39k in and 38k out is nearly twice over a
    // 40k ceiling, and looks comfortable from either column alone.
    const spent = { tokens_in: 39_000, tokens_out: 38_000 }
    assert.equal(tokensSpent(spent), 77_000)
    assert.equal(checkBudget(spent, { tokens: 40_000 }).exhausted, true)
    assert.equal(checkBudget({ tokens_in: 39_000 }, { tokens: 40_000 }).exhausted, false)
  })

  test('reports what is left, negative when overspent', () => {
    const check = checkBudget({ tokens_in: 50_000, tokens_out: 5_000 }, { tokens: 40_000 })
    assert.deepEqual(check.remaining, { tokens: -15_000 })
    assert.deepEqual(check.over, ['tokens'])
  })
})

describe('what counts as exhausted', () => {
  test('a budget with nothing set is not a ceiling of zero', () => {
    // The version of this that ships broken pauses every thread in the
    // workspace the moment budgets are deployed.
    assert.equal(checkBudget({ tokens_in: 1_000_000 }, {}).exhausted, false)
    assert.equal(checkBudget({ tokens_in: 1_000_000 }, undefined).exhausted, false)
  })

  test('a stated ceiling of zero is exhausted immediately', () => {
    // Which makes `set_budget {usd: 0}` a freeze, using a capability that
    // already exists rather than a new verb for stopping a thread.
    assert.equal(checkBudget(undefined, { usd: 0 }).exhausted, true)
    assert.deepEqual(checkBudget(undefined, { usd: 0 }).over, ['usd'])
  })

  test('at the ceiling is over it', () => {
    assert.equal(checkBudget({ usd: 5 }, { usd: 5 }).exhausted, true)
    assert.equal(checkBudget({ usd: 4.999 }, { usd: 5 }).exhausted, false)
  })

  test('any stated dimension is enough, and the answer names which', () => {
    const check = checkBudget({ usd: 6, tokens_in: 10 }, { usd: 5, tokens: 40_000 })
    assert.equal(check.exhausted, true)
    assert.deepEqual(check.over, ['usd'])
    assert.equal(check.remaining.tokens, 39_990)
  })
})

describe('describing it to a human', () => {
  test('states the spend against every ceiling there is', () => {
    assert.equal(
      describeBudget({ tokens_in: 100, tokens_out: 50, usd: 0.25 }, { tokens: 1000, usd: 5 }),
      '150/1000 tokens, $0.2500/$5',
    )
  })

  test('says so when there is no ceiling', () => {
    assert.equal(describeBudget({ tokens_in: 100 }, undefined), '100 tokens, no ceiling')
    assert.equal(describeBudget(undefined, undefined), 'nothing spent, no ceiling')
  })
})
