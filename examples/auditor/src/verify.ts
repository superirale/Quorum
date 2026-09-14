/**
 * The accusation, checked by a stranger.
 *
 * `pnpm --filter @quorum/auditor verify [proof.json]`
 *
 * This is M7's actual claim and it is worth being precise about what it is.
 * Detecting that a window is short is easy and proves nothing — the reader may
 * simply not have asked for everything. What this file does is take three
 * things (a relay's signed checkpoint, the ids it served for that window, and
 * some events from anywhere else) and decide, from the bytes alone, whether the
 * relay committed to an event it is not serving.
 *
 * No relay, no keys, no session, no network, no trust in whoever produced the
 * file. Every step is redone here: the signature on the checkpoint, the
 * signature on each event said to be withheld, that each falls inside the
 * committed window and the right group, that none of them is in the served set
 * after all, and that the two sets together reproduce the signed root.
 *
 * The withheld events have to be verified too, and it is the step easiest to
 * skip. Without it anyone could invent an event, claim the relay was hiding it,
 * and get a failure that reads as an accusation gone wrong rather than as a
 * fabrication.
 *
 * Try it: edit `proof.json` by hand and run this again.
 */

import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { checkpoints, verifyWithholdingProof, type WithholdingProof } from '@quorum/sdk'

const path = process.argv[2] ?? join(import.meta.dirname, '..', 'proof.json')

let proof: WithholdingProof
try {
  proof = JSON.parse(await readFile(path, 'utf8')) as WithholdingProof
} catch (error) {
  console.error(`could not read ${path}: ${(error as Error).message}`)
  console.error('Run `pnpm --filter @quorum/auditor demo` first — act 3 writes it.')
  process.exit(2)
}

const [checkpoint] = checkpoints([proof.checkpoint])
if (!checkpoint) {
  console.error(`${path} does not contain a validly signed kind 8108.`)
  process.exit(1)
}

const { from, to, count, merkle_root, algorithm } = checkpoint.body
console.log(`checkpoint  ${checkpoint.event.id.slice(0, 16)}…`)
console.log(`signed by   ${checkpoint.relay.slice(0, 16)}…   (the relay's own key)`)
console.log(`group       #${checkpoint.group}`)
console.log(`window      ${stamp(from)} → ${stamp(to)}`)
console.log(`commitment  ${count} events, root ${merkle_root.slice(0, 16)}…  (${algorithm})`)
console.log(`served      ${proof.served.length} ids`)
console.log(`claimed     ${proof.withheld.length} withheld\n`)

const verdict = verifyWithholdingProof(proof)

if (!verdict.proven) {
  console.log(`\x1b[33mnot proven\x1b[0m — ${verdict.reason}`)
  console.log(
    '\nThat is the right answer to give when it is the right answer. This program refuses to\n' +
      'name a relay on anything less than arithmetic that only the relay could have produced.',
  )
  process.exit(1)
}

console.log('\x1b[31mproven\x1b[0m\n')
for (const id of verdict.withheld) {
  const event = proof.withheld.find((e) => e.id === id)!
  console.log(`  ${id}`)
  console.log(`    kind ${event.kind}, by ${event.pubkey.slice(0, 16)}…, at ${stamp(event.created_at)}`)
  console.log(`    ${JSON.stringify(event.content.slice(0, 72))}`)
}

const n = verdict.withheld.length
console.log(
  `\nRelay ${verdict.relay.slice(0, 16)}… signed a commitment covering ${count} events in #${verdict.group},\n` +
    `served ${proof.served.length} of them, and the ${n === 1 ? 'one above is' : `${n} above are`} the difference —\n` +
    'each independently signed by its author, each inside the window the relay closed.\n' +
    'Putting them back reproduces the root the relay signed, which no other set of events does.',
)

function stamp(seconds: number): string {
  return new Date(seconds * 1000).toISOString().replace('T', ' ').slice(0, 19)
}
