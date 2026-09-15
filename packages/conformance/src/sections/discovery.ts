/**
 * What the relay says about itself before anybody publishes anything.
 *
 * All of it is NIP-11, and none of it is a Quorum invention — which is the
 * point. A relay that answers nothing here is still usable and still passes
 * Option A; what it costs its members is the ability to find the context packer
 * or to verify a checkpoint, both of which need the relay's own pubkey and have
 * no other place to get it.
 */

import { type Session } from '../harness.ts'
import { held, section, type Ctx } from '../section.ts'
import type { Section } from '../report.ts'

/** The NIPs a Quorum workspace relay is built out of. */
const EXPECTED_NIPS: [number, string][] = [
  [1, 'the base protocol'],
  [11, 'this document'],
  [29, 'relay-based groups, which is what a workspace is'],
  [42, 'AUTH, without which read control is not possible'],
]

export async function discovery(session: Session, ctx: Ctx): Promise<Section> {
  const run = section(
    'discovery',
    'What NIP-11 says this relay is, and whether a client can act on it.',
    ctx,
  )
  const info = session.info
  const served = Object.keys(info).length > 0

  await run.check(
    { id: 'nip11', what: 'serves a NIP-11 relay information document', level: 'SHOULD', profile: 'any' },
    async () =>
      held(
        served,
        'no NIP-11 document over HTTP; a client cannot discover the relay’s pubkey, ' +
          'so checkpoints cannot be verified and the context packer cannot be addressed',
      ),
  )

  for (const [nip, why] of EXPECTED_NIPS) {
    await run.check(
      {
        id: `nip-${nip}`,
        what: `declares NIP-${String(nip).padStart(2, '0')} — ${why}`,
        level: 'SHOULD',
        profile: 'any',
        unless: served ? false : 'no NIP-11 document to read',
      },
      async () =>
        held(
          info.supported_nips?.includes(nip) ?? false,
          `supported_nips does not list ${nip}; it lists ${info.supported_nips?.join(', ') ?? 'nothing'}`,
        ),
    )
  }

  await run.check(
    {
      id: 'pubkey',
      what: 'publishes its own pubkey, so its signed events can be attributed',
      level: 'SHOULD',
      profile: 'quorum',
      unless: served ? false : 'no NIP-11 document to read',
    },
    async () =>
      held(
        /^[0-9a-f]{64}$/.test(info.pubkey ?? ''),
        'no `pubkey` in NIP-11: a reader cannot tell a relay-signed thread state or ' +
          'checkpoint from a forgery, and has no address to send a 5600 to',
      ),
  )

  await run.check(
    {
      id: 'version',
      what: 'names the Quorum protocol version it implements',
      level: 'MAY',
      profile: 'quorum',
      unless: served ? false : 'no NIP-11 document to read',
    },
    async () =>
      held(
        (info.version ?? '').length > 0,
        'no `version`; a client cannot tell which revision of the NIP this relay enforces',
      ),
  )

  return run.done()
}
