/**
 * Capabilities: issuing them, withdrawing them, and seeing what a key holds.
 *
 * A grant is a signed addressable event, not a row. Nothing here tells the
 * relay to enforce anything — the relay stores it like any other event, and the
 * resource that might act on it re-derives the whole question from signatures
 * when the moment comes. That is why `revoke` works against a relay that has
 * never heard of capabilities, and why an operator who loses their database
 * loses nothing that matters.
 */

import { Kinds, type NostrEvent } from '@quorum/protocol'
import {
  Grants,
  effectiveAddressable,
  grantId,
  summariseGrant,
  type GrantState,
} from '@quorum/sdk'
import { flag, flagAll, int, pairs, type ParsedArgs } from '../args.ts'
import { bold, dim, green, red, short, yellow } from '../format.ts'
import { open, resolvePubkey } from '../session.ts'

export async function grantCommand(args: ParsedArgs): Promise<void> {
  const [, who, resource] = args.words
  if (!who || !resource) {
    throw new Error('usage: quorum grant <name|pubkey> <resource> [--scope k=v] [--actions a,b]')
  }

  const session = await open(flag(args, 'as'))
  try {
    const grantee = await resolvePubkey(who)
    const scope = pairs(flagAll(args, 'scope'), '--scope')
    const actions = (flag(args, 'actions') ?? 'invoke').split(',').map((a) => a.trim()).filter(Boolean)
    const expiresIn = int(args, 'expires')
    const maxUses = int(args, 'max-uses')

    const grants = new Grants({ client: session.client, group: session.config.group, publisher: session.publisher })
    const event = await grants.issue({
      grantee,
      resource,
      actions,
      ...(Object.keys(scope).length ? { scope } : {}),
      ...(expiresIn !== undefined ? { expiresAt: Math.floor(Date.now() / 1000) + expiresIn } : {}),
      ...(maxUses !== undefined ? { maxUses } : {}),
    })

    console.log(`${green('✓')} ${bold(session.name)} granted ${bold(who)} ${bold(resource)}`)
    console.log(`  actions ${actions.join(', ')}`)
    if (Object.keys(scope).length) console.log(`  scope   ${JSON.stringify(scope)}`)
    console.log(`  event   ${dim(short(event.id))} ${dim(`d=${grantId({ grantee, resource, actions, scope })}`)}`)
    console.log(
      dim(
        '  the resource decides whether to honour this; it will only do so if it\n' +
          `  trusts ${short(session.me)} as an issuer.`,
      ),
    )
  } finally {
    session.close()
  }
}

export async function revokeCommand(args: ParsedArgs): Promise<void> {
  const [, who, resource] = args.words
  if (!who || !resource) {
    throw new Error('usage: quorum revoke <name|pubkey> <resource> [--scope k=v]')
  }

  const session = await open(flag(args, 'as'))
  try {
    const grantee = await resolvePubkey(who)
    const scope = pairs(flagAll(args, 'scope'), '--scope')
    const actions = (flag(args, 'actions') ?? 'invoke').split(',').map((a) => a.trim()).filter(Boolean)
    const spec = {
      grantee,
      resource,
      actions,
      ...(Object.keys(scope).length ? { scope } : {}),
    }

    // The grant being withdrawn is fetched first so the revocation can be dated
    // after it. A revocation that ties with its grant on `created_at` is
    // ambiguous, and `effectiveAddressable` fails closed on a tie — correct,
    // but it would leave a revocation that looks applied and is not.
    const held = await new Grants({ client: session.client, group: session.config.group }).held(grantee)
    const d = grantId(spec)
    const previous = held.find((e) => e.kind === Kinds.CapabilityGrant && idOf(e) === d)

    const grants = new Grants({ client: session.client, group: session.config.group, publisher: session.publisher })
    await grants.revoke(spec, flag(args, 'reason') ?? 'revoked from the console', previous)

    console.log(`${green('✓')} revoked ${bold(resource)} from ${bold(who)}`)
    if (!previous) {
      console.log(dim('  no matching grant was found to revoke — the revocation stands anyway,'))
      console.log(dim('  which is right: it must be publishable before the grant it withdraws arrives.'))
    }
  } finally {
    session.close()
  }
}

export async function grantsCommand(args: ParsedArgs): Promise<void> {
  const session = await open(flag(args, 'as'))
  try {
    const who = args.words[1] ?? session.me
    const grantee = await resolvePubkey(who)
    const held = await new Grants({ client: session.client, group: session.config.group }).held(grantee)

    // `effectiveAddressable`, not `latestAddressable`: a revocation dated after
    // the grant it withdraws must win, including against a later re-issue of
    // the same coordinate.
    const current = effectiveAddressable(held)
    if (!current.length) {
      console.log(`${short(grantee)} holds nothing in #${session.config.group}`)
      return
    }

    console.log(`${bold(short(grantee))} in ${bold(`#${session.config.group}`)}`)
    for (const event of current) {
      console.log(`  ${describeGrant(event)} ${dim(`by ${short(event.pubkey)}`)}`)
    }
  } finally {
    session.close()
  }
}

function idOf(event: NostrEvent): string | undefined {
  return event.tags.find((t) => t[0] === 'd')?.[1]
}

/**
 * One line describing what a 38102 or 38106 actually says.
 *
 * The reading is `summariseGrant()` in the SDK and this is only the rendering,
 * which is the split the audit-verdict bug argued for: the browser draws these
 * as a table and the console as a line of ANSI, and a second parser would be a
 * second opinion about what a grant covers. The first version of this function
 * was that second opinion — it read `body.resource` where the spec nests it
 * under `body.grant`, and printed a confident `?` for every grant ever issued.
 *
 * Expiry is shown even though `effectiveAddressable` does not filter on it. An
 * expired grant is still the newest event at its coordinate, so it is still
 * "current" in the replaceable-event sense while authorising nothing — and
 * `authorize` refuses it. A listing that disagreed with the verifier would be
 * describing a capability that does not work.
 */
export function describeGrant(event: NostrEvent, now = Math.floor(Date.now() / 1000)): string {
  const summary = summariseGrant(event, now)

  if (summary.state === 'invalid') {
    return summary.problem === 'unparseable'
      ? `${red('corrupt')} ${'?'.padEnd(10)} ${dim('body is not JSON')}`
      : `${red('invalid')} ${summary.kind.padEnd(10)} ${dim('body does not match the schema')}`
  }

  const resources =
    summary.kind === 'delegation' && !summary.resources.length
      ? dim('anything the delegate already holds')
      : summary.resources.join(', ')

  return [
    state(summary.state),
    summary.kind.padEnd(10),
    resources,
    summary.actions.length ? dim(summary.actions.join(',')) : '',
    summary.scope ? dim(JSON.stringify(summary.scope)) : '',
    summary.maxUses !== undefined ? dim(`max ${summary.maxUses} uses`) : '',
    until(summary.expiresAt),
    // A grant issued under a delegation is only as wide as that delegation, and
    // a reader cannot check that without knowing there was one.
    summary.via ? dim(`via ${summary.via}`) : '',
  ]
    .filter(Boolean)
    .join(' ')
}

function state(state: GrantState): string {
  if (state === 'revoked') return red('revoked')
  if (state === 'expired') return yellow('expired')
  return green('active ')
}

function until(expiresAt: number | undefined): string {
  return expiresAt === undefined ? '' : dim(`until ${new Date(expiresAt * 1000).toISOString()}`)
}
