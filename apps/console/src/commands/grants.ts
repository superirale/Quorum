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

import { CapabilityGrantBody, DelegationBody, Kinds, type NostrEvent } from '@quorum/protocol'
import { Grants, effectiveAddressable, grantId } from '@quorum/sdk'
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
          `  trusts ${short(session.signer.publicKey)} as an issuer.`,
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
 * Read through the body schemas rather than by reaching into the JSON, because
 * the first version of this did the latter — it looked for `body.resource` when
 * the spec lives one level down under `body.grant`, and printed a confident
 * `?` for every grant ever issued. A listing that cannot say what a capability
 * covers is worse than no listing: it invites an operator to conclude the grant
 * is malformed and re-issue it.
 *
 * Expiry is marked here even though `effectiveAddressable` does not filter on
 * it. An expired grant is still the newest event at its coordinate, so it is
 * still "current" in the replaceable-event sense while authorising nothing —
 * and `verifyGrant` will refuse it. The two must not read differently.
 */
export function describeGrant(event: NostrEvent, now = Math.floor(Date.now() / 1000)): string {
  const parsed = parse(event.content)
  if (parsed === undefined) {
    return `${red('corrupt')} ${'?'.padEnd(10)} ${dim('body is not JSON')}`
  }

  if (event.kind === Kinds.Delegation) {
    const body = DelegationBody.safeParse(parsed)
    if (!body.success) return malformed('delegation')
    const { resources, scope, expires_at, revoked } = body.data
    return [
      state(revoked, expires_at, now),
      'delegation'.padEnd(10),
      resources?.length ? resources.join(', ') : dim('anything the delegate already holds'),
      scope ? dim(JSON.stringify(scope)) : '',
      until(expires_at),
    ]
      .filter(Boolean)
      .join(' ')
  }

  const body = CapabilityGrantBody.safeParse(parsed)
  if (!body.success) return malformed('grant')
  const { grant, revoked, via } = body.data
  return [
    state(revoked, grant.expires_at, now),
    'grant'.padEnd(10),
    grant.resource,
    dim(grant.actions.join(',')),
    grant.scope ? dim(JSON.stringify(grant.scope)) : '',
    grant.max_uses !== undefined ? dim(`max ${grant.max_uses} uses`) : '',
    until(grant.expires_at),
    // A grant issued under a delegation is only as wide as that delegation, and
    // the reader cannot check that without knowing there was one.
    via ? dim(`via ${via}`) : '',
  ]
    .filter(Boolean)
    .join(' ')
}

function state(revoked: boolean, expiresAt: number | undefined, now: number): string {
  if (revoked) return red('revoked')
  if (expiresAt !== undefined && expiresAt < now) return yellow('expired')
  return green('active ')
}

function until(expiresAt: number | undefined): string {
  return expiresAt === undefined ? '' : dim(`until ${new Date(expiresAt * 1000).toISOString()}`)
}

function malformed(kind: string): string {
  return `${red('invalid')} ${kind.padEnd(10)} ${dim('body does not match the schema')}`
}

function parse(content: string): unknown {
  try {
    return JSON.parse(content)
  } catch {
    return undefined
  }
}
