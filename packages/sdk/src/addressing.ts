/**
 * Filters, and the difference between "the relay sent me this" and "this is
 * addressed to me".
 *
 * Two rules from earlier milestones live here, because both are invisible until
 * they bite:
 *
 * **`#p` is a prefilter, never an answer.** Quorum marks an addressee with a
 * fourth element — `["p", "<pubkey>", "<relay>", "to"]` — and relays index only
 * a tag's first value. So `{"#p": [me]}` returns everything that mentions me,
 * everything I authored a parent of, and everything actually addressed to me,
 * with no way for the relay to tell them apart. Exact matching is local, and it
 * is `isAddressedTo` from `@quorum/protocol` — never prose. M0's agent deployed
 * to production because a message *described* how to mention it.
 *
 * **A filter that names `#p` must also name `#h`.** relay29 requires every
 * filter to identify an `h`, an `e`, an `a` or explicit ids, so the obvious
 * subscription — "everything addressed to me" — is refused. That is correct
 * behaviour: without it, one REQ would rake `p`-tagged events out of every
 * workspace on the relay. But the refusal arrives as a CLOSED that a careless
 * client reads as "no results", so {@link assertScopedFilter} turns it into an
 * error at the call site instead.
 */

import {
  AddressableKinds,
  BorrowedKinds,
  EphemeralKinds,
  RegularKinds,
  TagName,
  isAddressedTo,
  type Filter,
  type NostrEvent,
} from '@quorum/protocol'

/**
 * What an agent watching a channel for work normally wants.
 *
 * `approval_request` is here because an agent can be an *approver*: a request
 * `to`-addresses the people it asks, and some of them are agents.
 *
 * `approval_response` is deliberately **not** here, and the omission is
 * load-bearing. A response is `to`-addressed back to the agent that asked, so
 * leaving it in means every response wakes the handler as if it were a fresh
 * instruction — while the handler that is actually waiting for it sits inside
 * `act()`, which consumes responses through its own subscription. On a restart
 * the two collide: the response and the replayed trigger arrive together, and
 * whichever the relay happens to send first wins. An agent that wants to watch
 * other people's approvals can ask for the kind explicitly.
 */
export const WORK_KINDS: readonly number[] = Object.freeze([
  BorrowedKinds.ChatMessage,
  BorrowedKinds.Thread,
  BorrowedKinds.Comment,
  RegularKinds.Action,
  RegularKinds.ApprovalRequest,
  RegularKinds.Handoff,
  RegularKinds.Artifact,
  RegularKinds.Error,
])

/**
 * Control-plane kinds. Ephemeral, so a relay never replays them, and delivered
 * outside the handler queue — a handler blocked awaiting approval must not be
 * the reason its own interrupt cannot be read (M0 finding #4).
 */
export const CONTROL_KINDS: readonly number[] = Object.freeze(Object.values(EphemeralKinds))

export interface ScopeOptions {
  /** NIP-29 group id. Required — see the note on relay29 above. */
  group: string
  kinds?: readonly number[]
  since?: number
  until?: number
  limit?: number
}

/** Everything in a channel. */
export function channelFilter(options: ScopeOptions): Filter {
  return scoped({ [`#${TagName.Group}`]: [options.group] }, options)
}

/**
 * Everything in a channel that names this pubkey in a `p` tag.
 *
 * A superset of "addressed to me". Narrow it with {@link isForMe} on arrival;
 * this filter exists to keep the relay from shipping the whole channel, not to
 * decide anything.
 */
export function addressedFilter(options: ScopeOptions & { pubkey: string }): Filter {
  return scoped(
    {
      [`#${TagName.Group}`]: [options.group],
      [`#${TagName.Pubkey}`]: [options.pubkey],
    },
    options,
  )
}

/** Everything inside one thread, by its NIP-22 root scope. */
export function threadFilter(options: ScopeOptions & { threadId: string }): Filter {
  return scoped(
    {
      [`#${TagName.Group}`]: [options.group],
      [`#${TagName.RootEvent}`]: [options.threadId],
    },
    options,
  )
}

/** The control plane for a channel: leases, interrupts, presence. */
export function controlFilter(options: Omit<ScopeOptions, 'kinds'>): Filter {
  return channelFilter({ ...options, kinds: CONTROL_KINDS })
}

/**
 * The two events that change what a reader can read: key wraps and the policy.
 *
 * Two filters and not one, because they are scoped differently — a wrap is
 * addressed with `p` and the policy is addressable on `d` — and a single filter
 * would AND the two tags and match neither.
 *
 * A plaintext channel subscribes to these too, and that is the point rather
 * than an oversight. The transition a client must never miss is *plaintext →
 * nip44*: an agent that kept writing in the clear after the channel was
 * encrypted would be publishing readable messages into a channel where every
 * other member believes the relay is holding ciphertext. Watching only when
 * already encrypted would watch for everything except the case that matters.
 *
 * No `since`. A wrap for an older epoch is exactly as useful as a new one — it
 * is how a joiner reads history — and the policy is addressable, so there is
 * one of it per author and the relay serves the current one regardless.
 */
export function keyFilters(options: { group: string; pubkey: string }): Filter[] {
  return [
    {
      kinds: [RegularKinds.ChannelKey],
      [`#${TagName.Group}`]: [options.group],
      [`#${TagName.Pubkey}`]: [options.pubkey],
    },
    {
      kinds: [AddressableKinds.ChannelPolicy],
      [`#${TagName.Group}`]: [options.group],
      [`#${TagName.Identifier}`]: [options.group],
    },
  ]
}

/** True for the kinds {@link keyFilters} asks for. */
export function isKeyManagement(kind: number): boolean {
  return kind === RegularKinds.ChannelKey || kind === AddressableKinds.ChannelPolicy
}

function scoped(tags: Record<string, string[]>, options: ScopeOptions): Filter {
  const filter: Filter = { ...tags }
  if (options.kinds) filter.kinds = [...options.kinds]
  if (options.since !== undefined) filter.since = options.since
  if (options.until !== undefined) filter.until = options.until
  if (options.limit !== undefined) filter.limit = options.limit
  return filter
}

/**
 * The addressing predicate, as an agent should ask it.
 *
 * Thin on purpose — the logic is `isAddressedTo` in the protocol package, and
 * duplicating it here would give the SDK its own opinion about what "addressed"
 * means. This function exists to be the thing you find when you go looking.
 */
export function isForMe(event: NostrEvent, pubkey: string): boolean {
  return isAddressedTo(event.tags, pubkey)
}

/**
 * Reject a filter the relay will refuse, at the call site.
 *
 * The check mirrors relay29's `RequireKindAndSingleGroupIDOrSpecificEventReference`.
 * Doing it locally costs nothing and replaces a CLOSED that looks like an empty
 * result with an error naming the missing tag.
 */
export function assertScopedFilter(filter: Filter): void {
  if (filter.ids?.length) return
  for (const letter of [TagName.Group, TagName.Event, TagName.Address]) {
    const values = filter[`#${letter}`]
    if (Array.isArray(values) && values.length) return
  }
  throw new Error(
    'filter must name a group (#h), an event (#e), an address (#a) or explicit ids. ' +
      'A relay-based-groups relay refuses anything broader — including the one you probably ' +
      'wanted, {"#p": [me]} — and refuses it with a CLOSED that is easy to mistake for an ' +
      `empty result. Filter was: ${JSON.stringify(filter)}`,
  )
}
