/**
 * Kind allocation.
 *
 * Checked against the NIP registry (nostr-protocol/nips README) and the
 * machine-readable registry (nostr-protocol/registry-of-kinds schema.yaml) on
 * 2026-09-11. Every number below was unallocated at that time. They are
 * PROVISIONAL until the Quorum NIP PR is merged; treat a change here as a
 * breaking protocol change and bump PROTOCOL_VERSION.
 *
 * Three ranges, with semantics defined by NIP-01:
 *   1000–9999    regular      relays store all of them
 *   20000–29999  ephemeral    relays do not store them
 *   30000–39999  addressable  relays keep only the newest per (pubkey, kind, d)
 *
 * The range choice is load-bearing, not cosmetic. Control-plane traffic
 * (interrupt/lease/presence) is ephemeral because storing it would poison
 * replay: an agent resuming from history must not re-apply a cancel from
 * last Tuesday. M0 found this the hard way with an in-memory queue; on Nostr
 * the correct behaviour is a property of the kind number.
 */

/** Kinds Quorum reuses from other NIPs rather than reinventing. */
export const BorrowedKinds = {
  /** NIP-C7 chat message. Channel-level talk, outside any thread. */
  ChatMessage: 9,
  /** NIP-7D thread root. In Quorum this is also the task; see ThreadState. */
  Thread: 11,
  /** NIP-22 comment. Every human/agent utterance inside a thread. */
  Comment: 1111,
  /** NIP-09 deletion request. Advisory everywhere; honoured by our relay. */
  DeletionRequest: 5,
  /** NIP-42 client auth. */
  ClientAuth: 22242,
  /** NIP-29 group metadata, relay-signed. Carries `supported_kinds`. */
  GroupMetadata: 39000,
  /** NIP-29 group admins, relay-signed. */
  GroupAdmins: 39001,
  /** NIP-29 group members, relay-signed. */
  GroupMembers: 39002,
  /** NIP-90 job feedback. Used by the context-packing DVM. */
  JobFeedback: 7000,
  /**
   * Marmot MLS KeyPackage — the `mls` bootstrap. Addressable; `d` is the group.
   *
   * Borrowed rather than allocated, because the *content* really is Marmot's: a
   * framed `mls_key_package` MLSMessage, readable by any RFC 9420 library. The
   * tags are where Quorum diverges, and `spec/nip-quorum.md` says how.
   *
   * The number is the third thing this project has had to re-check about
   * Marmot. The plan wrote down 443 in M1; the Marmot repo moved to 30443 by the
   * M10 spec pass; and the NIPs README still says 443 today while the
   * machine-readable registry says 30443 with a required `encoding` tag that
   * Marmot's own current document does not list. Two registries, two answers,
   * both behind the source. A borrowed kind number is not a decision anyone gets
   * to keep.
   */
  MlsKeyPackage: 30443,
} as const

/** Regular kinds: stored by relays, replayable, the durable record. */
export const RegularKinds = {
  /** A discrete unit of consequential work. See `bodies/action.ts`. */
  Action: 8101,
  /** "A human must decide before I proceed." */
  ApprovalRequest: 8102,
  /** The signed decision. This event *is* the audit record. */
  ApprovalResponse: 8103,
  /** Opt-in, provenance-tagged compaction of a range. Never automatic. */
  Summary: 8104,
  /** A failure that is not an action failure (parse error, crash, refusal). */
  Error: 8105,
  /** A file/blob reference produced by an agent. */
  Artifact: 8106,
  /** Explicit transfer of a thread from one actor to another. */
  Handoff: 8107,
  /** Relay-signed attestation of what the relay holds. See ordering, layer 3. */
  Checkpoint: 8108,
  /** A request to change thread task state. The relay folds these into ThreadState. */
  ThreadOp: 8109,
  /**
   * One member's copy of a channel key, wrapped to them with pairwise NIP-44.
   *
   * Regular rather than addressable, and that is a decision rather than a
   * default. Addressable would mean re-wrapping an epoch for a member replaces
   * the earlier wrap, and there is no case where that is what anyone wants: a
   * wrap is the historical fact that this admin handed this member this epoch
   * at this moment, and a member who has lost their copy needs a *second* one,
   * not a substitute for the first.
   */
  ChannelKey: 8110,
  /**
   * One member's MLS Welcome, wrapped to them with pairwise NIP-44.
   *
   * The `mls` analogue of 8110 and deliberately the same shape: an inviter hands
   * one named member the material that lets them read the channel, in the clear
   * about *who* was handed *what*, and unreadable as to the material itself.
   *
   * ## Why this is not NIP-59's 1059 → 13 → 444
   *
   * Marmot delivers a Welcome as an unsigned kind 444 rumor inside a kind 13
   * seal inside a kind 1059 gift wrap, and this plan said Quorum would too. It
   * cannot, and the reason is verifiable rather than aesthetic: **relay29
   * refuses any event carrying an `h` tag whose author is not a member of that
   * group** (`RestrictWritesBasedOnGroupRules`, "unknown member"), and a Quorum
   * gift wrap has to carry `h`, because relay29 equally refuses a `#p` filter
   * that does not also name a group — so `{kinds:[1059], '#p':[me]}` comes back
   * CLOSED and the recipient could never fetch it. An `h` tag and an ephemeral
   * author cannot both be true here.
   *
   * Sign the wrap with the inviter's real key instead and the two inner layers
   * stop buying anything. Kinds 1059 and 13 exist *only* to hide the sender:
   * 1059 from the relay, 13 from everyone but the recipient. With `h` naming the
   * group, a `to`-marked `p` naming the recipient and a real signature naming
   * the sender, all three facts are already published, and the MLS Welcome's own
   * confidentiality never depended on the Nostr layer — it is HPKE-encrypted to
   * the recipient's `init_key` inside the MLSMessage. Keeping the stack would be
   * claiming NIP-59 while breaking the one property NIP-59 is for.
   *
   * And 444 could not be the stored kind regardless. NIP-01 defines storage
   * behaviour by range, and 444 falls in none of them — it is only ever a rumor
   * inside a wrap, so Marmot never has to care. Option A says every Quorum event
   * is valid on any generic relay, which means the Welcome needs a kind whose
   * storage semantics are specified. This is that kind.
   *
   * The cost is stated rather than hidden: the workspace relay learns that this
   * inviter added this member to the ratchet at this time. It already knew both
   * parties were in the NIP-29 group, which under Quorum's two-lists rule had to
   * happen first. See `bodies/encryption.ts`.
   */
  MlsWelcome: 8111,
  /**
   * One MLS commit, broadcast to the members who are already in the tree.
   *
   * A Welcome carries a *new* member into the group. This carries the existing
   * members across with them, and without it they are left behind: MLS advances
   * the key schedule on every commit, so a member who never processes one holds
   * epoch N while the committer writes at N+1, and every message after that is
   * unreadable to them. Not "unreadable" in the way an encrypted channel is
   * unreadable to an outsider — unreadable to a member in good standing, with no
   * event anywhere saying what went wrong.
   *
   * That failure was live in this repo until it was tested with three members.
   * `add()` created the commit, kept the new state and dropped the message, so
   * the second person added to any channel silently locked out the first. The
   * error that surfaced was `CryptoError: OperationError` from HPKE, four frames
   * inside `ts-mls`, which is the least actionable thing this system has ever
   * printed.
   *
   * ## Unsealed, and not for the usual reason
   *
   * 8110, 8111, 30443 and 38107 are on `UNSEALED_KINDS` because their readers
   * hold no key yet. A commit's readers are members who hold one. It is on the
   * list because the content is *already* an MLS `PrivateMessage` — sealing a
   * commit inside an application message of the group the commit is advancing
   * would require the recipient to do the thing the commit is what enables, and
   * would encrypt, to exactly the same group, something already encrypted to it.
   *
   * ## The epoch in the body is what orders them
   *
   * `epoch` is the epoch the commit was created *at*, not the one it produces,
   * because that is the question a receiver has: *can I apply this?* It is in
   * the body rather than in the `epoch` tag, which means what it says on a
   * sealed event — the epoch the content was sealed under — and this content is
   * not sealed by us. It is in the clear so that a relay can serialise commits
   * without parsing an MLSMessage, which is the difference between a relay that
   * needs no MLS code and one that needs a wire-format parser.
   */
  MlsCommit: 8112,
} as const

/**
 * Ephemeral kinds: relays MUST NOT store these.
 *
 * This is the native home for M0 finding #4 — control-plane events must not sit
 * in the same queue as conversation, because a handler blocked awaiting approval
 * would otherwise deadlock the queue that delivers its own answer.
 */
export const EphemeralKinds = {
  /** Cancel / pause / steer a running action. */
  Interrupt: 28101,
  /** Single-holder claim on a thread, so two replicas don't both answer. */
  Lease: 28102,
  /** Agent liveness and "what I'm working on". */
  Presence: 28103,
} as const

/** Addressable kinds: newest per (pubkey, kind, d) wins. Mutable state. */
export const AddressableKinds = {
  /** Task state for a thread: status, assignee, budget, spend. d = thread id. */
  ThreadState: 38101,
  /** "This pubkey may invoke X until T." Verified at the resource. */
  CapabilityGrant: 38102,
  /** What an agent is, and what capabilities it wants. d = agent slug. */
  AgentManifest: 38103,
  /** Scoped agent memory. d = memory key. */
  AgentMemory: 38104,
  /** Resume watermarks. d = subscription id. */
  AgentCursor: 38105,
  /** A human authorising an agent to act on their behalf. d = delegation id. */
  Delegation: 38106,
  /**
   * The channel's encryption policy and current key epoch. d = group id.
   *
   * This exists so that "should I encrypt?" has an answer a writer can look up
   * rather than one their operator configured. A member who posts plaintext
   * into a channel everyone else is encrypting leaks the thread and gets no
   * error, so the policy has to be discoverable, and — because it is
   * discoverable — the relay can enforce it without being able to read a word.
   */
  ChannelPolicy: 38107,
} as const

/**
 * NIP-90 data vending machine kinds for context packing.
 *
 * The context API is a DVM rather than a privileged relay endpoint so that the
 * packer is addressed by pubkey and is therefore swappable. 5600/6600 were
 * unallocated in the data-vending-machines registry on 2026-09-11.
 */
export const DvmKinds = {
  ContextPackRequest: 5600,
  ContextPackResult: 6600,
} as const

export const Kinds = {
  ...BorrowedKinds,
  ...RegularKinds,
  ...EphemeralKinds,
  ...AddressableKinds,
  ...DvmKinds,
} as const

export type KindName = keyof typeof Kinds
export type Kind = (typeof Kinds)[KindName]

/** Kinds this NIP defines. Excludes the ones we merely reuse. */
export const QUORUM_KINDS: readonly number[] = Object.freeze([
  ...Object.values(RegularKinds),
  ...Object.values(EphemeralKinds),
  ...Object.values(AddressableKinds),
  ...Object.values(DvmKinds),
])

/** Kinds a Quorum channel carries, including borrowed ones. Goes in `supported_kinds`. */
export const SUPPORTED_KINDS: readonly number[] = Object.freeze([
  BorrowedKinds.ChatMessage,
  BorrowedKinds.Thread,
  BorrowedKinds.Comment,
  BorrowedKinds.DeletionRequest,
  // NIP-90's job feedback, which is how a packer refuses. Listed because a
  // relay that would not carry it makes "the packer will not answer" and "the
  // thread is empty" the same observation, and an agent that cannot tell those
  // apart reasons happily from no history at all. The relay's own packer is
  // not the only one: from M9 the SDK-side packer answers encrypted channels
  // and publishes its refusals here like anyone else.
  BorrowedKinds.JobFeedback,
  // The `mls` bootstrap. Listed for the same reason as job feedback: a relay
  // that would not carry a KeyPackage makes "nobody has published one" and "you
  // may not publish one" the same observation, and the member who cannot tell
  // those apart is one who is waiting to be let into a channel.
  BorrowedKinds.MlsKeyPackage,
  ...QUORUM_KINDS,
])

const isQuorumKindSet = new Set(QUORUM_KINDS)

/** True for kinds defined by this NIP (so: subject to the Quorum envelope rules). */
export function isQuorumKind(kind: number): boolean {
  return isQuorumKindSet.has(kind)
}

// --- NIP-01 range predicates ------------------------------------------------

export function isRegular(kind: number): boolean {
  return (kind >= 1000 && kind < 10000) || kind === 1 || kind === 2 || (kind >= 4 && kind < 45)
}

export function isReplaceable(kind: number): boolean {
  return kind === 0 || kind === 3 || (kind >= 10000 && kind < 20000)
}

export function isEphemeral(kind: number): boolean {
  return kind >= 20000 && kind < 30000
}

export function isAddressable(kind: number): boolean {
  return kind >= 30000 && kind < 40000
}

/**
 * Ephemeral events are never replayed from storage, so a handler must not treat
 * them as durable facts. The SDK uses this to route them past the serial queue.
 */
export function isControlPlane(kind: number): boolean {
  return isEphemeral(kind)
}

const kindNames = new Map<number, KindName>(
  (Object.entries(Kinds) as [KindName, Kind][]).map(([name, kind]) => [kind, name]),
)

export function kindName(kind: number): KindName | undefined {
  return kindNames.get(kind)
}
