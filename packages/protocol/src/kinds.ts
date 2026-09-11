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
