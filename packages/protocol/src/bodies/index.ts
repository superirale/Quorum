/**
 * Kind → body schema registry.
 *
 * The rule this encodes: for every Quorum kind, `content` is a single JSON
 * object matching the schema below. For the borrowed kinds (9, 11, 1111)
 * `content` is plain text, as their own NIPs specify — those have no entry
 * here, and that absence is meaningful rather than an oversight.
 *
 * Schemas are non-strict: unknown properties are allowed through. That is the
 * forward-compatibility contract for bodies, mirroring what `alt` does for
 * kinds. A v0.2 agent adding an optional field must not make its events
 * unreadable to a v0.1 reader.
 */

import type { z } from 'zod'
import { AddressableKinds, DvmKinds, EphemeralKinds, RegularKinds } from '../kinds.ts'
import { ActionBody, ErrorBody, InterruptBody } from './action.ts'
import { ApprovalRequestBody, ApprovalResponseBody } from './approval.ts'
import { ArtifactBody, CheckpointBody } from './artifact.ts'
import { AgentCursorBody, AgentManifestBody, AgentMemoryBody, LeaseBody, PresenceBody } from './agent.ts'
import { CapabilityGrantBody, DelegationBody } from './capability.ts'
import { ContextPackRequestBody, ContextPackResultBody, SummaryBody } from './context.ts'
import { ChannelKeyBody, ChannelPolicyBody } from './encryption.ts'
import { HandoffBody, ThreadOpBody, ThreadStateBody } from './thread.ts'

export * from './common.ts'
export * from './action.ts'
export * from './approval.ts'
export * from './artifact.ts'
export * from './agent.ts'
export * from './capability.ts'
export * from './context.ts'
export * from './encryption.ts'
export * from './thread.ts'

export const BODY_SCHEMAS = {
  [RegularKinds.Action]: ActionBody,
  [RegularKinds.ApprovalRequest]: ApprovalRequestBody,
  [RegularKinds.ApprovalResponse]: ApprovalResponseBody,
  [RegularKinds.Summary]: SummaryBody,
  [RegularKinds.Error]: ErrorBody,
  [RegularKinds.Artifact]: ArtifactBody,
  [RegularKinds.Handoff]: HandoffBody,
  [RegularKinds.Checkpoint]: CheckpointBody,
  [RegularKinds.ThreadOp]: ThreadOpBody,
  [RegularKinds.ChannelKey]: ChannelKeyBody,

  [EphemeralKinds.Interrupt]: InterruptBody,
  [EphemeralKinds.Lease]: LeaseBody,
  [EphemeralKinds.Presence]: PresenceBody,

  [AddressableKinds.ThreadState]: ThreadStateBody,
  [AddressableKinds.CapabilityGrant]: CapabilityGrantBody,
  [AddressableKinds.AgentManifest]: AgentManifestBody,
  [AddressableKinds.AgentMemory]: AgentMemoryBody,
  [AddressableKinds.AgentCursor]: AgentCursorBody,
  [AddressableKinds.Delegation]: DelegationBody,
  [AddressableKinds.ChannelPolicy]: ChannelPolicyBody,

  [DvmKinds.ContextPackRequest]: ContextPackRequestBody,
  [DvmKinds.ContextPackResult]: ContextPackResultBody,
} as const satisfies Record<number, z.ZodType>

export type BodySchemas = typeof BODY_SCHEMAS

/** The body type for a kind, or `never` for kinds with a plain-text content. */
export type BodyOf<K extends keyof BodySchemas> = z.infer<BodySchemas[K]>

export function bodySchema(kind: number): z.ZodType | undefined {
  return (BODY_SCHEMAS as Record<number, z.ZodType>)[kind]
}
