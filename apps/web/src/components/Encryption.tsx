/**
 * What this client says about the channel's encryption, and what it refuses.
 *
 * Two sentences live here and they are the two the rest of the app must not
 * compose for itself. The header chip names the mode; the banner says why
 * something could not be read *and what to do about it* — and that second half
 * is where the modes genuinely differ. Under `nip44` a missing key has a cure
 * somebody can perform: a member holding the epoch wraps it for you and the
 * history opens. Under `mls` the material that opens those messages has been
 * deleted, by design, by every member who held it. Offering the nip44 cure
 * there sends an operator to ask an admin for something no admin has.
 *
 * Both are exported and tested as functions of the policy rather than written
 * inline in `App.tsx`, for the reason the console's `sealing`/`noKey` were split
 * out: this is the layer where every value is correct and the English composed
 * from them can still be false, and it is the one layer an SDK suite cannot
 * reach.
 */

import { EncMode } from '@quorum/protocol'
import type { ChannelPolicy } from '@quorum/sdk'
import { short } from '../format.ts'

/**
 * Which mode the channel is in.
 *
 * Read off the policy the relay serves rather than assumed, because it is a
 * property of the channel and not of this client, and it decides whether the
 * relay can read what you are about to type. `mls` is styled as a warning
 * rather than as a success: the channel is sealed, which is good, and this
 * client cannot participate in it, which the operator needs to know at a
 * glance rather than after typing a message.
 */
export function ModeBadge({ policy }: { policy: ChannelPolicy }) {
  if (policy.enc === EncMode.Mls) {
    // No epoch, deliberately, and the spec forbids the policy from carrying
    // one. The MLS epoch is a fact about a ratchet, this client holds none,
    // and a number here would invite a reader to compare it with a member's.
    return <span className="warn-text">MLS · no ratchet here</span>
  }
  if (policy.enc === EncMode.Nip44) {
    return <span className="sealed">sealed · epoch {policy.epoch ?? '?'}</span>
  }
  return <span className="dim">plaintext</span>
}

/**
 * The banner for events this client was served and cannot read.
 *
 * Renders nothing when there are none — including on an mls channel nobody has
 * said anything in yet, where the refusal is still true but there is nothing to
 * refuse and a standing warning would just be furniture.
 */
export function Unreadable({
  count,
  policy,
  me,
}: {
  count: number
  policy: ChannelPolicy
  me: string
}) {
  if (count <= 0) return null

  if (policy.enc === EncMode.Mls) {
    return (
      <div className="banner warn">
        {count} event(s) here are sealed to an MLS group this client is not in — and cannot join.
        <div className="dim">
          There is no admin who can fix this and no key anyone can send you: MLS deletes the
          material that opens old messages as the group moves on, so even a member added a
          moment from now gets none of this history. A Nostr key also has exactly one KeyPackage
          slot per channel, so this tab cannot join as a second device of an identity that is
          already in the group — publishing one from here would retire the offer the console
          published. Read and write this channel with the <code>quorum</code> console, which
          keeps the ratchet and its own archive of what it has read.
        </div>
      </div>
    )
  }

  return (
    <div className="banner warn">
      {count} event(s) here are sealed under a key this identity does not hold.
      <div className="dim">
        They are listed in the channel and cannot be read, and nothing derived from them —
        approvals, tasks, capabilities — can appear. Ask an admin to wrap the current epoch for{' '}
        {short(me)}. Rotating a key does not re-wrap history for you automatically.
      </div>
    </div>
  )
}
