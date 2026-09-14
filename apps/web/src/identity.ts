/**
 * The key this page signs with — or, better, the key it does not have.
 *
 * There are two backings, and they are not equal:
 *
 * **`bunker`** — NIP-46. The secret key lives in a remote signer and this page
 * sends it events to sign. A compromised page can ask for a signature while it
 * is open and cannot walk away with the ability to sign forever, which is the
 * whole difference. This is the one to use.
 *
 * **`local`** — a secret key in `localStorage`, in the clear. Worse than the
 * console's key file, which is at least mode 0600 and out of reach of anything
 * that can run script on this origin: any XSS here, any extension with host
 * permissions, and anyone with a minute at your unlocked laptop can read it.
 * Kept because a browser client with no signer at all is useless for testing,
 * and because a throwaway key on a local relay is a reasonable thing to have.
 * The UI says so on the screen where the key is made, not only in this comment.
 *
 * ## What a bunker session stores, and why that is not the same risk
 *
 * A saved session is the `bunker://` URI and the **client** key — a throwaway
 * generated here that signs the kind 24133 RPC envelopes and nothing else. It
 * is not an identity. Leaking it grants the right to ask a bunker that has
 * already approved this client, which the bunker can revoke; leaking the user
 * key grants everything, forever, with nobody able to revoke anything. It is
 * persisted so a reload does not make a human approve the connection again.
 */

import { LocalSigner, Nip46Signer, generateSecretKey, type Signer } from '@quorum/sdk'

const KEY = 'quorum.secret'
const NAME = 'quorum.name'
const BUNKER = 'quorum.bunker'

export interface Identity {
  /** Four methods wide, which is what lets a bunker drop in unchanged. */
  signer: Signer
  pubkey: string
  name: string
  /** Which of the two above this is. Shown in the header, because it matters. */
  backing: 'local' | 'bunker'
  /** Drops a bunker connection. A no-op for a local key. */
  close(): void
}

export interface BunkerSession {
  uri: string
  clientSecretKey: string
  /** What the bunker said its user pubkey was at connect time. */
  pubkey: string
  connectedAt: number
}

/** The saved bunker session, if there is one. Nothing is connected by reading it. */
export function savedBunker(): BunkerSession | undefined {
  const raw = localStorage.getItem(BUNKER)
  if (!raw) return undefined
  try {
    const parsed = JSON.parse(raw) as BunkerSession
    return parsed.uri && parsed.clientSecretKey && parsed.pubkey ? parsed : undefined
  } catch {
    return undefined
  }
}

/**
 * The local dev key, if one was saved. Synchronous, so the first paint can use
 * it; a bunker cannot be, because it is a network handshake.
 */
export function loadLocal(): Identity | undefined {
  const secret = localStorage.getItem(KEY)
  if (!secret) return undefined
  try {
    const signer = LocalSigner.from(secret)
    return local(signer)
  } catch {
    // A corrupt or truncated value is not worth preserving, but it is worth
    // saying so: silently generating a new key would change who you are
    // mid-session, and every grant issued to the old pubkey would stop working
    // for no visible reason.
    console.error('the saved key is not a valid secret key; clear it and start again')
    return undefined
  }
}

export function save(secret: string, name: string): Identity {
  // Parsed before it is stored, so a typo fails at the form rather than on the
  // next page load. What goes to storage is what was typed — the signer does
  // not hand its secret back, which is the one thing about it worth keeping.
  const signer = LocalSigner.from(secret)
  localStorage.setItem(KEY, secret.trim())
  localStorage.setItem(NAME, name.trim() || 'me')
  // Exactly one backing at a time. See `connectBunker`.
  localStorage.removeItem(BUNKER)
  return local(signer)
}

/**
 * Connect to a bunker and remember the session.
 *
 * `onAuth` is not optional in practice: a bunker may answer the very first
 * request with "a human must approve this at <url>", and a caller that
 * swallows it shows a spinner for sixty seconds and then a timeout nobody can
 * explain. It is passed through rather than handled here because where that
 * URL goes is a UI decision — this app shows it as a link rather than opening
 * a window, since a page that redirects you somewhere a pasted URI chose is a
 * worse habit than one extra click.
 *
 * Connecting **deletes any saved dev key**, and `save()` deletes any saved
 * bunker session, because two backings in storage at once is not "two ways in",
 * it is two identities and a race over which one the next reload picks: the
 * first paint takes the local key, the restore then replaces it with whoever
 * the bunker says you are, and a page that changes pubkey a second after it
 * loads will have you signing as the wrong person. Dropping the key is also the
 * right move on its own terms — moving to a remote signer and leaving the
 * secret in `localStorage` keeps every risk the move was meant to end.
 */
export async function connectBunker(
  uri: string,
  name: string,
  onAuth: (url: string) => void,
): Promise<Identity> {
  const signer = await Nip46Signer.open({ uri: uri.trim(), onAuth })
  try {
    const pubkey = await signer.pubkey()
    const session: BunkerSession = {
      uri: uri.trim(),
      clientSecretKey: signer.clientSecretKey,
      pubkey,
      connectedAt: Math.floor(Date.now() / 1000),
    }
    localStorage.setItem(BUNKER, JSON.stringify(session))
    localStorage.setItem(NAME, name.trim() || 'me')
    localStorage.removeItem(KEY)
    return bunker(signer, pubkey)
  } catch (error) {
    signer.close()
    throw error
  }
}

/**
 * Reopen the saved bunker session on a reload.
 *
 * Refuses if the bunker now reports a different user pubkey. That is not
 * paranoia about an attacker: a bunker with several accounts can be switched
 * behind this page, and every grant, membership and approval saved under the
 * old key belongs to somebody else. Signing as a stranger with this page's
 * history on screen is the worst available outcome, so it fails and says to
 * reconnect.
 */
export async function resumeBunker(onAuth: (url: string) => void): Promise<Identity | undefined> {
  const saved = savedBunker()
  if (!saved) return undefined

  const signer = await Nip46Signer.open({
    uri: saved.uri,
    clientSecretKey: saved.clientSecretKey,
    onAuth,
  })
  const pubkey = await signer.pubkey()
  if (pubkey !== saved.pubkey) {
    signer.close()
    localStorage.removeItem(BUNKER)
    throw new Error(
      `the bunker now signs as ${pubkey.slice(0, 16)}… but this session was connected to ` +
        `${saved.pubkey.slice(0, 16)}…. Connect again if that change was intended.`,
    )
  }
  return bunker(signer, pubkey)
}

export function generate(): string {
  return generateSecretKey()
}

/** Forget everything about who you are. Both backings, because a half-signed-out page lies. */
export function forget(): void {
  localStorage.removeItem(KEY)
  localStorage.removeItem(NAME)
  localStorage.removeItem(BUNKER)
}

function displayName(): string {
  return localStorage.getItem(NAME) ?? 'me'
}

function local(signer: LocalSigner): Identity {
  return {
    signer,
    pubkey: signer.publicKey,
    name: displayName(),
    backing: 'local',
    close: () => {},
  }
}

function bunker(signer: Nip46Signer, pubkey: string): Identity {
  return {
    signer,
    pubkey,
    name: displayName(),
    backing: 'bunker',
    close: () => signer.close(),
  }
}
