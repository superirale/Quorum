/**
 * The key this page signs with, and where it is kept.
 *
 * ## Read this before pointing it at anything real
 *
 * The secret key is held in `localStorage`, in the clear. That is a worse
 * compromise than the console's key file, which is at least mode 0600 and
 * outside the reach of anything that can run script in a page: any XSS on this
 * origin, any extension with host permissions, and anyone with a minute at your
 * unlocked laptop can read it. It is here because this is a development client
 * and the alternative — no browser client at all until NIP-46 lands — is worse
 * for the thing this app exists to test.
 *
 * The real answer is NIP-46 (M9): a remote signer holds the key and this page
 * sends it events to sign, so a compromised page can ask for a signature and
 * cannot walk away with the ability to sign forever. NIP-07 is the same shape
 * with the signer in an extension, and is the smaller step of the two. Until
 * one of those lands, `Signer` is an interface for exactly this reason and
 * swapping this module out touches nothing else.
 *
 * The UI says all of the above out loud rather than hiding it in a comment,
 * because a dev tool that *looks* production-shaped is how a throwaway key
 * stops being throwaway.
 */

import { LocalSigner, generateSecretKey } from '@quorum/sdk'

const KEY = 'quorum.secret'
const NAME = 'quorum.name'

export interface Identity {
  signer: LocalSigner
  pubkey: string
  name: string
}

export function load(): Identity | undefined {
  const secret = localStorage.getItem(KEY)
  if (!secret) return undefined
  try {
    const signer = LocalSigner.from(secret)
    return { signer, pubkey: signer.publicKey, name: localStorage.getItem(NAME) ?? 'me' }
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
  return { signer, pubkey: signer.publicKey, name: name.trim() || 'me' }
}

export function generate(): string {
  return generateSecretKey()
}

export function forget(): void {
  localStorage.removeItem(KEY)
  localStorage.removeItem(NAME)
}
