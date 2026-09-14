/**
 * Where the console keeps its keys and its defaults.
 *
 * **A `.key` here is a secret key in a file, and this is a development tool.**
 * They are written `0600` and never logged, which is the floor rather than the
 * bar: a plaintext key on a laptop is fine for driving a local relay and is not
 * how anyone should hold a production identity.
 *
 * Saying so here rather than in a README footnote is deliberate. The whole
 * argument of this project is that an identity is a keypair and nobody can
 * forge it; a tool that then leaves those keypairs lying around casually has
 * quietly moved the trust back onto whoever can read the disk.
 *
 * Since M9 there is a second kind of identity — a `.bunker` file, a NIP-46
 * session — and it is the one to use for anything that matters. See
 * {@link BunkerSession}. Both kinds answer to the same names, because every
 * command above this layer asks for a `Signer` and does not care which it got;
 * that is the whole reason the interface is four methods wide.
 */

import { chmod, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

export interface Config {
  relay: string
  group: string
  /** The identity commands sign as, unless `--as` overrides it. */
  identity?: string
}

const DEFAULTS: Config = { relay: 'ws://localhost:3334', group: 'payments' }

/**
 * The console's home. `.quorum` under the working directory by default, so a
 * checkout can hold a whole test workspace and deleting the directory is a
 * complete reset.
 */
export function home(): string {
  return process.env.QUORUM_HOME ?? join(process.cwd(), '.quorum')
}

export async function loadConfig(): Promise<Config> {
  let saved: Partial<Config> = {}
  try {
    saved = JSON.parse(await readFile(join(home(), 'config.json'), 'utf8')) as Partial<Config>
  } catch {
    // No config yet is the normal first run, not an error.
  }
  // Environment beats file beats default, so a one-off `QUORUM_GROUP=other`
  // needs no `use` and leaves nothing behind.
  return {
    relay: process.env.QUORUM_RELAY ?? saved.relay ?? DEFAULTS.relay,
    group: process.env.QUORUM_GROUP ?? saved.group ?? DEFAULTS.group,
    ...((process.env.QUORUM_IDENTITY ?? saved.identity)
      ? { identity: process.env.QUORUM_IDENTITY ?? saved.identity }
      : {}),
  }
}

export async function saveConfig(config: Config): Promise<void> {
  await mkdir(home(), { recursive: true })
  await writeFile(join(home(), 'config.json'), `${JSON.stringify(config, null, 2)}\n`)
}

const KEY_SUFFIX = '.key'
const BUNKER_SUFFIX = '.bunker'

export function keyPath(name: string): string {
  return named(name, KEY_SUFFIX)
}

function named(name: string, suffix: string): string {
  if (!/^[a-z0-9][a-z0-9_-]*$/i.test(name)) {
    // The name becomes a filename, so this is a path-traversal guard as much as
    // a tidiness rule.
    throw new Error(`"${name}" is not a usable identity name — use letters, digits, - and _`)
  }
  return join(home(), `${name}${suffix}`)
}

export async function saveKey(name: string, secretHex: string): Promise<string> {
  const path = keyPath(name)
  await mkdir(home(), { recursive: true })
  // Written, then narrowed. `writeFile`'s mode is masked by the process umask,
  // so it cannot be relied on alone to produce 0600.
  await writeFile(path, `${secretHex}\n`, { mode: 0o600 })
  await chmod(path, 0o600)
  return path
}

export async function loadKey(name: string): Promise<string> {
  try {
    return (await readFile(keyPath(name), 'utf8')).trim()
  } catch {
    throw new Error(`no identity called "${name}" — make one with \`quorum keygen ${name}\``)
  }
}

export async function listIdentities(): Promise<string[]> {
  return suffixed(KEY_SUFFIX)
}

/**
 * A saved NIP-46 session: which bunker, and the client key that reaches it.
 *
 * This file is the reason the paragraph at the top of this module is not the
 * whole story any more. An identity backed by a bunker leaves **no secret of
 * its own** on this disk — `pubkey` is public, `uri` is a connection string,
 * and `clientSecretKey` signs nothing but RPC to one bunker that has already
 * approved it and can un-approve it. Someone who steals this file can ask the
 * bunker to sign; they cannot walk away with the identity, and the human
 * holding it can see them asking.
 *
 * It is still written 0600, because "less dangerous" is not "harmless".
 */
export interface BunkerSession {
  uri: string
  clientSecretKey: string
  /**
   * The user pubkey the bunker reported when we connected.
   *
   * Recorded so a later session can notice it changed. Every grant, approval
   * and membership this console issued names the old key; a bunker quietly
   * answering `get_public_key` with a different one is either a
   * misconfiguration or an attempt to inherit an identity's history, and both
   * deserve to stop the command rather than be discovered later in an audit.
   */
  pubkey: string
  connectedAt: number
}

export async function saveBunker(name: string, session: BunkerSession): Promise<string> {
  const path = named(name, BUNKER_SUFFIX)
  await mkdir(home(), { recursive: true })
  await writeFile(path, `${JSON.stringify(session, null, 2)}\n`, { mode: 0o600 })
  await chmod(path, 0o600)
  return path
}

/** The saved session, or `undefined` for an identity that is a local key. */
export async function loadBunker(name: string): Promise<BunkerSession | undefined> {
  try {
    return JSON.parse(await readFile(named(name, BUNKER_SUFFIX), 'utf8')) as BunkerSession
  } catch {
    return undefined
  }
}

export async function forgetBunker(name: string): Promise<void> {
  await rm(named(name, BUNKER_SUFFIX), { force: true })
}

export async function listBunkers(): Promise<string[]> {
  return suffixed(BUNKER_SUFFIX)
}

async function suffixed(suffix: string): Promise<string[]> {
  try {
    const files = await readdir(home())
    return files.filter((f) => f.endsWith(suffix)).map((f) => f.slice(0, -suffix.length))
  } catch {
    return []
  }
}
