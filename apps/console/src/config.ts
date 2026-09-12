/**
 * Where the console keeps its keys and its defaults.
 *
 * **These are secret keys in files, and this is a development tool.** They are
 * written `0600` and never logged, which is the floor rather than the bar: a
 * plaintext key on a laptop is fine for driving a local relay and is not how
 * anyone should hold a production identity. The real answer is NIP-46, where
 * the console never sees a secret at all and a remote signer approves each
 * signature — that is M9, and this file should shrink to almost nothing when it
 * lands.
 *
 * Saying so here rather than in a README footnote is deliberate. The whole
 * argument of this project is that an identity is a keypair and nobody can
 * forge it; a tool that then leaves those keypairs lying around casually has
 * quietly moved the trust back onto whoever can read the disk.
 */

import { chmod, mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
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

export function keyPath(name: string): string {
  if (!/^[a-z0-9][a-z0-9_-]*$/i.test(name)) {
    // The name becomes a filename, so this is a path-traversal guard as much as
    // a tidiness rule.
    throw new Error(`"${name}" is not a usable identity name — use letters, digits, - and _`)
  }
  return join(home(), `${name}${KEY_SUFFIX}`)
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
  try {
    const files = await readdir(home())
    return files.filter((f) => f.endsWith(KEY_SUFFIX)).map((f) => f.slice(0, -KEY_SUFFIX.length))
  } catch {
    return []
  }
}
