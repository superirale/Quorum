/** Keys: making them, choosing one, and showing what is saved. */

import { LocalSigner, generateSecretKey } from '@quorum/sdk'
import { bool, flag, type ParsedArgs } from '../args.ts'
import {
  listBunkers,
  listIdentities,
  loadBunker,
  loadConfig,
  loadKey,
  saveConfig,
  saveKey,
} from '../config.ts'
import { bold, cyan, dim, green } from '../format.ts'

export async function keygen(args: ParsedArgs): Promise<void> {
  const name = args.words[1]
  if (!name) throw new Error('usage: quorum keygen <name>')

  const existing = await listIdentities()
  if (existing.includes(name) && !bool(args, 'force')) {
    // Overwriting a key destroys an identity: every grant issued to it, every
    // approval signed by it and every membership it holds refer to a pubkey
    // that no longer has an owner. Nothing here can undo that, so it takes a
    // flag.
    throw new Error(`"${name}" already exists. \`--force\` overwrites it, which orphans its key.`)
  }

  // The bytes are generated here and handed to the signer, rather than asking
  // the signer to give them back: `LocalSigner` keeps its secret in a `#private`
  // field with no accessor, and redacts on every stringification. A key that
  // can be printed is a key that ends up in a log.
  const secret = generateSecretKey()
  const signer = LocalSigner.fromHex(secret)
  const path = await saveKey(name, secret)

  console.log(`${green('✓')} ${bold(name)}`)
  console.log(`  pubkey  ${signer.publicKey}`)
  console.log(`  npub    ${signer.npub}`)
  console.log(`  secret  ${dim(path)} ${dim('(0600, plaintext — this is a dev tool)')}`)

  const config = await loadConfig()
  if (!config.identity) {
    await saveConfig({ ...config, identity: name })
    console.log(`  ${dim(`now signing as ${name}`)}`)
  }
}

export async function use(args: ParsedArgs): Promise<void> {
  const name = args.words[1]
  if (!name) throw new Error('usage: quorum use <name>')
  // Either backing will do. A bunker identity has no key file, and requiring
  // one would make `use` the single command that could not select the safer
  // kind of identity.
  if (!(await loadBunker(name))) await loadKey(name) // fails loudly if it is not there
  const config = await loadConfig()
  await saveConfig({ ...config, identity: name })
  console.log(`${green('✓')} signing as ${bold(name)}`)
}

export async function whoami(args: ParsedArgs): Promise<void> {
  const config = await loadConfig()
  const current = flag(args, 'as') ?? config.identity

  console.log(`relay   ${cyan(config.relay)}`)
  console.log(`group   ${cyan(`#${config.group}`)}`)

  if (!current) {
    console.log(dim('\nno identity yet — `quorum keygen ada`'))
    return
  }

  const names = bool(args, 'all')
    ? [...new Set([...(await listBunkers()), ...(await listIdentities())])].sort()
    : [current]

  for (const name of names) {
    const mark = name === current ? green('*') : ' '
    const saved = await loadBunker(name)
    // The hex is printed every time, next to the name, because the name is a
    // fiction of this console. Grants, approvals and the relay all speak keys.
    // How the key is held is printed too: "who am I" and "what could sign as
    // me" are different questions, and only one of them is about a file here.
    const pubkey = saved ? saved.pubkey : LocalSigner.fromHex(await loadKey(name)).publicKey
    const held = saved ? dim('bunker') : dim('local key')
    console.log(`${mark} ${bold(name.padEnd(10))} ${pubkey} ${held}`)
  }
}
