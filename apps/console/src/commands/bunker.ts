/**
 * NIP-46: an identity this console can use and cannot steal.
 *
 * Every other identity here is a secret key in a file under `.quorum/`, which
 * has been the honest compromise since M4 and is written down as one in
 * `config.ts`. This is the other option. The key stays in a bunker — a phone, a
 * hardware signer, a process on another machine — and the console holds only a
 * throwaway client key that lets it *ask* for signatures. Two things follow
 * that no amount of care with file permissions could buy:
 *
 * The console can be compromised without the identity being compromised. An
 * attacker who reads `.quorum/ada.bunker` can ask Ada's bunker to sign, and
 * Ada can watch them ask and say no, and then revoke the client key. With a
 * `.key` file they simply *are* Ada, everywhere, forever, and nobody finds out
 * until an approval turns up that nobody remembers signing.
 *
 * And a signature can be refused at the moment it is asked for. The whole
 * argument of this project is that a human approval is a signed event that
 * nobody can forge; a tool that holds the human's key and signs on their behalf
 * whenever it feels like it has quietly made that claim untrue for the one
 * identity it matters most for.
 *
 * The commands are deliberately three: connect, status, forget. Anything more
 * would be re-implementing the bunker's own UI from the wrong side of the
 * connection.
 */

import { Nip46Signer, parseBunkerUri } from '@quorum/sdk'
import { flag, type ParsedArgs } from '../args.ts'
import {
  forgetBunker,
  loadBunker,
  loadConfig,
  saveBunker,
  saveConfig,
  type BunkerSession,
} from '../config.ts'
import { bold, dim, green, short, yellow } from '../format.ts'

export async function bunker(args: ParsedArgs): Promise<void> {
  const sub = args.words[1]
  switch (sub) {
    case 'connect':
      return connect(args)
    case 'status':
      return status(args)
    case 'forget':
      return forget(args)
    default:
      throw new Error('usage: quorum bunker connect <name> <bunker://…> | status [name] | forget <name>')
  }
}

async function connect(args: ParsedArgs): Promise<void> {
  const [, , name, uri] = args.words
  if (!name || !uri) {
    throw new Error('usage: quorum bunker connect <name> "bunker://<pubkey>?relay=wss://…&secret=…"')
  }

  // Parsed before anything is opened, so a mistyped URI fails in a
  // millisecond with a sentence about the URI rather than in sixty seconds
  // with a timeout against a relay nobody meant to contact.
  const parsed = parseBunkerUri(uri)
  console.log(`connecting to ${dim(short(parsed.remote))} via ${dim(parsed.relays.join(', '))}…`)

  const signer = await Nip46Signer.open({
    uri: parsed,
    onAuth: (url) => {
      console.log(`${yellow('!')} the bunker wants you to approve this in a browser:`)
      console.log(`  ${url}`)
    },
    log: { warn: () => {}, error: (m) => console.error(m) },
  })

  try {
    const pubkey = await signer.pubkey()
    const session: BunkerSession = {
      uri,
      clientSecretKey: signer.clientSecretKey,
      pubkey,
      connectedAt: Math.floor(Date.now() / 1000),
    }
    const path = await saveBunker(name, session)

    console.log(`${green('✓')} ${bold(name)}`)
    console.log(`  pubkey  ${pubkey}`)
    console.log(`  client  ${signer.clientPubkey} ${dim('(this console, on the bunker’s allowlist)')}`)
    console.log(`  session ${dim(path)} ${dim('(0600 — it holds the client key, not yours)')}`)

    const config = await loadConfig()
    if (!config.identity) {
      await saveConfig({ ...config, identity: name })
      console.log(`  ${dim(`now signing as ${name}`)}`)
    } else if (config.identity !== name) {
      console.log(dim(`  still signing as ${config.identity} — \`quorum use ${name}\` to switch`))
    }

    // Said once, at the only moment anyone is looking at this screen. The
    // client key is what the bunker recognises; if it is thrown away, the
    // bunker sees a stranger and the human is asked to approve again.
    console.log(
      dim(
        '\n  The secret in the URI is single-use on most bunkers. Keep this session file\n' +
          '  and the console stays connected across restarts; delete it and you reconnect\n' +
          '  from scratch, with a new client key and a fresh approval.',
      ),
    )
  } finally {
    signer.close()
  }
}

async function status(args: ParsedArgs): Promise<void> {
  const config = await loadConfig()
  const name = args.words[2] ?? flag(args, 'as') ?? config.identity
  if (!name) throw new Error('usage: quorum bunker status <name>')

  const saved = await loadBunker(name)
  if (!saved) {
    console.log(`${bold(name)} is a local key, not a bunker session.`)
    console.log(dim(`  \`quorum bunker connect ${name} bunker://…\` to move it behind a signer.`))
    return
  }

  const parsed = parseBunkerUri(saved.uri)
  console.log(`${bold(name)}`)
  console.log(`  pubkey    ${saved.pubkey}`)
  console.log(`  bunker    ${parsed.remote}`)
  console.log(`  relays    ${parsed.relays.join(', ')}`)
  console.log(`  connected ${dim(new Date(saved.connectedAt * 1000).toISOString())}`)

  // Reaching it is a separate claim from having a file about it, and it is the
  // claim an operator is actually asking for: a bunker that is asleep looks
  // exactly like one that is working right up until the first signature.
  process.stdout.write('  reachable ')
  const signer = await Nip46Signer.open({
    uri: parsed,
    clientSecretKey: saved.clientSecretKey,
    requestTimeoutMs: 10_000,
    log: { warn: () => {}, error: () => {} },
  }).catch((error: unknown) => {
    console.log(`${yellow('no')} ${dim((error as Error).message)}`)
    return undefined
  })
  if (!signer) return
  try {
    const answer = await signer.pubkey()
    console.log(answer === saved.pubkey ? green('yes') : yellow(`answers as ${short(answer)} — not ${short(saved.pubkey)}`))
  } finally {
    signer.close()
  }
}

async function forget(args: ParsedArgs): Promise<void> {
  const name = args.words[2]
  if (!name) throw new Error('usage: quorum bunker forget <name>')
  if (!(await loadBunker(name))) throw new Error(`"${name}" is not a saved bunker session`)

  await forgetBunker(name)
  console.log(`${green('✓')} forgot the bunker session for ${bold(name)}`)
  // The asymmetry is worth stating, because "forget" sounds like it undoes the
  // connection and it only undoes this side of it.
  console.log(
    dim(
      '  This console can no longer ask that bunker to sign. The bunker still lists\n' +
        '  the client key it approved — revoke it there too if that matters.',
    ),
  )
}
