#!/usr/bin/env node
/**
 * `npx @quorum/conformance <relay-url>`.
 *
 * Two decisions about the output are worth stating, because both are the
 * opposite of what a test runner does.
 *
 * **Checks print as they settle.** A full run publishes a few hundred events,
 * waits on relay-authored ones, and paces its polling at 1200ms to stay under
 * khatru's filter limiter — so it takes a minute or two, and a tool that
 * printed nothing for two minutes would be indistinguishable from one that had
 * hung. `--json` turns that off, since a stream of prose interleaved with a
 * JSON document is neither.
 *
 * **The exit code follows MUST failures only.** A failed SHOULD prints in red
 * and exits zero: a SHOULD that fails a build is a MUST with a gentler name,
 * and the spec would then be lying about which is which. A `skip` also exits
 * zero, because a precondition this suite could not meet is not a verdict on
 * the relay — but skips are counted in the footer so nobody reads a run that
 * asked half its questions as a clean one.
 */

import { conformant, render, toJson } from './report.ts'
import { run } from './run.ts'

const USAGE = `usage: quorum-conformance <relay-url> [options]

  --json            the whole report as JSON, and nothing else on stdout
  --verbose         include checks that did not apply, and their reasons
  --group <id>      use an existing workspace instead of creating one, so the
                    run sees a workspace with history — which is what makes the
                    checkpoint checks real rather than n/a. Needs a key that is
                    already a member of it, so pass --key too.
  --key <secret>    run as this key, hex or nsec1…, instead of a fresh one.
                    QUORUM_CONFORMANCE_KEY does the same and keeps the secret
                    off the command line, where ps can read it.
  --patience <ms>   how long to wait for a relay-authored event, default 20000

  The run prints the pubkey it is using on stderr before it starts, because a
  relay with QUORUM_OWNER_PUBKEYS set has to be told about that key first.

  exits non-zero only when a MUST check inside a profile this relay was
  detected to implement failed.
`

interface Args {
  url: string
  json: boolean
  verbose: boolean
  group?: string
  ownerKey?: string
  patienceMs?: number
}

function parse(argv: string[], env = process.env): Args | string {
  const args: Args = { url: '', json: false, verbose: false }
  const fromEnv = env['QUORUM_CONFORMANCE_KEY']?.trim()
  if (fromEnv) args.ownerKey = fromEnv
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '--json') args.json = true
    else if (arg === '--verbose' || arg === '-v') args.verbose = true
    else if (arg === '--help' || arg === '-h') return USAGE
    else if (arg === '--group') args.group = argv[(i += 1)]
    else if (arg === '--key') args.ownerKey = argv[(i += 1)]
    else if (arg === '--patience') args.patienceMs = Number(argv[(i += 1)])
    else if (arg.startsWith('-')) return `unknown option ${arg}\n\n${USAGE}`
    else if (args.url) return `two relay urls given: ${args.url} and ${arg}\n\n${USAGE}`
    else args.url = arg
  }
  if (!args.url) return USAGE
  // A bare hostname is the likeliest way to get this wrong, and `new URL` would
  // accept `localhost:7777` as a protocol. Say so rather than failing later in
  // a socket error nobody can read.
  if (!/^wss?:\/\//.test(args.url)) {
    return `the relay url must start with ws:// or wss:// — got ${args.url}\n\n${USAGE}`
  }
  if (args.patienceMs !== undefined && !Number.isFinite(args.patienceMs)) {
    return `--patience wants a number of milliseconds\n\n${USAGE}`
  }
  // Refused here rather than left to fail at the first publish, because the
  // failure it produces is "unknown member" on every check — a report that
  // reads as a broken relay rather than as a run that was never going to work.
  if (args.group && !args.ownerKey) {
    return `--group needs --key: the workspace already exists, so a key generated a moment ago
is not a member of it and every event this run publishes will be refused. Pass
the key you added to that workspace.\n\n${USAGE}`
  }
  return args
}

const GREEN = '\x1b[32m'
const RED = '\x1b[31m'
const YELLOW = '\x1b[33m'
const DIM = '\x1b[2m'
const OFF = '\x1b[0m'

async function main(): Promise<number> {
  const args = parse(process.argv.slice(2))
  if (typeof args === 'string') {
    process.stdout.write(args)
    return args === USAGE ? 0 : 2
  }

  const live = !args.json && process.stdout.isTTY !== false
  const report = await run({
    url: args.url,
    ...(args.group ? { group: args.group } : {}),
    ...(args.ownerKey ? { ownerKey: args.ownerKey } : {}),
    ...(args.patienceMs !== undefined ? { patienceMs: args.patienceMs } : {}),
    // Setup noise goes to stderr, so `--json > report.json` stays a document.
    log: (line) => {
      if (!args.json) process.stderr.write(`${DIM}${line}${OFF}\n`)
    },
    ...(live
      ? {
          onSection: (section) => process.stderr.write(`${DIM}${section.name}${OFF}\n`),
          onCheck: (check) => {
            if (check.outcome === 'n/a') return
            const mark =
              check.outcome === 'pass'
                ? `${GREEN}✔${OFF}`
                : check.outcome === 'fail'
                  ? `${RED}✘${OFF}`
                  : `${YELLOW}?${OFF}`
            process.stderr.write(`  ${mark} ${check.id}\n`)
          },
        }
      : {}),
  })

  if (live) process.stderr.write('\n')
  process.stdout.write(args.json ? `${toJson(report)}\n` : `${render(report, { verbose: args.verbose })}\n`)
  return conformant(report) ? 0 : 1
}

main().then(
  (code) => {
    process.exitCode = code
  },
  (error: unknown) => {
    // A thrown error here is the suite failing to run at all — an unreachable
    // relay, a DNS failure, a socket closed on connect. Exit 2 rather than 1,
    // because "this relay is not conformant" and "this run did not happen" are
    // different answers and a CI job has to be able to tell them apart.
    process.stderr.write(`${RED}the run did not happen${OFF}: ${(error as Error)?.message ?? error}\n`)
    process.exitCode = 2
  },
)
