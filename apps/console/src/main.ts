#!/usr/bin/env -S node --experimental-strip-types
/**
 * `quorum` — the operator console.
 *
 * A Quorum workspace has two kinds of participant and, until M5, only one of
 * them had a way in. An agent is a process you start; a human is someone who
 * has to create the workspace, hand out a capability, ask for something, and
 * then sign or refuse the request that comes back. All of that existed only as
 * library calls inside the example scripts, which play every part themselves
 * and exit — so there was no way to sit at a terminal and *be* Ada.
 *
 * This is that. It is a thin thing on purpose: every command below is a few
 * lines over `@quorum/sdk`, holds no state the relay does not hold, and makes
 * no decision the protocol does not already define. When the reference client
 * lands it will do the same work behind buttons, and this will remain the
 * headless path — nobody scripts a workspace from a web UI.
 *
 *   quorum help
 */

import { bool, flag, parseArgs, type ParsedArgs } from './args.ts'
import { audit, exportEvents } from './commands/audit.ts'
import { approve, deny, inboxCommand } from './commands/approvals.ts'
import { grantCommand, grantsCommand, revokeCommand } from './commands/grants.ts'
import { keygen, use, whoami } from './commands/identity.ts'
import { say, watch } from './commands/messages.ts'
import { budget, stop, tasks } from './commands/tasks.ts'
import { workspace } from './commands/workspace.ts'
import { bold, dim, red } from './format.ts'

const COMMANDS: Record<string, (args: ParsedArgs) => Promise<void>> = {
  keygen,
  whoami,
  use,
  workspace,
  grant: grantCommand,
  revoke: revokeCommand,
  grants: grantsCommand,
  say,
  inbox: inboxCommand,
  approve,
  deny,
  watch,
  tasks,
  budget,
  stop,
  audit,
  export: exportEvents,
}

const args = parseArgs(process.argv.slice(2))
const name = args.words[0]

if (!name || name === 'help' || bool(args, 'help')) {
  usage()
  process.exit(name ? 0 : 1)
}

const command = COMMANDS[name]
if (!command) {
  console.error(`unknown command "${name}". Run \`quorum help\`.`)
  process.exit(1)
}

// `--relay` and `--group` are folded into the environment rather than threaded
// through every command, because that is already the precedence the config
// loader implements: environment beats file beats default. One override rule,
// not two that can disagree.
const relayFlag = flag(args, 'relay')
if (relayFlag) process.env.QUORUM_RELAY = relayFlag
const groupFlag = flag(args, 'group')
if (groupFlag) process.env.QUORUM_GROUP = groupFlag

try {
  await command(args)
  process.exit(0)
} catch (error) {
  // The relay's rejection message is the interesting part of most failures
  // here — "did not ask", "input_digest" — so it is printed as the error
  // rather than buried under a stack trace.
  console.error(`${red('✗')} ${(error as Error).message}`)
  if (flag(args, 'debug') !== undefined) console.error(error)
  process.exit(1)
}

function usage(): void {
  console.log(`
${bold('quorum')} — drive a Quorum workspace by hand

${bold('identity')}
  keygen <name>              make a keypair and save it ${dim('(0600, plaintext — dev tool)')}
  use <name>                 sign as this identity from now on
  whoami [--all]             who am I, and what else is saved

${bold('workspace')}
  workspace create <group>   create it and become its admin
  workspace add <who>        admit a member ${dim('(name or hex pubkey)')}
  workspace invite <who>     sign a join capability they present themselves
      --expires <seconds>    from now
  workspace join             present the invitation you were given
  workspace remove <who>     put someone out ${dim('(revoke their invitation too)')}
  workspace members          who is in it
  workspace use <group>      work in this group from now on

${bold('capabilities')}
  grant <who> <resource>     issue a capability
      --scope k=v            narrowing constraints, repeatable
      --actions invoke,read  default: invoke
      --expires <seconds>    from now
      --max-uses <n>
  revoke <who> <resource>    withdraw it ${dim('(same --scope as the grant)')}
  grants [who]               what this key holds

${bold('conversation')}
  say <text> --to <who>      start a thread addressed to someone
      --title <t>
  watch                      tail the group as events arrive

${bold('tasks, cost and stopping')}
  tasks                      every thread, its status and what it has spent
  budget <thread>            show the ceiling ${dim('(id prefixes are fine)')}
      --tokens n --usd n     set it; 0 is a freeze
      --none                 remove it
  stop <thread>              interrupt whatever is running ${dim('(ephemeral — nothing stores it)')}
      --action <id>          just that one action
      --pause                pause instead of cancel
      --steer "<text>"       send an instruction; the agent decides
      --reason <r>

${bold('approvals')}
  inbox [--all]              what is waiting on me
  approve <id> [--set k=v]   sign consent, optionally editing the payload first
  deny <id> [--reason r]

${bold('audit')}
  audit [--thread <id>]      verify every action chain in the group
  export <file>              dump the group's events for offline verification

${bold('global')}
  --as <name>                sign as someone else, just this once
  --relay <url> --group <g>  override the saved defaults

${dim('Defaults live in .quorum/config.json; $QUORUM_HOME moves the whole directory.')}
`)
}
