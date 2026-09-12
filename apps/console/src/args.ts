/**
 * Argument parsing, kept pure so it can be tested without a relay.
 *
 * Deliberately not a dependency. The flags this console needs are a closed set
 * and every argument parser worth adding brings opinions about what a flag
 * means — `--scope env=production` repeated twice, or `--set replicas=3` where
 * the value must survive as the number 3 rather than the string "3". Those two
 * rules are the whole reason this file exists, and both are load-bearing: a
 * scope that silently keeps only its last value grants more than it looks like
 * it grants, and a digest computed over `"3"` does not match one computed over
 * `3`, so the approval would be refused for reasons nobody could see.
 */

export interface ParsedArgs {
  /** The command words before the first flag, e.g. `['workspace', 'create']`. */
  words: string[]
  /** Every occurrence of every flag, in order. */
  flags: Map<string, string[]>
}

/**
 * Split argv into command words and flags.
 *
 * `--flag value` and `--flag=value` are both accepted; a flag with no value is
 * recorded as the empty string, which {@link bool} reads as true. Everything
 * after a bare `--` is a word, so a message beginning with a dash can still be
 * posted.
 */
export function parseArgs(argv: readonly string[]): ParsedArgs {
  const words: string[] = []
  const flags = new Map<string, string[]>()
  let literal = false

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!

    if (literal || !arg.startsWith('--')) {
      words.push(arg)
      continue
    }
    if (arg === '--') {
      literal = true
      continue
    }

    const eq = arg.indexOf('=')
    const name = eq === -1 ? arg.slice(2) : arg.slice(2, eq)
    let value: string
    if (eq !== -1) {
      value = arg.slice(eq + 1)
    } else {
      // A following token is this flag's value unless it is itself a flag. That
      // makes `--reason --set x=1` a missing reason rather than a reason of
      // "--set", which is the mistake worth catching early.
      const next = argv[i + 1]
      if (next !== undefined && !next.startsWith('--')) {
        value = next
        i++
      } else {
        value = ''
      }
    }

    const existing = flags.get(name)
    if (existing) existing.push(value)
    else flags.set(name, [value])
  }

  return { words, flags }
}

/** The last occurrence of a flag, or undefined. */
export function flag(args: ParsedArgs, name: string): string | undefined {
  const values = args.flags.get(name)
  return values?.[values.length - 1]
}

/** Every occurrence of a flag, in order. Empty if absent. */
export function flagAll(args: ParsedArgs, name: string): string[] {
  return args.flags.get(name) ?? []
}

/** Whether a flag was given at all. `--force` and `--force=yes` are both true. */
export function bool(args: ParsedArgs, name: string): boolean {
  return args.flags.has(name)
}

/** A flag that must be an integer, so a typo fails here and not three calls later. */
export function int(args: ParsedArgs, name: string): number | undefined {
  const raw = flag(args, name)
  if (raw === undefined || raw === '') return undefined
  const value = Number(raw)
  if (!Number.isInteger(value)) throw new Error(`--${name} must be a whole number, got "${raw}"`)
  return value
}

/**
 * `k=v` pairs into an object, with values JSON-parsed where they parse.
 *
 * The JSON step is what makes `replicas=3` the number 3 and `env=production`
 * the string "production", which matters twice over. A grant scope is compared
 * by value, so a scope of `{replicas: "3"}` does not match an action asking for
 * `{replicas: 3}` and the deploy is refused with no visible cause. And an
 * approval's digest is taken over canonical JSON, where `3` and `"3"` are
 * different bytes.
 *
 * Quote it — `--set version='"1.4.2"'` — only if you need a string that happens
 * to look like a number. A bare `1.4.2` is not valid JSON and stays a string,
 * which is the common case and the right default.
 */
export function pairs(values: readonly string[], what: string): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const raw of values) {
    const eq = raw.indexOf('=')
    if (eq <= 0) {
      throw new Error(`${what} must look like key=value, got "${raw}"`)
    }
    const key = raw.slice(0, eq)
    const value = raw.slice(eq + 1)
    out[key] = parseValue(value)
  }
  return out
}

/** JSON where it parses, the raw string otherwise. */
export function parseValue(raw: string): unknown {
  try {
    return JSON.parse(raw)
  } catch {
    return raw
  }
}
