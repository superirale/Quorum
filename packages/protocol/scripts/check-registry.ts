/**
 * Re-check Quorum's kind numbers against the live NIP registries.
 *
 * Deliberately not a unit test. It makes two network calls, so as a test it
 * would fail on a plane and flake in CI for reasons that have nothing to do
 * with the code — and a flaky test gets muted, which is the worst outcome for
 * a check whose entire job is to notice a rare event.
 *
 * Run it before publishing, and when the NIP PR is being prepared:
 *
 *     node --experimental-strip-types scripts/check-registry.ts
 *
 * A collision is not a bug to work around. It means someone else registered the
 * number first and Quorum has to move — which is a MAJOR version bump, per
 * src/version.ts.
 */

import { QUORUM_KINDS, kindName } from '../src/kinds.ts'

interface Source {
  name: string
  url: string
  /**
   * How to turn the response into a set of claimed kind numbers.
   *
   * `scrape` pulls every integer out of a document. `listing` reads a GitHub
   * directory whose files are named `<kind>.md`, which is exact rather than
   * approximate — worth the special case, because it is the only authority for
   * the DVM range that 5600/6600 sit in.
   */
  mode: 'scrape' | 'listing'
}

const SOURCES: Source[] = [
  {
    name: 'registry-of-kinds',
    url: 'https://raw.githubusercontent.com/nostr-protocol/registry-of-kinds/master/schema.yaml',
    mode: 'scrape',
  },
  {
    name: 'nips/README',
    url: 'https://raw.githubusercontent.com/nostr-protocol/nips/master/README.md',
    mode: 'scrape',
  },
  {
    name: 'data-vending-machines',
    url: 'https://api.github.com/repos/nostr-protocol/data-vending-machines/contents/kinds',
    mode: 'listing',
  },
]

/**
 * Scrape kind numbers out of prose and YAML.
 *
 * A parser tuned to either format would be more precise and would silently stop
 * matching the day that format changed — leaving a green run that checked
 * nothing. Over-matching is the safe failure direction here: a false collision
 * costs a minute of reading, a missed one costs a protocol migration.
 */
function extractKinds(text: string): Set<number> {
  const found = new Set<number>()
  for (const match of text.matchAll(/\b(\d{1,5})\b/g)) {
    const n = Number(match[1])
    if (Number.isInteger(n) && n >= 0 && n <= 65535) found.add(n)
  }
  return found
}

/** Kind numbers from a GitHub directory of `<kind>.md` files. */
function listedKinds(payload: unknown): Set<number> {
  if (!Array.isArray(payload)) throw new Error('expected a directory listing')
  const found = new Set<number>()
  for (const entry of payload) {
    const match = /^(\d{1,5})\.md$/.exec(String((entry as { name?: unknown }).name ?? ''))
    if (match) found.add(Number(match[1]))
  }
  if (found.size === 0) throw new Error('listing contained no <kind>.md files')
  return found
}

async function load(source: Source): Promise<Set<number>> {
  const response = await fetch(source.url, {
    headers: source.mode === 'listing' ? { accept: 'application/vnd.github+json' } : {},
  })
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`)
  return source.mode === 'listing'
    ? listedKinds(await response.json())
    : extractKinds(await response.text())
}

const results = await Promise.all(
  SOURCES.map(async (source) => {
    try {
      return { source, kinds: await load(source), error: null }
    } catch (cause) {
      return { source, kinds: new Set<number>(), error: cause as Error }
    }
  }),
)

let unreachable = 0
for (const { source, error } of results) {
  if (error) {
    console.error(`  unreachable  ${source.name}: ${error.message}`)
    unreachable++
  }
}

if (unreachable === results.length) {
  console.error('\nno registry could be reached — this run proved nothing')
  process.exit(2)
}

console.log(`checking ${QUORUM_KINDS.length} Quorum kinds against ${results.length - unreachable} registry source(s)\n`)

const collisions: string[] = []
for (const kind of QUORUM_KINDS) {
  const hits = results.filter((r) => !r.error && r.kinds.has(kind)).map((r) => r.source.name)
  if (hits.length > 0) {
    collisions.push(`  ${kind} (${kindName(kind)}) appears in: ${hits.join(', ')}`)
  }
}

if (collisions.length === 0) {
  console.log(`clear — no Quorum kind appears in any registry source.`)
  process.exit(0)
}

console.log(`${collisions.length} kind(s) need a human to look:\n`)
for (const line of collisions) console.log(line)
console.log(
  '\nThese are candidates, not verdicts: the scrape matches any number in the\n' +
    'document, so a hit may be a line number, a byte count or a year. Open the\n' +
    'source and check whether the number is actually registered as a kind.',
)
process.exit(1)
