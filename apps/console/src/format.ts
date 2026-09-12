/**
 * Terminal output.
 *
 * Colour is switched off when stdout is not a TTY, so piping `quorum export`
 * or `quorum inbox` into another program yields text rather than escape codes.
 */

const plain = !process.stdout.isTTY || process.env.NO_COLOR !== undefined

const wrap = (code: string) => (text: string) => (plain ? text : `\x1b[${code}m${text}\x1b[0m`)

export const bold = wrap('1')
export const dim = wrap('2')
export const red = wrap('31')
export const green = wrap('32')
export const yellow = wrap('33')
export const cyan = wrap('36')

/** Enough of a hex id to recognise, short enough to scan a column of them. */
export function short(hex: string): string {
  return hex.length > 12 ? `${hex.slice(0, 8)}…` : hex
}

export function when(seconds: number): string {
  return new Date(seconds * 1000).toLocaleTimeString()
}

/**
 * A one-line, human-readable description of any event.
 *
 * Reads the NIP-31 `alt` tag first, which is exactly what that tag is for and
 * the reason the spec requires it on every Quorum kind: a reader that has never
 * heard of kind 8102 still gets a usable line. Falling back to the kind number
 * is the honest failure, not a crash.
 */
export function describe(kind: number, alt: string | undefined, content: string): string {
  if (alt) return alt
  if (content && content.length < 120) return content
  return `kind ${kind}`
}
