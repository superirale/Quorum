/**
 * Editing a payload on the way to approving it.
 *
 * A human who changes a parameter before agreeing is the case the whole
 * approval mechanism exists to make safe: the agent must run the edit, the
 * signature must cover the edit, and an auditor must be able to see both the
 * proposal and the edit side by side. What that requires from *this* file is
 * narrow and absolute — an approver may change a value the agent proposed, and
 * may not introduce a field the agent never proposed.
 *
 * That rule lives here rather than in either client because there are now two
 * of them. The console takes `--set replicas=3`; the web client renders one
 * input per field. They must reach the same answer, and the way to guarantee
 * that is for them to call the same function rather than to each be careful.
 *
 * `leaves()` is the other half: it is how a UI can generate a form from a
 * payload it has never seen. A form built from the proposal's own fields cannot
 * offer a field the proposal did not have, so the browser enforces the rule
 * structurally and `applyEdits` catches the case where something else tried.
 */

export interface Leaf {
  /** Dotted path into the payload, e.g. `limits.cpu`. */
  path: string
  value: unknown
}

/**
 * Every editable position in a payload, as a dotted path.
 *
 * Recurses into plain objects only. An array is a leaf, not a branch: `tags.0`
 * would let an approver rewrite one element while the length silently stayed
 * the same, and "approved with the third item changed" is not a thing a form
 * should make easy to do without noticing. Edit the whole array as JSON.
 */
export function leaves(input: unknown, prefix = ''): Leaf[] {
  if (!isPlainObject(input)) return prefix ? [{ path: prefix, value: input }] : []

  const out: Leaf[] = []
  for (const [key, value] of Object.entries(input)) {
    const path = prefix ? `${prefix}.${key}` : key
    if (isPlainObject(value) && Object.keys(value).length) out.push(...leaves(value, path))
    else out.push({ path, value })
  }
  return out
}

/**
 * Apply `path -> value` edits to a payload, supporting `a.b` for nested keys.
 *
 * The result is a copy. The original proposal must stay intact, because the
 * chain records the digest of both and an auditor compares them.
 */
export function applyEdits(input: unknown, edits: Record<string, unknown>): unknown {
  if (Object.keys(edits).length === 0) return input
  if (!isPlainObject(input)) {
    throw new Error('editing needs an object payload; this action proposed something else')
  }

  const out = structuredClone(input) as Record<string, unknown>
  for (const [path, value] of Object.entries(edits)) {
    const parts = path.split('.')
    let target = out
    for (const part of parts.slice(0, -1)) {
      const next = target[part]
      if (!isPlainObject(next)) {
        throw new Error(`${path}: "${part}" is not an object in the proposed input`)
      }
      target = next as Record<string, unknown>
    }
    const leaf = parts[parts.length - 1]!
    if (!(leaf in target)) {
      // Refused rather than added. An approver editing a field the agent never
      // proposed is either a typo or an attempt to smuggle an argument past the
      // agent's own validation, and neither should be silently accepted.
      throw new Error(
        `${path}: the proposed input has no "${leaf}". ` +
          `It has: ${Object.keys(target).join(', ') || '(nothing)'}`,
      )
    }
    target[leaf] = value
  }
  return out
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}
