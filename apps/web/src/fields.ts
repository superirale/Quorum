/**
 * Reading an edited field back out of an HTML input without changing its type.
 *
 * An `<input>` yields a string, always. If the agent proposed `replicas: 30`
 * and a human types `3`, the payload that gets signed must contain the number
 * 3 and not the string "3" — they are different bytes, so they are a different
 * digest, and the agent that validates its own input will reject the second one
 * *after* a human has already signed it. Quietly changing a field's type during
 * an edit is a way to turn an approval into a failed action nobody can explain.
 *
 * So the original value decides how the new one is read. There is no guessing:
 * the proposal is right there.
 */

export type FieldKind = 'string' | 'number' | 'boolean' | 'json'

export function kindOf(value: unknown): FieldKind {
  if (typeof value === 'string') return 'string'
  if (typeof value === 'number') return 'number'
  if (typeof value === 'boolean') return 'boolean'
  return 'json'
}

/** How the field is shown when nothing has been typed into it yet. */
export function toInput(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number') return String(value)
  if (typeof value === 'boolean') return String(value)
  return JSON.stringify(value, null, 2) ?? 'null'
}

export type Parsed = { ok: true; value: unknown } | { ok: false; problem: string }

export function parseField(original: unknown, raw: string): Parsed {
  switch (kindOf(original)) {
    case 'string':
      return { ok: true, value: raw }
    case 'number': {
      // `Number('')` is 0 and `Number(' ')` is 0, which would turn an emptied
      // field into a silent zero — a plausible replica count, a plausible
      // budget, and not what anyone meant.
      if (!raw.trim()) return { ok: false, problem: 'this field needs a number' }
      const value = Number(raw)
      if (!Number.isFinite(value)) return { ok: false, problem: `"${raw}" is not a number` }
      return { ok: true, value }
    }
    case 'boolean':
      return { ok: true, value: raw === 'true' }
    case 'json':
      try {
        return { ok: true, value: JSON.parse(raw) }
      } catch (error) {
        return { ok: false, problem: `not valid JSON: ${(error as Error).message}` }
      }
  }
}

/** True when the edited text means something different from what was proposed. */
export function changed(original: unknown, parsed: unknown): boolean {
  return JSON.stringify(original) !== JSON.stringify(parsed)
}
