package contextpack

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// CanonicalJSON renders a result as RFC 8785 canonical JSON — the same bytes
// the TypeScript packer produces for the same result.
//
// Written by hand rather than with encoding/json, which cannot produce these
// bytes. `json.Marshal` HTML-escapes `<`, `>` and `&` into `<` and
// friends, escapes U+2028 and U+2029, and formats floats by Go's rules rather
// than ECMAScript's. Any one of those turns a byte-equality conformance check
// into a permanent red, and `SetEscapeHTML(false)` fixes only the first.
//
// The shape here is fixed and contains only strings, ints and bools, so there
// is no float formatting to get wrong and no key sorting to do at runtime: the
// keys below are already in RFC 8785 order (sorted by UTF-16 code unit) and a
// test asserts that they stay that way. This is a writer for one struct, not a
// general canonicaliser — packages/protocol/src/digest.ts is the general one,
// and if Go ever needs the general version it belongs beside the digest code,
// not here.
func (r Result) CanonicalJSON() string {
	var b strings.Builder

	b.WriteString(`{"algorithm":`)
	writeString(&b, r.Algorithm)
	b.WriteString(`,"budget_tokens":`)
	b.WriteString(strconv.Itoa(r.BudgetTokens))
	b.WriteString(`,"dropped_events":`)
	b.WriteString(strconv.Itoa(r.DroppedEvents))
	b.WriteString(`,"segments":[`)
	for i, segment := range r.Segments {
		if i > 0 {
			b.WriteByte(',')
		}
		writeSegment(&b, segment)
	}
	b.WriteString(`],"thread":`)
	writeString(&b, r.Thread)
	b.WriteString(`,"used_tokens":`)
	b.WriteString(strconv.Itoa(r.UsedTokens))
	b.WriteByte('}')

	return b.String()
}

func writeSegment(b *strings.Builder, s Segment) {
	b.WriteString(`{"created_at":`)
	b.WriteString(strconv.FormatInt(s.CreatedAt, 10))
	b.WriteString(`,"event_id":`)
	writeString(b, s.EventID)
	b.WriteString(`,"kind":`)
	b.WriteString(strconv.Itoa(s.Kind))
	b.WriteString(`,"mandatory":`)
	writeBool(b, s.Mandatory)
	b.WriteString(`,"provenance":{"kind":`)
	writeString(b, s.Provenance.Kind)
	b.WriteString(`,"pubkey":`)
	writeString(b, s.Provenance.Pubkey)
	b.WriteString(`,"trust":`)
	writeString(b, s.Provenance.Trust)
	b.WriteString(`},"text":`)
	writeString(b, s.Text)
	b.WriteString(`,"truncated":`)
	writeBool(b, s.Truncated)
	b.WriteByte('}')
}

func writeBool(b *strings.Builder, value bool) {
	if value {
		b.WriteString("true")
		return
	}
	b.WriteString("false")
}

const hex = "0123456789abcdef"

// writeString escapes exactly as ECMAScript's JSON.stringify does, because
// that is what the other packer uses for strings and RFC 8785 defers to it.
//
// So: the two-character escapes for the five characters that have them,
// `\u00xx` in *lowercase* hex for the rest of C0, and everything else written
// through as UTF-8 — no HTML escaping, and U+2028/U+2029 left alone. They are
// legal in a JSON string and only JavaScript source has a problem with them.
//
// The one input on which the two writers can still differ is a lone surrogate.
// A JavaScript string can hold one and JSON.stringify emits `\ud800`; Go
// strings are UTF-8 and `encoding/json` has already replaced it with U+FFFD by
// the time an event body reaches here, so this writer emits the replacement
// character and the digests differ. Unreachable through a signed event whose
// content parsed on both sides, and not worth a WTF-8 decoder to close.
func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c >= utf8.RuneSelf || (c >= 0x20 && c != '"' && c != '\\') {
			i++
			continue
		}
		if start < i {
			b.WriteString(s[start:i])
		}
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteString(`\u00`)
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
		}
		i++
		start = i
	}
	if start < len(s) {
		b.WriteString(s[start:])
	}
	b.WriteByte('"')
}
