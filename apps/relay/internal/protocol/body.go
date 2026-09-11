package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// BodySchema validates the `content` of one Quorum kind against the JSON Schema
// published for it.
type BodySchema struct {
	compiled *jsonschema.Schema
}

func loadBodySchema(path string) (*BodySchema, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading the body schema: %w", err)
	}
	defer file.Close()

	document, err := jsonschema.UnmarshalJSON(file)
	if err != nil {
		return nil, fmt.Errorf("parsing the body schema: %w", err)
	}

	compiler := jsonschema.NewCompiler()
	// The $id in these files is a quorum.chat URL. Registering the document
	// under the same name it claims keeps the compiler from trying to resolve
	// that URL over the network — which would make relay startup depend on a
	// website being up, and would silently start validating against whatever
	// that website served rather than the file shipped alongside the binary.
	if err := compiler.AddResource(path, document); err != nil {
		return nil, fmt.Errorf("registering the body schema: %w", err)
	}
	compiled, err := compiler.Compile(path)
	if err != nil {
		return nil, fmt.Errorf("compiling the body schema: %w", err)
	}
	return &BodySchema{compiled: compiled}, nil
}

// Validate checks a JSON body string against the schema.
func (b *BodySchema) Validate(content string) error {
	decoder := json.NewDecoder(strings.NewReader(content))
	// Bodies carry costs and budgets. Decoding those through float64 loses
	// precision on large integers, and a msat amount that changes when it is
	// parsed is not an amount anyone should bill against.
	decoder.UseNumber()

	var body any
	if err := decoder.Decode(&body); err != nil {
		return fmt.Errorf("content is not JSON: %w", err)
	}
	if decoder.More() {
		return fmt.Errorf("content has trailing data after the JSON body")
	}

	if err := b.compiled.Validate(body); err != nil {
		return fmt.Errorf("%s", summarize(err))
	}
	return nil
}

// summarize turns a jsonschema error into something that fits in a relay's
// NIP-01 OK message, which clients typically show verbatim in a toast.
func summarize(err error) string {
	var validation *jsonschema.ValidationError
	if !errors.As(err, &validation) {
		return err.Error()
	}

	var out bytes.Buffer
	leaves := 0
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			if leaves >= 3 {
				return
			}
			if leaves > 0 {
				out.WriteString("; ")
			}
			location := strings.Join(e.InstanceLocation, "/")
			if location == "" {
				location = "body"
			}
			fmt.Fprintf(&out, "%s: %v", location, e.ErrorKind)
			leaves++
			return
		}
		for _, cause := range e.Causes {
			walk(cause)
		}
	}
	walk(validation)

	if leaves == 0 {
		return validation.Error()
	}
	return out.String()
}
