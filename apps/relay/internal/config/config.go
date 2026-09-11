// Package config reads the relay's settings from the environment.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

type Config struct {
	// Addr is the listen address, e.g. ":3334".
	Addr string
	// Domain is the public host, used in NIP-29 group identifiers.
	Domain string
	// DataDir holds the event database and the relay's key.
	DataDir string
	// SchemaDir holds the JSON Schema published by @quorum/protocol.
	SchemaDir string
	// SecretKey signs the relay's own events: NIP-29 group metadata now,
	// Quorum checkpoints from M7.
	SecretKey string

	// RequireAuth makes the relay demand NIP-42 before serving reads.
	RequireAuth bool

	// Owners may create workspaces. Empty means anyone may, which is relay29's
	// default and is only reasonable on a laptop.
	Owners []string

	Name        string
	Description string

	// Rate limits. Zero disables the limiter.
	EventsPerMinute  int
	MaxEventsBurst   int
	FiltersPerMinute int
	MaxFiltersBurst  int

	// ClockSkew bounds how far an event's created_at may sit from now.
	ClockSkew time.Duration
}

func Load() (Config, error) {
	c := Config{
		Addr:             env("QUORUM_ADDR", ":3334"),
		Domain:           env("QUORUM_DOMAIN", "localhost:3334"),
		DataDir:          env("QUORUM_DATA_DIR", "./data"),
		SchemaDir:        env("QUORUM_SCHEMA_DIR", "../../packages/protocol/schemas"),
		Name:             env("QUORUM_NAME", "quorum reference relay"),
		Description:      env("QUORUM_DESCRIPTION", "An agent-first messaging relay. NIP-01, NIP-11, NIP-29, NIP-42 and the Quorum kinds."),
		RequireAuth:      boolEnv("QUORUM_REQUIRE_AUTH", false),
		EventsPerMinute:  intEnv("QUORUM_EVENTS_PER_MINUTE", 120),
		MaxEventsBurst:   intEnv("QUORUM_EVENTS_BURST", 40),
		FiltersPerMinute: intEnv("QUORUM_FILTERS_PER_MINUTE", 120),
		MaxFiltersBurst:  intEnv("QUORUM_FILTERS_BURST", 40),
		ClockSkew:        time.Duration(intEnv("QUORUM_CLOCK_SKEW_SECONDS", 900)) * time.Second,
	}

	owners, err := listEnv("QUORUM_OWNER_PUBKEYS")
	if err != nil {
		return c, err
	}
	c.Owners = owners

	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return c, fmt.Errorf("creating the data directory: %w", err)
	}

	key, err := loadOrCreateKey(c.DataDir)
	if err != nil {
		return c, err
	}
	c.SecretKey = key

	return c, nil
}

func (c Config) PublicKey() (string, error) { return nostr.GetPublicKey(c.SecretKey) }

// loadOrCreateKey reads the relay's secret key, generating one on first run.
//
// The key is the relay's identity: it signs the NIP-29 group metadata clients
// trust, and from M7 the checkpoints that make withholding an event provable.
// Losing it means every group's metadata is suddenly signed by a stranger, so
// it is written 0600 to the data directory and never to a log or the NIP-11
// document. Supplying QUORUM_SECRET_KEY takes precedence, for deployments that
// keep secrets outside the filesystem.
func loadOrCreateKey(dataDir string) (string, error) {
	if fromEnv := os.Getenv("QUORUM_SECRET_KEY"); fromEnv != "" {
		if err := validKey(fromEnv); err != nil {
			return "", fmt.Errorf("QUORUM_SECRET_KEY: %w", err)
		}
		return fromEnv, nil
	}

	path := filepath.Join(dataDir, "relay.key")
	raw, err := os.ReadFile(path)
	if err == nil {
		key := strings.TrimSpace(string(raw))
		if err := validKey(key); err != nil {
			return "", fmt.Errorf("%s: %w", path, err)
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating a relay key: %w", err)
	}
	key := hex.EncodeToString(buf)

	// O_EXCL so two relays starting at once cannot each believe they created
	// the key and then disagree about which one is the relay's identity.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	defer file.Close()
	if _, err := file.WriteString(key + "\n"); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return key, nil
}

func validKey(key string) error {
	if len(key) != 64 {
		return fmt.Errorf("must be 64 hex characters, got %d", len(key))
	}
	if _, err := hex.DecodeString(key); err != nil {
		return fmt.Errorf("must be hex: %w", err)
	}
	return nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// listEnv reads a comma-separated list of hex pubkeys.
//
// A typo here fails loudly. The alternative — skipping the unparseable entry —
// would silently lock the real owner out of their own relay, and the symptom
// (a rejected group creation) points nowhere near the cause.
func listEnv(name string) ([]string, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil, nil
	}
	var list []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !nostr.IsValidPublicKey(entry) {
			return nil, fmt.Errorf("%s: %q is not a 32-byte hex public key", name, entry)
		}
		list = append(list, entry)
	}
	return list, nil
}

func intEnv(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func boolEnv(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
