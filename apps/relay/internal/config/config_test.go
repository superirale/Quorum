package config

import (
	"strings"
	"testing"
)

// The one setting in here that is refused rather than corrected.
//
// A checkpoint window has to close behind the oldest event the relay will still
// accept. Below that line the relay signs a commitment and then legitimately
// stores an event inside it, and the next reader to recompute the root
// concludes the relay withheld something. Clamping the value would leave a
// relay running with a mechanism whose failure mode is a false accusation
// against itself, so this is fatal at boot.
func TestRefusesACheckpointLagShorterThanTheClockSkew(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("QUORUM_DATA_DIR", dir)
	t.Setenv("QUORUM_CLOCK_SKEW_SECONDS", "900")
	t.Setenv("QUORUM_CHECKPOINT_LAG", "60")

	_, err := Load()
	if err == nil {
		t.Fatal("a lag shorter than the skew was accepted")
	}
	if !strings.Contains(err.Error(), "QUORUM_CHECKPOINT_LAG") {
		t.Errorf("the error does not name the setting to change: %v", err)
	}
}

func TestAllowsAShortLagWhenCheckpointingIsOff(t *testing.T) {
	// Turning checkpoints off is a supported configuration — it is what every
	// generic relay does — and the constraint only exists to keep signed
	// windows honest, so there is nothing to enforce when nothing is signed.
	dir := t.TempDir()
	t.Setenv("QUORUM_DATA_DIR", dir)
	t.Setenv("QUORUM_CLOCK_SKEW_SECONDS", "900")
	t.Setenv("QUORUM_CHECKPOINT_LAG", "60")
	t.Setenv("QUORUM_CHECKPOINT_EVERY", "0")

	if _, err := Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestDefaultLagMeetsTheDefaultSkew(t *testing.T) {
	// The two defaults are in different places and nothing else ties them
	// together, so a change to one that forgets the other stops the relay from
	// booting. This catches it here instead.
	dir := t.TempDir()
	t.Setenv("QUORUM_DATA_DIR", dir)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CheckpointLag < cfg.ClockSkew {
		t.Fatalf("default lag %s is shorter than default skew %s", cfg.CheckpointLag, cfg.ClockSkew)
	}
}
