package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDefaultReturnsValidThresholds(t *testing.T) {
	cfg := Default()
	if cfg.OOM.RSSMB <= 0 {
		t.Fatal("OOM RSSMB must be positive")
	}
	if cfg.RSSTracker.WindowTicks < 2 {
		t.Fatal("RSSTracker WindowTicks must be >= 2")
	}
	if cfg.OOM.RSSRatio <= 0 || cfg.OOM.RSSRatio >= 1 {
		t.Fatalf("OOM RSSRatio should be between 0 and 1, got %f", cfg.OOM.RSSRatio)
	}
}

func TestLoadFileOverridesPartial(t *testing.T) {
	content := []byte(`
oom:
  rss_mb: 1024
starved:
  min_preempted: 50
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	// Overridden values
	if cfg.OOM.RSSMB != 1024 {
		t.Fatalf("expected OOM RSSMB=1024, got %f", cfg.OOM.RSSMB)
	}
	if cfg.Starved.MinPreempted != 50 {
		t.Fatalf("expected Starved MinPreempted=50, got %d", cfg.Starved.MinPreempted)
	}

	// Non-overridden values retain defaults
	defaults := Default()
	if cfg.OOM.FaultsPerSec != defaults.OOM.FaultsPerSec {
		t.Fatalf("expected OOM FaultsPerSec=%f (default), got %f", defaults.OOM.FaultsPerSec, cfg.OOM.FaultsPerSec)
	}
	if cfg.CPUBound.CPUPercent != defaults.CPUBound.CPUPercent {
		t.Fatalf("expected CPUBound CPUPercent=%f (default), got %f", defaults.CPUBound.CPUPercent, cfg.CPUBound.CPUPercent)
	}
	if cfg.RSSTracker.WindowTicks != defaults.RSSTracker.WindowTicks {
		t.Fatalf("expected RSSTracker WindowTicks=%d (default), got %d", defaults.RSSTracker.WindowTicks, cfg.RSSTracker.WindowTicks)
	}
}

func TestLoadFileMissingFile(t *testing.T) {
	_, err := LoadFile("/nonexistent/file.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadFileInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("{{invalid"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadFileWithExclude(t *testing.T) {
	content := []byte(`
exclude:
  - wdavdaemon
  - "2574"
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(cfg.Exclude) != 2 {
		t.Fatalf("expected 2 exclude entries, got %d", len(cfg.Exclude))
	}
	if cfg.Exclude[0] != "wdavdaemon" || cfg.Exclude[1] != "2574" {
		t.Fatalf("unexpected exclude: %v", cfg.Exclude)
	}
}

func TestDefaultYAMLIsValidYAML(t *testing.T) {
	var cfg Thresholds
	if err := yaml.Unmarshal([]byte(DefaultYAML()), &cfg); err != nil {
		t.Fatalf("DefaultYAML is not valid YAML: %v", err)
	}
	if cfg.OOM.RSSMB != 500 {
		t.Fatalf("parsed DefaultYAML OOM RSSMB=%f, want 500", cfg.OOM.RSSMB)
	}
}

