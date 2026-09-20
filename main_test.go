package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

type recordingRunner struct {
	commands [][]string
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.commands = append(r.commands, append([]string{name}, args...))
	if name == "sh" {
		return []byte("1001\n"), nil
	}
	return nil, nil
}

func TestConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	want := Config{IntervalSeconds: 120, Country: "de", KillSwitch: false, Mode: "proxy", LogLines: 25, ConfigPath: path}
	if err := saveConfig(want); err != nil {
		t.Fatal(err)
	}

	got, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if got.IntervalSeconds != want.IntervalSeconds || got.Country != want.Country || got.Mode != want.Mode || got.LogLines != want.LogLines || got.KillSwitch != want.KillSwitch {
		t.Fatalf("round trip mismatch: got %#v want %#v", got, want)
	}
}

func TestLoadFirewallUsesManagedChains(t *testing.T) {
	runner := &recordingRunner{}
	controller := NewTorController(runner)
	if err := controller.LoadFirewall(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	joined := make([]string, 0, len(runner.commands))
	for _, command := range runner.commands {
		joined = append(joined, strings.Join(command, " "))
	}
	text := strings.Join(joined, "\n")
	if !strings.Contains(text, "iptables -N TORFUSION") || !strings.Contains(text, "iptables -t nat -N TORFUSION_NAT") {
		t.Fatalf("managed chain creation missing:\n%s", text)
	}
	if !strings.Contains(text, "TORFUSION -j REJECT") {
		t.Fatalf("kill-switch reject rule missing:\n%s", text)
	}
}

func TestDefaultConfigIsSafeForTransparentMode(t *testing.T) {
	cfg := defaultConfig()
	if cfg.Mode != "transparent" || !cfg.KillSwitch || cfg.Country != "auto" {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
	if _, err := os.Stat(cfg.ConfigPath); !os.IsNotExist(err) && cfg.ConfigPath != "" {
		t.Fatalf("default config should not point at an existing file: %q", cfg.ConfigPath)
	}
}

func TestDaemonServiceKeepsFirewallWhenTorStops(t *testing.T) {
	if strings.Contains(daemonService, "Requires=tor@default.service") {
		t.Fatal("daemon service must not stop with Tor, or it will flush the kill-switch rules")
	}
	if !strings.Contains(daemonService, "Wants=network-online.target tor@default.service") {
		t.Fatal("daemon service must still start after the network and request Tor startup")
	}
}

func TestInstallBinaryAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "torfusion")
	if err := os.WriteFile(path, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := installBinaryAtomically(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("installed binary mismatch: %q", got)
	}
}

func TestValidateCountryRejectsTorrcInjection(t *testing.T) {
	for _, country := range []string{"DE\nControlPort 0.0.0.0:9051", "de}", "d e", "d#", "1a", "USA"} {
		if err := validateCountry(country); err == nil {
			t.Errorf("validateCountry(%q) accepted unsafe value", country)
		}
	}
	for _, country := range []string{"auto", "de", "US"} {
		if err := validateCountry(strings.ToLower(country)); err != nil {
			t.Errorf("validateCountry(%q) rejected valid value: %v", country, err)
		}
	}
}

func TestStatusUsesDefaultTorInstance(t *testing.T) {
	runner := &recordingRunner{}
	controller := NewTorController(runner)
	if _, err := controller.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 || strings.Join(runner.commands[0], " ") != "systemctl is-active tor@default" {
		t.Fatalf("unexpected status command: %#v", runner.commands)
	}
}

func TestFlushFirewallIsIdempotentForMissingChains(t *testing.T) {
	runner := &errorRunner{err: &mockError{msg: "Chain 'TORFUSION' does not exist"}}
	controller := NewTorController(runner)
	if err := controller.FlushFirewall(context.Background()); err != nil {
		t.Fatalf("missing managed chains must be harmless: %v", err)
	}

}

type errorRunner struct {
	err error
}

func (r *errorRunner) Run(_ context.Context, _ string, _ ...string) ([]byte, error) {
	return nil, r.err
}

func TestParseRotationSpec(t *testing.T) {
	tests := []struct {
		spec     string
		min, max int
	}{
		{"300", 300, 300},
		{"30-120", 30, 120},
		{"30s-2m", 30, 120},
	}
	for _, test := range tests {
		min, max, err := parseRotationSpec(test.spec)
		if err != nil || min != test.min || max != test.max {
			t.Errorf("parseRotationSpec(%q) = %d, %d, %v", test.spec, min, max, err)
		}
	}
	for _, spec := range []string{"0", "120-30", "5m/10", "5x"} {
		if _, _, err := parseRotationSpec(spec); err == nil {
			t.Errorf("parseRotationSpec(%q) accepted invalid input", spec)
		}
	}
}

func TestNormalizeRotationConfigPreservesLegacyInterval(t *testing.T) {
	cfg := Config{IntervalSeconds: 120}
	if err := normalizeRotationConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.IntervalMin != 120 || cfg.IntervalMax != 120 {
		t.Fatalf("legacy interval was not normalized: %#v", cfg)
	}
}

func TestBusyOperationAllowsMenuNavigation(t *testing.T) {
	uiModel := newModel(defaultConfig(), NewTorController(&recordingRunner{}))
	uiModel.busy = true
	uiModel.selected = 0

	updated, _ := uiModel.Update(tea.KeyMsg{Type: tea.KeyDown})
	got := updated.(model)
	if got.selected != 1 {
		t.Fatalf("busy operation blocked menu navigation: selected=%d", got.selected)
	}
	if !got.busy {
		t.Fatal("menu navigation unexpectedly cleared busy state")
	}

	updated, _ = got.Update(tea.KeyMsg{Type: tea.KeyUp})
	got = updated.(model)
	if got.selected != 0 {
		t.Fatalf("busy operation blocked upward navigation: selected=%d", got.selected)
	}
}
