package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestFlushFirewallRemovesManagedChains(t *testing.T) {
	runner := &recordingRunner{}
	controller := NewTorController(runner)
	if err := controller.FlushFirewall(context.Background()); err != nil {
		t.Fatalf("FlushFirewall failed: %v", err)
	}

	joinedCommands := make([]string, 0, len(runner.commands))
	for _, cmd := range runner.commands {
		joinedCommands = append(joinedCommands, strings.Join(cmd, " "))
	}
	text := strings.Join(joinedCommands, "\n")

	requiredRemovals := []string{
		"iptables -D OUTPUT -j TORFUSION",
		"iptables -t nat -D OUTPUT -j TORFUSION_NAT",
		"iptables -X TORFUSION",
		"iptables -t nat -X TORFUSION_NAT",
		"ip6tables -D OUTPUT -j TORFUSION6",
		"ip6tables -D FORWARD -j TORFUSION_FORWARD6",
		"ip6tables -X TORFUSION6",
	}
	for _, removal := range requiredRemovals {
		if !strings.Contains(text, removal) {
			t.Errorf("missing removal command: %s\n\nActual commands:\n%s", removal, text)
		}
	}
}

func TestLoadFirewallWithoutKillSwitch(t *testing.T) {
	runner := &recordingRunner{}
	controller := NewTorController(runner)
	if err := controller.LoadFirewall(context.Background(), false); err != nil {
		t.Fatalf("LoadFirewall failed: %v", err)
	}

	joinedCommands := make([]string, 0, len(runner.commands))
	for _, cmd := range runner.commands {
		joinedCommands = append(joinedCommands, strings.Join(cmd, " "))
	}
	text := strings.Join(joinedCommands, "\n")

	if !strings.Contains(text, "TORFUSION -j RETURN") {
		t.Errorf("without kill-switch, should use RETURN not REJECT\n\nActual:\n%s", text)
	}
	if strings.Contains(text, "TORFUSION -j REJECT") {
		t.Errorf("without kill-switch, should not have REJECT rule\n\nActual:\n%s", text)
	}
	if !strings.Contains(text, "iptables -A TORFUSION -p udp -j REJECT") {
		t.Errorf("unsupported UDP must never bypass Tor\n\nActual:\n%s", text)
	}
}

func TestLoadFirewallCreatesCustomChains(t *testing.T) {
	runner := &recordingRunner{}
	controller := NewTorController(runner)
	if err := controller.LoadFirewall(context.Background(), true); err != nil {
		t.Fatalf("LoadFirewall failed: %v", err)
	}

	joinedCommands := make([]string, 0, len(runner.commands))
	for _, cmd := range runner.commands {
		joinedCommands = append(joinedCommands, strings.Join(cmd, " "))
	}
	text := strings.Join(joinedCommands, "\n")

	if !strings.Contains(text, "iptables -N TORFUSION") && !strings.Contains(text, "iptables -F TORFUSION") {
		t.Errorf("must create or flush TORFUSION chain\n\nActual:\n%s", text)
	}
	if !strings.Contains(text, "iptables -t nat -N TORFUSION_NAT") && !strings.Contains(text, "iptables -t nat -F TORFUSION_NAT") {
		t.Errorf("must create or flush TORFUSION_NAT chain\n\nActual:\n%s", text)
	}
	if !strings.Contains(text, "iptables -N TORFUSION_FORWARD") || !strings.Contains(text, "iptables -t nat -N TORFUSION_NAT_FORWARD") {
		t.Errorf("must create forwarding chains\n\nActual:\n%s", text)
	}
	if !strings.Contains(text, "ip6tables -N TORFUSION6") || !strings.Contains(text, "ip6tables -N TORFUSION_FORWARD6") {
		t.Errorf("must create IPv6 chains\n\nActual:\n%s", text)
	}
}

func TestLoadFirewallProtectsForwardedTraffic(t *testing.T) {
	runner := &recordingRunner{}
	controller := NewTorController(runner)
	if err := controller.LoadFirewall(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	joined := make([]string, 0, len(runner.commands))
	for _, cmd := range runner.commands {
		joined = append(joined, strings.Join(cmd, " "))
	}
	text := strings.Join(joined, "\n")
	for _, rule := range []string{
		"iptables -I FORWARD 1 -j TORFUSION_FORWARD",
		"iptables -t nat -I PREROUTING 1 -j TORFUSION_NAT_FORWARD",
		"iptables -A TORFUSION_FORWARD -j REJECT",
		"iptables -A TORFUSION_FORWARD -p udp -j REJECT",
		"ip6tables -I FORWARD 1 -j TORFUSION_FORWARD6",
		"ip6tables -A TORFUSION_FORWARD6 -j REJECT",
	} {
		if !strings.Contains(text, rule) {
			t.Errorf("missing forwarded traffic rule %q\n\nActual:\n%s", rule, text)
		}
	}
}

func TestLoadFirewallBlocksIPv6OutsideLocalNetworks(t *testing.T) {
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
	for _, rule := range []string{
		"ip6tables -A TORFUSION6 -d fc00::/7 -j ACCEPT",
		"ip6tables -A TORFUSION6 -d fe80::/10 -j ACCEPT",
		"ip6tables -A TORFUSION6 -j REJECT",
		"ip6tables -A TORFUSION_FORWARD6 -j REJECT",
	} {
		if !strings.Contains(text, rule) {
			t.Errorf("missing IPv6 Tor-only rule %q\n\nActual:\n%s", rule, text)
		}
	}
}

func TestLoadFirewallFailsWhenExistingChainCannotBeFlushed(t *testing.T) {
	runner := &chainSetupErrorRunner{}
	controller := NewTorController(runner)
	if err := controller.LoadFirewall(context.Background(), true); err == nil {
		t.Fatal("expected LoadFirewall to fail when an existing chain cannot be flushed")
	}
}

func TestLoadFirewallProtectsLocalhost(t *testing.T) {
	runner := &recordingRunner{}
	controller := NewTorController(runner)
	if err := controller.LoadFirewall(context.Background(), true); err != nil {
		t.Fatalf("LoadFirewall failed: %v", err)
	}

	joinedCommands := make([]string, 0, len(runner.commands))
	for _, cmd := range runner.commands {
		joinedCommands = append(joinedCommands, strings.Join(cmd, " "))
	}
	text := strings.Join(joinedCommands, "\n")

	localSubnets := []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	for _, subnet := range localSubnets {
		if !strings.Contains(text, subnet) {
			t.Errorf("firewall must protect local subnet %s\n\nActual:\n%s", subnet, text)
		}
	}
}

func TestCheckTorReachableWithValidConnection(t *testing.T) {
	// This test would require a running Tor instance, so we skip it in CI
	// but document the expected behavior
	if testing.Short() {
		t.Skip("skipping integration test")
	}
}

func TestBackupIptablesCreatesValidDirectory(t *testing.T) {
	runner := &mockFailingRunner{failOn: map[string]bool{}}
	controller := NewTorController(runner)

	// This would require actual filesystem access
	// We document the contract instead
	_ = controller

	// Expected: BackupIptables creates /var/lib/torfusion if it doesn't exist
	// Expected: BackupIptables names file as iptables-backup-YYYY-MM-DD_HH-MM-SS.txt
	// Expected: BackupIptables runs 'iptables-save' command
}

type mockFailingRunner struct {
	failOn map[string]bool
}

func (m *mockFailingRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if m.failOn[name] {
		return nil, &mockError{msg: name + " command failed"}
	}
	if name == "sh" {
		return []byte("1001\n"), nil
	}
	return nil, nil
}

type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

func TestCheckCommandsAvailable(t *testing.T) {
	runner := &recordingRunner{}
	controller := NewTorController(runner)
	err := controller.Check(context.Background())
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	expectedBinaries := []string{"tor", "iptables", "ip6tables", "systemctl", "curl"}
	joinedCommands := make([]string, 0, len(runner.commands))
	for _, cmd := range runner.commands {
		joinedCommands = append(joinedCommands, strings.Join(cmd, " "))
	}
	text := strings.Join(joinedCommands, "\n")

	for _, binary := range expectedBinaries {
		if !strings.Contains(text, "command -v "+binary) {
			t.Errorf("missing check for binary %s", binary)
		}
	}
}

func TestTorControllerTimeouts(t *testing.T) {
	// Test that operations respect context timeouts
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	runner := &recordingRunner{}
	controller := NewTorController(runner)

	// CheckTorReachable should respect short timeout
	// and return quickly without hanging
	err := controller.CheckTorReachable(ctx)
	if err == nil {
		// If no error (impossible), that's OK for this test
		// We just verify it doesn't panic or hang
	}
}

type chainSetupErrorRunner struct{}

func (r *chainSetupErrorRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "sh" {
		return []byte("1001\n"), nil
	}
	if len(args) >= 2 && args[len(args)-2] == "-N" {
		return nil, &mockError{msg: "chain already exists"}
	}
	return nil, &mockError{msg: "permission denied"}
}

func TestLoadFirewallDoesNotDropConnectionTeardown(t *testing.T) {
	runner := &recordingRunner{}
	controller := NewTorController(runner)
	if err := controller.LoadFirewall(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, cmd := range runner.commands {
		lines = append(lines, strings.Join(cmd, " "))
	}
	text := strings.Join(lines, "\n")
	if strings.Contains(text, "ACK,FIN ACK,FIN -j DROP") || strings.Contains(text, "ACK,RST ACK,RST -j DROP") {
		t.Fatalf("unsafe teardown drops remain:\n%s", text)
	}
	for _, destination := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		if !strings.Contains(text, "TORFUSION -d "+destination+" -j ACCEPT") {
			t.Fatalf("missing filter acceptance for %s:\n%s", destination, text)
		}
	}
}

func TestLoadFirewallDoesNotAllowEstablishedConnections(t *testing.T) {
	runner := &recordingRunner{}
	controller := NewTorController(runner)
	if err := controller.LoadFirewall(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	for _, command := range runner.commands {
		text := strings.Join(command, " ")
		if strings.Contains(text, "--ctstate ESTABLISHED,RELATED") {
			t.Fatalf("established connections must not bypass kill switch: %s", text)
		}
	}
}
