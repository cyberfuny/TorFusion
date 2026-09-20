package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

const (
	transPort        = 9040
	dnsPort          = 5353
	controlPort      = 9051
	torChain         = "TORFUSION"
	natChain         = "TORFUSION_NAT"
	forwardChain     = "TORFUSION_FORWARD"
	natForwardChain  = "TORFUSION_NAT_FORWARD"
	torChain6        = "TORFUSION6"
	forwardChain6    = "TORFUSION_FORWARD6"
	backupDir        = "/var/lib/torfusion"
	backupFilename   = "iptables-backup.txt"
	daemonBinary     = "/usr/local/bin/torfusion"
	daemonConfig     = "/etc/torfusion/config.json"
	daemonUnit       = "/etc/systemd/system/torfusion.service"
	rotationAttempts = 3
	rotationSettle   = 5 * time.Second
)

const daemonService = `[Unit]
Description=TorFusion persistent Tor routing and IP rotation
After=network-online.target tor@default.service
Wants=network-online.target tor@default.service

[Service]
Type=simple
ExecStart=/usr/local/bin/torfusion --action daemon --config /etc/torfusion/config.json
Restart=on-failure
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`

type Config struct {
	IntervalSeconds int    `json:"interval_seconds" yaml:"interval_seconds"`
	IntervalMin     int    `json:"interval_min_seconds,omitempty" yaml:"interval_min_seconds,omitempty"`
	IntervalMax     int    `json:"interval_max_seconds,omitempty" yaml:"interval_max_seconds,omitempty"`
	Country         string `json:"country" yaml:"country"`
	KillSwitch      bool   `json:"kill_switch" yaml:"kill_switch"`
	Mode            string `json:"mode" yaml:"mode"`
	LogLines        int    `json:"log_lines" yaml:"log_lines"`
	ConfigPath      string `json:"-" yaml:"-"`
}

func defaultConfig() Config {
	return Config{IntervalSeconds: 0, Country: "auto", KillSwitch: true, Mode: "transparent", LogLines: 100}
}

func normalizeRotationConfig(cfg *Config) error {
	if cfg.IntervalSeconds < 0 || cfg.IntervalSeconds > 86400 {
		return errors.New("interval_seconds має бути від 0 до 86400")
	}
	if cfg.IntervalMin == 0 && cfg.IntervalMax == 0 {
		cfg.IntervalMin, cfg.IntervalMax = cfg.IntervalSeconds, cfg.IntervalSeconds
	}
	if cfg.IntervalMin < 0 || cfg.IntervalMax < 0 || cfg.IntervalMin > 86400 || cfg.IntervalMax > 86400 {
		return errors.New("інтервал ротації має бути від 0 до 86400 секунд")
	}
	if cfg.IntervalMin == 0 || cfg.IntervalMax == 0 {
		if cfg.IntervalMin != 0 || cfg.IntervalMax != 0 {
			return errors.New("мінімальний і максимальний інтервали мають бути задані разом")
		}
	} else if cfg.IntervalMin > cfg.IntervalMax {
		return errors.New("мінімальний інтервал не може бути більшим за максимальний")
	}
	if cfg.IntervalMin == cfg.IntervalMax {
		cfg.IntervalSeconds = cfg.IntervalMin
	} else {
		cfg.IntervalSeconds = 0
	}
	return nil
}

func parseDurationSeconds(value string) (int, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return 0, errors.New("порожній інтервал")
	}
	if !strings.ContainsAny(value, "smhd") {
		seconds, err := strconv.Atoi(value)
		if err != nil {
			return 0, errors.New("інтервал має бути числом або форматом 30s, 5m, 2h, 1d")
		}
		if seconds < 1 || seconds > 86400 {
			return 0, errors.New("інтервал має бути від 1 до 86400 секунд")
		}
		return seconds, nil
	}
	unit := value[len(value)-1]
	number, err := strconv.Atoi(value[:len(value)-1])
	if err != nil || number < 1 {
		return 0, errors.New("некоректний інтервал")
	}
	multiplier := map[byte]int{'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[unit]
	if multiplier == 0 || number > 86400/multiplier {
		return 0, errors.New("інтервал має бути від 1 до 86400 секунд")
	}
	return number * multiplier, nil
}

func parseRotationSpec(spec string) (min, max int, err error) {
	if strings.Contains(spec, "/") {
		return 0, 0, errors.New("кількість ротацій більше не налаштовується: ротація працює без обмеження")
	}
	interval := strings.Split(strings.TrimSpace(spec), "-")
	if len(interval) > 2 || interval[0] == "" {
		return 0, 0, errors.New("формат інтервалу: 5m або 30-120")
	}
	min, err = parseDurationSeconds(interval[0])
	if err != nil {
		return 0, 0, err
	}
	max = min
	if len(interval) == 2 {
		max, err = parseDurationSeconds(interval[1])
		if err != nil {
			return 0, 0, err
		}
		if min > max {
			return 0, 0, errors.New("початок діапазону не може бути більшим за кінець")
		}
	}
	return min, max, nil
}

func validateCountry(country string) error {
	if country == "auto" {
		return nil
	}
	if len(country) != 2 {
		return errors.New("country має бути auto або ISO-кодом із двох латинських літер")
	}
	for _, r := range country {
		if r < 'a' || r > 'z' {
			return errors.New("country має містити лише дві латинські літери")
		}
	}
	return nil
}

func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		cfg.ConfigPath = path
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("помилка читання конфігурації: %w", err)
	}
	cfg.ConfigPath = path
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &cfg)
	default:
		err = json.Unmarshal(data, &cfg)
	}
	if err != nil {
		return cfg, fmt.Errorf("помилка розбору конфігурації: %w", err)
	}
	if err := normalizeRotationConfig(&cfg); err != nil {
		return cfg, err
	}
	if cfg.Country == "" {
		cfg.Country = "auto"
	}
	cfg.Country = strings.ToLower(cfg.Country)
	if err := validateCountry(cfg.Country); err != nil {
		return cfg, err
	}
	if cfg.Mode == "" {
		cfg.Mode = "transparent"
	}
	if cfg.Mode != "transparent" && cfg.Mode != "proxy" {
		return cfg, errors.New("mode має бути transparent або proxy")
	}
	if cfg.LogLines < 1 || cfg.LogLines > 10000 {
		return cfg, errors.New("log_lines має бути від 1 до 10000")
	}
	cfg.ConfigPath = path
	return cfg, nil
}

func saveConfig(cfg Config) error {
	var data []byte
	var err error
	if strings.HasSuffix(strings.ToLower(cfg.ConfigPath), ".yaml") || strings.HasSuffix(strings.ToLower(cfg.ConfigPath), ".yml") {
		data, err = yaml.Marshal(cfg)
	} else {
		data, err = json.MarshalIndent(cfg, "", "  ")
	}
	if err != nil {
		return fmt.Errorf("помилка кодування конфігурації: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.ConfigPath), 0700); err != nil {
		return fmt.Errorf("помилка створення каталогу конфігурації: %w", err)
	}
	if err := os.WriteFile(cfg.ConfigPath, data, 0600); err != nil {
		return fmt.Errorf("помилка запису конфігурації: %w", err)
	}
	return nil
}

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type CommandRunner struct{}

func (CommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
		}
		return nil, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

type TorController struct {
	runner Runner
}

func NewTorController(r Runner) *TorController { return &TorController{runner: r} }

func (t *TorController) Check(ctx context.Context) error {
	for _, binary := range []string{"tor", "iptables", "ip6tables", "systemctl", "curl"} {
		if _, err := t.runner.Run(ctx, "sh", "-c", "command -v "+binary); err != nil {
			return fmt.Errorf("необхідна команда %q недоступна: %w", binary, err)
		}
	}
	return nil
}

func (t *TorController) CheckTorReachable(ctx context.Context) error {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:9050")
	if err != nil {
		return fmt.Errorf("Tor SOCKS5 (127.0.0.1:9050) не доступний: %w. Запустіть 'sudo systemctl start tor@default' перед увімкненням маршрутизації", err)
	}
	conn.Close()
	return nil
}

func (t *TorController) BackupIptables(ctx context.Context) (string, error) {
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", fmt.Errorf("не вдалося створити каталог резервної копії: %w", err)
	}
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("iptables-backup-%s.txt", timestamp))

	out, err := t.runner.Run(ctx, "iptables-save")
	if err != nil {
		return "", fmt.Errorf("помилка резервної копії iptables: %w", err)
	}

	if err := os.WriteFile(backupPath, out, 0600); err != nil {
		return "", fmt.Errorf("помилка запису резервної копії: %w", err)
	}
	ip6out, err := t.runner.Run(ctx, "ip6tables-save")
	if err != nil {
		return "", fmt.Errorf("помилка резервної копії ip6tables: %w", err)
	}
	file, err := os.OpenFile(backupPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return "", fmt.Errorf("помилка відкриття резервної копії для IPv6: %w", err)
	}
	defer file.Close()
	if _, err := file.WriteString("\n# TORFUSION IPv6\n"); err != nil {
		return "", fmt.Errorf("помилка запису заголовка IPv6 резервної копії: %w", err)
	}
	if _, err := file.Write(ip6out); err != nil {
		return "", fmt.Errorf("помилка запису IPv6 резервної копії: %w", err)
	}
	return backupPath, nil
}

func (t *TorController) ConfigureTor(ctx context.Context, country string) error {
	country = strings.ToLower(country)
	if err := validateCountry(country); err != nil {
		return fmt.Errorf("небезпечне значення country: %w", err)
	}
	content, err := os.ReadFile("/etc/tor/torrc")
	if err != nil {
		return fmt.Errorf("помилка читання /etc/tor/torrc: %w", err)
	}
	const begin = "# BEGIN TORFUSION MANAGED CONFIG"
	const end = "# END TORFUSION MANAGED CONFIG"
	raw := string(content)
	if start := strings.Index(raw, begin); start >= 0 {
		if stop := strings.Index(raw[start:], end); stop >= 0 {
			raw = raw[:start] + raw[start+stop+len(end):]
		}
	}
	block := "\n" + begin + "\nVirtualAddrNetwork 10.0.0.0/10\nAutomapHostsOnResolve 1\nTransPort 9040\nDNSPort 5353\nControlPort 9051\nCookieAuthentication 1\n"
	if country != "" && country != "auto" {
		block += "ExitNodes {" + strings.ToUpper(country) + "}\nStrictNodes 1\n"
	}
	block += end + "\n"
	if err := os.WriteFile("/etc/tor/torrc", []byte(strings.TrimRight(raw, "\n")+block), 0644); err != nil {
		return fmt.Errorf("помилка запису /etc/tor/torrc: %w", err)
	}
	return nil
}

func (t *TorController) Start(ctx context.Context, country, mode string, killSwitch bool) error {
	// Не перезапускаємо вже готовий Tor без потреби: systemd може заблокувати
	// часті старти, а робоче SOCKS-з'єднання не потрібно чіпати.
	ready := false
	if err := t.CheckTorReachable(ctx); err == nil {
		if _, ipErr := t.CurrentIP(ctx); ipErr == nil {
			ready = true
		}
	}

	if !ready {
		if err := t.ConfigureTor(ctx, country); err != nil {
			return err
		}
		if _, err := t.runner.Run(ctx, "tor", "--verify-config", "-f", "/etc/tor/torrc"); err != nil {
			return fmt.Errorf("конфігурація Tor не пройшла перевірку; firewall не змінювався: %w", err)
		}
		if _, err := t.runner.Run(ctx, "systemctl", "reset-failed", "tor@default"); err != nil {
			// reset-failed не є критичним, якщо systemd не використовує цей unit.
		}
		if _, err := t.runner.Run(ctx, "systemctl", "start", "tor@default"); err != nil {
			return fmt.Errorf("не вдалося запустити Tor; firewall не змінювався: %w", err)
		}
		deadline := time.Now().Add(15 * time.Second)
		for {
			if err := t.CheckTorReachable(ctx); err == nil {
				if _, ipErr := t.CurrentIP(ctx); ipErr == nil {
					ready = true
					break
				}
			}
			if time.Now().After(deadline) {
				return errors.New("Tor SOCKS5 відкритий, але проксі не готовий: firewall не змінювався")
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	if mode == "proxy" {
		return nil
	}

	_, err := t.BackupIptables(ctx)
	if err != nil {
		return fmt.Errorf("помилка резервної копії перед запуском: %w. Для відновлення запустіть: sudo ./restore.sh", err)
	}
	if err := t.LoadFirewall(ctx, killSwitch); err != nil {
		return err
	}
	return nil
}

func (t *TorController) LoadFirewall(ctx context.Context, killSwitch bool) error {
	uid, err := t.runner.Run(ctx, "sh", "-c", "id -u debian-tor 2>/dev/null || id -u tor")
	if err != nil {
		return fmt.Errorf("не вдалося визначити UID користувача Tor: %w", err)
	}
	torUID := strings.TrimSpace(string(uid))
	for _, chain := range []struct {
		table string
		name  string
	}{
		{"filter", torChain},
		{"filter", forwardChain},
		{"nat", natChain},
		{"nat", natForwardChain},
	} {
		if err := t.ensureChain(ctx, chain.table, chain.name); err != nil {
			return fmt.Errorf("не вдалося підготувати ланцюг %s: %w", chain.name, err)
		}
	}
	for _, jump := range []struct {
		table string
		base  string
		chain string
	}{
		{"filter", "OUTPUT", torChain},
		{"filter", "FORWARD", forwardChain},
		{"nat", "OUTPUT", natChain},
		{"nat", "PREROUTING", natForwardChain},
	} {
		if err := t.removeJumps(ctx, jump.table, jump.base, jump.chain); err != nil {
			return err
		}
	}
	for _, chain := range []struct {
		table string
		name  string
	}{
		{"filter", torChain},
		{"filter", forwardChain},
		{"nat", natChain},
		{"nat", natForwardChain},
	} {
		if _, err := t.runner.Run(ctx, "iptables", tableArgs(chain.table, "-F", chain.name)...); err != nil {
			return fmt.Errorf("не вдалося очистити ланцюг %s: %w", chain.name, err)
		}
	}
	rules := [][]string{
		{"-t", "nat", "-A", natChain, "-m", "owner", "--uid-owner", torUID, "-j", "RETURN"},
		{"-t", "nat", "-A", natChain, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(dnsPort)},
		{"-A", torChain, "-o", "lo", "-j", "ACCEPT"},
	}
	for _, network := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		rules = append(rules, []string{"-t", "nat", "-A", natChain, "-d", network, "-j", "RETURN"})
		rules = append(rules, []string{"-t", "nat", "-A", natForwardChain, "-d", network, "-j", "RETURN"})
	}
	rules = append(rules,
		[]string{"-t", "nat", "-A", natChain, "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", strconv.Itoa(transPort)},
		[]string{"-A", torChain, "-m", "owner", "--uid-owner", torUID, "-j", "ACCEPT"},
		[]string{"-A", torChain, "-d", "127.0.0.0/8", "-j", "ACCEPT"},
		[]string{"-A", torChain, "-d", "10.0.0.0/8", "-j", "ACCEPT"},
		[]string{"-A", torChain, "-d", "172.16.0.0/12", "-j", "ACCEPT"},
		[]string{"-A", torChain, "-d", "192.168.0.0/16", "-j", "ACCEPT"},
		[]string{"-t", "nat", "-I", "OUTPUT", "1", "-j", natChain},
		[]string{"-I", "OUTPUT", "1", "-j", torChain},
		[]string{"-t", "nat", "-A", natForwardChain, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(dnsPort)},
		[]string{"-A", forwardChain, "-d", "127.0.0.0/8", "-j", "ACCEPT"},
		[]string{"-A", forwardChain, "-d", "10.0.0.0/8", "-j", "ACCEPT"},
		[]string{"-A", forwardChain, "-d", "172.16.0.0/12", "-j", "ACCEPT"},
		[]string{"-A", forwardChain, "-d", "192.168.0.0/16", "-j", "ACCEPT"},
		[]string{"-t", "nat", "-A", natForwardChain, "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", strconv.Itoa(transPort)},
		[]string{"-t", "nat", "-I", "PREROUTING", "1", "-j", natForwardChain},
		[]string{"-I", "FORWARD", "1", "-j", forwardChain},
	)
	// Tor transparently supports TCP and DNS only. Reject unsupported external
	// UDP before the final policy so it can never leave the host directly.
	rules = append(rules,
		[]string{"-A", torChain, "-p", "udp", "-j", "REJECT"},
		[]string{"-A", forwardChain, "-p", "udp", "-j", "REJECT"},
	)
	if killSwitch {
		rules = append(rules, []string{"-A", torChain, "-j", "REJECT"})
		rules = append(rules, []string{"-A", forwardChain, "-j", "REJECT"})
	} else {
		rules = append(rules, []string{"-A", torChain, "-j", "RETURN"})
		rules = append(rules, []string{"-A", forwardChain, "-j", "RETURN"})
	}
	for _, rule := range rules {
		if _, err := t.runner.Run(ctx, "iptables", rule...); err != nil {
			_ = t.FlushFirewall(ctx)
			return fmt.Errorf("помилка застосування правила firewall %q: %w", strings.Join(rule, " "), err)
		}
	}
	if err := t.LoadIPv6Firewall(ctx, killSwitch); err != nil {
		_ = t.FlushFirewall(ctx)
		return err
	}
	return nil
}

func (t *TorController) LoadIPv6Firewall(ctx context.Context, killSwitch bool) error {
	for _, chain := range []string{torChain6, forwardChain6} {
		if err := t.ensureChainWith(ctx, "ip6tables", "", chain); err != nil {
			return fmt.Errorf("не вдалося підготувати IPv6 ланцюг %s: %w", chain, err)
		}
	}
	for _, jump := range []struct {
		base  string
		chain string
	}{
		{"OUTPUT", torChain6},
		{"FORWARD", forwardChain6},
	} {
		if err := t.removeJumpsWith(ctx, "ip6tables", "", jump.base, jump.chain); err != nil {
			return err
		}
	}
	for _, chain := range []string{torChain6, forwardChain6} {
		if _, err := t.runner.Run(ctx, "ip6tables", "-F", chain); err != nil {
			return fmt.Errorf("не вдалося очистити IPv6 ланцюг %s: %w", chain, err)
		}
	}

	rules := [][]string{
		{"-A", torChain6, "-o", "lo", "-j", "ACCEPT"},
		{"-A", torChain6, "-d", "::1/128", "-j", "ACCEPT"},
		{"-A", torChain6, "-d", "fc00::/7", "-j", "ACCEPT"},
		{"-A", torChain6, "-d", "fe80::/10", "-j", "ACCEPT"},
		{"-A", forwardChain6, "-d", "fc00::/7", "-j", "ACCEPT"},
		{"-A", forwardChain6, "-d", "fe80::/10", "-j", "ACCEPT"},
		{"-I", "OUTPUT", "1", "-j", torChain6},
		{"-I", "FORWARD", "1", "-j", forwardChain6},
	}
	if killSwitch {
		rules = append(rules,
			[]string{"-A", torChain6, "-j", "REJECT"},
			[]string{"-A", forwardChain6, "-j", "REJECT"},
		)
	} else {
		rules = append(rules,
			[]string{"-A", torChain6, "-j", "RETURN"},
			[]string{"-A", forwardChain6, "-j", "RETURN"},
		)
	}
	for _, rule := range rules {
		if _, err := t.runner.Run(ctx, "ip6tables", rule...); err != nil {
			return fmt.Errorf("помилка застосування правила IPv6 firewall %q: %w", strings.Join(rule, " "), err)
		}
	}
	return nil
}

func tableArgs(table string, args ...string) []string {
	if table == "nat" {
		return append([]string{"-t", "nat"}, args...)
	}
	return args
}

func (t *TorController) ensureChain(ctx context.Context, table, chain string) error {
	return t.ensureChainWith(ctx, "iptables", table, chain)
}

func (t *TorController) ensureChainWith(ctx context.Context, binary, table, chain string) error {
	if _, err := t.runner.Run(ctx, binary, tableArgs(table, "-N", chain)...); err == nil {
		return nil
	}
	if _, err := t.runner.Run(ctx, binary, tableArgs(table, "-F", chain)...); err != nil {
		return fmt.Errorf("створення та очищення не вдалися: %w", err)
	}
	return nil
}

func (t *TorController) removeJump(ctx context.Context, table, base, chain string) error {
	return t.removeJumpWith(ctx, "iptables", table, base, chain)
}

func (t *TorController) removeJumpWith(ctx context.Context, binary, table, base, chain string) error {
	if _, err := t.runner.Run(ctx, binary, tableArgs(table, "-D", base, "-j", chain)...); err != nil && !ignorableFirewallError(err) {
		return fmt.Errorf("не вдалося видалити старий jump %s -> %s: %w", base, chain, err)
	}
	return nil
}

func (t *TorController) removeJumps(ctx context.Context, table, base, chain string) error {
	return t.removeJumpsWith(ctx, "iptables", table, base, chain)
}

func (t *TorController) removeJumpsWith(ctx context.Context, binary, table, base, chain string) error {
	if err := t.removeJumpWith(ctx, binary, table, base, chain); err != nil {
		return err
	}
	// A previous run may have inserted the same managed jump more than once.
	// Remove all remaining copies before deleting the managed chain.
	script := `while "$0" -D "$1" -j "$2" 2>/dev/null; do :; done; rc=$?; [ "$rc" -eq 1 ] || exit "$rc"`
	args := []string{"-c", script, binary, base, chain}
	if table != "" {
		script = `while "$0" -t "$3" -D "$1" -j "$2" 2>/dev/null; do :; done; rc=$?; [ "$rc" -eq 1 ] || exit "$rc"`
		args = []string{"-c", script, binary, base, chain, table}
	}
	if _, err := t.runner.Run(ctx, "sh", args...); err != nil && !ignorableFirewallError(err) {
		return fmt.Errorf("не вдалося видалити дублікати jump %s -> %s: %w", base, chain, err)
	}
	return nil
}

func (t *TorController) FlushFirewall(ctx context.Context) error {
	for _, jump := range []struct {
		binary string
		table  string
		base   string
		chain  string
	}{
		{"iptables", "", "OUTPUT", torChain},
		{"iptables", "", "FORWARD", forwardChain},
		{"iptables", "nat", "OUTPUT", natChain},
		{"iptables", "nat", "PREROUTING", natForwardChain},
		{"ip6tables", "", "OUTPUT", torChain6},
		{"ip6tables", "", "FORWARD", forwardChain6},
	} {
		if err := t.removeJumpsWith(ctx, jump.binary, jump.table, jump.base, jump.chain); err != nil {
			return err
		}
	}
	commands := [][]string{
		{"iptables", "-F", torChain},
		{"iptables", "-F", forwardChain},
		{"iptables", "-t", "nat", "-F", natChain},
		{"iptables", "-t", "nat", "-F", natForwardChain},
		{"iptables", "-X", torChain},
		{"iptables", "-X", forwardChain},
		{"iptables", "-t", "nat", "-X", natChain},
		{"iptables", "-t", "nat", "-X", natForwardChain},
		{"ip6tables", "-D", "OUTPUT", "-j", torChain6},
		{"ip6tables", "-D", "FORWARD", "-j", forwardChain6},
		{"ip6tables", "-F", torChain6},
		{"ip6tables", "-F", forwardChain6},
		{"ip6tables", "-X", torChain6},
		{"ip6tables", "-X", forwardChain6},
	}
	for _, command := range commands {
		if _, err := t.runner.Run(ctx, command[0], command[1:]...); err != nil && !ignorableFirewallError(err) {
			return err
		}
	}
	return nil
}

func ignorableFirewallError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no chain") ||
		strings.Contains(message, "does not exist") ||
		strings.Contains(message, "bad rule") ||
		strings.Contains(message, "rule not found")
}

func (t *TorController) NewCircuit(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:9051", 5*time.Second)
	if err != nil {
		return fmt.Errorf("ControlPort Tor 9051 недоступний: %w. Перевірте ControlPort 9051 у /etc/tor/torrc і перезапустіть Tor один раз вручну", err)
	}
	defer conn.Close()
	auth := ""
	for _, path := range []string{"/run/tor/control.authcookie", "/var/lib/tor/control_auth_cookie"} {
		if cookie, readErr := os.ReadFile(path); readErr == nil {
			auth = fmt.Sprintf("%X", cookie)
			break
		}
	}
	if _, err = io.WriteString(conn, "AUTHENTICATE "+auth+"\r\n"); err != nil {
		return err
	}
	if !readTorOK(conn) {
		return errors.New("автентифікація в Tor не вдалася")
	}
	if _, err = io.WriteString(conn, "SIGNAL NEWNYM\r\n"); err != nil {
		return err
	}
	if !readTorOK(conn) {
		return errors.New("Tor відхилив SIGNAL NEWNYM")
	}
	return nil
}

func (t *TorController) RotateToDifferentIP(ctx context.Context, previousIP string) (string, error) {
	if previousIP == "" {
		var err error
		previousIP, err = t.CurrentIP(ctx)
		if err != nil {
			return "", fmt.Errorf("не вдалося визначити поточну IP перед ротацією: %w", err)
		}
	}
	for attempt := 1; attempt <= rotationAttempts; attempt++ {
		if err := t.NewCircuit(ctx); err != nil {
			return "", err
		}
		if err := waitForRotationSettle(ctx); err != nil {
			return "", err
		}

		ip, err := t.CurrentIP(ctx)
		if err != nil {
			if attempt == rotationAttempts {
				return "", fmt.Errorf("не вдалося перевірити IP після ротації: %w", err)
			}
			continue
		}
		if ip != previousIP {
			return ip, nil
		}
	}

	return "", fmt.Errorf("Tor не змінив IP після %d спроб", rotationAttempts)
}

func waitForRotationSettle(ctx context.Context) error {
	timer := time.NewTimer(rotationSettle)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (t *TorController) Status(ctx context.Context) (string, error) {
	out, err := t.runner.Run(ctx, "systemctl", "is-active", "tor@default")
	if err != nil {
		return strings.TrimSpace(string(out)), err
	}
	return strings.TrimSpace(string(out)), nil
}

func (t *TorController) Logs(ctx context.Context, lines int) (string, error) {
	out, err := t.runner.Run(ctx, "journalctl", "-u", "tor@default", "-n", strconv.Itoa(lines), "--no-pager")
	return string(out), err
}

func (t *TorController) DNSLeakTest(ctx context.Context) (string, error) {
	out, err := t.runner.Run(ctx, "curl", "--socks5-hostname", "127.0.0.1:9050", "--max-time", "15",
		"https://1.1.1.1/cdn-cgi/trace")
	if err != nil {
		return "", fmt.Errorf("помилка запиту тесту DNS-витоку: %w", err)
	}
	return string(out), nil
}

func readTorOK(conn net.Conn) bool {
	line, err := bufio.NewReader(conn).ReadString('\n')
	return err == nil && strings.HasPrefix(line, "250")
}

func (t *TorController) CurrentIP(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://check.torproject.org/api/ip", nil)
	if err != nil {
		return "", err
	}
	req.Close = true
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		return "", fmt.Errorf("помилка створення Tor SOCKS5 dialer: %w", err)
	}
	httpTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.Dial(network, address)
		},
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second, Transport: httpTransport}).Do(req)
	if err != nil {
		return "", fmt.Errorf("помилка перевірки IP через Tor: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("помилка перевірки IP через Tor: HTTP %s", resp.Status)
	}
	var payload struct {
		IP string `json:"IP"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.IP == "" {
		return "", errors.New("API Tor повернув порожню IP-адресу")
	}
	return payload.IP, nil
}

type item struct{ title, desc string }

func (i item) FilterValue() string { return i.title }
func (i item) Title() string       { return i.title }
func (i item) Description() string { return i.desc }

type model struct {
	items          []item
	controller     *TorController
	config         Config
	status         string
	ip             string
	active         bool
	busy           bool
	operations     int
	busyLabel      string
	spinnerFrame   int
	selected       int
	intervalPicker bool
	intervalIndex  int
	customInterval bool
	intervalInput  textinput.Model
	width          int
	height         int
	ctx            context.Context
	cancel         context.CancelFunc
}

var rotationIntervals = []int{0, 30, 60, 300, 900, -1}

func nextRotationInterval(current int) int {
	if current <= 0 {
		return 60
	}
	for i, value := range rotationIntervals {
		if value == current {
			if i+1 < len(rotationIntervals) {
				return rotationIntervals[i+1]
			}
			return rotationIntervals[0]
		}
	}
	for _, value := range rotationIntervals {
		if value > current {
			return value
		}
	}
	return 60
}

func rotationLabel(seconds int) string {
	if seconds <= 0 {
		if seconds < 0 {
			return "кастомне"
		}
		return "вимкнено"
	}
	if seconds%60 == 0 {
		return fmt.Sprintf("%dm", seconds/60)
	}
	return fmt.Sprintf("%ds", seconds)
}

func rotationSpec(cfg Config) string {
	if cfg.IntervalMin == 0 && cfg.IntervalMax == 0 {
		return "вимкнено"
	}
	label := rotationLabel(cfg.IntervalMin)
	if cfg.IntervalMin != cfg.IntervalMax {
		label += "–" + rotationLabel(cfg.IntervalMax)
	}
	return label
}

func bootLogo() string {
	return "◈ TORFUSION // ONION NETWORK CONTROL ◈"
}

func intervalIndex(seconds int) int {
	for i, value := range rotationIntervals {
		if value == seconds || (value == -1 && seconds > 0 && seconds != 30 && seconds != 60 && seconds != 300 && seconds != 900) {
			return i
		}
	}
	return 0
}

func (m *model) updateIntervalDescription() {
	if len(m.items) < 4 {
		return
	}
	m.items[3] = item{"Авто-ротація IP", fmt.Sprintf("Поточний режим: %s — Enter для вибору", rotationSpec(m.config))}
}

type resultMsg struct {
	status, ip string
	active     *bool
}
type tickMsg time.Time
type progressMsg struct{}

func newModel(cfg Config, controller *TorController) model {
	items := []item{
		item{"Увімкнути прозору маршрутизацію Tor", "Автоматично встановити фоновий режим, запустити Tor і завантажити правила iptables"},
		item{"Зупинити маршрутизацію / очистити правила", "Видалити правила TorFusion і вимкнути kill-switch"},
		item{"Змінити Tor-ланцюжок", "Запросити новий Tor-ланцюжок та оновити зовнішню IP-адресу"},
		item{"Авто-ротація IP", fmt.Sprintf("Поточний режим: %s — Enter для вибору", rotationSpec(cfg))},
		item{"Оновити статус", "Перевірити поточну IP-адресу вихідної ноди Tor"},
		item{"Перевірити DNS-витік", "Виконати DNS-запит через Tor SOCKS"},
		item{"Показати статус служби Tor", "Прочитати стан служби Tor через systemd"},
		item{"Показати журнали Tor", "Показати останні записи журналу Tor"},
		item{"Зберегти конфігурацію", "Зберегти країну, інтервал і параметри kill-switch"},
		item{"Увімкнути фоновий режим", "Запустити TorFusion як systemd-сервіс після виходу з TUI та перезавантаження"},
		item{"Вимкнути фоновий режим", "Зупинити фоновий сервіс, очистити правила та вимкнути автозапуск"},
	}
	input := textinput.New()
	input.Prompt = "Ротація: "
	input.CharLimit = 24
	input.Width = 20
	return model{items: items, controller: controller, config: cfg, status: "Готово", intervalIndex: intervalIndex(cfg.IntervalSeconds), intervalInput: input, ctx: context.Background()}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if key.Matches(msg, key.NewBinding(key.WithKeys("q", "ctrl+c"))) {
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		}
		if m.customInterval {
			switch msg.String() {
			case "esc":
				m.customInterval = false
				m.intervalPicker = true
				return m, clearScreenCmd()
			case "enter":
				min, max, err := parseRotationSpec(m.intervalInput.Value())
				if err != nil {
					m.status = "Налаштування ротації: " + err.Error()
					return m, nil
				}
				m.config.IntervalMin, m.config.IntervalMax = min, max
				m.config.IntervalSeconds = 0
				if min == max {
					m.config.IntervalSeconds = min
				}
				m.customInterval = false
				m.intervalPicker = false
				m.updateIntervalDescription()
				if err := saveConfig(m.config); err != nil {
					m.status = "Помилка збереження інтервалу: " + err.Error()
					return m, nil
				}
				m.status = "Ротація: " + rotationSpec(m.config)
				return m, tea.Batch(m.rotationTick(), clearScreenCmd())
			}
			var cmd tea.Cmd
			m.intervalInput, cmd = m.intervalInput.Update(msg)
			return m, cmd
		}
		if m.intervalPicker {
			switch msg.String() {
			case "up", "k":
				if m.intervalIndex > 0 {
					m.intervalIndex--
				}
				return m, nil
			case "down", "j":
				if m.intervalIndex < len(rotationIntervals)-1 {
					m.intervalIndex++
				}
				return m, nil
			case "enter":
				if rotationIntervals[m.intervalIndex] == -1 {
					m.customInterval = true
					m.intervalPicker = false
					m.intervalInput.SetValue("")
					m.intervalInput.Focus()
					return m, tea.Batch(textinput.Blink, clearScreenCmd())
				}
				m.config.IntervalSeconds = rotationIntervals[m.intervalIndex]
				m.config.IntervalMin = m.config.IntervalSeconds
				m.config.IntervalMax = m.config.IntervalSeconds
				m.intervalPicker = false
				m.updateIntervalDescription()
				if err := saveConfig(m.config); err != nil {
					m.status = "Помилка збереження інтервалу: " + err.Error()
					return m, nil
				}
				m.status = "Ротація: " + rotationSpec(m.config)
				return m, tea.Batch(m.rotationTick(), clearScreenCmd())
			case "esc", "i":
				m.intervalPicker = false
				return m, clearScreenCmd()
			}
			return m, nil
		}
		switch msg.String() {
		case "up", "k":
			if m.selected > 0 {
				m.selected--
			}
			return m, nil
		case "down", "j":
			if m.selected < len(m.items)-1 {
				m.selected++
			}
			return m, nil
		}
		switch msg.String() {
		case "i":
			m.intervalPicker = true
			m.intervalIndex = intervalIndex(m.config.IntervalSeconds)
			return m, clearScreenCmd()
		case "r":
			return m.beginExecute(2)
		case "enter":
			if m.selected == 3 {
				m.intervalPicker = true
				m.intervalIndex = intervalIndex(m.config.IntervalSeconds)
				return m, clearScreenCmd()
			}
			return m.beginExecute(m.selected)
		}
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case resultMsg:
		if m.operations > 0 {
			m.operations--
		}
		m.busy = m.operations > 0
		if !m.busy {
			m.busyLabel = ""
		}
		m.status, m.ip = msg.status, msg.ip
		if msg.active != nil {
			m.active = *msg.active
			if m.active {
				return m, m.rotationTick()
			}
		}
		return m, nil

	case tickMsg:
		if m.config.IntervalMin > 0 && m.active {
			nextTick := m.rotationTick()
			nextModel, execute := m.beginExecute(2)
			return nextModel, tea.Batch(nextTick, execute)
		}
	case progressMsg:
		if m.busy {
			m.spinnerFrame = (m.spinnerFrame + 1) % len(progressFrames)
			return m, m.progressTick()
		}
	}
	return m, nil
}

var progressFrames = []string{"|", "/", "-", "\\"}

func clearScreenCmd() tea.Cmd {
	return func() tea.Msg {
		return tea.ClearScreen()
	}
}

func (m model) beginExecute(index int) (tea.Model, tea.Cmd) {
	m.operations++
	m.busy = true
	m.spinnerFrame = 0
	m.busyLabel = actionLabel(index)
	m.status = "Виконується"
	return m, tea.Batch(m.execute(index), m.progressTick())
}

func (m model) progressTick() tea.Cmd {
	if !m.busy {
		return nil
	}
	return tea.Tick(250*time.Millisecond, func(time.Time) tea.Msg {
		return progressMsg{}
	})
}

func actionLabel(index int) string {
	switch index {
	case 0:
		return "запуск маршрутизації"
	case 1:
		return "очищення правил"
	case 2:
		return "зміна Tor-ланцюжка"
	case 4:
		return "перевірка статусу"
	case 5:
		return "перевірка DNS"
	case 6:
		return "отримання статусу Tor"
	case 7:
		return "читання журналу Tor"
	case 8:
		return "збереження конфігурації"
	case 9:
		return "увімкнення фонового режиму"
	case 10:
		return "вимкнення фонового режиму"
	default:
		return "виконання команди"
	}
}

func (m model) rotationTick() tea.Cmd {
	if m.active && m.config.IntervalMin > 0 {
		return tea.Tick(time.Duration(nextRotationDelay(m.config))*time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		})
	}
	return nil
}

func (m model) execute(index int) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		switch index {
		case 0:
			if os.Geteuid() != 0 {
				return resultMsg{status: "Помилка запуску: TUI потрібно запускати через sudo"}
			}
			if err := installDaemon(m.config.ConfigPath, m.config); err != nil {
				active := false
				return resultMsg{status: "Помилка автоматичного запуску: " + err.Error(), active: &active}
			}
			active := true
			ip, err := m.controller.CurrentIP(ctx)
			if err != nil {
				return resultMsg{status: "Фоновий режим і маршрутизацію увімкнено; помилка перевірки IP: " + err.Error(), active: &active}
			}
			return resultMsg{status: "Tor і фоновий режим увімкнено автоматично", ip: ip, active: &active}
		case 1:
			if os.Geteuid() != 0 {
				return resultMsg{status: "Помилка зупинки: TUI потрібно запускати через sudo"}
			}
			if err := m.controller.FlushFirewall(ctx); err != nil {
				return resultMsg{status: "Помилка зупинки: " + err.Error()}
			}
			active := false
			return resultMsg{status: "Правила firewall очищено", active: &active}
		case 2:
			ip, err := m.controller.RotateToDifferentIP(ctx, m.ip)
			if err != nil {
				return resultMsg{status: "Помилка зміни ланцюжка: " + err.Error()}
			}
			return resultMsg{status: "Новий Tor-ланцюжок активний", ip: ip}
		case 3:
			m.config.IntervalSeconds = nextRotationInterval(m.config.IntervalSeconds)
			m.config.IntervalMin = m.config.IntervalSeconds
			m.config.IntervalMax = m.config.IntervalSeconds
			if err := saveConfig(m.config); err != nil {
				return resultMsg{status: "Помилка збереження інтервалу: " + err.Error()}
			}
			return resultMsg{status: "Авто-ротація увімкнена: " + rotationLabel(m.config.IntervalSeconds)}
		case 4:
			ip, err := m.controller.CurrentIP(ctx)
			if err != nil {
				return resultMsg{status: "Помилка перевірки статусу: " + err.Error()}
			}
			return resultMsg{status: "API Tor доступний", ip: ip}
		case 5:
			result, err := m.controller.DNSLeakTest(ctx)
			if err != nil {
				return resultMsg{status: "Помилка DNS-тесту: " + err.Error()}
			}
			return resultMsg{status: "DNS-тест завершено: " + strings.TrimSpace(strings.ReplaceAll(result, "\n", " | "))}
		case 6:
			status, err := m.controller.Status(ctx)
			if err != nil {
				return resultMsg{status: "Статус Tor: " + status + ": " + err.Error()}
			}
			return resultMsg{status: "Служба Tor: " + status}
		case 7:
			logs, err := m.controller.Logs(ctx, m.config.LogLines)
			if err != nil {
				return resultMsg{status: "Помилка журналу Tor: " + err.Error()}
			}
			lines := strings.Split(strings.TrimSpace(logs), "\n")
			if len(lines) > 0 {
				return resultMsg{status: "Tor: " + lines[len(lines)-1]}
			}
			return resultMsg{status: "Журнал Tor порожній"}
		case 8:
			if err := saveConfig(m.config); err != nil {
				return resultMsg{status: "Помилка збереження конфігурації: " + err.Error()}
			}
			return resultMsg{status: "Конфігурацію збережено у " + m.config.ConfigPath}
		case 9:
			if err := saveConfig(m.config); err != nil {
				return resultMsg{status: "Помилка збереження конфігурації: " + err.Error()}
			}
			if err := installDaemon(m.config.ConfigPath, m.config); err != nil {
				return resultMsg{status: "Помилка фонового режиму: " + err.Error()}
			}
			return resultMsg{status: "Фоновий режим увімкнено; TUI можна закрити"}
		case 10:
			if err := uninstallDaemon(m.controller); err != nil {
				return resultMsg{status: "Помилка вимкнення фонового режиму: " + err.Error()}
			}
			active := false
			return resultMsg{status: "Фоновий режим вимкнено, правила очищено", active: &active}
		}
		return resultMsg{status: "Невідома дія"}
	}
}

func (m model) View() string {
	statusStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("229"))
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D4698"))
	width := m.width
	if width <= 0 {
		width = 80
	}
	state := "ВИМК."
	if m.active {
		state = "УВІМК."
	}
	displayStatus := m.status
	if m.busy {
		displayStatus = fmt.Sprintf("Виконується %s %s", progressFrames[m.spinnerFrame], m.busyLabel)
	}
	status := truncateLine("Статус: "+displayStatus, width)
	info := truncateLine(fmt.Sprintf("Маршрутизація: %s | Режим: %s | Країна: %s | IP: %s | Авто-ротація: %s", state, m.config.Mode, m.config.Country, valueOr(m.ip, "невідомо"), rotationSpec(m.config)), width)
	navigation := truncateLine("↑/↓: навігація • Enter: виконати • i: інтервал • r: новий IP • q: вихід", width)
	parts := []string{
		titleStyle.Render(bootLogo()),
	}
	if m.intervalPicker || m.customInterval {
		if m.customInterval {
			parts = append(parts, statusStyle.Render("НАЛАШТУВАННЯ КАСТОМНОГО ІНТЕРВАЛУ"))
		} else {
			parts = append(parts, statusStyle.Render(intervalPickerView(m.intervalIndex)))
		}
	}
	if m.customInterval {
		input := lipgloss.NewStyle().
			Foreground(lipgloss.Color("229")).
			Render("Формат: 5m, 30-120 або 30s-2m\nРотація працює без обмеження кількості\n" + m.intervalInput.View() + "\nEnter: зберегти • Esc: назад")
		parts = append(parts, input)
	} else if !m.intervalPicker {
		parts = append(parts, m.menuView(width))
	}
	parts = append(parts, statusStyle.Render(status), statusStyle.Render(info), statusStyle.Render(navigation))
	return strings.Join(parts, "\n")
}

func (m model) menuView(width int) string {
	selectedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#7D4698"))
	normalStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	items := m.items
	lines := make([]string, 0, len(items))
	for index, menuItem := range items {
		cursor := fmt.Sprintf("%2d. ", index+1)
		style := normalStyle
		if index == m.selected {
			cursor = fmt.Sprintf("▸ %2d. ", index+1)
			style = selectedStyle
		}
		lines = append(lines, style.Render(truncateLine(cursor+menuItem.title, width)))
	}
	return strings.Join(lines, "\n")
}

func truncateLine(value string, width int) string {
	if width < 1 {
		return ""
	}
	return ansi.Truncate(value, width, "…")
}

func (m model) listHeight() int {
	height := m.height
	if height <= 0 {
		height = 24
	}
	reserved := 4
	if m.intervalPicker {
		reserved += len(rotationIntervals) + 6
	}
	if m.customInterval {
		reserved += 5
	}
	if available := height - reserved; available > 4 {
		if itemCount := len(m.items); available >= itemCount {
			return itemCount
		}
		return available
	}
	return 4
}

func intervalPickerView(selected int) string {
	lines := []string{"ВИБЕРИ ІНТЕРВАЛ АВТО-РОТАЦІЇ", ""}
	for i, seconds := range rotationIntervals {
		cursor := "  "
		if i == selected {
			cursor = "➜ "
		}
		lines = append(lines, cursor+rotationLabel(seconds))
	}
	lines = append(lines, "", "↑/↓ або j/k: переміщення • Enter: зберегти • Esc: скасувати")
	return strings.Join(lines, "\n")
}
func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func nextRotationDelay(cfg Config) int {
	if cfg.IntervalMin <= 0 {
		return 0
	}
	if cfg.IntervalMin == cfg.IntervalMax {
		return cfg.IntervalMin
	}
	return cfg.IntervalMin + rand.Intn(cfg.IntervalMax-cfg.IntervalMin+1)
}

func runDaemon(ctx context.Context, controller *TorController, cfg Config) error {
	startCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := controller.Start(startCtx, cfg.Country, cfg.Mode, cfg.KillSwitch); err != nil {
		return fmt.Errorf("daemon не вдалося запустити маршрутизацію: %w", err)
	}
	if cfg.IntervalMin <= 0 {
		fmt.Fprintln(os.Stdout, "TorFusion daemon запущено; авто-ротація вимкнена")
		<-ctx.Done()
		if cfg.Mode != "proxy" {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer stopCancel()
			if err := controller.FlushFirewall(stopCtx); err != nil {
				return fmt.Errorf("daemon не зміг очистити firewall: %w", err)
			}
		}
		return nil
	}
	fmt.Fprintf(os.Stdout, "TorFusion daemon запущено; ротація: %s\n", rotationSpec(cfg))
	currentIP, err := controller.CurrentIP(ctx)
	if err != nil {
		return fmt.Errorf("daemon не зміг перевірити початкову IP: %w", err)
	}
	nextRotationAt := time.Now().Add(time.Duration(nextRotationDelay(cfg)) * time.Second)
	timer := time.NewTimer(time.Until(nextRotationAt))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer stopCancel()
			if cfg.Mode != "proxy" {
				if err := controller.FlushFirewall(stopCtx); err != nil {
					return fmt.Errorf("daemon не зміг очистити firewall: %w", err)
				}
			}
			return nil
		case <-timer.C:
			rotateCtx, rotateCancel := context.WithTimeout(ctx, 60*time.Second)
			nextIP, err := controller.RotateToDifferentIP(rotateCtx, currentIP)
			rotateCancel()
			if err != nil {
				fmt.Fprintf(os.Stderr, "помилка автоматичної ротації: %v\n", err)
			} else {
				currentIP = nextIP
				fmt.Fprintln(os.Stdout, "TorFusion daemon: IP-ланцюжок змінено")
			}
			nextRotationAt = nextRotationAt.Add(time.Duration(nextRotationDelay(cfg)) * time.Second)
			timer.Reset(time.Until(nextRotationAt))
		}
	}
}

func runSystemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := (CommandRunner{}).Run(ctx, "systemctl", args...); err != nil {
		return err
	}
	return nil
}

func installDaemon(configPath string, cfg Config) error {
	if os.Geteuid() != 0 {
		return errors.New("--install потребує прав root; запусти через sudo")
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("не вдалося визначити шлях до бінарника: %w", err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		return fmt.Errorf("не вдалося прочитати бінарник: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(daemonConfig), 0700); err != nil {
		return fmt.Errorf("не вдалося створити каталог конфігурації: %w", err)
	}
	if err := installBinaryAtomically(daemonBinary, binary); err != nil {
		return fmt.Errorf("не вдалося встановити бінарник: %w", err)
	}
	if err := saveConfigToPath(cfg, daemonConfig); err != nil {
		return err
	}
	if err := os.WriteFile(daemonUnit, []byte(daemonService), 0644); err != nil {
		return fmt.Errorf("не вдалося встановити systemd-сервіс: %w", err)
	}
	if err := runSystemctl("daemon-reload"); err != nil {
		return fmt.Errorf("не вдалося оновити systemd: %w", err)
	}
	if err := runSystemctl("enable", "torfusion.service"); err != nil {
		return fmt.Errorf("не вдалося увімкнути автозапуск: %w", err)
	}
	if err := runSystemctl("restart", "torfusion.service"); err != nil {
		return fmt.Errorf("не вдалося перезапустити фоновий режим: %w", err)
	}
	return nil
}

func installBinaryAtomically(path string, binary []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".torfusion-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	cleanup := func(closeErr error) error {
		if closeErr != nil {
			_ = tmp.Close()
			return closeErr
		}
		return nil
	}
	if _, err := tmp.Write(binary); err != nil {
		return cleanup(err)
	}
	if err := tmp.Chmod(0755); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func saveConfigToPath(cfg Config, path string) error {
	originalPath := cfg.ConfigPath
	cfg.ConfigPath = path
	if err := saveConfig(cfg); err != nil {
		cfg.ConfigPath = originalPath
		return err
	}
	return nil
}

func uninstallDaemon(controller *TorController) error {
	if os.Geteuid() != 0 {
		return errors.New("--uninstall потребує прав root; запусти через sudo")
	}
	if err := runSystemctl("disable", "--now", "torfusion.service"); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "not loaded") {
			return fmt.Errorf("не вдалося зупинити фоновий режим: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := controller.FlushFirewall(ctx); err != nil {
		return fmt.Errorf("не вдалося очистити правила TorFusion: %w", err)
	}
	for _, path := range []string{daemonUnit, daemonBinary, daemonConfig} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("не вдалося видалити %s: %w", path, err)
		}
	}
	if err := runSystemctl("daemon-reload"); err != nil {
		return fmt.Errorf("не вдалося оновити systemd після видалення: %w", err)
	}
	return nil
}

func main() {
	var (
		action    = flag.String("action", "", "неінтерактивна дія: start, stop, rotate, daemon, ip, status, dns, logs")
		country   = flag.String("country", "", "код країни вихідної ноди Tor, наприклад de")
		interval  = flag.Int("interval", -1, "інтервал ротації у секундах; 0 — вимкнено")
		config    = flag.String("config", "", "шлях до конфігурації")
		install   = flag.Bool("install", false, "встановити фоновий режим і автозапуск")
		uninstall = flag.Bool("uninstall", false, "видалити фоновий режим і очистити правила")
	)
	flag.Parse()
	configPath := filepath.Join(os.Getenv("HOME"), ".config", "torfusion", "config.json")
	if value := os.Getenv("TORFUSION_CONFIG"); value != "" {
		configPath = value
	}
	if *config != "" {
		configPath = *config
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *country != "" {
		cfg.Country = strings.ToLower(*country)
		if err := validateCountry(cfg.Country); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if *interval >= 0 {
		cfg.IntervalSeconds = *interval
		cfg.IntervalMin = *interval
		cfg.IntervalMax = *interval
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	controller := NewTorController(CommandRunner{})
	if *install && *uninstall {
		fmt.Fprintln(os.Stderr, "не можна одночасно використовувати --install і --uninstall")
		os.Exit(2)
	}
	if *install {
		if err := installDaemon(configPath, cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("TorFusion встановлено у фоновий режим")
		return
	}
	if *uninstall {
		if err := uninstallDaemon(controller); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("Фоновий режим TorFusion вимкнено, правила очищено")
		return
	}
	if *action != "" {
		if os.Geteuid() != 0 && (*action == "start" || *action == "stop" || *action == "daemon") {
			fmt.Fprintln(os.Stderr, "ця дія потребує прав root")
			os.Exit(2)
		}
		if *action == "daemon" {
			if err := runDaemon(ctx, controller, cfg); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
		actionCtx, actionCancel := context.WithTimeout(ctx, 60*time.Second)
		defer actionCancel()
		var actionErr error
		switch *action {
		case "start":
			actionErr = controller.Start(actionCtx, cfg.Country, cfg.Mode, cfg.KillSwitch)
		case "stop":
			actionErr = controller.FlushFirewall(actionCtx)
		case "rotate":
			actionErr = controller.NewCircuit(actionCtx)
		case "ip":
			var ip string
			ip, actionErr = controller.CurrentIP(actionCtx)
			fmt.Println(ip)
		case "status":
			var status string
			status, actionErr = controller.Status(actionCtx)
			fmt.Println(status)
		case "dns":
			var result string
			result, actionErr = controller.DNSLeakTest(actionCtx)
			fmt.Print(result)
		case "logs":
			var logs string
			logs, actionErr = controller.Logs(actionCtx, cfg.LogLines)
			fmt.Print(logs)
		default:
			actionErr = fmt.Errorf("unknown action %q", *action)
		}
		if actionErr != nil {
			fmt.Fprintln(os.Stderr, actionErr)
			os.Exit(1)
		}
		return
	}
	p := tea.NewProgram(newModel(cfg, controller), tea.WithAltScreen(), tea.WithContext(ctx))
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
