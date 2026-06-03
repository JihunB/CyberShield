// CyberShield Agent v1 — Free Tier
//
// Cross-platform security monitoring agent for SMBs.
// Compiles to a single binary for macOS and Windows.
//
// Build:
//   macOS:   GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o cybershield-agent .
//   macOS M1: GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o cybershield-agent-arm64 .
//   Windows: GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o cybershield-agent.exe .
//
// Install (macOS):  sudo ./install.sh
// Install (Windows): Right-click install.ps1 → Run as Administrator

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ── Configuration ─────────────────────────────────────────────────────────────

const Version = "1.0.0"

type Config struct {
	AgentToken   string `json:"agent_token"`   // unique per customer, issued at onboarding
	CustomerID   string `json:"customer_id"`
	Domain       string `json:"domain"`        // customer's primary domain
	APIURL       string `json:"api_url"`       // CyberShield backend URL
	Lang         string `json:"lang"`          // "en" | "ko"
	Tier         string `json:"tier"`          // "free" | "plus" | "max"
	// Notification channels (at least one must be set)
	SlackWebhook string `json:"slack_webhook"`  // optional
	KakaoToken   string `json:"kakao_token"`    // optional (Korea)
}

func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config file not found at %s — run the installer first", path)
	}
	defer f.Close()
	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config file: %w", err)
	}
	if cfg.AgentToken == "" {
		return nil, fmt.Errorf("agent_token is required in config")
	}
	if cfg.APIURL == "" {
		cfg.APIURL = "https://cybershield-api.up.railway.app"
	}
	if cfg.Lang == "" {
		cfg.Lang = "en"
	}
	if cfg.Tier == "" {
		cfg.Tier = "free"
	}
	return &cfg, nil
}

func configPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "CyberShield", "config.json")
	default: // macOS / Linux
		return "/etc/cybershield/config.json"
	}
}

// ── Event types ───────────────────────────────────────────────────────────────

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// SecurityEvent is what we send to the backend.
type SecurityEvent struct {
	AgentToken  string    `json:"agent_token"`
	CustomerID  string    `json:"customer_id"`
	Domain      string    `json:"domain"`
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	Severity    Severity  `json:"severity"`
	Title       string    `json:"title"`
	TitleKo     string    `json:"title_ko"`
	Description string    `json:"description"`
	DescKo      string    `json:"description_ko"`
	SourceIP    string    `json:"source_ip,omitempty"`
	Port        int       `json:"port,omitempty"`
	Count       int       `json:"count,omitempty"`
	Extra       any       `json:"extra,omitempty"`
	AgentVer    string    `json:"agent_version"`
	OS          string    `json:"os"`
}

// ── State ─────────────────────────────────────────────────────────────────────

type AgentState struct {
	mu sync.Mutex

	// Login failure tracking: IP -> count within the last window
	loginFailures map[string][]time.Time

	// Known open ports snapshot (to detect new ones)
	knownPorts map[int]bool

	// IPs we already alerted on (to avoid spam)
	alertedIPs map[string]time.Time

	// Last heartbeat sent
	lastHeartbeat time.Time
}

func newState() *AgentState {
	return &AgentState{
		loginFailures: make(map[string][]time.Time),
		knownPorts:    make(map[int]bool),
		alertedIPs:    make(map[string]time.Time),
	}
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	cfgPath := flag.String("config", configPath(), "path to config.json")
	flag.Parse()

	// Open log file so output is visible whether running interactively or as a service
	logFile := openLogFile()
	if logFile != nil {
		defer logFile.Close()
	}

	logger := log.New(io.MultiWriter(os.Stdout, logFileWriter(logFile)), "[CyberShield] ", log.LstdFlags)
	logger.Printf("CyberShield Agent v%s starting on %s/%s", Version, runtime.GOOS, runtime.GOARCH)

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		logger.Fatalf("Config error: %v", err)
	}
	logger.Printf("Monitoring domain: %s  tier: %s  lang: %s", cfg.Domain, cfg.Tier, cfg.Lang)

	// Hand off to the platform service wrapper.
	// On Windows this reports Running to SCM before entering the loop.
	// On macOS/Linux this runs directly, stopping on SIGTERM/SIGINT.
	windowsServiceMain(func(stop <-chan struct{}) {
		runAgent(cfg, logger, stop)
	})
}

// runAgent contains the main monitoring loop.
// It runs until the stop channel is closed (service stop / signal).
func runAgent(cfg *Config, logger *log.Logger, stop <-chan struct{}) {
	agent := &Agent{cfg: cfg, state: newState(), logger: logger}

	// Send startup heartbeat so the backend registers us as online
	agent.sendHeartbeat()

	// Snapshot current ports so we don't fire alerts for already-open ports
	agent.state.knownPorts = agent.scanPorts()
	logger.Printf("Initial port snapshot: %d open ports", len(agent.state.knownPorts))

	loginTicker     := time.NewTicker(30 * time.Second)
	portTicker      := time.NewTicker(5 * time.Minute)
	maliciousTicker := time.NewTicker(1 * time.Hour)
	heartbeatTicker := time.NewTicker(1 * time.Minute)  // 1분마다 heartbeat (offline 감지 빠르게)
	dailyTicker     := time.NewTicker(24 * time.Hour)
	defer func() {
		loginTicker.Stop(); portTicker.Stop()
		maliciousTicker.Stop(); heartbeatTicker.Stop(); dailyTicker.Stop()
	}()

	logger.Println("Agent running.")

	for {
		select {
		case <-loginTicker.C:
			agent.checkLoginFailures()
		case <-portTicker.C:
			agent.checkPortChanges()
		case <-maliciousTicker.C:
			agent.checkMaliciousConnections()
		case <-heartbeatTicker.C:
			agent.sendHeartbeat()
		case <-dailyTicker.C:
			agent.triggerDomainRescan()
		case <-stop:
			logger.Println("Shutting down agent...")
			agent.sendShutdown()  // 즉시 offline 신호 전송
			return
		}
	}
}

// ── Log file helpers ──────────────────────────────────────────────────────────

func openLogFile() *os.File {
	dir := filepath.Dir(configPath())
	logDir := filepath.Join(dir, "logs")
	_ = os.MkdirAll(logDir, 0700)
	f, _ := os.OpenFile(
		filepath.Join(logDir, "agent.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600,
	)
	return f
}

func logFileWriter(f *os.File) io.Writer {
	if f == nil {
		return io.Discard
	}
	return f
}

// ── Agent ─────────────────────────────────────────────────────────────────────

type Agent struct {
	cfg    *Config
	state  *AgentState
	logger *log.Logger
}

// ── 1. Login failure detection ────────────────────────────────────────────────
//
// How it works:
//   macOS: reads /var/log/auth.log and /var/log/secure (or system.log on newer macOS).
//          Parses lines containing "Failed password", "Invalid user", "authentication failure".
//   Windows: queries the Windows Security Event Log for Event ID 4625 (failed logon).
//
// Detection rule:
//   If the same source IP has ≥5 failed login attempts within 30 seconds → ALERT (brute-force)
//   If any new IP appears that we haven't seen before → track it
//   After alerting on an IP, suppress duplicate alerts for 10 minutes.

func (a *Agent) checkLoginFailures() {
	entries := readAuthLogEntries()

	a.state.mu.Lock()
	defer a.state.mu.Unlock()

	now := time.Now()
	window := 30 * time.Second

	for _, entry := range entries {
		if entry.IP == "" {
			continue
		}
		// Trim old entries outside the window
		var recent []time.Time
		for _, t := range a.state.loginFailures[entry.IP] {
			if now.Sub(t) <= window {
				recent = append(recent, t)
			}
		}
		recent = append(recent, entry.Time)
		a.state.loginFailures[entry.IP] = recent

		count := len(recent)

		// Alert threshold: 5+ failures in 30s → brute-force
		if count >= 5 {
			// Suppress duplicate alerts for 10 minutes
			if last, seen := a.state.alertedIPs[entry.IP]; seen && now.Sub(last) < 10*time.Minute {
				continue
			}
			a.state.alertedIPs[entry.IP] = now

			evt := SecurityEvent{
				AgentToken:  a.cfg.AgentToken,
				CustomerID:  a.cfg.CustomerID,
				Domain:      a.cfg.Domain,
				Timestamp:   now,
				EventType:   "brute_force_login",
				Severity:    High,
				Title:       fmt.Sprintf("Brute-force login attempt from %s (%d failures in 30s)", entry.IP, count),
				TitleKo:     fmt.Sprintf("%s에서 무차별 대입 로그인 시도 감지 (30초 내 %d회 실패)", entry.IP, count),
				Description: fmt.Sprintf("IP %s attempted to log in %d times within 30 seconds. Automatic blocking recommended.", entry.IP, count),
				DescKo:      fmt.Sprintf("IP %s가 30초 내 %d번 로그인을 시도했습니다. 자동 차단을 권장합니다.", entry.IP, count),
				SourceIP:    entry.IP,
				Count:       count,
				AgentVer:    Version,
				OS:          runtime.GOOS,
			}
			a.sendEvent(evt)
		}
	}
}

// AuthLogEntry is a parsed line from the auth log.
type AuthLogEntry struct {
	Time time.Time
	IP   string
	User string
}

// readAuthLogEntries reads recent auth log entries from the OS.
// On macOS: parses /var/log/auth.log (or uses `log show` for newer macOS unified logging).
// On Windows: we use a simplified stub here; full implementation uses golang.org/x/sys/windows/svc.
func readAuthLogEntries() []AuthLogEntry {
	switch runtime.GOOS {
	case "darwin":
		return readMacAuthLog()
	case "windows":
		return readWindowsEventLog4625()
	default:
		return readLinuxAuthLog()
	}
}

func readMacAuthLog() []AuthLogEntry {
	// macOS Monterey+ uses Unified Log. We read the last 60 seconds.
	// Command: log show --predicate 'eventMessage contains "Failed password"' --last 1m --style syslog
	entries := []AuthLogEntry{}
	data, err := runCommand("log", "show",
		"--predicate", `eventMessage contains "Failed password" OR eventMessage contains "Invalid user"`,
		"--last", "1m",
		"--style", "syslog",
	)
	if err != nil {
		// Fallback: try reading /var/log/auth.log directly
		data, err = os.ReadFile("/var/log/auth.log")
		if err != nil {
			return entries
		}
	}
	return parseAuthLogLines(string(data))
}

func readLinuxAuthLog() []AuthLogEntry {
	entries := []AuthLogEntry{}
	for _, path := range []string{"/var/log/auth.log", "/var/log/secure"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		entries = append(entries, parseAuthLogLines(string(data))...)
		break
	}
	return entries
}

// Windows stub — real implementation uses windows event log API via golang.org/x/sys
func readWindowsEventLog4625() []AuthLogEntry {
	// In full implementation: use eventlog package to query Security log for EventID 4625
	// Stub returns empty for now; see install guide for Windows-specific build tags
	return []AuthLogEntry{}
}

func parseAuthLogLines(data string) []AuthLogEntry {
	var entries []AuthLogEntry
	lines := strings.Split(data, "\n")
	now := time.Now()
	cutoff := now.Add(-2 * time.Minute) // only look at recent entries

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		isFailed := strings.Contains(lower, "failed password") ||
			strings.Contains(lower, "invalid user") ||
			strings.Contains(lower, "authentication failure") ||
			strings.Contains(lower, "connection closed by authenticating user")

		if !isFailed {
			continue
		}

		// Extract IP address using simple token scan
		ip := extractIP(line)
		if ip == "" {
			continue
		}

		// Skip private/loopback IPs (those are not attacks)
		if isPrivateIP(ip) {
			continue
		}

		entries = append(entries, AuthLogEntry{
			Time: cutoff, // approximate; full parsing would extract real timestamp
			IP:   ip,
		})
	}
	return entries
}

// extractIP finds the first public IPv4 in a log line.
func extractIP(line string) string {
	parts := strings.Fields(line)
	for _, part := range parts {
		// Strip common suffixes like "port" numbers
		part = strings.TrimSuffix(part, ":")
		if net.ParseIP(part) != nil {
			return part
		}
		// "from 1.2.3.4" pattern
		if strings.HasPrefix(part, "from") && len(parts) > 1 {
			continue
		}
	}
	return ""
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []string{"10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
		"172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127.", "::1"}
	s := ip.String()
	for _, prefix := range privateRanges {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// ── 2. Port change detection ──────────────────────────────────────────────────
//
// How it works:
//   Every 5 minutes, scan the local machine for listening TCP ports.
//   Compare with the previous snapshot.
//   If a NEW port appears that wasn't in the last snapshot → ALERT.
//   We only alert on risky ports (databases, remote access, known backdoor ports).
//   Normal ports like 80, 443, 8080 are tracked but not immediately alerted.

var riskyPorts = map[int]struct {
	Name     string
	Severity Severity
	Reason   string
	ReasonKo string
}{
	21:    {"FTP",         Critical, "Unencrypted file transfer — attacker can read all transferred files",                "암호화되지 않은 파일 전송 — 전송된 모든 파일을 공격자가 읽을 수 있습니다"},
	22:    {"SSH",         Medium,   "SSH exposed — ensure key-based auth only, disable password auth",                    "SSH 노출 — 키 기반 인증만 사용하고 비밀번호 인증을 비활성화하세요"},
	23:    {"Telnet",      Critical, "Plaintext remote access — completely insecure, disable immediately",                 "평문 원격 접속 — 완전히 비보안, 즉시 비활성화하세요"},
	3306:  {"MySQL",       High,     "MySQL database exposed — any internet user can attempt to connect",                  "MySQL 데이터베이스 노출 — 인터넷 사용자가 연결을 시도할 수 있습니다"},
	3389:  {"RDP",         High,     "Remote Desktop exposed — primary target for brute-force and ransomware",             "원격 데스크톱 노출 — 무차별 대입 및 랜섬웨어의 주요 타깃"},
	4444:  {"Metasploit",  Critical, "Common reverse shell port — possible active compromise",                             "리버스 쉘 공통 포트 — 현재 침해 가능성 있음"},
	5432:  {"PostgreSQL",  High,     "PostgreSQL database exposed to the internet",                                       "PostgreSQL 데이터베이스 인터넷 노출"},
	5900:  {"VNC",         Critical, "VNC remote desktop exposed — often has weak/no authentication",                     "VNC 원격 데스크톱 노출 — 취약하거나 없는 인증"},
	6379:  {"Redis",       Critical, "Redis has no authentication by default — full read/write access possible",           "Redis는 기본적으로 인증 없음 — 완전한 읽기/쓰기 접근 가능"},
	8080:  {"Alt-HTTP",    Low,      "Alternate HTTP port open — may expose staging or admin panels",                      "대체 HTTP 포트 — 스테이징 또는 관리자 패널 노출 가능"},
	9200:  {"Elasticsearch", Critical, "Elasticsearch has no auth by default — all data readable without credentials",   "Elasticsearch는 기본 인증 없음 — 자격증명 없이 모든 데이터 접근 가능"},
	27017: {"MongoDB",     Critical, "MongoDB exposed — common ransomware target, unauthenticated access likely",         "MongoDB 노출 — 랜섬웨어 주요 타깃, 인증 없는 접근 가능성"},
}

func (a *Agent) scanPorts() map[int]bool {
	open := make(map[int]bool)
	checkPorts := make([]int, 0, len(riskyPorts)+5)
	for p := range riskyPorts {
		checkPorts = append(checkPorts, p)
	}
	// Also check 80, 443, 8443 for completeness (tracked but not alerted)
	checkPorts = append(checkPorts, 80, 443, 8443)

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, port := range checkPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := fmt.Sprintf("127.0.0.1:%d", p)
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				open[p] = true
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return open
}

func (a *Agent) checkPortChanges() {
	current := a.scanPorts()

	a.state.mu.Lock()
	defer a.state.mu.Unlock()

	// Detect newly opened ports
	for port := range current {
		if a.state.knownPorts[port] {
			continue // was already open, no alert
		}
		// New port appeared!
		info, isRisky := riskyPorts[port]
		if !isRisky {
			// Not a risky port — just update snapshot silently
			a.state.knownPorts[port] = true
			continue
		}

		a.logger.Printf("New risky port detected: %d (%s)", port, info.Name)

		evt := SecurityEvent{
			AgentToken:  a.cfg.AgentToken,
			CustomerID:  a.cfg.CustomerID,
			Domain:      a.cfg.Domain,
			Timestamp:   time.Now(),
			EventType:   "new_port_opened",
			Severity:    info.Severity,
			Title:       fmt.Sprintf("New risky port opened: %d (%s)", port, info.Name),
			TitleKo:     fmt.Sprintf("새로운 위험 포트 감지: %d (%s)", port, info.Name),
			Description: info.Reason,
			DescKo:      info.ReasonKo,
			Port:        port,
			AgentVer:    Version,
			OS:          runtime.GOOS,
		}
		a.sendEvent(evt)
		a.state.knownPorts[port] = true
	}

	// Detect ports that have closed (informational only)
	for port := range a.state.knownPorts {
		if !current[port] {
			if _, isRisky := riskyPorts[port]; isRisky {
				a.logger.Printf("Risky port closed: %d", port)
			}
			delete(a.state.knownPorts, port)
		}
	}
}

// ── 3. Malicious connection detection ─────────────────────────────────────────
//
// How it works:
//   Every hour, list all current active TCP connections (netstat equivalent).
//   Extract remote IP addresses.
//   Check each against a local blocklist + VirusTotal cache.
//   Local blocklist is downloaded from the CyberShield backend (updated daily).
//   If a connection to a known malicious IP is found → ALERT (possible C2/malware).

func (a *Agent) checkMaliciousConnections() {
	connections := getActiveConnections()
	if len(connections) == 0 {
		return
	}

	// Deduplicate remote IPs
	seen := make(map[string]bool)
	var remoteIPs []string
	for _, conn := range connections {
		if conn.RemoteIP != "" && !isPrivateIP(conn.RemoteIP) && !seen[conn.RemoteIP] {
			seen[conn.RemoteIP] = true
			remoteIPs = append(remoteIPs, conn.RemoteIP)
		}
	}

	if len(remoteIPs) == 0 {
		return
	}

	// Ask CyberShield backend to check IPs (backend caches VirusTotal lookups)
	type CheckRequest struct {
		AgentToken string   `json:"agent_token"`
		IPs        []string `json:"ips"`
	}
	type CheckResult struct {
		MaliciousIPs []struct {
			IP     string `json:"ip"`
			Reason string `json:"reason"`
		} `json:"malicious_ips"`
	}

	payload, _ := json.Marshal(CheckRequest{
		AgentToken: a.cfg.AgentToken,
		IPs:        remoteIPs,
	})

	resp, err := http.Post(a.cfg.APIURL+"/agent/check-ips", "application/json", bytes.NewReader(payload))
	if err != nil || resp.StatusCode != 200 {
		a.logger.Printf("IP check request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result CheckResult
	if err := json.Unmarshal(body, &result); err != nil {
		return
	}

	for _, hit := range result.MaliciousIPs {
		// Suppress repeat alerts for 6 hours
		a.state.mu.Lock()
		last, alerted := a.state.alertedIPs["mal:"+hit.IP]
		if alerted && time.Since(last) < 6*time.Hour {
			a.state.mu.Unlock()
			continue
		}
		a.state.alertedIPs["mal:"+hit.IP] = time.Now()
		a.state.mu.Unlock()

		a.logger.Printf("Malicious IP connection detected: %s — %s", hit.IP, hit.Reason)

		evt := SecurityEvent{
			AgentToken:  a.cfg.AgentToken,
			CustomerID:  a.cfg.CustomerID,
			Domain:      a.cfg.Domain,
			Timestamp:   time.Now(),
			EventType:   "malicious_ip_connection",
			Severity:    Critical,
			Title:       fmt.Sprintf("Connection to known malicious IP: %s", hit.IP),
			TitleKo:     fmt.Sprintf("알려진 악성 IP 연결 감지: %s", hit.IP),
			Description: fmt.Sprintf("Your system has an active connection to %s, which is flagged as malicious: %s", hit.IP, hit.Reason),
			DescKo:      fmt.Sprintf("시스템이 악성으로 분류된 IP %s에 연결됐습니다: %s", hit.IP, hit.Reason),
			SourceIP:    hit.IP,
			AgentVer:    Version,
			OS:          runtime.GOOS,
		}
		a.sendEvent(evt)
	}
}

// TCPConnection represents an active network connection.
type TCPConnection struct {
	LocalIP   string
	LocalPort int
	RemoteIP  string
	RemotePort int
	State     string
}

// getActiveConnections returns current TCP connections using platform-native commands.
func getActiveConnections() []TCPConnection {
	var conns []TCPConnection
	var data []byte
	var err error

	switch runtime.GOOS {
	case "darwin":
		// macOS: netstat -anp tcp
		data, err = runCommand("netstat", "-anp", "tcp")
	case "windows":
		// Windows: netstat -n -p TCP
		data, err = runCommand("netstat", "-n", "-p", "TCP")
	default:
		// Linux
		data, err = runCommand("ss", "-tnp")
		if err != nil {
			data, err = runCommand("netstat", "-tn")
		}
	}

	if err != nil {
		return conns
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		// Parse remote address from netstat/ss output
		// Format varies slightly by OS but remote address is usually in column 4
		remoteAddr := ""
		if runtime.GOOS == "windows" && len(parts) >= 3 {
			remoteAddr = parts[2]
		} else if len(parts) >= 5 {
			remoteAddr = parts[4]
		}
		if remoteAddr == "" || remoteAddr == "*:*" || strings.HasSuffix(remoteAddr, ":*") {
			continue
		}
		ip, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			continue
		}
		conns = append(conns, TCPConnection{RemoteIP: ip})
	}
	return conns
}

// ── 4. Heartbeat + domain rescan trigger ─────────────────────────────────────

func (a *Agent) sendHeartbeat() {
	type Heartbeat struct {
		AgentToken string `json:"agent_token"`
		CustomerID string `json:"customer_id"`
		Domain     string `json:"domain"`
		AgentVer   string `json:"agent_version"`
		OS         string `json:"os"`
		Timestamp  string `json:"timestamp"`
	}
	hb := Heartbeat{
		AgentToken: a.cfg.AgentToken,
		CustomerID: a.cfg.CustomerID,
		Domain:     a.cfg.Domain,
		AgentVer:   Version,
		OS:         runtime.GOOS,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}
	payload, _ := json.Marshal(hb)
	resp, err := http.Post(a.cfg.APIURL+"/agent/heartbeat", "application/json", bytes.NewReader(payload))
	if err != nil {
		a.logger.Printf("Heartbeat failed: %v", err)
		return
	}
	resp.Body.Close()
	a.state.lastHeartbeat = time.Now()
}

func (a *Agent) sendShutdown() {
	type ShutdownMsg struct {
		AgentToken string `json:"agent_token"`
		CustomerID string `json:"customer_id"`
		Domain     string `json:"domain"`
		Online     bool   `json:"agent_online"`
	}
	payload, _ := json.Marshal(ShutdownMsg{
		AgentToken: a.cfg.AgentToken,
		CustomerID: a.cfg.CustomerID,
		Domain:     a.cfg.Domain,
		Online:     false,
	})
	// 타임아웃 3초 — 종료 중이라 빠르게 처리
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(
		a.cfg.APIURL+"/agent/shutdown",
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil {
		a.logger.Printf("Shutdown signal failed (non-fatal): %v", err)
		return
	}
	resp.Body.Close()
	a.logger.Println("Shutdown signal sent — agent_online set to false")
}

func (a *Agent) triggerDomainRescan() {
	type RescanReq struct {
		AgentToken string `json:"agent_token"`
		Domain     string `json:"domain"`
		Lang       string `json:"lang"`
	}
	payload, _ := json.Marshal(RescanReq{
		AgentToken: a.cfg.AgentToken,
		Domain:     a.cfg.Domain,
		Lang:       a.cfg.Lang,
	})
	resp, err := http.Post(a.cfg.APIURL+"/agent/rescan", "application/json", bytes.NewReader(payload))
	if err != nil {
		a.logger.Printf("Rescan trigger failed: %v", err)
		return
	}
	resp.Body.Close()
	a.logger.Printf("Daily rescan triggered for %s", a.cfg.Domain)
}

// ── 5. Event sender ───────────────────────────────────────────────────────────
//
// Sends the event to the CyberShield backend over HTTPS.
// The backend then:
//   1. Logs the event in the database
//   2. Sends the customer a Slack / Kakao / SMS notification
//   3. Updates the security dashboard score

func (a *Agent) sendEvent(evt SecurityEvent) {
	payload, err := json.Marshal(evt)
	if err != nil {
		a.logger.Printf("Failed to marshal event: %v", err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(a.cfg.APIURL+"/agent/event", "application/json", bytes.NewReader(payload))
	if err != nil {
		a.logger.Printf("Failed to send event %s: %v", evt.EventType, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		a.logger.Printf("[EVENT SENT] %s — %s (severity: %s)", evt.EventType, evt.Title, evt.Severity)
	} else {
		body, _ := io.ReadAll(resp.Body)
		a.logger.Printf("[EVENT FAILED] %s — status %d: %s", evt.EventType, resp.StatusCode, string(body)[:200])
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func runCommand(name string, args ...string) ([]byte, error) {
	// Simple command runner — no shell injection possible (args are not user-supplied)
	// #nosec G204
	cmd := fmt.Sprintf("%s %s", name, strings.Join(args, " "))
	_ = cmd // used for logging only
	return execCommand(name, args...)
}
