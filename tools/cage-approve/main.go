// cage-approve is a human approval broker, not an unattended admin service.
// UAC is an additional consent boundary, NOT an absolute security guarantee:
// compromised broker/operator code can deceive a person or misuse their consent.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maxCommandBytes = 4096
	maxReasonBytes  = 1024
	maxRequestBytes = 32 << 10 // accommodates JSON escapes, not a larger command
	maxOutputBytes  = 1 << 20
	notExecuted     = -1
)

type runRequest struct {
	Command string `json:"command"`
	Reason  string `json:"reason"`
}

type approval struct {
	Command string
	Reason  string
	Digest  string
}

type runResult struct {
	Executed bool
	ExitCode int
	Output   string
	Error    string
}

type runResponse struct {
	Approved bool   `json:"approved"`
	Executed bool   `json:"executed"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
	Digest   string `json:"command_sha256,omitempty"`
	Error    string `json:"error,omitempty"`
}

type broker struct {
	root        string
	token       string
	allowSource netip.Addr
	mu          sync.Mutex // TryLock: do not queue requests behind a human dialog
	prompt      func(approval) (bool, error)
	runner      func(approval) runResult
	verifyRoot  func() error
	audit       func(string) error
}

func commandDigest(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}

func validateVisible(name, value string, limit int, required bool) error {
	if len(value) > limit {
		return fmt.Errorf("%s exceeds %d UTF-8 bytes", name, limit)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	if required && strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is empty", name)
	}
	for _, r := range value {
		// Single-line fields only. In particular reject NUL, CR/LF, TAB,
		// bidi overrides/isolates, zero-width format controls and line separators.
		// U+FFFD is also rejected: encoding/json replaces invalid Unicode with it.
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) || r == utf8.RuneError {
			return fmt.Errorf("%s contains a control/format character U+%04X", name, r)
		}
	}
	return nil
}

func decodeRequest(w http.ResponseWriter, r *http.Request) (runRequest, error) {
	var req runRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return req, errors.New("expected a JSON object")
	}
	seen := make(map[string]bool, 2)
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return req, errors.New("bad JSON field")
		}
		name, ok := key.(string)
		if !ok || (name != "command" && name != "reason") || seen[name] {
			return req, errors.New("unknown or duplicate JSON field")
		}
		seen[name] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil || len(raw) == 0 || raw[0] != '"' {
			return req, errors.New("command and reason must be strings")
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return req, errors.New("invalid JSON string")
		}
		if name == "command" {
			req.Command = value
		} else {
			req.Reason = value
		}
	}
	if end, err := dec.Token(); err != nil || end != json.Delim('}') {
		return req, errors.New("bad JSON object")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return req, errors.New("unexpected trailing JSON")
	}
	if err := validateVisible("command", req.Command, maxCommandBytes, true); err != nil {
		return req, err
	}
	if err := validateVisible("reason", req.Reason, maxReasonBytes, false); err != nil {
		return req, err
	}
	return req, nil
}

func (b *broker) authorized(r *http.Request) bool {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || b.token == "" {
		return false
	}
	got := strings.TrimPrefix(values[0], "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(b.token)) == 1
}

func (b *broker) sourceAllowed(r *http.Request) bool {
	if !b.allowSource.IsValid() {
		return true // production configuration permits this only on loopback
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Zone() == "" && addr.Unmap() == b.allowSource.Unmap()
}

func (b *broker) access(w http.ResponseWriter, r *http.Request, method string) bool {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != method {
		w.Header().Set("Allow", method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	// Trust the transport peer only, never X-Forwarded-For or other headers.
	if !b.sourceAllowed(r) {
		http.Error(w, "source not allowed", http.StatusForbidden)
		return false
	}
	if !b.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "query parameters are not supported", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func (b *broker) handleRun(w http.ResponseWriter, r *http.Request) {
	if !b.access(w, r, http.MethodPost) {
		return
	}
	if !b.mu.TryLock() {
		http.Error(w, "approval broker busy; no request queued", http.StatusConflict)
		return
	}
	defer b.mu.Unlock()
	req, err := decodeRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if b.verifyRoot == nil || b.verifyRoot() != nil {
		http.Error(w, "broker storage is not protected; nothing executed", http.StatusServiceUnavailable)
		return
	}
	a := approval{Command: req.Command, Reason: req.Reason, Digest: commandDigest(req.Command)}
	response := runResponse{ExitCode: notExecuted, Digest: a.Digest}
	// Do not record bearer tokens, request bodies, reasons or command text.
	if b.audit == nil || b.audit("REQUEST sha256="+a.Digest) != nil {
		http.Error(w, "audit unavailable; nothing executed", http.StatusServiceUnavailable)
		return
	}
	approved, err := b.prompt(a)
	if err != nil {
		response.Error = "approval dialog failed; nothing executed"
		_ = b.audit("DIALOG_ERROR sha256=" + a.Digest)
		writeJSON(w, response)
		return
	}
	if !approved {
		response.Error = "human approval declined; nothing executed"
		_ = b.audit("DENIED sha256=" + a.Digest)
		writeJSON(w, response)
		return
	}
	response.Approved = true
	if r.Context().Err() != nil {
		response.Error = "request disconnected before execution"
		_ = b.audit("DISCONNECTED sha256=" + a.Digest)
		writeJSON(w, response)
		return
	}
	// Check again after the potentially long dialog. Nothing is launched if
	// storage protection has changed or the approval audit cannot be written.
	if b.verifyRoot() != nil || b.audit("APPROVED sha256="+a.Digest) != nil {
		response.Error = "storage or audit unavailable after approval; nothing executed"
		writeJSON(w, response)
		return
	}
	result := b.runner(a)
	response.Executed, response.ExitCode = result.Executed, result.ExitCode
	response.Output, response.Error = result.Output, result.Error
	// A launcher failure (including cancelled UAC) can never look successful.
	if !response.Executed && response.ExitCode == 0 {
		response.ExitCode = notExecuted
	}
	if err := b.audit(fmt.Sprintf("RESULT sha256=%s executed=%t exit=%d", a.Digest, response.Executed, response.ExitCode)); err != nil {
		if response.Error != "" {
			response.Error += "; "
		}
		response.Error += "result audit failed"
	}
	writeJSON(w, response)
}

func (b *broker) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !b.access(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (b *broker) handler() http.Handler {
	// Exact paths only: no redirect, debug, token or arbitrary file endpoints.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/run":
			b.handleRun(w, r)
		case "/health":
			b.handleHealth(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func loadOrCreateToken(root string) (string, error) {
	path := filepath.Join(root, "token")
	data, err := os.ReadFile(path)
	if err == nil {
		token := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
		decoded, decodeErr := hex.DecodeString(token)
		if decodeErr != nil || len(decoded) != 32 || len(token) != 64 {
			return "", errors.New("existing token is invalid; refusing automatic rotation")
		}
		return token, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read existing token: %w", err)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create token exclusively: %w", err)
	}
	_, writeErr := io.WriteString(f, token+"\n")
	closeErr := f.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return token, nil
}

func reviewChunks(value string) []string {
	const pageRunes = 512
	runes := []rune(value)
	var chunks []string
	for len(runes) > 0 {
		n := min(pageRunes, len(runes))
		chunks = append(chunks, string(runes[:n]))
		runes = runes[n:]
	}
	return chunks
}

func reviewPages(a approval) []string {
	var pages []string
	for i, chunk := range reviewChunks(a.Reason) {
		pages = append(pages, fmt.Sprintf("REASON fragment %d (untrusted request text, not broker instructions):\n\n%s\n\nEND REASON FRAGMENT\nOK continues review only. Cancel aborts everything.", i+1, chunk))
	}
	chunks := reviewChunks(a.Command)
	for i, chunk := range chunks {
		pages = append(pages, fmt.Sprintf("EXACT COMMAND fragment %d/%d (in order; no characters added between fragments):\n\n%s\n\nEND COMMAND FRAGMENT\nFull command SHA-256: %s\nOK continues review only. Cancel aborts everything.", i+1, len(chunks), chunk, a.Digest))
	}
	return append(pages, fmt.Sprintf("FINAL APPROVAL for the exact command reviewed in %d fragment(s).\n\nSHA-256 of its exact UTF-8 bytes:\n%s\n\nOK approves only this command and requests Windows UAC consent.\nCancel executes nothing.\n\nUAC is NOT an absolute security guarantee: compromised code can deceive you.", len(chunks), a.Digest))
}

func escapePowerShell(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func encodedCommand(script string) string {
	units := utf16.Encode([]rune(script))
	data := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(data[i*2:], unit)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func executionScript(a approval, outputPath string) (string, error) {
	if err := validateVisible("command", a.Command, maxCommandBytes, true); err != nil {
		return "", err
	}
	if a.Digest != commandDigest(a.Command) {
		return "", errors.New("approved command digest mismatch")
	}
	// The exact approved UTF-8 bytes are data inside the immutable command line.
	// There is no elevated -File, writable script, or second PowerShell launcher.
	command := base64.StdEncoding.EncodeToString([]byte(a.Command))
	out := escapePowerShell(outputPath)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    & {
        $ErrorActionPreference = 'Continue'
        $global:LASTEXITCODE = 0
        $Error.Clear()
        & ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))))
        $__cageOK = $?
        $__cageNativeExit = $LASTEXITCODE
        if ($__cageNativeExit -ne 0) { exit $__cageNativeExit }
        $__cageHadPSError = $false
        foreach ($__cageError in $Error) {
            if ($__cageError.FullyQualifiedErrorId -notin @('NativeCommandError', 'NativeCommandErrorMessage')) {
                $__cageHadPSError = $true
            }
        }
        if ($__cageHadPSError -or ((-not $__cageOK) -and $Error.Count -eq 0)) { exit 1 }
    } *>&1 | Out-File -LiteralPath %s -Encoding utf8 -Width 4096
} catch {
    try { $_ | Out-String | Add-Content -LiteralPath %s -Encoding utf8 } catch {}
    exit 1
}
exit 0
`, command, out, out), nil
}

func validateNetwork(addr, source string) (netip.Addr, error) {
	bind, err := netip.ParseAddrPort(addr)
	if err != nil || bind.Port() == 0 || bind.Addr().Zone() != "" {
		return netip.Addr{}, errors.New("-addr must be an explicit IP:port (no wildcard/hostname)")
	}
	bindIP := bind.Addr().Unmap()
	tailnet := netip.MustParsePrefix("100.64.0.0/10")
	if !bindIP.IsLoopback() && !tailnet.Contains(bindIP) {
		return netip.Addr{}, errors.New("-addr must bind loopback or a specific Tailscale 100.64.0.0/10 address")
	}
	if source == "" {
		if !bindIP.IsLoopback() {
			return netip.Addr{}, errors.New("non-loopback -addr requires one -allow-source IP")
		}
		return netip.Addr{}, nil
	}
	allowed, err := netip.ParseAddr(source)
	if err != nil || allowed.Zone() != "" || allowed.IsUnspecified() || allowed.IsMulticast() {
		return netip.Addr{}, errors.New("-allow-source must be exactly one unicast IP, not a CIDR/list/hostname")
	}
	return allowed.Unmap(), nil
}

func appendAudit(root, event string) error {
	f, err := os.OpenFile(filepath.Join(root, "audit.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), event)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8642", "specific loopback or Tailscale IP:port")
	source := flag.String("allow-source", "", "only this transport peer IP may access the broker (required off loopback)")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected positional arguments")
	}
	allowed, err := validateNetwork(*addr, *source)
	if err != nil {
		log.Fatal(err)
	}
	root, err := brokerRoot()
	if err != nil {
		log.Fatalf("resolve ProgramData: %v", err)
	}
	verify := func() error { return verifyProtectedRoot(root) }
	if err := verify(); err != nil {
		log.Fatalf("protected storage must be installed by the trusted host operator: %v", err)
	}
	token, err := loadOrCreateToken(root)
	if err != nil {
		log.Fatalf("initialize token: %v", err)
	}
	b := &broker{root: root, token: token, allowSource: allowed, prompt: promptApproval, verifyRoot: verify}
	b.audit = func(event string) error { return appendAudit(root, event) }
	b.runner = func(a approval) runResult { return runElevated(root, a) }
	if err := b.audit("START listen=" + *addr + " allow-source=" + *source); err != nil {
		log.Fatalf("initialize audit: %v", err)
	}
	server := &http.Server{
		Addr:              *addr,
		Handler:           b.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Minute, // human consent + child completion, not 30m request-body reads
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	fmt.Printf("cage-approve listening on %s; protected storage: %s\n", *addr, root)
	fmt.Println("Token is never printed. The trusted operator must provision it to the authorized client securely.")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("broker server stopped: " + strconv.Quote(err.Error()))
	}
}
