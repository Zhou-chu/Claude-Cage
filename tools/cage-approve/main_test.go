//go:build windows

package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testBroker() *broker {
	return &broker{
		token:      testToken,
		prompt:     func(approval) (bool, error) { return true, nil },
		runner:     func(approval) runResult { return runResult{Executed: true} },
		verifyRoot: func() error { return nil },
		audit:      func(string) error { return nil },
	}
}

func testRequest(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.RemoteAddr = "100.100.100.101:51234"
	return r
}

func runJSON(b *broker, body string) (*httptest.ResponseRecorder, runResponse) {
	w := httptest.NewRecorder()
	b.handler().ServeHTTP(w, testRequest(http.MethodPost, "/run", body))
	var response runResponse
	_ = json.Unmarshal(w.Body.Bytes(), &response)
	return w, response
}

func TestExactApprovedCommandAndChildExit(t *testing.T) {
	b := testBroker()
	command := "  Write-Output '你好'; exit 17  "
	reason := "Install only the reviewed change"
	calls := 0
	b.prompt = func(a approval) (bool, error) {
		if a.Command != command || a.Reason != reason || a.Digest != commandDigest(command) {
			t.Fatalf("dialog was not bound to exact original bytes: %+v", a)
		}
		return true, nil
	}
	b.runner = func(a approval) runResult {
		calls++
		if a.Command != command || a.Digest != commandDigest(command) {
			t.Fatal("runner received something other than the approved command")
		}
		return runResult{Executed: true, ExitCode: 17, Output: "child output"}
	}
	body, _ := json.Marshal(runRequest{Command: command, Reason: reason})
	w, response := runJSON(b, string(body))
	if w.Code != http.StatusOK || !response.Approved || !response.Executed || response.ExitCode != 17 || response.Output != "child output" || response.Digest != commandDigest(command) || calls != 1 {
		t.Fatalf("unexpected exact-command/child result: HTTP %d %+v calls=%d", w.Code, response, calls)
	}
}

func TestApprovalAndRunnerOutcomes(t *testing.T) {
	cases := []struct {
		name         string
		approved     bool
		promptErr    error
		result       runResult
		wantRun      bool
		wantExecuted bool
		wantExit     int
	}{
		{"human denial", false, nil, runResult{}, false, false, notExecuted},
		{"dialog failure", false, errors.New("window unavailable"), runResult{}, false, false, notExecuted},
		{"UAC cancelled", true, nil, runResult{ExitCode: notExecuted, Error: "UAC cancelled (1223); nothing executed"}, true, false, notExecuted},
		{"launch failed cannot report success", true, nil, runResult{Error: "launch failed"}, true, false, notExecuted},
		{"child success", true, nil, runResult{Executed: true, ExitCode: 0}, true, true, 0},
		{"native child error", true, nil, runResult{Executed: true, ExitCode: 37}, true, true, 37},
		{"child termination DWORD", true, nil, runResult{Executed: true, ExitCode: 0xC000013A}, true, true, 0xC000013A},
		{"unknown running child", true, nil, runResult{Executed: true, ExitCode: notExecuted, Error: "wait failed"}, true, true, notExecuted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := testBroker()
			called := false
			b.prompt = func(approval) (bool, error) { return tc.approved, tc.promptErr }
			b.runner = func(approval) runResult { called = true; return tc.result }
			w, response := runJSON(b, `{"command":"Write-Output 'fixture'"}`)
			if w.Code != http.StatusOK || response.Approved != tc.approved || response.Executed != tc.wantExecuted || response.ExitCode != tc.wantExit || called != tc.wantRun {
				t.Fatalf("HTTP %d response=%+v runner=%t", w.Code, response, called)
			}
		})
	}
}

func TestRejectInvalidRequestBeforePrompt(t *testing.T) {
	validJSON := func(command, reason string) string {
		data, _ := json.Marshal(runRequest{Command: command, Reason: reason})
		return string(data)
	}
	cases := map[string]string{
		"empty":                       `{"command":""}`,
		"whitespace":                  `{"command":"   "}`,
		"missing":                     `{"reason":"why"}`,
		"unknown":                     `{"command":"echo yes","approve":true}`,
		"duplicate command":           `{"command":"safe","command":"different"}`,
		"duplicate reason":            `{"command":"safe","reason":"one","reason":"two"}`,
		"null command":                `{"command":null}`,
		"null reason":                 `{"command":"safe","reason":null}`,
		"array":                       `["echo yes"]`,
		"numeric command":             `{"command":123}`,
		"trailing object":             `{"command":"safe"}{"command":"different"}`,
		"trailing text":               `{"command":"safe"} garbage`,
		"invalid JSON":                `{"command":`,
		"command over limit":          validJSON(strings.Repeat("x", maxCommandBytes+1), ""),
		"reason over limit":           validJSON("echo yes", strings.Repeat("x", maxReasonBytes+1)),
		"UTF8 byte limit":             validJSON(strings.Repeat("界", 1400), ""),
		"NUL":                         validJSON("echo\x00yes", ""),
		"LF":                          validJSON("echo yes\nwhoami", ""),
		"CR":                          validJSON("echo yes\rwhoami", ""),
		"tab":                         validJSON("echo\tyes", ""),
		"escape":                      validJSON("echo \x1b[31m", ""),
		"delete":                      validJSON("echo \x7f", ""),
		"reason control":              validJSON("echo yes", "why\x00not"),
		"bidi override":               validJSON("echo \u202eyes", ""),
		"bidi isolate":                validJSON("echo yes", "why\u2066not"),
		"zero width format":           validJSON("echo\u200byes", ""),
		"unicode line separator":      validJSON("echo\u2028yes", ""),
		"unicode paragraph separator": validJSON("echo\u2029yes", ""),
		"unpaired surrogate":          `{"command":"echo \ud800"}`,
		"invalid utf8":                "{\"command\":\"echo \xff\"}",
		"oversized HTTP body":         `{"command":"safe","reason":"` + strings.Repeat("x", maxRequestBytes) + `"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			b := testBroker()
			b.prompt = func(approval) (bool, error) { t.Fatal("invalid request reached dialog"); return false, nil }
			b.runner = func(approval) runResult { t.Fatal("invalid request reached runner"); return runResult{} }
			w, _ := runJSON(b, body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestRequestExactLimitsAccepted(t *testing.T) {
	b := testBroker()
	body, _ := json.Marshal(runRequest{Command: strings.Repeat("x", maxCommandBytes), Reason: strings.Repeat("y", maxReasonBytes)})
	if w, _ := runJSON(b, string(body)); w.Code != http.StatusOK {
		t.Fatalf("exact limits rejected: %d %s", w.Code, w.Body.String())
	}
}

func TestStrictAuthenticationMethodsAndHealthOnly(t *testing.T) {
	cases := []struct {
		name, method, path string
		headers            []string
		want               int
	}{
		{"health", "GET", "/health", []string{"Bearer " + testToken}, 200},
		{"no token", "GET", "/health", nil, 401},
		{"raw token", "GET", "/health", []string{testToken}, 401},
		{"wrong token", "GET", "/health", []string{"Bearer " + strings.Repeat("a", 64)}, 401},
		{"wrong scheme", "GET", "/health", []string{"Basic " + testToken}, 401},
		{"lowercase scheme", "GET", "/health", []string{"bearer " + testToken}, 401},
		{"extra spaces", "GET", "/health", []string{"Bearer  " + testToken}, 401},
		{"trailing space", "GET", "/health", []string{"Bearer " + testToken + " "}, 401},
		{"duplicate auth", "GET", "/health", []string{"Bearer " + testToken, "Bearer " + testToken}, 401},
		{"query token", "GET", "/health?token=" + testToken, nil, 401},
		{"queries not accepted", "GET", "/health?debug=1", []string{"Bearer " + testToken}, 400},
		{"health POST", "POST", "/health", []string{"Bearer " + testToken}, 405},
		{"health HEAD", "HEAD", "/health", []string{"Bearer " + testToken}, 405},
		{"run GET", "GET", "/run", []string{"Bearer " + testToken}, 405},
		{"run OPTIONS", "OPTIONS", "/run", []string{"Bearer " + testToken}, 405},
		{"no token endpoint", "GET", "/token", []string{"Bearer " + testToken}, 404},
		{"no token file serving", "GET", "/token/../token", []string{"Bearer " + testToken}, 404},
		{"no debug", "GET", "/debug/vars", []string{"Bearer " + testToken}, 404},
		{"no health subtree", "GET", "/health/", []string{"Bearer " + testToken}, 404},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			for _, value := range tc.headers {
				r.Header.Add("Authorization", value)
			}
			w := httptest.NewRecorder()
			testBroker().handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("want %d got %d: %s", tc.want, w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), testToken) {
				t.Fatal("token exposed in response")
			}
			if tc.want == 200 && strings.TrimSpace(w.Body.String()) != `{"ok":true}` {
				t.Fatalf("health exposed extra data: %s", w.Body.String())
			}
			if tc.want == 405 && w.Header().Get("Allow") == "" {
				t.Fatal("missing Allow header")
			}
		})
	}
}

func TestSourceAllowlistUsesTransportNotForwardedHeaders(t *testing.T) {
	for _, tc := range []struct {
		peer string
		want int
	}{
		{"100.100.100.101:50000", 200},
		{"[::ffff:100.100.100.101]:50000", 200},
		{"100.100.100.102:50000", 403},
		{"127.0.0.1:50000", 403},
		{"garbage", 403},
		{"100.100.100.101", 403},
	} {
		t.Run(tc.peer, func(t *testing.T) {
			b := testBroker()
			b.allowSource = netip.MustParseAddr("100.100.100.101")
			r := testRequest("GET", "/health", "")
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-For", "100.100.100.101")
			w := httptest.NewRecorder()
			b.handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("peer %s: want %d got %d", tc.peer, tc.want, w.Code)
			}
		})
	}
}

func TestBusyRequestRejectedWithoutQueuingPrompt(t *testing.T) {
	b := testBroker()
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	b.prompt = func(approval) (bool, error) { close(entered); <-release; return false, nil }
	go func() { defer close(finished); runJSON(b, `{"command":"first"}`) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not enter prompt")
	}
	defer func() { close(release); <-finished }()
	w, _ := runJSON(b, `{"command":"second"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "no request queued") {
		t.Fatalf("busy request not immediately rejected: %d %s", w.Code, w.Body.String())
	}
}

func TestStorageAndAuditFailuresNeverExecute(t *testing.T) {
	for _, tc := range []string{"root before prompt", "root after prompt", "audit before prompt", "audit after prompt"} {
		t.Run(tc, func(t *testing.T) {
			b := testBroker()
			rootCalls, auditCalls, prompts := 0, 0, 0
			b.verifyRoot = func() error {
				rootCalls++
				if tc == "root before prompt" || tc == "root after prompt" && rootCalls == 2 {
					return errors.New("insecure DACL")
				}
				return nil
			}
			b.audit = func(string) error {
				auditCalls++
				if tc == "audit before prompt" || tc == "audit after prompt" && auditCalls == 2 {
					return errors.New("disk unavailable")
				}
				return nil
			}
			b.prompt = func(approval) (bool, error) { prompts++; return true, nil }
			b.runner = func(approval) runResult { t.Fatal("insecure storage/audit reached execution"); return runResult{} }
			w, response := runJSON(b, `{"command":"fixture"}`)
			if strings.Contains(tc, "before") {
				if w.Code != 503 || prompts != 0 {
					t.Fatalf("pre-prompt failure: %d prompts=%d", w.Code, prompts)
				}
			} else if w.Code != 200 || !response.Approved || response.Executed || response.ExitCode != notExecuted || prompts != 1 {
				t.Fatalf("post-prompt failure: %d %+v prompts=%d", w.Code, response, prompts)
			}
		})
	}
}

func TestDisconnectedApprovalDoesNotExecute(t *testing.T) {
	b := testBroker()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.prompt = func(approval) (bool, error) { cancel(); return true, nil }
	b.runner = func(approval) runResult { t.Fatal("disconnected request executed"); return runResult{} }
	r := testRequest("POST", "/run", `{"command":"fixture"}`).WithContext(ctx)
	w := httptest.NewRecorder()
	b.handler().ServeHTTP(w, r)
	var response runResponse
	_ = json.Unmarshal(w.Body.Bytes(), &response)
	if response.Executed || response.ExitCode != notExecuted {
		t.Fatalf("disconnected request result: %+v", response)
	}
}

func TestAuditContainsDigestNotRequestSecrets(t *testing.T) {
	b := testBroker()
	var events []string
	b.audit = func(s string) error { events = append(events, s); return nil }
	command, reason := "echo SECRET-COMMAND", "SECRET-REASON"
	body, _ := json.Marshal(runRequest{Command: command, Reason: reason})
	runJSON(b, string(body))
	text := strings.Join(events, "\n")
	if !strings.Contains(text, commandDigest(command)) || strings.Contains(text, command) || strings.Contains(text, reason) || strings.Contains(text, testToken) {
		t.Fatalf("audit disclosed request text or omitted digest: %q", text)
	}
}

func TestNetworkConfiguration(t *testing.T) {
	for _, tc := range []struct {
		addr, source string
		valid        bool
	}{
		{"127.0.0.1:8642", "", true},
		{"[::1]:8642", "", true},
		{"100.100.100.100:8642", "100.100.100.101", true},
		{"100.64.0.1:8642", "100.64.0.2", true},
		{"100.100.100.100:8642", "", false},
		{":8642", "", false},
		{"0.0.0.0:8642", "100.100.100.101", false},
		{"[::]:8642", "::1", false},
		{"localhost:8642", "", false},
		{"192.168.1.2:8642", "192.168.1.3", false},
		{"127.0.0.1:0", "", false},
		{"127.0.0.1:8642", "100.64.0.0/10", false},
		{"127.0.0.1:8642", "100.64.0.1,100.64.0.2", false},
		{"127.0.0.1:8642", "0.0.0.0", false},
		{"127.0.0.1:8642", "224.0.0.1", false},
		{"127.0.0.1:8642", "guest", false},
	} {
		t.Run(tc.addr+"/"+tc.source, func(t *testing.T) {
			_, err := validateNetwork(tc.addr, tc.source)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", tc.valid, err)
			}
		})
	}
}

func TestTokenIsPersistentAndInvalidTokenNeverRotated(t *testing.T) {
	root := t.TempDir()
	first, err := loadOrCreateToken(root)
	if err != nil || len(first) != 64 {
		t.Fatalf("initial token: len=%d err=%v", len(first), err)
	}
	second, err := loadOrCreateToken(root)
	if err != nil || first != second {
		t.Fatal("token rotated during normal restart")
	}
	path := filepath.Join(root, "token")
	original := []byte("INVALID-EXISTING-TOKEN\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateToken(root); err == nil {
		t.Fatal("invalid token accepted/replaced")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(original) {
		t.Fatal("invalid existing token was changed")
	}
}

func TestEncodedCommandIsUTF16LEAndBindsExactCommand(t *testing.T) {
	source := "Unicode 界😀 'literal'"
	encoded := encodedCommand(source)
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data)%2 != 0 {
		t.Fatal("bad encoded command")
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	if string(utf16.Decode(units)) != source {
		t.Fatal("encoded command did not preserve UTF16LE source")
	}
	command := "  Write-Output '界😀'; exit 7  "
	a := approval{Command: command, Digest: commandDigest(command)}
	script, err := executionScript(a, `C:\ProgramData\CageBroker\output-'test.txt`)
	if err != nil || !strings.Contains(script, base64.StdEncoding.EncodeToString([]byte(command))) || !strings.Contains(script, "output-''test.txt'") || strings.Contains(script, " -File ") || strings.Contains(script, "Start-Process") {
		t.Fatalf("bad immutable execution envelope: %v\n%s", err, script)
	}
	a.Command += "; different"
	if _, err := executionScript(a, "out"); err == nil {
		t.Fatal("digest mismatch accepted")
	}
}

func TestWindowsACLPolicy(t *testing.T) {
	host := "S-1-5-21-1-2-3-1001"
	trusted := map[string]bool{host: true, "S-1-5-18": true, "S-1-5-32-544": true}
	for _, sid := range []string{"S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-21-1-2-3-1002"} {
		for _, mask := range []uint32{2, 4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000} {
			if err := validateACE(0, 0, mask, sid, trusted, false, true); err == nil {
				t.Fatalf("untrusted write accepted: %s mask=%x", sid, mask)
			}
			if err := validateACE(0, inheritOnlyACE, mask, sid, trusted, false, true); err == nil {
				t.Fatalf("inheritable untrusted write accepted: %s mask=%x", sid, mask)
			}
		}
	}
	if err := validateACE(0, 0, 0x1F01FF, host, trusted, false, true); err != nil {
		t.Fatal(err)
	}
	if err := validateACE(0, 0, 1, "S-1-1-0", trusted, false, true); err == nil {
		t.Fatal("root allows Everyone to read token/output")
	}
	if err := validateACE(0, 0, 0x40, "S-1-1-0", trusted, true, false); err == nil {
		t.Fatal("parent allows untrusted delete-child")
	}
	if err := validateACE(0, inheritOnlyACE, 0x1F01FF, "S-1-3-0", trusted, true, false); err != nil {
		t.Fatal("inherited-only parent creator-owner incorrectly applies to parent")
	}
	if err := validateACE(0, 0, 4, "S-1-5-11", trusted, true, false); err != nil {
		t.Fatal("parent sibling creation incorrectly treated as root mutation")
	}
	if err := validateACE(9, 0, 0, host, trusted, false, true); err == nil {
		t.Fatal("unknown conditional ACE accepted")
	}
}

func TestShellExecuteInfoLayout(t *testing.T) {
	var info shellExecuteInfo
	if unsafe.Sizeof(uintptr(0)) == 8 {
		if unsafe.Sizeof(info) != 112 || unsafe.Offsetof(info.Process) != 104 {
			t.Fatalf("invalid x64 SHELLEXECUTEINFOW size=%d process=%d", unsafe.Sizeof(info), unsafe.Offsetof(info.Process))
		}
	} else if unsafe.Sizeof(info) != 60 || unsafe.Offsetof(info.Process) != 56 {
		t.Fatalf("invalid x86 SHELLEXECUTEINFOW size=%d process=%d", unsafe.Sizeof(info), unsafe.Offsetof(info.Process))
	}
}

// This exercises ONLY a non-elevating local PowerShell child with hardcoded
// harmless fixtures. No dialog, ShellExecuteEx, runas, UAC or broker /run call.
func TestExecutionWrapperNonElevatingPowerShell(t *testing.T) {
	powershell, err := trustedPowerShellPath()
	if err != nil {
		t.Fatalf("trusted OS PowerShell: %v", err)
	}
	for _, tc := range []struct {
		name, command string
		code          uint32
		output        string
	}{
		{"success", "Write-Output 'fixture success'", 0, "fixture success"},
		{"native exit", "cmd.exe /d /c exit 7", 7, ""},
		{"native error then PS output", "cmd.exe /d /c exit 23; Write-Output 'after native'", 23, "after native"},
		{"explicit exit", "Write-Output 'before exit'; exit 19", 19, "before exit"},
		{"terminating error", "throw 'fixture failure'", 1, "fixture failure"},
		{"nonterminating error", "Write-Error 'fixture error'; Write-Output 'after error'", 1, "fixture error"},
		{"missing command", "Invoke-CageBrokerDefinitelyMissingFixture", 1, ""},
		{"parse error", "if (", 1, ""},
		{"native stderr failure", `cmd.exe /d /c "echo native fixture error 1>&2 & exit 27"`, 27, "native fixture error"},
		{"native stderr success", `cmd.exe /d /c "echo native fixture progress 1>&2 & exit 0"`, 0, "native fixture progress"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "capture.txt")
			script, err := executionScript(approval{Command: tc.command, Digest: commandDigest(tc.command)}, out)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedCommand(script))
			// Inherit output streams: never capture a subprocess through a pipe.
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			err = cmd.Run()
			var code uint32
			if err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatal(err)
				}
				code = exitErr.Sys().(syscall.WaitStatus).ExitCode
			}
			if code != tc.code {
				t.Fatalf("expected actual child code %d got %d (%v)", tc.code, code, err)
			}
			capture, err := os.Open(out)
			if err != nil {
				t.Fatal(err)
			}
			defer capture.Close()
			data, err := io.ReadAll(capture)
			if err != nil || !strings.Contains(string(data), tc.output) {
				t.Fatalf("missing fixture output %q: %s err=%v", tc.output, data, err)
			}
		})
	}
}
