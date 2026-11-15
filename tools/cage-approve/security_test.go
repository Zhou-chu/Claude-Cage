//go:build windows

package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestReviewPagesPreserveEveryRuneAndDigest(t *testing.T) {
	command := strings.Repeat("界😀abc ", 200)
	chunks := reviewChunks(command)
	if strings.Join(chunks, "") != command {
		t.Fatal("review chunks changed the command")
	}
	for _, chunk := range chunks {
		if !utf8.ValidString(chunk) || utf8.RuneCountInString(chunk) > 512 {
			t.Fatal("unbounded or broken review fragment")
		}
	}
	a := approval{Command: command, Reason: "untrusted reason", Digest: commandDigest(command)}
	pages := reviewPages(a)
	if len(pages) != len(chunks)+2 {
		t.Fatalf("missing reason/command/final page: %d", len(pages))
	}
	for i, chunk := range chunks {
		if !strings.Contains(pages[i+1], chunk) || !strings.Contains(pages[i+1], a.Digest) {
			t.Fatal("review page missing exact fragment or digest")
		}
	}
	last := pages[len(pages)-1]
	if !strings.Contains(last, "FINAL APPROVAL") || !strings.Contains(last, a.Digest) || !strings.Contains(last, "NOT an absolute security guarantee") {
		t.Fatal("final approval did not identify command and boundary")
	}
}

func TestOperatorMustBeUnelevatedAndNotCageops(t *testing.T) {
	for _, tc := range []struct {
		name            string
		elevated, valid bool
	}{
		{"hostoperator", false, true},
		{"hostoperator", true, false},
		{"cageops", false, false},
		{"CaGeOpS", false, false},
		{"cageops", true, false},
	} {
		if err := validateOperatorIdentity(tc.name, tc.elevated); (err == nil) != tc.valid {
			t.Fatalf("name=%s elevated=%t err=%v", tc.name, tc.elevated, err)
		}
	}
}

func TestEncodedMaximumCommandFitsWindowsLimit(t *testing.T) {
	command := strings.Repeat("x", maxCommandBytes)
	script, err := executionScript(approval{Command: command, Digest: commandDigest(command)}, `C:\ProgramData\CageBroker\output-0123456789abcdef0123456789abcdef.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if len(encodedCommand(script))+512 >= 32767 {
		t.Fatal("accepted command cannot fit an immutable Windows command line")
	}
}
