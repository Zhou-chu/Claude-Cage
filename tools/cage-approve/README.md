# Cage human approval broker (Windows)

This broker supports **B: a standard, untrusted `cageops` client plus a trusted host operator's human approval broker**. It is not an unattended administrator endpoint. Do not launch it as administrator, SYSTEM, `cageops`, or a scheduled task with `RunHighest`. Startup rejects an elevated broker token and the `cageops` account.

## Boundary and execution

- Human review is required for every request. Review pages default to **Cancel**. Reason and command are explicitly labeled untrusted text. Command fragments are bounded, preserve every character, and identify the SHA-256 of the exact UTF-8 command. Only accepting every page and the final approval proceeds to Windows UAC.
- Cancelling, closing, or failing any approval dialog never invokes the runner. A concurrent request is immediately rejected with HTTP 409; there is no queue of future approvals.
- The approved command is not trimmed or rewritten. Its digest is checked again by the runner. It is encoded as data inside a UTF-16LE `-EncodedCommand` passed **directly** to `ShellExecuteExW` (`runas`). There is no writable `run-N.ps1`, `-File` handoff, PATH-selected PowerShell, or second launcher shell.
- Windows PowerShell is resolved through `GetSystemDirectoryW` to its absolute OS path, normally `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. The executable and ancestors are checked for untrusted write access/reparse points. Normal trusted Windows servicing hard links are permitted only for this executable.
- The broker waits on the actual elevated process handle and reads its DWORD exit code. It does not report success merely because a launcher succeeded. Explicit `exit N` and native command failures propagate; PowerShell errors produce a nonzero result. Arbitrary approved code can deliberately override its own status; exit codes are not an attestation.
- UAC cancellation returns `approved: true`, `executed: false`, `exit_code: -1`, and an explicit cancellation error. Human denial returns `approved: false`, `executed: false`, `exit_code: -1`. `executed: true` means Windows created the child, not proof that every operation completed. Missing child handles/wait failures yield an unknown nonzero result; **do not automatically retry**.
- **UAC is not an absolute security guarantee. Compromised broker/operator code can deceive the human, misuse consent, alter the UI, or change execution context.** Protect the executable, operator session, and installation; scrutinize the command, not merely its stated reason. A digest binds bytes but does not establish that a command is safe. Arbitrary approved administrator commands can change system/ACL policy or deliberately lie about their status.
- Review binds the command text, not the contents of external scripts/binaries, environment variables, or files it references. Prefer trusted absolute paths and do not approve loading untrusted mutable code.

## Required host installation (lead/operator responsibility)

The broker **does not create or repair its own root ACL**. Before starting it, a trusted operator must install the real OS ProgramData known-folder child `CageBroker` (normally `C:\ProgramData\CageBroker`) and protect the executable's installation path. No environment-controlled ProgramData or temporary-directory fallback is used.

The root must have a **protected DACL (inheritance disabled)** and a trusted owner. Allow entries, including file/subdirectory inheritance, must grant access **only** to:

1. the SID of the trusted host operator who will run the broker unelevated;
2. LocalSystem (`S-1-5-18`);
3. BUILTIN Administrators (`S-1-5-32-544`).

Use ordinary inheritable (`OI`/`CI`) grants for these principals so newly created token, audit, and output files remain protected. Grant the host operator's **user SID explicitly**; relying only on the Administrators group will not let their filtered, unelevated token write capture/audit files. The operator/SYSTEM/Administrators may own the directory/files. Inheritance-disabled root plus only those three full-control entries is the intended simple installation shape.

Do not grant `cageops`, Everyone, Users, Authenticated Users, CREATOR OWNER, another operator/group, or arbitrary service SIDs access to the root. The implementation is stricter than merely blocking broad write access: it also refuses broad token/output read access. Existing token/audit files must have compatible owners/DACLs. Preserve the existing valid token when repairing deployment permissions; there is no routine token rotation. Conditional/object/unsupported DACL forms fail closed rather than being guessed at.

Runtime verification uses Windows owner/DACL APIs (standard library syscalls), not Unix mode bits or parsed localized `icacls` output. It checks startup, pre-review, post-review, immediately before elevation, and after child completion. It rejects missing/null/inherited root DACLs, untrusted grants, reparse-point paths, and hard-linked broker data. Parent paths must not allow untrusted delete-child/owner/DACL/generic-write mutation; ordinary creation of a sibling in ProgramData is not equivalent to permission to replace the protected root.

Each approved run precreates an exclusive capture file with a cryptographically random 128-bit filename under the protected root. Only the trusted principals above may write it. Capture files are retained for operator-controlled audit/retention; they are **never executed**. HTTP output is limited to 1 MiB; a truncated response is marked and the full protected capture remains. An operator must manage disk retention. Output capture is not a sandbox or an absolute disk-usage quota.

The broker executable itself must not be replaceable by `cageops` or other untrusted users. An ACL-protected data directory cannot secure a compromised executable or trusted operator account.

## CLI and network

Default bind is **`127.0.0.1:8642`**, never `:8642`. To accept a single authorized Tailscale peer:

```text
cage-approve.exe -addr 100.100.100.100:8642 -allow-source 100.100.100.101
```

These are illustrative IPs, not discovery/installation commands. Substitute the actual host and authorized guest IPs. Bind must be an explicit loopback or Tailscale `100.64.0.0/10` IP with a nonzero port. Any non-loopback bind requires one `-allow-source` IP, not a CIDR, hostname, or list. The filter compares the actual transport peer; forwarded headers are ignored. Keep the host firewall restricted to that same peer and use only the trusted Tailscale transport (the broker does not add application TLS).

Only exact paths/methods are served:

| Route | Method | Behavior |
| --- | --- | --- |
| `/health` | GET | Authenticated `{"ok":true}` only; no PID, token, environment, or debug data |
| `/run` | POST | Authenticated bounded human-approved request |

Every route above requires exactly one `Authorization: Bearer <token>` header. Raw tokens, alternate schemes, duplicate headers, query tokens, and query parameters are not accepted. There is no token/file/debug endpoint. No CORS allowance is added. HTTP has 5 s header-read, 10 s total read, 30 s idle, 30 min response-write timeouts, and 8 KiB max headers. A response timeout does not mean an approved child was stopped: consult the protected audit before any manual retry.

On the first successful protected startup, a 32-byte random token is created exclusively in the protected directory. A valid existing 64-hex token is reused unchanged. Unreadable/malformed existing tokens fail startup instead of being replaced. **The token is never printed or returned by HTTP.** The trusted operator must provision it to the authorized client through an appropriate secure channel; do not paste it into chat, command arguments, logs, or a broad-readable file.

Request JSON accepts exactly one `command` string and optionally one `reason` string. Unknown/duplicate fields, trailing JSON, null/nonstring fields, command >4096 UTF-8 bytes, reason >1024 bytes, and body >32 KiB fail before any dialog. These are **single-line fields**: NUL, all control characters (including newline/tab), Unicode format controls (including bidi), line/paragraph separators, invalid Unicode, and U+FFFD are rejected. Use semicolons or explicitly reviewed PowerShell syntax for multiple statements. Audit records digests and outcomes, not tokens, reasons, or full command text.

## Build and tests

Run from this directory with the local Go compiler, without installing dependencies:

```powershell
& 'D:\code\.tools\go\bin\go.exe' test -count=1 ./...
& 'D:\code\.tools\go\bin\go.exe' vet ./...
& 'D:\code\.tools\go\bin\go.exe' build -trimpath -o cage-approve-new.exe .
```

The new executable is a build artifact for the lead/operator to inspect and deploy, **not an automatic replacement of the existing host-access binary**.

Tests exercise the broker using `httptest` and injected prompt/runner/storage/audit functions. They do not listen on the live broker address and do not call a real approval dialog or elevation API. Additional hardcoded harmless fixtures run the encoded wrapper in a direct Windows PowerShell child that **does not request elevation** and inherits the test process token, to verify actual exit/output semantics; these never use `runas`, ShellExecuteEx, or UAC. The tests do not attest the surrounding harness token's integrity level. ACL grant-policy and ABI layout checks are included. Passing these tests is **not** a claim of live UAC/elevated end-to-end validation or installation verification.
