# cage-host: guest SSH and approval-broker wrappers

**Review artifact, not an installation.** Python 3.9+ standard library only; use
system CPython (`/usr/bin/python3`), not Conda. Runtime permission checking is
intentionally POSIX-only and fails closed on Windows. Nothing in this directory
installs itself, starts/restarts Cage or a VM, enrolls a tailnet node, or requests
approval merely by being imported or by displaying help.

## Native OpenSSH integration

The host installer explicitly runs `cage_host_native.py` after provisioning the
private client config and pinned host key. It installs `ssh windows-host` and
`sftp windows-host`, using `/usr/local/bin/cage-tailnet dial` directly, not a VPN,
public fallback, or a bearer token embedded in SSH arguments. The managed native
include is prepended while retaining Cage's automatic tailnet include unchanged.
The original SSH config is backed up once; reinstallation is idempotent and
rejects symlink/unmanaged native files. A real `ssh -G` parse validates the
candidate before installation. Full guest usage is in
`~/.config/cage-host/USAGE.md`; it explicitly retains the standard-user and
Desktop-tool boundaries. This does not modify Claude Desktop settings/login,
start services, or submit approval requests. Importing the module has no effects.

## Protocol verified in this checkout

The implementation was derived from these sources, not a `--help` probe:

- [`tools/tailnet/main.go`](../../tailnet/main.go): the daemon uses **newline JSON
  on its owning process's stdin**, e.g. `{"action":"status"}`. It is not a
  conventional status CLI. Starting another instance may acquire state locks or
  attempt startup; this wrapper never starts it or writes to that channel.
- [`internal/cage/tailnet-client.mjs`](../../../internal/cage/tailnet-client.mjs):
  Cage owns and serializes that stdio protocol, launching as guest user `cage` on
  Linux.
- [`tools/tailnet/dial.go`](../../tailnet/dial.go): the running daemon writes
  `~/.config/cage-tailnet/control.json`, mode `0600`, containing exactly
  `{"address":"127.0.0.1:<ephemeral-port>","token":"<64-lowercase-hex>"}`.
  This is the stable discovery location, **not** a stable proxy URL/port. The
  wrapper reopens it for every CONNECT, with no cache and no alternate source.
  Stale/disconnected records fail the CONNECT; there is no retry or fallback.
- [`tools/tailnet/network_forward.go`](../../tailnet/network_forward.go): status
  `proxy_url` is derived from the same record as HTTP Basic username `cage` plus
  its token. The wrapper sends this only as `Proxy-Authorization` in the local
  CONNECT handshake; credentials never appear in argv, an environment variable,
  a generated script, or diagnostic logging. It never emits the proxy URL.
- [`tools/tailnet/network.go`](../../tailnet/network.go): the proxy resolves only
  visible tailnet peers, using peer IPv4, DNS name, or short name and tsnet dial.
  It never falls back to host/guest public, LAN, or loopback destination sockets.
- [`tools/cage-approve/main.go`](../../cage-approve/main.go): authenticated
  `GET /health` returns `{"ok":true,"pid":...}`; `POST /run` accepts exactly the
  command/reason fields used here, returning `approved`, `exit_code`, `output`.

A CONNECT goes **only to the discovered IPv4 loopback proxy**. Its target is the
single configured tailnet host and either `ssh_port` or `broker_port`. There is
no arbitrary destination argument. DNS hostnames are not resolved by Python;
only the proxy resolves them against its visible tailnet peers. IPv4 literals
must be in `100.64.0.0/10` (the proxy additionally verifies peer membership).
Environment `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` and system proxy
settings are not consulted. HTTP redirects and reconnects are not followed.

## Review-time configuration and integration steps

Do these steps **only after lead review**; no integration has been performed by
the implementation agent.

1. Keep `cage-host` and `cage_host.py` together in an owner-controlled guest
   directory (no group/world write); make the launcher executable, or invoke
   `/usr/bin/python3 -I /absolute/path/cage_host.py` directly. Never invoke it with
   `sudo` just to bypass a file-permission error. Use the same guest user as the
   running tailnet daemon; if another identity is intended, review the access
   policy rather than copying the rotating proxy token.
2. Create the config directory with mode `0700` and configuration with mode
   `0600`. Use the following **placeholder-only** schema and fill in reviewed
   values. Paths must be absolute or begin with `~/`; symlinks, `..`, `%`, NUL,
   and line breaks in paths are rejected. No secret is embedded in this example.

   ```json
   {
     "version": 1,
     "host": "REPLACE-WITH-HOST-TAILNET-NAME",
     "ssh_user": "REPLACE-WITH-STANDARD-USER",
     "ssh_port": 22,
     "broker_port": 8642,
     "identity_file": "~/.ssh/REPLACE-WITH-PRIVATE-IDENTITY",
     "known_hosts_file": "~/.config/cage-host/known_hosts",
     "broker_token_file": "~/.config/cage-host/broker-token",
     "control_file": "~/.config/cage-tailnet/control.json",
     "connect_timeout": 10,
     "broker_timeout": 300
   }
   ```

   Default config: `~/.config/cage-host/config.json`. Override with
   `--config /absolute/private/config.json` **before** the subcommand. Unknown or
   duplicate config keys and missing required keys fail closed. Timeout limits:
   CONNECT `(0,60]` seconds, broker I/O `(0,3600]` seconds.
3. Provision the SSH identity and pin the expected host public key using a
   separately authenticated host-side source. Do **not** blindly trust
   `ssh-keyscan` output. The key and known-hosts files must have mode `0600`
   (or `0400`) and be owned by the invoking user or root. Pin the exact configured
   hostname (or `[hostname]:port` for nondefault SSH ports), not a proxy address.
   SSH uses `/usr/bin/ssh -F /dev/null`, strict checking `yes`, the dedicated
   known-hosts file, no global known-hosts fallback or DNS key trust, the selected
   identity only, no agent, no password authentication, no ControlMaster socket,
   no forwarding, and a self `ProxyCommand`. The wrapper accepts **no arbitrary
   SSH options**; remote command strings beginning with `-` are rejected to
   prevent guest-side SSH option parsing. Unknown/changed keys fail rather than
   prompting acceptance.
4. Provision the broker token through a reviewed confidential channel directly
   into its final private file, with restrictive mode at creation. Do not put it
   in shell command arguments, shell history, world-readable files, environment
   variables, or `/tmp` scripts. The wrapper reads the token via an already
   permission-checked file descriptor; it never creates or changes credentials.
5. For all private files (configuration, daemon record, token, key, known-hosts,
   optional request JSON): current-user/root ownership, no group/other mode
   bits, one hardlink, regular file only. All path components are opened using
   directory FDs plus `O_NOFOLLOW`; writable or foreign-owned ancestor directories
   are rejected. Root-owned sticky directories are allowed only as non-immediate
   ancestors (e.g. a private test directory below `/tmp`). POSIX ACLs and
   same-user malicious processes are not an isolation boundary of this wrapper;
   review guest account/ACL policy independently.
6. First run a reviewed read-only SSH command and then `health`, if desired.
   `health` is authenticated GET only; it never posts a run request.

   ```sh
   /usr/bin/python3 -I /absolute/path/cage_host.py ssh 'whoami; hostname'
   /usr/bin/python3 -I /absolute/path/cage_host.py health
   ```

   Omitting the single SSH command string opens a normal SSH session. Its exit
   code is preserved; a signal maps to `128 + signal`. No command rewriting or
   shell execution is performed on the guest for the SSH child.
7. **Only on a separate, explicit decision to request execution**, use `run`.
   It reads one UTF-8 JSON object from stdin by default; or use
   `run --request /absolute/private/request.json`. Both nonempty `command` and
   `reason` strings are required, no extra fields. This example is documentation
   only and was not executed:

   ```sh
   /usr/bin/python3 -I /absolute/path/cage_host.py run <<'JSON'
   {"command":"Write-Output 'reviewed example'","reason":"Explicitly approved integration test"}
   JSON
   ```

   The command is sent verbatim as JSON to the broker, which may request
   elevated execution. One POST only: no health preflight, automatic retries,
   redirect following, reconnect, polling, or resubmission. A timeout,
   interruption, malformed response, or broken connection after submission can
   mean **the operation already ran**. Consult host audit/state; do not retry
   blindly. Broker timeout is an I/O inactivity timeout, not cancellation of a
   host operation or an overall execution deadline.

## Output and exit status

Broker success/denial output is a JSON object on stdout. Credential strings
known to the wrapper are redacted if echoed in broker `output`; untrusted HTTP
error bodies and CONNECT reason phrases are never printed. Commands/reasons
and all other host output can still be sensitive: protect captured output.
No automatic request/output logs are written by the wrapper.

- health success: exit `0`, `{ok,pid}`.
- explicit broker denial: exit `3`, `approved:false`, and a clear stderr message.
- approved run: preserve the broker-reported exit code if `0..255`; otherwise
  exit `1`, retain the original `exit_code` in JSON. Nonzero is explicit on stderr.
- configuration/permission/CONNECT/HTTP/protocol errors: exit `2` and a sanitized
  diagnostic. HTTP 401/403/other status numbers are explicit.
- interrupt: exit `130` and an execution-outcome warning.

## Important broker limitations — NOT an admin-safety claim

The current host broker has **not received a complete security review**. This
client does not make its privileged execution safe. It merely constrains its
own transport and faithfully sends the explicit request. Review authentication,
listener/firewall policy, audit exposure, host filesystem ACLs, script/output
lifecycle and race handling, human consent/UAC, and cancellation separately.

The revised host broker no longer uses the old outer `Start-Process` launcher:
it passes an immutable encoded command to OS Windows PowerShell and waits on
the actual elevated child process handle. It adds `executed` and optional
`error` metadata, which this client preserves and redacts for known credentials.
An approved request with `executed:false` is a nonzero client result, including
cancelled UAC; approval alone is not execution success. Older responses remain
parseable, but an old broker's zero cannot be trusted as a true child exit status.
Health accepts `{ok:true}` and the older `{ok:true,pid:positive-int}` schema.
Automated tests use mock prompt/runner functions, not actual UAC: human desktop
end-to-end acceptance is still required. A reported zero is not a security verdict.

## Tests (no live requests)

From this directory using **system CPython**:

```sh
/usr/bin/python3 -I -B -m unittest discover -s tests -v
```

On Windows for isolated cross-platform tests:

```powershell
& 'D:\Programme Files\Python\python.exe' -I -B -m unittest discover -s tools/host-access/guest/tests -v
```

Mock sockets exercise the exact CONNECT handshake, errors/timeout, fresh
record/credential rotation, byte preservation/half-close, no direct/reconnect or
proxy-env fallback, HTTP health vs single-POST run, denial, nonzero status,
response validation and redaction. Pure permission-policy tests run everywhere;
a real `O_NOFOLLOW`/ownership/mode test runs only on POSIX. The suite makes no
real network connections and does not invoke SSH, the VM, or a broker.
