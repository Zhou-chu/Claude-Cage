#!/usr/bin/env python3
"""Guest-only, stdlib-only SSH/broker client for the Cage tailnet proxy.

No environment proxy, direct destination socket, daemon launch, retry, or install.
See README.md for the source-verified protocol and remaining broker limitations.
"""
import argparse
import base64
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field

MAX_FILE = 65536
MAX_RESPONSE = 2 * 1024 * 1024
DEFAULT_CONFIG = "~/.config/cage-host/config.json"
DEFAULT_CONTROL = "~/.config/cage-tailnet/control.json"


class ClientError(Exception):
    """An intentionally credential-free, user-facing diagnostic."""


def strict_json(data, description):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        result = json.loads(data, object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise ClientError("invalid " + description) from None
    if not isinstance(result, dict):
        raise ClientError("invalid " + description)
    return result


def absolute_path(value):
    if not isinstance(value, str) or not value or any(c in value for c in "\r\n\x00%"):
        raise ClientError("invalid configured path")
    expanded = os.path.expanduser(value)
    if not os.path.isabs(expanded):
        raise ClientError("configured paths must be absolute (or start with ~/)")
    # Do not resolve symlinks: private_open must reject them, not hide them.
    if ".." in Path(expanded).parts:
        raise ClientError("parent traversal is not allowed in configured paths")
    return os.path.abspath(expanded)


def validate_directory(info, owners, immediate):
    sticky_ancestor = info.st_uid == 0 and info.st_mode & stat.S_ISVTX and not immediate
    if info.st_uid not in owners or (info.st_mode & 0o022 and not sticky_ancestor):
        raise ClientError("private file has an unsafe containing directory")


def validate_private_file(info, owners):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in owners
            or stat.S_IMODE(info.st_mode) not in (0o400, 0o600) or info.st_nlink != 1):
        raise ClientError("private file must be owner/root-owned, single-linked, and mode 0600 or stricter")


def private_open(path):
    """Open root/current-user-owned POSIX files without symlink/permission races.

    Traverse via directory FDs and O_NOFOLLOW. Public read/execute of ancestor
    directories is fine; public writes are not (except root-owned sticky
    ancestors, e.g. /tmp, never the immediate containing directory).
    Fail closed on platforms without the required permission semantics.
    """
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ClientError("cage-host requires a POSIX guest with ownership/mode checks")
    path = absolute_path(str(path))
    parts = Path(path).parts[1:]
    if not parts:
        raise ClientError("private file path is invalid")
    owners = {0, os.geteuid()}
    directory = None
    try:
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for index, part in enumerate(parts[:-1]):
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=directory)
            os.close(directory)
            directory = next_fd
            info = os.fstat(directory)
            validate_directory(info, owners, immediate=index == len(parts) - 2)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        try:
            info = os.fstat(fd)
            validate_private_file(info, owners)
            return os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise
    except OSError:
        raise ClientError("cannot securely open required private file") from None
    finally:
        if directory is not None:
            os.close(directory)


def private_read(path, limit=MAX_FILE):
    with private_open(path) as source:
        result = source.read(limit + 1)
    if len(result) > limit:
        raise ClientError("private file exceeds size limit")
    return result


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ClientError("port must be an integer between 1 and 65535")
    return value


def timeout(value, maximum):
    if type(value) not in (int, float) or not 0 < value <= maximum:
        raise ClientError("invalid timeout")
    return float(value)


def tailnet_host(value):
    if not isinstance(value, str) or len(value) > 253:
        raise ClientError("invalid configured tailnet host")
    value = value.lower().removesuffix(".")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        labels = value.split(".")
        if not labels or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
                                 for p in labels):
            raise ClientError("invalid configured tailnet host") from None
        if re.fullmatch(r"[0-9.]+", value):
            raise ClientError("invalid configured tailnet IP")
        # The proxy independently restricts all names to visible tailnet peers.
        if value == "localhost" or value.endswith(".localhost"):
            raise ClientError("loopback is not a tailnet host")
        return value
    if not isinstance(address, ipaddress.IPv4Address) or address not in ipaddress.ip_network("100.64.0.0/10"):
        raise ClientError("configured IP must be a tailnet IPv4 address")
    return str(address)


@dataclass(frozen=True)
class Config:
    host: str
    ssh_user: str
    ssh_port: int
    broker_port: int
    identity_file: str
    known_hosts_file: str
    broker_token_file: str
    control_file: str
    connect_timeout: float = 10.0
    broker_timeout: float = 300.0

    def destination(self, service):
        if service == "ssh":
            return self.host, self.ssh_port
        if service == "broker":
            return self.host, self.broker_port
        raise ClientError("destination is not configured")


def load_config(path):
    data = strict_json(private_read(path), "configuration JSON")
    required = {"version", "host", "ssh_user", "ssh_port", "broker_port",
                "identity_file", "known_hosts_file", "broker_token_file"}
    optional = {"control_file", "connect_timeout", "broker_timeout"}
    if not required <= data.keys() or data.keys() - required - optional or type(data["version"]) is not int or data["version"] != 1:
        raise ClientError("unsupported configuration schema (expected version 1)")
    user = data["ssh_user"]
    if not isinstance(user, str) or not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}", user):
        raise ClientError("invalid SSH user")
    return Config(tailnet_host(data["host"]), user, port(data["ssh_port"]), port(data["broker_port"]),
                  absolute_path(data["identity_file"]), absolute_path(data["known_hosts_file"]),
                  absolute_path(data["broker_token_file"]),
                  absolute_path(data.get("control_file", DEFAULT_CONTROL)),
                  timeout(data.get("connect_timeout", 10), 60),
                  timeout(data.get("broker_timeout", 300), 3600))


@dataclass(frozen=True)
class Proxy:
    address: str
    port: int
    token: str = field(repr=False)

    @property
    def authorization(self):
        return "Basic " + base64.b64encode(("cage:" + self.token).encode("ascii")).decode("ascii")


def discover_proxy(control_file):
    """Read the exact tools/tailnet/dial.go dialRecord on EVERY invocation."""
    record = strict_json(private_read(control_file), "tailnet control record")
    if set(record) != {"address", "token"} or not isinstance(record["address"], str):
        raise ClientError("invalid tailnet discovery schema")
    match = re.fullmatch(r"127\.0\.0\.1:([1-9][0-9]{0,4})", record["address"])
    token = record["token"]
    if not match or not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ClientError("invalid tailnet discovery endpoint or credential")
    return Proxy("127.0.0.1", port(int(match[1])), token)


def connect_tunnel(config, service):
    host, number = config.destination(service)  # Not caller-provided host/port.
    proxy = discover_proxy(config.control_file)
    connection = None
    try:
        deadline = time.monotonic() + config.connect_timeout
        connection = socket.create_connection((proxy.address, proxy.port), timeout=config.connect_timeout)
        target = f"{host}:{number}"
        request = (f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
                   f"Proxy-Authorization: {proxy.authorization}\r\n\r\n").encode("ascii")
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        connection.sendall(request)
        # Avoid buffered read-ahead: the first SSH/application byte must survive.
        response = bytearray()
        while not response.endswith(b"\r\n\r\n"):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            connection.settimeout(remaining)
            chunk = connection.recv(1)
            if not chunk:
                raise ClientError("tailnet proxy closed during CONNECT")
            response += chunk
            if len(response) > 8192:
                raise ClientError("tailnet CONNECT headers exceed size limit")
        status = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?", bytes(response).split(b"\r\n", 1)[0])
        if not status:
            raise ClientError("invalid tailnet CONNECT response")
        for line in bytes(response).split(b"\r\n")[1:-2]:
            if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e\x80-\xff]*", line):
                raise ClientError("invalid tailnet CONNECT headers")
        code = int(status[1])
        if code != 200:
            raise ClientError(f"tailnet CONNECT refused (HTTP {code}); no fallback attempted")
        connection.settimeout(None)
        return connection, proxy
    except (TimeoutError, socket.timeout):
        if connection is not None:
            connection.close()
        raise ClientError("tailnet CONNECT timed out; no fallback attempted") from None
    except OSError:
        if connection is not None:
            connection.close()
        raise ClientError("tailnet proxy unavailable; no fallback attempted") from None
    except BaseException:
        if connection is not None:
            connection.close()
        raise


def relay(connection, source, destination):
    """Forward binary stdin/stdout; an input FIN does not truncate replies."""
    failures = []
    def upload():
        try:
            while True:
                # read1 avoids waiting to fill a buffer on interactive streams.
                block = source.read1(65536) if hasattr(source, "read1") else source.read(65536)
                if not block:
                    connection.shutdown(socket.SHUT_WR)
                    return
                connection.sendall(block)
        except OSError:
            failures.append(True)
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
    thread = threading.Thread(target=upload, daemon=True)
    thread.start()
    try:
        while True:
            block = connection.recv(65536)
            if not block:
                break
            destination.write(block)
            destination.flush()
        if failures:
            raise ClientError("tailnet stream upload failed")
    except OSError:
        raise ClientError("tailnet stream interrupted") from None
    finally:
        connection.close()
    # Do not wait forever on terminal stdin after the remote closes its stream.


def ssh_option_path(path):
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def ssh_arguments(config, config_path, command=None):
    # OpenSSH can parse options after its destination, too. Never let a remote
    # command string become a second set of guest-side SSH options.
    if command is not None and command.startswith("-"):
        raise ClientError("SSH remote command must not begin with '-' (options are forbidden)")
    # No user/global ssh_config can override routing, key verification, or hooks.
    for private in (config.identity_file, config.known_hosts_file):
        with private_open(private):
            pass
    script = str(Path(__file__).absolute())
    # OpenSSH expands %-tokens even inside shell quotes. Escape every literal %.
    proxy = shlex.join([sys.executable, "-I", script, "--config", absolute_path(config_path), "_connect", "ssh"]).replace("%", "%%")
    options = {
        "ProxyCommand": proxy, "ProxyUseFdpass": "no", "ProxyJump": "none",
        "StrictHostKeyChecking": "yes", "UserKnownHostsFile": ssh_option_path(config.known_hosts_file),
        "GlobalKnownHostsFile": "/dev/null", "VerifyHostKeyDNS": "no", "UpdateHostKeys": "no",
        "BatchMode": "yes", "IdentitiesOnly": "yes", "IdentityAgent": "none",
        "PreferredAuthentications": "publickey", "PasswordAuthentication": "no",
        "KbdInteractiveAuthentication": "no", "GSSAPIAuthentication": "no",
        "ForwardAgent": "no", "ForwardX11": "no", "ClearAllForwardings": "yes",
        "ControlMaster": "no", "ControlPath": "none", "ControlPersist": "no",
        "PermitLocalCommand": "no", "EscapeChar": "none", "ConnectionAttempts": "1",
        "ConnectTimeout": str(max(1, int(config.connect_timeout))),
    }
    arguments = ["/usr/bin/ssh", "-F", "/dev/null"]
    for name, value in options.items():
        arguments += ["-o", name + "=" + value]
    arguments += ["-i", config.identity_file, "-p", str(config.ssh_port), "-l", config.ssh_user, config.host]
    if command is not None:
        arguments.append(command)
    return arguments


class TunnelHTTPConnection(http.client.HTTPConnection):
    """A dropped tunnel must never trigger HTTPConnection's direct reconnect."""
    auto_open = 0

    def connect(self):
        raise ClientError("direct broker connections are forbidden")


def broker_token(path):
    try:
        token = private_read(path, 4096).decode("ascii").strip()
    except UnicodeError:
        raise ClientError("invalid broker token encoding") from None
    if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{32,4096}", token):
        raise ClientError("invalid broker token")
    return token


def request_document(data):
    document = strict_json(data, "broker request JSON")
    if set(document) != {"command", "reason"} or any(not isinstance(document[k], str) or not document[k].strip() or "\x00" in document[k]
                                                       for k in ("command", "reason")):
        raise ClientError("run request requires nonempty command and reason strings only")
    try:
        encoded = json.dumps(document, ensure_ascii=False).encode("utf-8")
    except UnicodeError:
        raise ClientError("broker request must contain valid UTF-8 text") from None
    if len(encoded) > (1 << 20):
        raise ClientError("broker request exceeds size limit")
    return document


def broker_call(config, action, document=None):
    if action not in ("health", "run"):
        raise ClientError("unknown broker action")
    if action == "run":
        document = request_document(json.dumps(document).encode("utf-8"))
    token = broker_token(config.broker_token_file)
    connection, proxy = connect_tunnel(config, "broker")
    connection.settimeout(config.broker_timeout)
    client = TunnelHTTPConnection(config.host, config.broker_port, timeout=config.broker_timeout)
    client.sock = connection
    started = False
    try:
        headers = {"Authorization": "Bearer " + token, "Connection": "close", "Accept": "application/json"}
        body = None
        if action == "run":
            body = json.dumps(document, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        started = True
        client.request("POST" if action == "run" else "GET", "/run" if action == "run" else "/health", body=body, headers=headers)
        response = client.getresponse()
        if response.status != 200:
            raise ClientError(f"broker HTTP {response.status}; response body withheld")
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ClientError("broker response exceeds size limit")
        result = strict_json(raw, "broker response JSON")
        if action == "health":
            if result.get("ok") is not True or ("pid" in result and (type(result["pid"]) is not int or result["pid"] <= 0)):
                raise ClientError("invalid broker health schema")
            health = {"ok": True}
            if "pid" in result:
                health["pid"] = result["pid"]
            return health, 0
        if (type(result.get("approved")) is not bool or type(result.get("exit_code")) is not int
                or not isinstance(result.get("output"), str)
                or ("executed" in result and type(result["executed"]) is not bool)
                or ("error" in result and not isinstance(result["error"], str))):
            raise ClientError("invalid broker run response schema")
        # Preserve execution/error metadata, but never reflect known credentials.
        cleaned = {"approved": result["approved"], "exit_code": result["exit_code"]}
        for field in ("output", "error"):
            if field in result:
                text = result[field]
                for secret in (token, proxy.token, proxy.authorization):
                    text = text.replace(secret, "[REDACTED]")
                cleaned[field] = text
        if "executed" in result:
            cleaned["executed"] = result["executed"]
        result = cleaned
        if not result["approved"]:
            return result, 3
        if result.get("executed") is False:
            return result, 1
        code = result["exit_code"]
        return result, code if 0 <= code <= 255 else 1
    except (OSError, http.client.HTTPException):
        suffix = "; execution outcome unknown; do not automatically retry" if action == "run" and started else ""
        raise ClientError("broker transport failed" + suffix) from None
    except ClientError as error:
        if action == "run" and started:
            raise ClientError(str(error) + "; execution outcome may be unknown; do not automatically retry") from None
        raise
    finally:
        client.close()
        connection.close()


def parser():
    result = argparse.ArgumentParser(prog="cage-host", description="Guest SSH and approval broker via Cage tailnet only")
    result.add_argument("--config", default=DEFAULT_CONFIG, help="private version-1 JSON configuration")
    commands = result.add_subparsers(dest="action", required=True)
    ssh = commands.add_parser("ssh", help="SSH with pinned host keys; optional single remote command string")
    ssh.add_argument("command", nargs="?")
    commands.add_parser("health", help="read-only authenticated broker health check")
    run = commands.add_parser("run", help="explicitly submit ONE approval request; never retried")
    run.add_argument("--request", default="-", help="JSON {command,reason} file; '-' reads stdin")
    connect = commands.add_parser("_connect", help=argparse.SUPPRESS)
    connect.add_argument("service", choices=["ssh", "broker"])
    return result


def main(argv=None):
    arguments = parser().parse_args(argv)
    try:
        config_path = absolute_path(arguments.config)
        config = load_config(config_path)
        if arguments.action == "_connect":
            connection, _ = connect_tunnel(config, arguments.service)
            relay(connection, sys.stdin.buffer, sys.stdout.buffer)
            return 0
        if arguments.action == "ssh":
            completed = subprocess.run(ssh_arguments(config, config_path, arguments.command), check=False)
            return completed.returncode if completed.returncode >= 0 else 128 - completed.returncode
        document = None
        if arguments.action == "run":
            if arguments.request == "-":
                data = sys.stdin.buffer.read((1 << 20) + 1)
            else:
                data = private_read(absolute_path(arguments.request), 1 << 20)
            if len(data) > (1 << 20):
                raise ClientError("broker request exceeds size limit")
            document = request_document(data)
        result, code = broker_call(config, arguments.action, document)
        print(json.dumps(result, ensure_ascii=False))
        if arguments.action == "run" and not result["approved"]:
            print("cage-host: request denied by approval broker", file=sys.stderr)
        elif code:
            print("cage-host: broker reported nonzero child status " + str(result["exit_code"]), file=sys.stderr)
        return code
    except ClientError as error:
        print("cage-host: " + str(error), file=sys.stderr)
        return 2
    except OSError:
        print("cage-host: local I/O or SSH launch failed", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("cage-host: interrupted; any submitted execution outcome is unknown; do not retry automatically", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
