"""Isolated unittest coverage. No VM, sshd, real broker, or approval requests."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "cage_host.py"
spec = importlib.util.spec_from_file_location("cage_host", MODULE_PATH)
client = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = client
spec.loader.exec_module(client)

TOKEN = "a" * 64  # Synthetic unit-test fixture, never a real credential.
BROKER_TOKEN = "b" * 64


def config(**changes):
    fields = dict(host="fixture-host.example.ts.net", ssh_user="fixture-user", ssh_port=2222,
                  broker_port=8642, identity_file="/private/key", known_hosts_file="/private/known_hosts",
                  broker_token_file="/private/token", control_file="/private/control.json",
                  connect_timeout=0.5, broker_timeout=1.0)
    fields.update(changes)
    return client.Config(**fields)


def record(**changes):
    fields = dict(address="127.0.0.1:43210", token=TOKEN)
    fields.update(changes)
    return json.dumps(fields).encode()


class FakeSocket:
    def __init__(self, response=b"HTTP/1.1 200 Connection Established\r\n\r\n"):
        self.incoming = io.BytesIO(response)
        self.sent = []
        self.timeouts = []
        self.closed = False
        self.shutdowns = []

    def sendall(self, data):
        self.sent.append(bytes(data))

    def recv(self, number):
        return self.incoming.read(number)

    def settimeout(self, value):
        self.timeouts.append(value)

    def makefile(self, *args, **kwargs):
        return self.incoming

    def close(self):
        self.closed = True

    def shutdown(self, how):
        self.shutdowns.append(how)


def http_response(body, status=200):
    if not isinstance(body, bytes):
        body = json.dumps(body).encode()
    return (f"HTTP/1.1 {status} Test\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)


class DiscoveryTests(unittest.TestCase):
    def discover(self, data):
        with mock.patch.object(client, "private_read", return_value=data):
            return client.discover_proxy("/fixture")

    def test_exact_record(self):
        proxy = self.discover(record())
        self.assertEqual((proxy.address, proxy.port), ("127.0.0.1", 43210))
        self.assertEqual(proxy.authorization, "Basic " + client.base64.b64encode(("cage:" + TOKEN).encode()).decode())
        self.assertNotIn(TOKEN, repr(proxy))

    def test_invalid_schemas(self):
        examples = [b"[]", b"null", b"{}", b"not-json", b'{"address":1,"token":"x"}',
                    record(address="localhost:123"), record(address="127.0.0.2:123"),
                    record(address="192.0.2.1:123"), record(address="127.0.0.1:0"),
                    record(address="127.0.0.1:65536"), record(address="127.0.0.1:0123"),
                    record(address="127.0.0.1:123\r\nX: injected"),
                    record(token="x"), record(token="A" * 64), record(extra="unexpected"),
                    b'{"address":"127.0.0.1:1","address":"127.0.0.1:2","token":"' + TOKEN.encode() + b'"}']
        for example in examples:
            with self.subTest(example=example), self.assertRaises(client.ClientError) as error:
                self.discover(example)
            self.assertNotIn(TOKEN, str(error.exception))

    def test_rotation_is_read_each_time(self):
        with mock.patch.object(client, "private_read", side_effect=[record(), record(address="127.0.0.1:54321", token="c" * 64)]) as read:
            first = client.discover_proxy("/fixture")
            second = client.discover_proxy("/fixture")
        self.assertEqual(read.call_count, 2)
        self.assertNotEqual(first.port, second.port)
        self.assertNotEqual(first.token, second.token)

    def test_no_proxy_environment_fallback(self):
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://public.invalid:80", "ALL_PROXY": "socks5://public.invalid:80"}), \
             mock.patch.object(client, "private_read", side_effect=client.ClientError("missing")), \
             mock.patch.object(client.socket, "create_connection") as create:
            with self.assertRaises(client.ClientError):
                client.connect_tunnel(config(), "ssh")
            create.assert_not_called()


class PermissionTests(unittest.TestCase):
    @staticmethod
    def info(mode=0o600, uid=1000, links=1, kind=stat.S_IFREG):
        return types.SimpleNamespace(st_mode=kind | mode, st_uid=uid, st_nlink=links)

    def test_private_file_modes(self):
        for mode in (0o600, 0o400):
            client.validate_private_file(self.info(mode), {0, 1000})
        client.validate_private_file(self.info(uid=0), {0, 1000})

    def test_loose_modes_wrong_owner_links_nonregular_rejected(self):
        for info in [self.info(0o644), self.info(0o640), self.info(0o606), self.info(0o700), self.info(0o000), self.info(uid=2000),
                     self.info(links=2), self.info(kind=stat.S_IFDIR), self.info(kind=stat.S_IFLNK)]:
            with self.subTest(info=info), self.assertRaises(client.ClientError):
                client.validate_private_file(info, {0, 1000})

    def test_unsafe_directory_rejected(self):
        for mode, uid, immediate in [(0o777, 1000, True), (0o775, 1000, False),
                                     (0o755, 2000, False), (0o1777, 0, True)]:
            with self.subTest(mode=mode), self.assertRaises(client.ClientError):
                client.validate_directory(self.info(mode, uid, kind=stat.S_IFDIR), {0, 1000}, immediate)
        client.validate_directory(self.info(0o755, kind=stat.S_IFDIR), {0, 1000}, True)
        client.validate_directory(self.info(0o1777, uid=0, kind=stat.S_IFDIR), {0, 1000}, False)

    @unittest.skipUnless(os.name == "posix", "real ownership/O_NOFOLLOW checks require POSIX")
    def test_real_private_file_symlink_and_permission_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            path = Path(directory) / "token"
            path.write_bytes(b"fixture")
            path.chmod(0o600)
            self.assertEqual(client.private_read(str(path)), b"fixture")
            path.chmod(0o644)
            with self.assertRaises(client.ClientError):
                client.private_read(str(path))
            path.chmod(0o600)
            alias = Path(directory) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(client.ClientError):
                client.private_read(str(alias))
            directory_alias = Path(directory) / "directory-alias"
            directory_alias.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(client.ClientError):
                client.private_read(str(directory_alias / "token"))
            with self.assertRaises(client.ClientError):
                client.private_read(str(path), 2)

    def test_nonposix_fails_closed(self):
        with mock.patch.object(client.os, "name", "nt"):
            with self.assertRaisesRegex(client.ClientError, "POSIX"):
                client.private_open("/fixture")


class ConfigTests(unittest.TestCase):
    def raw(self):
        return dict(version=1, host="fixture-host.example.ts.net", ssh_user="fixture-user", ssh_port=22,
                    broker_port=8642, identity_file="/private/key", known_hosts_file="/private/known_hosts",
                    broker_token_file="/private/token")

    def load(self, data):
        with mock.patch.object(client, "private_read", return_value=json.dumps(data).encode()), \
             mock.patch.object(client, "absolute_path", side_effect=lambda p: p):
            return client.load_config("/fixture")

    def test_valid(self):
        self.assertEqual(self.load(self.raw()).ssh_port, 22)

    def test_invalid_fields(self):
        for key, value in [("version", True), ("version", 2), ("ssh_port", True), ("ssh_port", 0),
                           ("broker_port", 65536), ("ssh_user", "user -o ProxyCommand=evil"),
                           ("host", "public.invalid:80"), ("host", "127.0.0.1"),
                           ("host", "192.0.2.4"), ("host", "localhost"),
                           ("connect_timeout", 0), ("connect_timeout", float("nan")),
                           ("broker_timeout", 3601), ("unknown", 1)]:
            data = self.raw()
            data[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(client.ClientError):
                self.load(data)

    def test_required_fields(self):
        for key in self.raw():
            data = self.raw()
            del data[key]
            with self.subTest(key=key), self.assertRaises(client.ClientError):
                self.load(data)

    def test_hosts(self):
        self.assertEqual(client.tailnet_host("Fixture-Host.Example.TS.Net."), "fixture-host.example.ts.net")
        self.assertEqual(client.tailnet_host("100.64.0.1"), "100.64.0.1")
        for invalid in ["", "-bad", "bad..host", "bad\r\nhost", "::1", "100.128.0.1", "100.64.0.999"]:
            with self.subTest(invalid=invalid), self.assertRaises(client.ClientError):
                client.tailnet_host(invalid)

    def test_service_allowlist(self):
        for service in ["http", "public.invalid:80", "SSH"]:
            with self.assertRaises(client.ClientError):
                config().destination(service)

    def test_path_injection_rejected(self):
        for value in ["", "relative", "/x\ny", "/x%h", "/x\x00y", "/x/../y"]:
            with self.subTest(value=value), self.assertRaises(client.ClientError):
                client.absolute_path(value)


class ConnectTests(unittest.TestCase):
    def connect(self, sock, service="ssh"):
        with mock.patch.object(client, "discover_proxy", return_value=client.Proxy("127.0.0.1", 43210, TOKEN)), \
             mock.patch.object(client.socket, "create_connection", return_value=sock) as create:
            result, proxy = client.connect_tunnel(config(), service)
            create.assert_called_once_with(("127.0.0.1", 43210), timeout=0.5)
            return result

    def test_auth_and_target_bytes_preserved(self):
        sock = FakeSocket(b"HTTP/1.1 200 Connection Established\r\n\r\nSSH-2.0-fixture\r\n")
        self.assertIs(self.connect(sock), sock)
        self.assertEqual(sock.recv(99), b"SSH-2.0-fixture\r\n")
        request = b"".join(sock.sent)
        self.assertTrue(request.startswith(b"CONNECT fixture-host.example.ts.net:2222 HTTP/1.1\r\n"))
        self.assertIn(b"Proxy-Authorization: Basic ", request)
        self.assertNotIn(TOKEN.encode(), request)
        self.assertIsNone(sock.timeouts[-1])

    def test_broker_only_configured_port(self):
        sock = FakeSocket()
        self.connect(sock, "broker")
        self.assertIn(b":8642 HTTP/1.1", sock.sent[0])

    def test_connect_refusals_and_malformed_response(self):
        examples = [(b"HTTP/1.1 407 secret\r\n\r\n", "407"),
                    (b"HTTP/1.1 502 secret\r\n\r\n", "502"),
                    (b"HTTP/1.1 302 secret\r\n\r\n", "302"),
                    (b"nonsense\r\n\r\n", "invalid"),
                    (b"HTTP/1.1 200 OK\r\nnot-a-header\r\n\r\n", "invalid"),
                    (b"HTTP/1.1 200 OK\r\nX: value\x00injection\r\n\r\n", "invalid"), (b"", "closed"),
                    (b"HTTP/1.1 200 OK\r\nX: " + b"a" * 8192, "size limit")]
        for response, diagnostic in examples:
            sock = FakeSocket(response)
            with self.subTest(diagnostic=diagnostic), self.assertRaises(client.ClientError) as error:
                self.connect(sock)
            self.assertIn(diagnostic, str(error.exception))
            self.assertNotIn("secret", str(error.exception))
            self.assertTrue(sock.closed)

    def test_connect_timeout_closes_socket(self):
        sock = FakeSocket()
        sock.recv = mock.Mock(side_effect=socket.timeout("secret"))
        with self.assertRaisesRegex(client.ClientError, "timed out"):
            self.connect(sock)
        self.assertTrue(sock.closed)

    def test_refused_connection_never_retries(self):
        with mock.patch.object(client, "discover_proxy", return_value=client.Proxy("127.0.0.1", 43210, TOKEN)), \
             mock.patch.object(client.socket, "create_connection", side_effect=OSError("secret")) as create:
            with self.assertRaisesRegex(client.ClientError, "no fallback"):
                client.connect_tunnel(config(), "ssh")
            self.assertEqual(create.call_count, 1)

    def test_absolute_handshake_deadline(self):
        sock = FakeSocket()
        with mock.patch.object(client, "discover_proxy", return_value=client.Proxy("127.0.0.1", 43210, TOKEN)), \
             mock.patch.object(client.socket, "create_connection", return_value=sock), \
             mock.patch.object(client.time, "monotonic", side_effect=[0, 0.1, 0.6]):
            with self.assertRaisesRegex(client.ClientError, "timed out"):
                client.connect_tunnel(config(), "ssh")
        self.assertTrue(sock.closed)

    def test_relay_half_close_preserves_binary_reply(self):
        sock = FakeSocket(b"\x00\xffreply")
        destination = io.BytesIO()
        client.relay(sock, io.BytesIO(b"\x00request"), destination)
        self.assertEqual(destination.getvalue(), b"\x00\xffreply")
        self.assertEqual(b"".join(sock.sent), b"\x00request")
        self.assertIn(socket.SHUT_WR, sock.shutdowns)
        self.assertTrue(sock.closed)


class BrokerTests(unittest.TestCase):
    def call(self, body, action="run", status=200):
        sock = FakeSocket(http_response(body, status))
        with mock.patch.object(client, "broker_token", return_value=BROKER_TOKEN), \
             mock.patch.object(client, "connect_tunnel", return_value=(sock, client.Proxy("127.0.0.1", 43210, TOKEN))) as connect, \
             mock.patch.object(client.socket, "create_connection") as direct:
            result = client.broker_call(config(), action, {"command": "fixture command", "reason": "fixture test"} if action == "run" else None)
            connect.assert_called_once()
            direct.assert_not_called()
        return result, sock

    def test_health_is_get_not_post(self):
        (result, code), sock = self.call({"ok": True, "pid": 42}, "health")
        self.assertEqual((result, code), ({"ok": True, "pid": 42}, 0))
        request = b"".join(sock.sent)
        self.assertIn(b"GET /health HTTP/1.1", request)
        self.assertNotIn(b"POST", request)
        self.assertNotIn(b"Proxy-Authorization", request)
        self.assertIn(b"Authorization: Bearer " + BROKER_TOKEN.encode(), request)
        self.assertTrue(sock.closed)

    def test_new_health_without_pid(self):
        (result, code), _ = self.call({"ok": True}, "health")
        self.assertEqual((result, code), ({"ok": True}, 0))

    def test_uac_cancel_and_execution_metadata(self):
        (result, code), _ = self.call({"approved": True, "executed": False,
                                      "exit_code": -1, "output": "",
                                      "error": "UAC cancelled " + BROKER_TOKEN})
        self.assertEqual(code, 1)
        self.assertFalse(result["executed"])
        self.assertIn("UAC cancelled", result["error"])
        self.assertNotIn(BROKER_TOKEN, result["error"])
        (_, code), _ = self.call({"approved": True, "executed": False,
                                 "exit_code": 0, "output": ""})
        self.assertNotEqual(code, 0)

    def test_explicit_run_single_post_exact_json(self):
        (result, code), sock = self.call({"approved": True, "exit_code": 0, "output": "done"})
        self.assertEqual(code, 0)
        request = b"".join(sock.sent)
        self.assertEqual(request.count(b"POST /run HTTP/1.1"), 1)
        self.assertEqual(json.loads(request.split(b"\r\n\r\n", 1)[1]), {"command": "fixture command", "reason": "fixture test"})

    def test_denial_and_nonzero_child_codes(self):
        for response, expected in [({"approved": False, "exit_code": 0, "output": ""}, 3),
                                   ({"approved": True, "exit_code": 17, "output": "failed"}, 17),
                                   ({"approved": True, "exit_code": -1, "output": "failed"}, 1),
                                   ({"approved": True, "exit_code": 65536, "output": "failed"}, 1)]:
            with self.subTest(response=response):
                (result, code), _ = self.call(response)
                self.assertEqual(code, expected)
                self.assertEqual(result["exit_code"], response["exit_code"])

    def test_secret_echo_redacted(self):
        proxy = client.Proxy("127.0.0.1", 43210, TOKEN)
        (result, _), _ = self.call({"approved": True, "exit_code": 0,
                                   "output": TOKEN + BROKER_TOKEN + proxy.authorization})
        for secret in (TOKEN, BROKER_TOKEN, proxy.authorization):
            self.assertNotIn(secret, result["output"])

    def test_http_errors_no_response_body_leak(self):
        for status in [301, 401, 403, 500]:
            with self.subTest(status=status), self.assertRaises(client.ClientError) as error:
                self.call((TOKEN + BROKER_TOKEN).encode(), status=status)
            self.assertIn(str(status), str(error.exception))
            self.assertIn("do not automatically retry", str(error.exception))
            self.assertNotIn(TOKEN, str(error.exception))
            self.assertNotIn(BROKER_TOKEN, str(error.exception))

    def test_invalid_response_schemas(self):
        for body in [{}, {"approved": "yes", "exit_code": 0, "output": ""},
                     {"approved": True, "exit_code": True, "output": ""},
                     {"approved": True, "exit_code": 0}, b"not-json"]:
            with self.subTest(body=body), self.assertRaises(client.ClientError):
                self.call(body)
        for body in [{"ok": False, "pid": 42}, {"ok": True, "pid": True}, {"ok": True, "pid": 0}]:
            with self.subTest(body=body), self.assertRaises(client.ClientError):
                self.call(body, "health")

    def test_request_schema(self):
        for body in [b"[]", b"null", b"{}", '{"command":"a","reason":"b"}'.encode("utf-16"),
                     b'{"command":"a","reason":"\\ud800"}', b'{"command":"a","reason":"b","extra":1}',
                     b'{"command":"","reason":"b"}', b'{"command":"a","reason":""}',
                     b'{"command":"a","reason":1}', b'{"command":"a","reason":"b\\u0000"}']:
            with self.subTest(body=body), self.assertRaises(client.ClientError):
                client.request_document(body)

    def test_timeout_after_post_no_retry(self):
        sock = FakeSocket()
        sock.makefile = mock.Mock(side_effect=socket.timeout("credential should not appear"))
        with mock.patch.object(client, "broker_token", return_value=BROKER_TOKEN), \
             mock.patch.object(client, "connect_tunnel", return_value=(sock, client.Proxy("127.0.0.1", 43210, TOKEN))) as connect:
            with self.assertRaisesRegex(client.ClientError, "outcome unknown") as error:
                client.broker_call(config(), "run", {"command": "fixture", "reason": "test"})
            connect.assert_called_once()
        self.assertNotIn("credential should not appear", str(error.exception))
        self.assertEqual(b"".join(sock.sent).count(b"POST /run HTTP/1.1"), 1)
        self.assertTrue(sock.closed)

    def test_direct_reconnect_forbidden(self):
        with self.assertRaisesRegex(client.ClientError, "forbidden"):
            client.TunnelHTTPConnection("public.invalid").connect()
        self.assertEqual(client.TunnelHTTPConnection.auto_open, 0)

    def test_broker_token_validation(self):
        for value in [b"short", b"x" * 32 + b"\r\nHeader: evil", b"\xff" * 32]:
            with mock.patch.object(client, "private_read", return_value=value), self.assertRaises(client.ClientError):
                client.broker_token("/fixture")
        with mock.patch.object(client, "private_read", return_value=BROKER_TOKEN.encode() + b"\n"):
            self.assertEqual(client.broker_token("/fixture"), BROKER_TOKEN)


class SSHAndCLITests(unittest.TestCase):
    def arguments(self, command=None):
        with mock.patch.object(client, "private_open", side_effect=lambda _: io.BytesIO(b"fixture")), \
             mock.patch.object(client, "absolute_path", side_effect=lambda p: p):
            return client.ssh_arguments(config(), "/fixture/config.json", command)

    def test_ssh_route_strict_keys_and_no_user_config(self):
        arguments = self.arguments("fixture command")
        self.assertEqual(arguments[:3], ["/usr/bin/ssh", "-F", "/dev/null"])
        options = [arguments[i + 1] for i, arg in enumerate(arguments[:-1]) if arg == "-o"]
        for required in ["StrictHostKeyChecking=yes", "ProxyJump=none", "IdentityAgent=none",
                         "ControlMaster=no", "ControlPath=none", "ClearAllForwardings=yes",
                         "PasswordAuthentication=no", "PermitLocalCommand=no", "ForwardAgent=no"]:
            self.assertIn(required, options)
        proxy = next(o for o in options if o.startswith("ProxyCommand="))
        self.assertIn(" -I ", proxy)
        self.assertTrue(proxy.endswith("_connect ssh"))
        self.assertNotIn(TOKEN, proxy)
        self.assertEqual(arguments[-2:], [config().host, "fixture command"])

    def test_remote_command_cannot_override_ssh_options(self):
        for command in ["-oProxyCommand=evil", "-F /untrusted/config", "--"]:
            with self.subTest(command=command), self.assertRaisesRegex(client.ClientError, "options are forbidden"):
                self.arguments(command)

    def test_ssh_exit_preserved(self):
        with mock.patch.object(client, "absolute_path", side_effect=lambda p: p), \
             mock.patch.object(client, "load_config", return_value=config()), \
             mock.patch.object(client, "ssh_arguments", return_value=["/fixture/ssh"]), \
             mock.patch.object(client.subprocess, "run", return_value=types.SimpleNamespace(returncode=23)) as run:
            self.assertEqual(client.main(["--config", "/fixture", "ssh", "fixture command"]), 23)
            run.assert_called_once_with(["/fixture/ssh"], check=False)

    def test_unknown_destination_cli_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            client.parser().parse_args(["_connect", "public.invalid:80"])

    def test_cli_denial_explicit(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(client, "absolute_path", side_effect=lambda p: p), \
             mock.patch.object(client, "load_config", return_value=config()), \
             mock.patch.object(client, "private_read", return_value=b'{"command":"fixture","reason":"test"}'), \
             mock.patch.object(client, "broker_call", return_value=({"approved": False, "exit_code": 0, "output": ""}, 3)), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = client.main(["--config", "/fixture", "run", "--request", "/request"])
        self.assertEqual(code, 3)
        self.assertIn("denied", stderr.getvalue())
        self.assertFalse(json.loads(stdout.getvalue())["approved"])

    def test_cli_nonzero_explicit(self):
        stderr = io.StringIO()
        with mock.patch.object(client, "absolute_path", side_effect=lambda p: p), \
             mock.patch.object(client, "load_config", return_value=config()), \
             mock.patch.object(client, "private_read", return_value=b'{"command":"fixture","reason":"test"}'), \
             mock.patch.object(client, "broker_call", return_value=({"approved": True, "exit_code": 9, "output": "failed"}, 9)), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            self.assertEqual(client.main(["--config", "/fixture", "run", "--request", "/request"]), 9)
        self.assertIn("nonzero child status 9", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
