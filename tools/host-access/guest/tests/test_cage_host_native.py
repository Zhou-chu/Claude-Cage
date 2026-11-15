"""Native SSH configuration tests; no live SSH, broker, dialogs or network."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

source = Path(__file__).resolve().parents[1] / "cage_host_native.py"
spec = importlib.util.spec_from_file_location("native_config_test", source)
native = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = native
spec.loader.exec_module(native)


def config():
    return SimpleNamespace(host="100.64.0.20", ssh_user="cageops", ssh_port=22,
                           identity_file="/home/fixture/.ssh/id_ed25519",
                           known_hosts_file="/home/fixture/.config/cage-host/known_hosts",
                           connect_timeout=10)


class NativeConfigTests(unittest.TestCase):
    def test_builtin_transport_fixed_target(self):
        text = native.render(config())
        self.assertIn("Host windows-host\n", text)
        self.assertIn("ProxyCommand /usr/local/bin/cage-tailnet dial 100.64.0.20 22\n", text)
        self.assertNotIn("%h", text)
        self.assertNotIn("Bearer", text)
        self.assertNotIn("Proxy-Authorization", text)

    def test_pinned_key_and_standard_user(self):
        text = native.render(config())
        for option in ("User cageops", "StrictHostKeyChecking yes", "GlobalKnownHostsFile /dev/null",
                       'IdentityFile "/home/fixture/.ssh/id_ed25519"',
                       'UserKnownHostsFile "/home/fixture/.config/cage-host/known_hosts"',
                       "IdentityAgent none", "IdentitiesOnly yes", "BatchMode yes",
                       "PasswordAuthentication no", "KbdInteractiveAuthentication no"):
            self.assertIn("    " + option + "\n", text)

    def test_no_forwarding_multiplex_or_hooks(self):
        text = native.render(config())
        for option in ("ForwardAgent no", "ClearAllForwardings yes", "ControlMaster no",
                       "ControlPath none", "ControlPersist no", "PermitLocalCommand no",
                       "LocalCommand none", "RemoteCommand none", "ProxyJump none"):
            self.assertIn("    " + option + "\n", text)

    def test_scope_reset(self):
        self.assertTrue(native.render(config()).endswith("Host *\n"))

    def test_existing_cage_rules_preserved(self):
        original = 'Include "/home/fixture/.config/cage-tailnet/ssh_config"\nHost other\n    User original\n'
        result = native.include_config(original, "/home/fixture/private.conf")
        self.assertTrue(result.endswith(original))
        self.assertTrue(result.startswith('Include "/home/fixture/private.conf"\n'))

    def test_install_idempotence(self):
        once = native.include_config("# original\n", "/home/fixture/private.conf")
        self.assertEqual(native.include_config(once, "/home/fixture/private.conf"), once)

    def test_misplaced_include_fails_closed(self):
        with self.assertRaises(native.client.ClientError):
            native.include_config('Host *\nInclude "/home/fixture/private.conf"\n', "/home/fixture/private.conf")

    def test_symlink_configuration_refused(self):
        path = mock.Mock()
        path.is_symlink.return_value = True
        with self.assertRaises(native.client.ClientError):
            native.existing(path)
        path.read_bytes.assert_not_called()

    def test_usage_keeps_permission_and_desktop_boundary(self):
        text = native.usage(config())
        self.assertIn("ssh windows-host", text)
        self.assertIn("sftp windows-host", text)
        self.assertIn("cage-host run", text)
        self.assertIn("尚未验收", text)
        self.assertIn("纯聊天模式", text)
        self.assertNotIn("sudo", text)


if __name__ == "__main__":
    unittest.main()
