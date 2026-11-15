"""Private Desktop MCP merge tests; no live Desktop, SSH or login access."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

source = Path(__file__).resolve().parents[1] / "cage_desktop_ssh_setup.py"
spec = importlib.util.spec_from_file_location("desktop_ssh_setup_test", source)
setup = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = setup
spec.loader.exec_module(setup)
HOME = Path.home() / "fixture-home"


class DesktopMergeTests(unittest.TestCase):
    def test_new_config_contains_only_local_server(self):
        result, changed = setup.merge(None, HOME)
        self.assertTrue(changed)
        data = json.loads(result)
        self.assertEqual(list(data), ["mcpServers"])
        entry = data["mcpServers"]["cage_ssh"]
        self.assertEqual(entry["command"], "/usr/bin/python3")
        self.assertIn("-I", entry["args"])
        self.assertIn("--targets", entry["args"])
        self.assertNotIn("env", entry)

    def test_existing_settings_and_other_servers_preserved(self):
        old = {"preferences": {"example": False}, "mcpServers": {
            "other": {"command": "existing-command", "env": {"FIXTURE": "not-a-real-secret"}}}}
        result, changed = setup.merge(json.dumps(old).encode(), HOME)
        self.assertTrue(changed)
        data = json.loads(result)
        self.assertEqual(data["preferences"], old["preferences"])
        self.assertEqual(data["mcpServers"]["other"], old["mcpServers"]["other"])

    def test_repeat_install_preserves_exact_bytes(self):
        once, _ = setup.merge(None, HOME)
        twice, changed = setup.merge(once, HOME)
        self.assertFalse(changed)
        self.assertEqual(once, twice)

    def test_user_disabled_choice_is_not_overridden(self):
        entry = dict(setup.entry(HOME), disabled=True)
        original = json.dumps({"mcpServers": {"cage_ssh": entry}}).encode()
        result, changed = setup.merge(original, HOME)
        self.assertFalse(changed)
        self.assertEqual(result, original)

    def test_conflicting_server_is_not_overwritten(self):
        with self.assertRaises(setup.client.ClientError):
            setup.merge(b'{"mcpServers":{"cage_ssh":{"command":"different"}}}', HOME)

    def test_bad_configuration_fails_closed(self):
        for value in (b'not JSON', b'[]', b'{"mcpServers":null}', b'{"mcpServers":[]}',
                      b'{"mcpServers":{},"mcpServers":{}}'):
            with self.subTest(value=value):
                with self.assertRaises(setup.client.ClientError):
                    setup.merge(value, HOME)

    def test_symlink_configuration_is_not_read(self):
        path = mock.Mock()
        path.is_symlink.return_value = True
        with self.assertRaises(setup.client.ClientError):
            setup.read_optional(path)
        path.exists.assert_not_called()

    def test_guide_distinguishes_cloud_shell_from_local_tools(self):
        text = setup.guide()
        for marker in ("cage_ssh_targets", "cage_ssh_execute", "云端", "私钥", "不要重置登录", "不自动重试"):
            self.assertIn(marker, text)
        self.assertNotIn("run_checks.ps1", text)


if __name__ == "__main__":
    unittest.main()
