"""Configure standard OpenSSH over Cage's built-in Tailscale dial transport.
No credentials are copied into SSH config; no Desktop/session data is accessed.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

MODULE = Path(__file__).resolve().with_name("cage_host.py")
spec = importlib.util.spec_from_file_location("cage_host_native_client", MODULE)
client = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = client
spec.loader.exec_module(client)
HEADER = "# Managed by Cage host access. Native SSH to the configured Windows host.\n"
ALIAS = "windows-host"
DIAL = "/usr/local/bin/cage-tailnet"


def render(config):
    options = {
        "HostName": config.host, "User": config.ssh_user, "Port": str(config.ssh_port),
        "ProxyCommand": shlex.join([DIAL, "dial", config.host, str(config.ssh_port)]),
        "IdentityFile": client.ssh_option_path(config.identity_file),
        "UserKnownHostsFile": client.ssh_option_path(config.known_hosts_file),
        "GlobalKnownHostsFile": "/dev/null", "StrictHostKeyChecking": "yes",
        "VerifyHostKeyDNS": "no", "UpdateHostKeys": "no", "BatchMode": "yes",
        "IdentitiesOnly": "yes", "IdentityAgent": "none", "PreferredAuthentications": "publickey",
        "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no",
        "GSSAPIAuthentication": "no", "ForwardAgent": "no", "ForwardX11": "no",
        "ClearAllForwardings": "yes", "ControlMaster": "no", "ControlPath": "none",
        "ControlPersist": "no", "PermitLocalCommand": "no", "LocalCommand": "none",
        "RemoteCommand": "none", "ProxyJump": "none", "ProxyUseFdpass": "no",
        "ConnectionAttempts": "1", "ConnectTimeout": str(max(1, int(config.connect_timeout))),
    }
    return HEADER + "Host " + ALIAS + "\n" + "".join("    " + k + " " + v + "\n" for k, v in options.items()) + "Host *\n"


def include_config(existing, path):
    line = "Include " + client.ssh_option_path(str(path))
    if line in existing.splitlines():
        # Do not silently accept an include that occurs after other defaults.
        if existing.startswith(line + "\n"):
            return existing
        raise client.ClientError("managed SSH include is not first; review existing rules")
    return line + "\n" + existing


def usage(config):
    return """# Windows宿主SSH使用说明

这是普通命令执行通道，不是桌面鼠标控制，也不提供宿主主账号权限。
Claude Desktop与Cage终端同用客机账号cage；有终端能力的模式可执行：

```bash
ssh windows-host 'whoami'
ssh windows-host 'powershell.exe -NoProfile -NonInteractive -Command "Get-Location"'
ssh windows-host 'git --version'
sftp windows-host
cage-host health
```

宿主用户：%s；宿主：%s；SSH端口：%s。
Windows命令不是Linux命令；需要PowerShell时显式调用powershell.exe。
可操作范围由cageops的Windows权限决定，个人工具和项目不会自动授权。
传文件用sftp或scp。先用SFTP的pwd或PowerShell的$env:USERPROFILE确认实际目录，
不要假定用户文件夹一定是C:/Users/cageops；建议使用该配置文件夹下的cage-work。
SSH走Cage内置cage-tailnet dial，自动发现私网端口/令牌；不配置系统VPN，
不关闭主机键检查，不复制私钥或令牌，不把标准用户加入管理员组。
不要修改Cage自动生成的Tailscale SSH配置；宿主专用配置由安装器管理。
管理员操作仍走cage-host run，必须本人审批和UAC，真实提权链尚未验收。
普通SSH/SFTP不需要审批代理运行；断开Cage私网或受控网络即无法连接。
此说明不代表Claude Desktop纯聊天模式获得了终端工具；不要声称未调用的工具可用。
""" % (config.ssh_user, config.host, config.ssh_port)


def existing(path):
    if path.is_symlink():
        raise client.ClientError("symlink configuration refused")
    if not path.exists():
        return None
    return client.private_read(str(path), 262144)


def store(path, data):
    # Validate the current object before replacing only this explicitly managed file.
    existing(path)
    fd, name = tempfile.mkstemp(prefix=".native-ssh-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def install():
    if os.name != "posix":
        raise client.ClientError("native SSH setup requires the Linux Cage guest")
    home = Path.home()
    root = home / ".config/cage-host"
    config = client.load_config(str(root / "config.json"))
    if config.control_file != str(home / ".config/cage-tailnet/control.json"):
        raise client.ClientError("built-in dial requires the standard Cage control location")
    for private in (config.identity_file, config.known_hosts_file):
        with client.private_open(private):
            pass
    binary = Path(DIAL)
    st = binary.stat()
    if not binary.is_file() or st.st_uid != 0 or st.st_mode & 0o022 or not os.access(binary, os.X_OK):
        raise client.ClientError("trusted built-in Cage tailnet executable required")
    sshdir = home / ".ssh"
    # The existing private identity validation above also checks these ancestors.
    main = sshdir / "config"
    target = root / "native_ssh_config"
    before = existing(main) or b""
    old_target = existing(target)
    if old_target is not None and not old_target.startswith(HEADER.encode()):
        raise client.ClientError("unmanaged native SSH configuration exists")
    rendered = render(config).encode()
    merged = include_config(before.decode("utf-8"), target).encode()
    # Parse the staged real config before changing the active include. ssh -G does not connect.
    fd, staged = tempfile.mkstemp(prefix=".native-candidate-", dir=root)
    os.close(fd)
    try:
        Path(staged).write_bytes(rendered)
        check = subprocess.run(["/usr/bin/ssh", "-G", "-F", staged, ALIAS],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if check.returncode:
            raise client.ClientError("native SSH candidate rejected; configuration unchanged")
    finally:
        os.unlink(staged)  # exact mkstemp-created path, inside the private config root
    backup = root / "ssh_config.before-native-access"
    if existing(backup) is None:
        store(backup, before)
    # The daemon owns its own include; preserve its exact bytes and all other rules.
    if (existing(main) or b"") != before:
        raise client.ClientError("SSH configuration changed during setup; retry after review")
    store(target, rendered)
    try:
        store(main, merged)
    except Exception:
        if old_target is not None:
            store(target, old_target)
        raise
    store(root / "USAGE.md", usage(config).encode("utf-8"))
    print("Configured native ssh/sftp alias: windows-host (Cage built-in Tailscale transport).")
    print("Guest instructions: ~/.config/cage-host/USAGE.md; no Desktop settings or credentials modified.")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        install()
    except (client.ClientError, OSError, ValueError, subprocess.SubprocessError):
        print("Native SSH setup failed; no credentials printed. Review private file permissions/configuration.", file=sys.stderr)
        sys.exit(2)
