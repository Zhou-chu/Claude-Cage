"""Explicit opt-in setup for Claude Desktop's local SSH MCP server.
Only the known tool config is merged. No chat, cookies, keyring or login stores.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

spec = importlib.util.spec_from_file_location("desktop_ssh_client", Path(__file__).with_name("cage_host.py"))
client = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = client
spec.loader.exec_module(client)
SERVER = "cage_ssh"
LIMIT = 1024 * 1024


def entry(home):
    root = home / ".config/cage-host"
    return {"command": "/usr/bin/python3", "args": [
        "-I", str(home / ".local/bin/cage_host_mcp.py"),
        "--config", str(root / "config.json"),
        "--targets", str(root / "mcp_targets.json"),
    ]}


def merge(raw, home):
    data = {} if raw is None else client.strict_json(raw, "Desktop tool configuration")
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        raise client.ClientError("existing mcpServers is not an object; refusing to overwrite")
    wanted = entry(home)
    if SERVER in servers:
        previous = servers[SERVER]
        if not isinstance(previous, dict) or any(previous.get(k) != v for k, v in wanted.items()):
            raise client.ClientError("MCP server name is already used by a different configuration")
        # Preserve user choices such as disabled flags or extra environment settings.
        return raw, False
    updated = dict(data)
    updated["mcpServers"] = dict(servers, **{SERVER: wanted})
    return (json.dumps(updated, ensure_ascii=False, indent=2) + "\n").encode("utf-8"), True


def read_optional(path):
    if path.is_symlink():
        raise client.ClientError("symlink tool configuration refused")
    if not path.exists():
        return None
    return client.private_read(str(path), LIMIT)


def atomic(path, data):
    read_optional(path)
    fd, temporary = tempfile.mkstemp(prefix=".desktop-ssh-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)  # exact file created by this function, never a glob


def guide():
    return """# Claude Desktop本地SSH工具

Claude的云端代码执行环境没有本机ssh、sftp或PowerShell，这是正常的隔离边界。
不要在云端Shell安装客户端、寻找windows-host或复制私钥/令牌。

本地MCP服务器名：cage_ssh。
先调用工具cage_ssh_targets查看已授权目标，再调用cage_ssh_execute：

{"target":"windows-host","shell":"powershell","command":"whoami; Get-Location","timeout_seconds":30}

这个工具由客机本地Python服务执行SSH，返回宿主真实输出。
它只使用显式授权目标、固定公钥身份、严格主机键校验及Cage私网传输。
所有命令都以目标标准账号运行。无管理员工具；提权仍需单独人工审批。
新增设备必须先开SSH、授权客机公钥、独立核对主机指纹，再加入私有目标注册表。
在线或22端口可达不代表已经授权。当前笔记本未完成授权时不要声称能登录。

首次加载配置可能需要先保存工作，手动退出并重新打开Claude Desktop（不退出账号），
在新会话启用本地cage_ssh工具。不要重置登录、删配置或重启整个Cage。
若只看见云端bash工具，不能声称已通过本地MCP调用；应请用户检查工具是否已加载。
长脚本宜放在已授权目标目录再调用；不要自动执行聊天引用的下载/构建脚本。
长构建应在宿主启动有状态后台任务并把日志写到项目目录，再分次查询状态；
不要直接阻塞工具超过其时间/输出限制，也不要将超时当作重新启动构建的依据。
SSH连接中断、超时或输出被截断时结果可能未知，先核对远端状态，不自动重试。
"""


def install(dry_run=False):
    if os.name != "posix":
        raise client.ClientError("Desktop SSH setup requires the POSIX Cage guest")
    home = Path.home()
    root = home / ".config/cage-host"
    client.load_config(str(root / "config.json"))
    script = home / ".local/bin/cage_host_mcp.py"
    info = script.lstat()
    if (not stat.S_ISREG(info.st_mode) or script.is_symlink() or info.st_uid != os.geteuid()
            or info.st_mode & 0o022 or info.st_nlink != 1):
        raise client.ClientError("trusted installed SSH MCP script required")
    directory = home / ".config/Claude"
    if directory.is_symlink():
        raise client.ClientError("symlink Desktop config directory refused")
    if directory.exists():
        client.validate_directory(directory.stat(), {0, os.geteuid()}, True)
    elif not dry_run:
        directory.mkdir(mode=0o700)
        client.validate_directory(directory.stat(), {0, os.geteuid()}, True)
    path = directory / "claude_desktop_config.json"
    before = read_optional(path)
    after, changed = merge(before, home)
    if dry_run:
        print("Desktop SSH configuration valid; write required=" + str(changed) + "; contents withheld.")
        return
    backup = root / "desktop-config.before-ssh.json"
    if before is not None and read_optional(backup) is None:
        atomic(backup, before)
    if read_optional(path) != before:
        raise client.ClientError("Desktop tool config changed concurrently; refusing to replace")
    if changed:
        atomic(path, after)
    atomic(root / "DESKTOP-SSH.md", guide().encode("utf-8"))
    print("Configured local MCP server: cage_ssh; other Desktop settings preserved.")
    print("Desktop was NOT restarted. Save work and reopen it manually if needed to load tools.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()
    try:
        install(arguments.dry_run)
    except (client.ClientError, OSError, ValueError):
        print("Desktop MCP configuration failed; existing contents/credentials withheld.", file=sys.stderr)
        sys.exit(2)
