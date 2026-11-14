# Cage → 宿主机访问（B 方案 + 审批代理）

让 Cage 客机里的 Claude 能操作宿主机，同时**不让客机获得常驻的管理员权限**。

## 结构

```
Cage 客机 (100.65.250.76)
   │  SSH（公钥，仅此来源地址，账号 cageops，标准用户）
   ├──────────────────────────────► 宿主机 sshd:22
   │                                  └─ 能跑普通命令，碰不到系统
   │
   │  HTTP（Bearer token，端口 8642）
   └──────────────────────────────► cage-approve（跑在你的用户会话，不提权）
                                      └─ 弹窗 → 你点批准 → runas 提权（UAC 再确认一次）
```

关键点：**审批代理自己不是管理员**。提权发生在你点「批准」之后，由 Windows 的
`runas` 触发 UAC——即使代理进程被攻破，攻击者也只能替你弹框，拿不到管理员权限。

## 安装（宿主机，需一次管理员权限）

```powershell
# 1. 以管理员身份打开 PowerShell，进入本目录
cd D:\code\Claude-cage\tools\host-access

# 2. 执行配置
.\setup-host-access.ps1
```

脚本会做六件事：

| 步骤 | 内容 |
| --- | --- |
| 1 | 创建标准用户 `cageops`（随机密码，**不在** Administrators 组） |
| 2 | 写入客机公钥，并把 `.ssh` 权限收紧到仅该用户 + SYSTEM + 管理员 |
| 3 | sshd 增加 `AllowUsers cageops@100.65.250.76 Zhouchu`（保留你自己的登录） |
| 4 | `sshd -t` 校验通过才重启服务，失败自动回滚 |
| 5 | 防火墙仅放行 `8642`，且来源限定客机地址 |
| 6 | 把 `cage-approve.exe` 装到 `C:\ProgramData\CageBroker` 并设为登录自启 |

## 客机侧使用

拿到 host 生成好的 token（`C:\ProgramData\CageBroker\token`）后：

```bash
echo '<token>' | sudo tee /etc/cage-broker-token >/dev/null
sudo chmod 600 /etc/cage-broker-token
```

普通命令直接走 SSH：

```bash
ssh cageops@100.75.85.58 'whoami; hostname'
```

需要管理员时调用代理（会弹窗找你批准）：

```bash
curl -sS -X POST http://100.75.85.58:8642/run \
  -H "Authorization: Bearer $(sudo cat /etc/cage-broker-token)" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"安装构建依赖","command":"winget install -e --id Git.Git"}'
```

返回：

```json
{"approved":true,"exit_code":0,"output":"..."}
```

`approved:false` 表示你点了取消。

## 审计

所有请求（含被拒）写入 `C:\ProgramData\CageBroker\audit.log`：

```
2026-11-14 19:46:53 START listen=:8642 root=C:\ProgramData\CageBroker
2026-11-14 19:50:12 APPROVED exit=0  "winget install -e --id Git.Git"
2026-11-14 19:51:03 DENIED  "Remove-Item C:\Windows\System32 -Recurse"
```

## 吊销

```powershell
# 管理员身份
.\revoke-host-access.ps1            # 保留账号，只断权限
.\revoke-host-access.ps1 -RemoveUser  # 连账号一起删
```

也可只删 `C:\Users\cageops\.ssh\authorized_keys` 里那一行，权限立即失效。

## 已知边界

- **SSH 会话里没有 UAC**，所以标准用户永远无法自助提权；所有管理员操作都必须经过审批代理。
- 代理的弹窗在你**当前登录会话**里出现；没有用户登录时（如锁屏前注销）请求会一直等待。
- `AllowUsers` 是全局白名单，改它之前确认里面包含你日常 SSH 用的账号。
- 客机已加入 tailnet，**它同时也能访问你的其它 tailnet 设备**——这与本方案无关，需要在 Tailscale ACL 里另做限制。