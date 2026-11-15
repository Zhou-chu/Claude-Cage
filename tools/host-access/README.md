# Cage → Windows宿主机：标准用户＋逐次人工审批

普通操作使用专用标准账号的SSH会话；管理员命令须由宿主用户阅读命令、批准，再完成Windows UAC。**安装成功不代表SSH认证或真实提权已验收。** 不会自动发送管理员执行请求。

## 宿主安装

1. 复制`host-access.example.psd1`为`host-access.local.psd1`，填写客机Ed25519公钥、客机tailnet IPv4、宿主tailnet IPv4。后者与本机参数文件、编译产物均被Git忽略。已有部署的本机参数已保留，不必重填。
2. 在**管理员PowerShell**中运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup-host-access.ps1
```

32位Windows PowerShell自动改用64位，并保留传入参数。脚本不依赖本地化管理员组名，使用SID `S-1-5-32-544`。专用账号不得是当前宿主操作员或Administrators成员；查询失败会停止，绝不解释成安全。

公钥写入`%ProgramData%\ssh\<username>_authorized_keys`：SYSTEM和Administrators可写，专用账号只读，所有者为内置管理员组SID。独立绝对路径避免依赖用户配置文件推断；**之前的认证失败原因尚未从sshd详细日志证实，不能断言只是首次登录问题。**

脚本用带边界标记的专用`Match User`配置启用固定来源、公钥认证，关闭密码/交互式认证和转发，不新增影响所有账号的全局AllowUsers。旧版本误放进管理员Match中的自有白名单按精确标记迁移；其他已有白名单不被清除。先验证候选配置，再写入并重启sshd；写入/重启失败恢复本次原字节。

审批代理安装目录受保护：SYSTEM、Administrators、指定宿主操作员可写，不授予专用账号。代理仅绑定配置的宿主tailnet地址，并检查来源IP；防火墙也限制相同端点。自启入口仅属于当前宿主操作员，不再对所有用户生效。脚本停止旧代理，但**不会从提权窗口启动新代理**。安装结束后，从普通桌面会话启动“Cage approval broker”快捷方式。

构建代理（需要Go）：

```powershell
# 在tools/cage-approve中
 go test ./...
 go build -o ..\host-access\cage-approve.exe .
```

## 客机封装部署

Cage的tailnet是userspace网络，不能把没有`tailscale0`当成故障，也不能用直接连接100.x或ping结果替代真实连通测试。客户端每次从客机私有控制记录读取最新代理端口/凭据，通过HTTP CONNECT访问**配置的单台宿主机和SSH/审批端口**。不使用环境代理，不直接回退，不提供通用出口，不改变Internet代理链或Cage安全关闭策略。

在宿主普通PowerShell中运行（不用提权）：

```powershell
.\install-guest-access.ps1
```

部署器读取宿主审批令牌，经Cage标准输入写入客机私有配置，不把凭据放进命令行、日志或临时脚本。它核对本机22端口属于sshd服务，再从独立本机连接取得公开Ed25519主机键，固定到客机专用known_hosts。不会读取宿主私钥，也不会更改原有客机known_hosts。

客机使用：

```bash
~/.local/bin/cage-host ssh 'whoami'
~/.local/bin/cage-host health
# 以下才会发送管理员请求：逐次人工批准；不自动重试
printf '%s\n' '{"reason":"查看宿主系统版本","command":"Get-ComputerInfo | Select-Object WindowsProductName"}' \
  | ~/.local/bin/cage-host run
```

SSH使用严格主机键检查、固定身份文件、公钥认证和一次连接，不继承用户SSH配置、代理跳转或连接复用。主机键变更会拒绝；请独立核对后重跑部署器，不要关闭校验。

客户端由系统Python3标准库实现；不安装第三方库。配置和令牌为0600，拒绝不安全权限、符号链接和非本用户/非root拥有的私有文件。具体客户端协议与测试见`guest/README.md`。

## 审批与失败语义

`health`只验证鉴权和可达性，不弹窗、不执行命令。`run`才提交一次`{command,reason}`。取消审批不执行；UAC取消或启动失败不等于成功；返回退出码应来自实际子进程。网络在提交后中断可能产生**执行结果未知**，禁止自动重投。输出/HTTP响应受大小限制。

新代理不再把已批准命令写成可替换的`run-N.ps1`再提升；它把固定命令编码后直接交给绝对路径的Windows PowerShell，校验安装目录权限，并拒绝排队弹窗。令牌不打印到控制台。新审计仅记录命令摘要和状态，不记录令牌、命令或原因原文；旧日志及受保护的输出文件仍可能含敏感信息，**不得在命令里放密码等秘密**。

真实的“批准→UAC→子进程→结果”必须由人在桌面验收；自动测试仅使用注入的提示/执行函数，不会偷点批准。当前源码/单元测试通过不等于这条真人链路已完成。

## 测试（不要求管理员、不改服务）

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\test-host-access.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup-host-access.ps1 -CheckOnly
```

测试包含SID所有者转换、精确ACL、配置迁移/幂等/作用域/吊销、参数拒绝，以及独立临时测试密钥下真实sshd `-t`/`-T`有效认证规则。不会读取实际宿主私钥，不代表真实账号认证成功。

## 吊销

```powershell
# 管理员窗口
.\revoke-host-access.ps1
.\revoke-host-access.ps1 -RemoveUser
```

先禁用专用账号，再移除自有配置、清空独立集成公钥、停代理并撤销自启/防火墙；不清空用户原有authorized_keys，也不删除第三方AllowUsers。已建立的SSH会话不会因此自动终止。代理令牌和日志保留用于审计，重新启用前应轮换令牌。

## 边界

- 标准账号仍能访问Windows默认允许普通用户访问的文件/程序，不是文件系统沙箱；本地管理员可更改ACL。若需要目录级隔离，必须另外设计权限。
- UAC不是“代理被攻破也绝对安全”的保证；恶意程序可以欺骗审批内容。保护代理代码、配置和宿主会话是前提。批准任意脚本本身就授予该脚本管理员权限。
- 批准的脚本仍可能读取可变外部文件、调用可变程序；操作者必须审查整个操作，不只是命令摘要。不要批准来源不明的脚本。
- 私有tailnet不能防止提示注入或错误操作；其他设备访问还需Tailscale ACL管理。本工具不会新增通用路由、退出节点或放宽Internet出口。
