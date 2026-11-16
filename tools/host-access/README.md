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

安装器还会配置标准OpenSSH别名`windows-host`，直接使用Cage内置的`cage-tailnet dial`传输，不依赖审批代理。它固定宿主用户、私钥和已独立核对的主机键；保留Cage自动维护的私网Include与用户其他SSH规则。首次原配置备份和使用说明存放在客机`~/.config/cage-host/`，新增配置通过真实`ssh -G`解析后才写入。

Claude Desktop服务与Cage终端都使用客机账号`cage`，但**Desktop会话的代码执行工具可能运行在云端**，并不共享客机的程序、SSH别名或网络。下面命令只适用于客机本地终端；不能用其测试冒充Desktop云端工具已经接通。云端会话须使用下文的本地MCP桥接，也不因此获得桌面鼠标控制。

客机使用：

```bash
ssh windows-host 'whoami'
ssh windows-host 'powershell.exe -NoProfile -NonInteractive -Command "Get-Location"'
sftp windows-host
# 下面的原有固定通道仍可使用
~/.local/bin/cage-host ssh 'whoami'
~/.local/bin/cage-host health
# 以下才会发送管理员请求：逐次人工批准；不自动重试
printf '%s\n' '{"reason":"查看宿主系统版本","command":"Get-ComputerInfo | Select-Object WindowsProductName"}' \
  | ~/.local/bin/cage-host run
```

原有`cage-host ssh`封装使用严格主机键检查、固定身份文件、公钥认证和一次连接，不继承用户SSH配置、代理跳转或连接复用。标准`ssh windows-host`则保留用户原规则，以置顶的宿主专用段固定传输、身份和主机键校验，并关闭代理转发及连接复用。主机键变更会拒绝；请独立核对后重跑部署器，不要关闭校验。

客户端由系统Python3标准库实现；不安装第三方库。配置和令牌为0600，拒绝不安全权限、符号链接和非本用户/非root拥有的私有文件。具体客户端协议与测试见`guest/README.md`。

## Claude Desktop云端会话：本地MCP桥接

客机终端能SSH，不代表Desktop的云端代码执行环境也能。若它报告没有`ssh`、`sftp`或PowerShell，应使用本地MCP工具，不要让它在云端安装客户端或复制私钥。

```powershell
# 普通宿主PowerShell；显式选择合并Desktop工具配置
.\install-guest-access.ps1 -ConfigureDesktop
```

仅合并客机`~/.config/Claude/claude_desktop_config.json`中的`mcpServers.cage_ssh`；其他设置/服务器保留，原配置备份在私有客户端目录。权限不安全、JSON损坏或同名陌生服务器时停止，不重置。脚本不读取聊天、Cookie、密钥环或登录存储，也不重启Desktop。先保存当前工作，再按需手动重开Desktop加载工具，不退出账号、不重启整个Cage。

让Claude**调用工具**`cage_ssh_targets`，再调用`cage_ssh_execute`，例如参数：

```json
{"target":"windows-host","shell":"powershell","command":"whoami; Get-Location","timeout_seconds":30}
```

工具由客机本地系统Python运行，只访问显式登记且已授权的SSH目标；默认仅`windows-host`，不提供管理员代理调用。新增设备必须独立授权公钥、核对主机键后，才可通过私有`mcp_targets.json`登记相应客户端配置。Tailscale在线不代表已授权。

服务端单元/协议测试及单独启动的真实MCP→SSH验证，不等于Desktop应用已加载工具。必须由Desktop实际工具调用确认，不能再用云端Shell执行`ssh`测试替代。详细提示在客机`~/.config/cage-host/DESKTOP-SSH.md`。长构建应在宿主记录日志并查询状态；超时或截断可能代表结果未知，不自动重试。

## 新Windows设备的一次性授权

`enroll-windows-peer.ps1`、`host-access-common.ps1`与`sshd-system-validation.ps1`放在一起，在**目标电脑本人管理员PowerShell**运行。参数为客机公钥、客机/目标tailnet IPv4、目标Windows计算机名和专用标准用户名。必须显式加`-UseSystemValidation`授权一次性、固定用途的SYSTEM配置校验；先加`-CheckOnly`预检，再去掉此开关应用。脚本会以计算机名阻止误在其他设备执行；需要已有以LocalSystem运行的sshd，不安装VPN或SSH、不改防火墙、不安装审批代理。

Windows管理员不等于SYSTEM，不能直接以自身身份让sshd取得另一用户令牌。校验器仅在受保护临时目录保存候选配置，以无触发器的一次性SYSTEM任务运行固定的`sshd -t/-T`检查；任务定义从创建时就使用Administrators所有者和受保护的SYSTEM/Administrators全权DACL，并读回验证，不允许操作者普通身份改写SYSTEM动作，不从桌面加载SYSTEM脚本，不执行任意业务命令。预检不会启用账号、改公钥/活动配置或重启服务，但会创建并清理临时校验文件/任务；成功前必须证明SYSTEM身份、候选哈希、七项策略与任务清理。终止或清理不确定时失败关闭并报告精确保留项，不自动重投。

既有账号的`-CheckOnly`必须真实验证用户上下文，不能再只报告计划；目标仍禁用时如果Windows无法生成识别令牌，预检就停止，不偷启用账号。首次账号不存在时只能报告静态检查，完整SYSTEM校验要在应用创建禁用账号后完成。单元测试和本机非SYSTEM拒绝测试不代替目标设备的真实SYSTEM预检。

新账号先禁用，只有公钥ACL、有效SSH规则和sshd重启成功后才启用；已有密码不重置，陌生公钥或管理员账号不覆盖。组成员检查通过系统原生API的新鲜SID列表完成，不使用ADSI路径比较；添加成员也以SID进行且仅允许内置Users组。公钥ACL核对所有者SID、禁止继承以及三条精确SID/权限掩码，拒绝额外/缺失/继承/拒绝条目或扩大权限；不把NTFS将`D:P`规范化为`D:PAI`等历史标记或无害允许条目排序当作权限变化。成功后只输出公开Ed25519主机键和SHA256指纹，不读私钥。

若上次安装失败留下禁用账号，不要删除或手动启用。目标电脑本人管理员可显式加`-ResumeFailedEnrollment`，先与`-CheckOnly`一起预检，再去掉`-CheckOnly`恢复。仅接受既有禁用、非管理员、非当前操作者、描述精确匹配本安装器的账号；描述不是密码学来源证明，因此必须由管理员显式确认。缺失或已启用账号不接受恢复参数，不重置密码。创建或恢复的账号均在完整验证后才启用，任意失败保持/恢复禁用。

本人从目标电脑回传并核对公开主机键后，才能固定到独立known_hosts、配置该设备的客户端配置并登记MCP目标，再实测非管理员SSH。不要将台式机审批令牌复用到其他设备；无审批代理的SSH专用配置应使用独立不存在的broker令牌路径，使误调用代理失败。在线、端口可达、脚本单元测试通过均不等于真实设备授权已完成。

## 禁用账号拒绝S4U时的隔离维护

部分Windows环境在账号仍禁用时，即便真实SYSTEM也会拒绝生成用户令牌。不要把管理员令牌、全局`sshd -T`、假用户或单元测试当作目标用户的有效配置证明，也不要直接启用账号后再修改正在监听的服务。

[peer-maintenance.ps1](./peer-maintenance.ps1)提供单独的SYSTEM维护事务：核对机器名、原SID、标准组、公钥ACL及配置/公钥哈希；保存精确原字节；停sshd并证明无残留监听后才临时启用；真实验证目标用户的七项策略，在保持停服的情况下安装，再启动验证。任何失败先隔离、禁用并确认原SID，再按原字节恢复；发现外部配置修改、禁用失败或原生进程终止未证明时拒绝恢复服务。它不改密码、公钥或组成员，不是通用管理员执行入口。

[invoke-laptop-maintenance.ps1](./invoke-laptop-maintenance.ps1)是当前已授权笔记本的**操作者专用、固定设备快照**入口，不属于Cage/MCP能力，不能不经审查套用于其他机器。它利用宿主既有管理员SSH身份，严格核对主机键；通过SFTP传送仅含公开代码/元数据的封装，短入口校验同一份内存字节的哈希后解析，避免Windows大标准输入/命令行封装问题。SYSTEM只加载ProgramData中具有固定哈希、SYSTEM/Administrators保护ACL的代码，不从用户可写桌面执行。先跑不改账号/服务的SYSTEM探针，再登记独立的限时主任务和回滚任务。

```powershell
# 仅供已获授权的宿主操作者；同一批操作始终使用同一个唯一state路径。
$state = Join-Path $PWD.Path '.test-output\peer-maintenance-unique.json'
.\invoke-laptop-maintenance.ps1 -Action Prepare -StatePath $state
.\invoke-laptop-maintenance.ps1 -Action Probe -StatePath $state
.\invoke-laptop-maintenance.ps1 -Action Collect -StatePath $state
# 仅在真实探针成功且快照未变后启动一次；保持笔记本唤醒、联网。
.\invoke-laptop-maintenance.ps1 -Action Start -StatePath $state
# 连接中断或结果未知时只收取，绝不重复Start。
.\invoke-laptop-maintenance.ps1 -Action Collect -StatePath $state
```

维护任务有短时、线程寿命内的防自动休眠请求，不改电源计划，也不能阻止本人强制睡眠。受保护轨迹用于定位中断；原生收据仅保留状态、脱敏令牌错误标记及七项策略。超时/离线不等于成功；只有原SID已禁用、原配置哈希恢复且服务运行的收据与新鲜状态一致，才可认定安全回滚。终止不明时保留任务/目录，由本人管理员处理。已成功接入的账号会被恢复前置条件拒绝，不能反复重跑。确认结论后使用`-Action Cleanup`移除仅属于该state且动作/主体匹配、已结束的任务；审计目录仍保留，不发布轨迹或本机state。

[install-laptop-guest-access.ps1](./install-laptop-guest-access.ps1)只接受真实维护成功收据及新鲜状态，通过已认证管理员SSH取得公开Ed25519主机键、重新计算指纹，并写入独立0600主机键文件/客户端配置，保留原目标。笔记本只有标准用户SSH权限，不复制或共享台式机审批令牌。之后以相同`-StatePath`运行[verify-guest-laptop.ps1](./verify-guest-laptop.ps1)，通过新启动的真实MCP stdio会话检验笔记本非管理员身份、远程退出码、未登记目标执行前拒绝及原桌面目标回归。目标表在每次工具调用时重新读取；新增目标不必重启已有桥接进程。该验收仍不冒充Desktop应用界面的实际工具调用。

```powershell
.\install-laptop-guest-access.ps1 -StatePath $state
.\verify-guest-laptop.ps1 -StatePath $state
.\invoke-laptop-maintenance.ps1 -Action Cleanup -StatePath $state
# 纯隔离回归：不执行真实账号/服务/任务操作。
powershell -NoProfile -ExecutionPolicy Bypass -File .\test-peer-maintenance.ps1
```

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
