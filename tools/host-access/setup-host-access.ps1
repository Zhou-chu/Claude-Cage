# Cage 宿主机访问配置（B 方案：专用标准用户 cageops）
#
# 以管理员身份运行：
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\setup-host-access.ps1
#
# 设计要点（均为实测踩坑得来）：
#   - 32 位 PowerShell 下 System32 被重定向到 SysWOW64，因此自动改用 64 位重启；
#   - 账号操作一律走 ADSI，不调用 net.exe（避免 PS 5.1 与原生程序的交互问题）；
#   - sshd.exe 路径从服务注册信息解析，本机 OpenSSH 装在 Program Files 而非 System32；
#   - 每一步打印进度，失败时直接指出是哪一步。

[CmdletBinding()]
param(
    [string]$GuestPublicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHUyxOBrXtTacXxJ0eTYbp2ijdeeYb1cqHZiiGLLCuI cage-guest@workstation',
    [string]$GuestAddress = '100.65.250.76',
    [string]$UserName = 'cageops',
    [string]$AlsoAllowUsers = 'Zhouchu',
    [int]$BrokerPort = 8642,
    [switch]$AlreadyRelaunched
)

$ErrorActionPreference = 'Stop'
$script:step = '初始化'

trap {
    Write-Host ''
    Write-Host ("[失败] 步骤: " + $script:step) -ForegroundColor Red
    Write-Host ("       " + $_.Exception.Message) -ForegroundColor Red
    Write-Host ("       位置: " + $_.InvocationInfo.ScriptLineNumber) -ForegroundColor DarkGray
    exit 1
}

function Step {
    param([string]$Name)
    $script:step = $Name
    Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Name) -ForegroundColor Cyan
}

# ---------------------------------------------------------------- 0. 位数适配
if (-not [Environment]::Is64BitProcess -and -not $AlreadyRelaunched) {
    $x64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $x64)) {
        $x64 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    Write-Host '检测到 32 位 PowerShell，正在以 64 位重新启动…' -ForegroundColor Yellow
    & $x64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -AlreadyRelaunched
    exit $LASTEXITCODE
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '需要管理员权限：请右键「以管理员身份运行」后再执行。'
}

Write-Host '== Cage 宿主机访问配置 ==' -ForegroundColor Green
Write-Host ("   PowerShell {0} / 64位={1} / 用户={2}" -f $PSVersionTable.PSVersion, [Environment]::Is64BitProcess, $identity.Name) -ForegroundColor DarkGray

$computerPath = "WinNT://{0},computer" -f $env:COMPUTERNAME

function Get-LocalUserNames {
    $computer = [ADSI]$computerPath
    @($computer.Children | Where-Object { $_.SchemaClassName -eq 'user' } | ForEach-Object { $_.Name })
}

function New-RandomPassword {
    param([int]$Length = 32)
    $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%*-_=+'
    -join (1..$Length | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

# ---------------------------------------------------------------- 1. 账号
Step "1/6 检查并创建本地账号 $UserName"
$exists = (Get-LocalUserNames) -contains $UserName
if ($exists) {
    Write-Host "   账号已存在，跳过创建。"
} else {
    $computer = [ADSI]$computerPath
    $newUser = $computer.Create('User', $UserName)
    $newUser.SetPassword((New-RandomPassword))
    $newUser.Put('Description', 'Cage guest SSH operator (standard user)')
    $newUser.SetInfo()
    # DONT_EXPIRE_PASSWORD (0x10000)：密码永不过期，避免数月后 SSH 突然失效
    $newUser.UserFlags.Value = $newUser.UserFlags.Value -bor 0x10000
    $newUser.SetInfo()
    Write-Host "   已创建（随机密码，仅公钥登录）。"
}

Step "2/6 确认为标准用户（不在 Administrators 组）"
try {
    $admins = [ADSI]("WinNT://{0}/Administrators,group" -f $env:COMPUTERNAME)
    $admins.Remove(("WinNT://{0}/{1}" -f $env:COMPUTERNAME, $UserName))
    Write-Host "   已从 Administrators 移除。" -ForegroundColor Yellow
} catch {
    Write-Host "   不在 Administrators 组（符合预期）。"
}

# ---------------------------------------------------------------- 2. 公钥
Step '3/6 写入客机公钥并收紧权限'
$profileDir = Join-Path $env:SystemDrive "Users\$UserName"
if (-not (Test-Path $profileDir)) {
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $dacl = Get-Acl $profileDir
    $dacl.SetOwner((New-Object System.Security.Principal.NTAccount($env:COMPUTERNAME, $UserName)))
    Set-Acl -Path $profileDir -AclObject $dacl
    Write-Host "   已创建用户目录 $profileDir。"
}

# 账号从未交互登录过时 Windows 不注册用户配置文件，sshd 解析不到家目录下的
# authorized_keys。因此公钥写到系统级绝对路径，并在 sshd_config 里用
# Match User 显式指向它——不依赖家目录解析。
$keyDir = Join-Path $env:ProgramData 'ssh'
$keyFile = Join-Path $keyDir "cageops_authorized_keys"
$keyLine = $GuestPublicKey.Trim()
$current = if (Test-Path $keyFile) { @(Get-Content $keyFile) } else { @() }
if ($current -notcontains $keyLine) {
    @($current | Where-Object { $_ -ne '' }) + $keyLine | Set-Content -Path $keyFile -Encoding ascii
    Write-Host "   已写入公钥到 $keyFile"
} else {
    Write-Host '   公钥已存在。'
}

# sshd 要求该文件只能由 SYSTEM/Administrators 写入
& icacls.exe $keyFile /inheritance:r /grant 'SYSTEM:F' /grant 'Administrators:F' | Out-Null
$acl = Get-Acl $keyFile
$acl.SetOwner((New-Object System.Security.Principal.NTAccount($env:COMPUTERNAME, 'Administrators')))
Set-Acl -Path $keyFile -AclObject $acl
Write-Host '   权限已收紧。'

# ---------------------------------------------------------------- 3. sshd
Step '4/6 配置 sshd 白名单'
$sshdConfig = Join-Path $env:ProgramData 'ssh\sshd_config'
if (-not (Test-Path $sshdConfig)) { throw "找不到 $sshdConfig，请确认 OpenSSH Server 已安装。" }
$backup = "$sshdConfig.cage-bak"
if (-not (Test-Path $backup)) { Copy-Item $sshdConfig $backup; Write-Host '   已备份 sshd_config。' }

$content = Get-Content $sshdConfig -Raw
$allowLine = "$UserName@$GuestAddress"
if ($AlsoAllowUsers) { $allowLine += ' ' + (($AlsoAllowUsers -split '[,\s]+' | Where-Object { $_ }) -join ' ') }
if ($content -match '(?m)^\s*AllowUsers\s') {
    Write-Host '   已存在 AllowUsers，不覆盖。请确认其中包含：' -ForegroundColor Yellow
    Write-Host "      $allowLine" -ForegroundColor Yellow
} else {
    $entry = "`r`n# Cage: dedicated standard user, fixed tailnet source only`r`nAllowUsers $allowLine`r`n"
    Add-Content -Path $sshdConfig -Value $entry -Encoding ascii
    Write-Host "   已添加 AllowUsers $allowLine"
}

# Match 块必须插在已有的 Match 块之前：sshd 的 Match 会一直生效到下一个 Match 或行尾
$matchBlock = @(
    "# Cage: absolute key path, does not depend on profile resolution"
    "Match User $UserName"
    "    AuthorizedKeysFile __PROGRAMDATA__/ssh/cageops_authorized_keys"
)
if ($content -match ('(?m)^\s*Match\s+User\s+' + [regex]::Escape($UserName))) {
    Write-Host '   已存在该用户的 Match User 块，跳过。'
} else {
    $lines = @(Get-Content $sshdConfig)
    $insertAt = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*Match\s+Group\s+administrators') { $insertAt = $i; break }
    }
    if ($insertAt -ge 0) {
        $before = $lines[0..($insertAt - 1)]
        $after = $lines[$insertAt..($lines.Count - 1)]
        $merged = @($before) + $matchBlock + @('') + @($after)
        Set-Content -Path $sshdConfig -Value $merged -Encoding ascii
    } else {
        Add-Content -Path $sshdConfig -Value ("`r`n" + ($matchBlock -join "`r`n") + "`r`n") -Encoding ascii
    }
    Write-Host '   已添加 Match User 块（绝对公钥路径）。'
}

$service = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue
if (-not $service) { throw 'sshd 服务不存在，请确认 OpenSSH Server 已安装。' }
$sshdExe = ($service.PathName -replace '^"([^"]+)".*$', '$1') -replace '^([^\s]+\.exe).*$', '$1'
if (-not (Test-Path $sshdExe)) { throw "sshd 可执行文件不存在：$sshdExe" }
Write-Host "   sshd: $sshdExe"

& $sshdExe -t
if ($LASTEXITCODE -ne 0) {
    Copy-Item $backup $sshdConfig -Force
    throw 'sshd 配置校验失败，已回滚，未重启服务。'
}
Restart-Service sshd
Write-Host '   校验通过，服务已重启。'

# ---------------------------------------------------------------- 4. 防火墙
Step "5/6 放行审批代理端口 $BrokerPort"
$ruleName = 'Cage approval broker'
& netsh.exe advfirewall firewall show rule "name=$ruleName" | Out-Null
$ruleExists = ($LASTEXITCODE -eq 0)
if ($ruleExists) {
    Write-Host '   规则已存在。'
} else {
    & netsh.exe advfirewall firewall add rule "name=$ruleName" dir=in action=allow protocol=TCP "localport=$BrokerPort" "remoteip=$GuestAddress" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "添加防火墙规则失败（netsh 退出码 $LASTEXITCODE）。" }
    Write-Host "   已放行（仅来源 $GuestAddress）。"
}

# ---------------------------------------------------------------- 5. 代理自启
Step '6/6 安装审批代理并设为登录自启'
$brokerExe = Join-Path $PSScriptRoot 'cage-approve.exe'
if (Test-Path $brokerExe) {
    $target = Join-Path $env:ProgramData 'CageBroker'
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    Copy-Item $brokerExe $target -Force
    $startup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
    $lnk = Join-Path $startup 'Cage approval broker.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $s = $shell.CreateShortcut($lnk)
    $s.TargetPath = Join-Path $target 'cage-approve.exe'
    $s.WorkingDirectory = $target
    $s.Save()
    Write-Host "   已安装到 $target 并设置自启。"
} else {
    Write-Host '   未找到 cage-approve.exe，跳过（把 exe 放到本脚本同目录后重跑）。' -ForegroundColor Yellow
}

# ---------------------------------------------------------------- 汇总
Write-Host ''
Write-Host '== 完成 ==' -ForegroundColor Green
Write-Host "账号        : $UserName（标准用户）"
Write-Host "允许来源    : $GuestAddress"
Write-Host "公钥文件    : $keyFile"
Write-Host "审批代理端口: $BrokerPort"
Write-Host ''
Write-Host '吊销：.\revoke-host-access.ps1' -ForegroundColor DarkGray