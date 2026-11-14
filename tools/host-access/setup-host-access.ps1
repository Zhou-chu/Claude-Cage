# Cage 宿主机访问配置（B 方案：专用标准用户 cageops）
#
# 以管理员身份运行：
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\setup-host-access.ps1
#
# 本脚本刻意不依赖 LocalAccounts / NetSecurity 等可选模块：
#   账号   → net user + ADSI
#   防火墙 → netsh advfirewall
# 这样在 32 位 PowerShell 或模块路径异常的环境里也能跑。

[CmdletBinding()]
param(
    [string]$GuestPublicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHUyxOBrXtTacXxJ0eTYbp2ijdeeYb1cqHZiiGLLCuI cage-guest@workstation',
    [string]$GuestAddress = '100.65.250.76',
    [string]$UserName = 'cageops',
    [string]$AlsoAllowUsers = 'Zhouchu',
    [int]$BrokerPort = 8642
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'need-elevation: 请以管理员身份运行本脚本。'
}

Write-Host '== Cage 宿主机访问配置 ==' -ForegroundColor Cyan
Write-Host ("   PowerShell {0} / 64位进程={1} / 用户={2}" -f $PSVersionTable.PSVersion, [Environment]::Is64BitProcess, $identity.Name) -ForegroundColor DarkGray

function Test-LocalUserExists {
    param([string]$Name)
    # net user <name> 在账号不存在时返回退出码 2
    & net.exe user $Name 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function New-RandomPassword {
    param([int]$Length = 40)
    $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%*-_=+'
    -join (1..$Length | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

# ---------------------------------------------------------------- 1. 账号
if (Test-LocalUserExists -Name $UserName) {
    Write-Host "账号 $UserName 已存在，跳过创建（不重置密码）。"
} else {
    $password = New-RandomPassword
    & net.exe user $UserName $password /add /expires:never "/comment:Cage guest SSH operator (standard user)" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "创建账号 $UserName 失败（net user 退出码 $LASTEXITCODE）。" }
    # DONT_EXPIRE_PASSWORD (0x10000)：密码永不过期，避免数月后 SSH 突然失效
    $acct = [ADSI]"WinNT://$env:COMPUTERNAME/$UserName,user"
    $acct.UserFlags.Value = $acct.UserFlags.Value -bor 0x10000
    $acct.SetInfo()
    Write-Host "已创建账号 $UserName（随机密码，仅公钥登录）。"
}

# 确保不是管理员：B 方案的意义全在于此
# 不先判断成员关系——非成员时该命令只会报错退出，避免依赖本地化后的组名解析
& net.exe localgroup Administrators $UserName /delete 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "已从 Administrators 组移除 $UserName。" -ForegroundColor Yellow
} else {
    Write-Host "$UserName 不在 Administrators 组（符合预期）。"
}

# ---------------------------------------------------------------- 2. 公钥
$profileDir = Join-Path $env:SystemDrive "Users\$UserName"
if (-not (Test-Path $profileDir)) {
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $dacl = Get-Acl $profileDir
    $dacl.SetOwner((New-Object System.Security.Principal.NTAccount($env:COMPUTERNAME, $UserName)))
    Set-Acl -Path $profileDir -AclObject $dacl
    icacls $profileDir /grant "${UserName}:(OI)(CI)F" /T | Out-Null
    Write-Host "已创建用户目录 $profileDir。"
}

$sshDir = Join-Path $profileDir '.ssh'
New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
$keyFile = Join-Path $sshDir 'authorized_keys'
$keyLine = $GuestPublicKey.Trim()
$current = if (Test-Path $keyFile) { @(Get-Content $keyFile) } else { @() }
if ($current -notcontains $keyLine) {
    @($current | Where-Object { $_ -ne '' }) + $keyLine | Set-Content -Path $keyFile -Encoding ascii
    Write-Host '已写入客机公钥。'
} else {
    Write-Host '客机公钥已存在。'
}

icacls $sshDir /inheritance:r /grant "${UserName}:(OI)(CI)F" /grant 'SYSTEM:(OI)(CI)F' /grant 'Administrators:(OI)(CI)F' | Out-Null
icacls $keyFile /inheritance:r /grant "${UserName}:F" /grant 'SYSTEM:F' /grant 'Administrators:F' | Out-Null
$acl = Get-Acl $keyFile
$acl.SetOwner((New-Object System.Security.Principal.NTAccount($env:COMPUTERNAME, $UserName)))
Set-Acl -Path $keyFile -AclObject $acl
Write-Host '已收紧 .ssh 目录与公钥权限。'

# ---------------------------------------------------------------- 3. sshd
$sshdConfig = Join-Path $env:ProgramData 'ssh\sshd_config'
if (-not (Test-Path $sshdConfig)) { throw "找不到 $sshdConfig，请确认 OpenSSH Server 已安装。" }
$backup = "$sshdConfig.cage-bak"
if (-not (Test-Path $backup)) { Copy-Item $sshdConfig $backup; Write-Host '已备份 sshd_config。' }

$content = Get-Content $sshdConfig -Raw
$allowLine = "$UserName@$GuestAddress"
if ($AlsoAllowUsers) { $allowLine += ' ' + (($AlsoAllowUsers -split '[,\s]+' | Where-Object { $_ }) -join ' ') }
if ($content -match '(?m)^\s*AllowUsers\s') {
    Write-Host 'sshd_config 已有 AllowUsers，脚本不覆盖。请确认其中包含：' -ForegroundColor Yellow
    Write-Host "    $allowLine" -ForegroundColor Yellow
} else {
    # 注释保持纯 ASCII：该文件按 ASCII 写入，中文会变成问号
    $entry = "`r`n# Cage: dedicated standard user, fixed tailnet source only`r`nAllowUsers $allowLine`r`n"
    Add-Content -Path $sshdConfig -Value $entry -Encoding ascii
    Write-Host "已添加 AllowUsers $allowLine"
}

$sshdExe = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
& $sshdExe -t
if ($LASTEXITCODE -ne 0) {
    Copy-Item $backup $sshdConfig -Force
    throw 'sshd 配置校验失败，已回滚，未重启服务。'
}
Restart-Service sshd
Write-Host 'sshd 配置校验通过并已重启。'

# ---------------------------------------------------------------- 4. 防火墙（netsh）
$ruleName = 'Cage approval broker'
$show = & netsh.exe advfirewall firewall show rule name="$ruleName" 2>&1 | Out-String
if ($show -match 'No rules match' -or $show -match '没有与指定条件相匹配的规则') {
    & netsh.exe advfirewall firewall add rule name="$ruleName" dir=in action=allow protocol=TCP localport=$BrokerPort remoteip=$GuestAddress 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "添加防火墙规则失败（netsh 退出码 $LASTEXITCODE）。" }
    Write-Host "已放行 $BrokerPort（仅来源 $GuestAddress）。"
} else {
    Write-Host "防火墙规则「$ruleName」已存在。"
}

# ---------------------------------------------------------------- 5. 审批代理自启
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
    Write-Host "审批代理已安装并设为登录自启：$target"
} else {
    Write-Host '未找到 cage-approve.exe（跳过自启安装）。' -ForegroundColor Yellow
}

# ---------------------------------------------------------------- 6. 汇总
Write-Host ''
Write-Host '== 完成 ==' -ForegroundColor Green
Write-Host "账号        : $UserName（标准用户）"
Write-Host "允许来源    : $GuestAddress"
Write-Host "公钥文件    : $keyFile"
Write-Host "审批代理端口: $BrokerPort"
Write-Host ''
Write-Host '吊销：.\revoke-host-access.ps1' -ForegroundColor DarkGray