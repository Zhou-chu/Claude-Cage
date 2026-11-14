# Cage 宿主机访问配置（B 方案：专用标准用户 cageops）
#
# 用途：允许 Cage 客机通过 Tailscale 以标准用户身份 SSH 到宿主机，
#       并为「审批代理」放行本机端口与开机自启。
#
# 运行方式：右键「以管理员身份运行 PowerShell」，然后执行本脚本。
# 本脚本只创建/更新 cageops 这一个账号，不修改 Zhouchu 账号的任何设置。

[CmdletBinding()]
param(
    # 客机公钥；默认是从当前 Cage 客机导出的那把
    [string]$GuestPublicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHUyxOBrXtTacXxJ0eTYbp2ijdeeYb1cqHZiiGLLCuI cage-guest@workstation',

    # 只允许这个来源地址连入（客机 tailnet IP）
    [string]$GuestAddress = '100.65.250.76',

    [string]$UserName = 'cageops',

    # AllowUsers 是全局白名单：只写 cageops 会把你自己的 SSH 一并挡掉，
    # 因此默认保留你当前用于登录的账号。
    [string]$AlsoAllowUsers = 'Zhouchu',

    # 审批代理监听端口（客户端空闲时也可不启动）
    [int]$BrokerPort = 8642
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '请以管理员身份运行本脚本（右键 → 以管理员身份运行）。'
    }
}

function New-RandomPassword {
    param([int]$Length = 40)
    $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%*-_=+'
    -join (1..$Length | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

Assert-Admin
Write-Host '== Cage 宿主机访问配置 ==' -ForegroundColor Cyan

# ---------------------------------------------------------------- 1. 账号
$existing = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "账号 $UserName 已存在，跳过创建（不重置密码）。"
} else {
    $password = New-RandomPassword
    # -PasswordNeverExpires：避免几个月后 SSH 突然失效
    # 密码本身不打算给人用，登录一律走公钥
    New-LocalUser -Name $UserName -Password (ConvertTo-SecureString $password -AsPlainText -Force) `
        -FullName 'Cage Ops' -Description 'Cage guest SSH operator (standard user)' `
        -PasswordNeverExpires -AccountNeverExpires | Out-Null
    Write-Host "已创建账号 $UserName（随机密码，请勿使用密码登录）。"
}

# 确保它不是管理员：B 方案的全部意义就在这里
$admins = Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name
if ($admins -contains "$env:COMPUTERNAME\$UserName") {
    Remove-LocalGroupMember -Group 'Administrators' -Member $UserName
    Write-Host "已从 Administrators 组移除 $UserName。" -ForegroundColor Yellow
} else {
    Write-Host "$UserName 不在 Administrators 组（符合预期）。"
}

# ---------------------------------------------------------------- 2. 公钥
$profileDir = Join-Path $env:SystemDrive "Users\$UserName"
if (-not (Test-Path $profileDir)) {
    # 新建账号不会立刻生成用户配置文件目录，但 sshd 以家目录解析 authorized_keys，
    # 所以这里手工建出来并把所有者交给该用户。
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $dacl = Get-Acl $profileDir
    $dacl.SetOwner((New-Object System.Security.Principal.NTAccount($env:COMPUTERNAME, $UserName)))
    Set-Acl -Path $profileDir -AclObject $dacl
    icacls $profileDir /grant "${UserName}:(OI)(CI)F" /T | Out-Null
    Write-Host "已创建用户目录 $profileDir（首次交互登录后 Windows 会补全配置文件）。"
}
$sshDir = Join-Path $profileDir '.ssh'
New-Item -ItemType Directory -Path $sshDir -Force | Out-Null

$keyFile = Join-Path $sshDir 'authorized_keys'
$keyLine = $GuestPublicKey.Trim()
$current = if (Test-Path $keyFile) { Get-Content $keyFile } else { @() }
if ($current -notcontains $keyLine) {
    @($current | Where-Object { $_ -ne '' }) + $keyLine | Set-Content -Path $keyFile -Encoding ascii
    Write-Host '已写入客机公钥。'
} else {
    Write-Host '客机公钥已存在。'
}

# sshd 会拒绝权限过宽的 authorized_keys：所有者归 cageops，仅 SYSTEM/管理员可读
icacls $sshDir /inheritance:r /grant "${UserName}:(OI)(CI)F" /grant 'SYSTEM:(OI)(CI)F' /grant 'Administrators:(OI)(CI)F' | Out-Null
icacls $keyFile /inheritance:r /grant "${UserName}:F" /grant 'SYSTEM:F' /grant 'Administrators:F' | Out-Null
# 目录与文件所有者必须是该用户，否则 sshd 认为「可被他人篡改」
$acl = Get-Acl $keyFile
$acl.SetOwner((New-Object System.Security.Principal.NTAccount($env:COMPUTERNAME, $UserName)))
Set-Acl -Path $keyFile -AclObject $acl
Write-Host '已收紧 .ssh 目录与公钥文件权限。'

# ---------------------------------------------------------------- 3. sshd
$sshdConfig = Join-Path $env:ProgramData 'ssh\sshd_config'
if (-not (Test-Path $sshdConfig)) { throw '找不到 sshd_config，请确认 OpenSSH Server 已安装。' }
$backup = "$sshdConfig.cage-bak"
if (-not (Test-Path $backup)) { Copy-Item $sshdConfig $backup; Write-Host "已备份 sshd_config → $backup" }

$content = Get-Content $sshdConfig -Raw
# AllowUsers 同时限定账号与来源，公钥在别处无法使用
$allowLine = "$UserName@$GuestAddress"
if ($AlsoAllowUsers) { $allowLine += ' ' + (($AlsoAllowUsers -split '[,\s]+' | Where-Object { $_ }) -join ' ') }
if ($content -match '(?m)^\s*AllowUsers\s') {
    Write-Host 'sshd_config 已有 AllowUsers，本脚本不覆盖，请手工确认其中包含：' -ForegroundColor Yellow
    Write-Host "    $allowLine" -ForegroundColor Yellow
} else {
    $entry = "`r`n# Cage: 客机以专用标准用户、仅从固定 tailnet 地址登录；其余账号保持原样`r`nAllowUsers $allowLine`r`n"
    Add-Content -Path $sshdConfig -Value $entry -Encoding ascii
    Write-Host "已添加 AllowUsers $UserName@$GuestAddress"
}

# 语法校验通过才继续，避免把自己锁在门外
& "$env:SystemRoot\System32\OpenSSH\sshd.exe" -t
if ($LASTEXITCODE -ne 0) {
    Copy-Item $backup $sshdConfig -Force
    throw 'sshd 配置校验失败，已回滚。未重启服务。'
}
Restart-Service sshd
Write-Host 'sshd 配置校验通过并已重启。'

# ---------------------------------------------------------------- 4. 防火墙
# 审批代理只监听 tailnet，仍然放行一条明确规则而不是整体关闭防火墙
$ruleName = 'Cage approval broker'
if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $BrokerPort `
        -RemoteAddress $GuestAddress -Action Allow | Out-Null
    Write-Host "已放行 $BrokerPort（仅来源 $GuestAddress）。"
} else {
    Write-Host "防火墙规则「$ruleName」已存在。"
}

# ---------------------------------------------------------------- 5. 审批代理自启
$brokerExe = Join-Path $PSScriptRoot 'cage-approve.exe'
$startup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
if (Test-Path $brokerExe) {
    $target = Join-Path $env:ProgramData 'CageBroker'
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    Copy-Item $brokerExe $target -Force
    # 以当前用户身份随登录启动：代理本身不提权，提权由每次 UAC 完成
    $lnk = Join-Path $startup 'Cage approval broker.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $s = $shell.CreateShortcut($lnk)
    $s.TargetPath = Join-Path $target 'cage-approve.exe'
    $s.WorkingDirectory = $target
    $s.Save()
    Write-Host "审批代理已安装并设为开机自启：$target"
} else {
    Write-Host "未找到 cage-approve.exe（跳过自启安装）。把它放到本脚本同目录后重跑即可。" -ForegroundColor Yellow
}

# ---------------------------------------------------------------- 6. 汇总
Write-Host ''
Write-Host '== 完成 ==' -ForegroundColor Green
Write-Host "账号        : $UserName（标准用户，非管理员）"
Write-Host "允许来源    : $GuestAddress"
Write-Host "公钥文件    : $keyFile"
Write-Host "审批代理端口: $BrokerPort（仅来源 $GuestAddress）"
Write-Host ''
Write-Host '吊销方式：在同目录运行 revoke-host-access.ps1，或删除上面那行公钥。' -ForegroundColor DarkGray