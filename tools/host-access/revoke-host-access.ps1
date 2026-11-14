# 吊销 Cage 对宿主机的访问
#
# 以管理员身份运行：
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\revoke-host-access.ps1
#
# 与 setup 脚本一致，不依赖 LocalAccounts / NetSecurity 模块。

[CmdletBinding()]
param(
    [string]$UserName = 'cageops',
    [int]$BrokerPort = 8642,
    [switch]$RemoveUser
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'need-elevation: 请以管理员身份运行。'
}

# 1. 清空公钥
$keyFile = Join-Path $env:SystemDrive "Users\$UserName\.ssh\authorized_keys"
if (Test-Path $keyFile) {
    Set-Content -Path $keyFile -Value '' -Encoding ascii
    Write-Host "已清空 $keyFile"
} else {
    Write-Host '公钥文件不存在，跳过。'
}

# 2. 移除 sshd 白名单行
$sshdConfig = Join-Path $env:ProgramData 'ssh\sshd_config'
if (Test-Path $sshdConfig) {
    $lines = Get-Content $sshdConfig | Where-Object { $_ -notmatch ('^\s*AllowUsers\s+.*' + [regex]::Escape($UserName) + '@') }
    Set-Content -Path $sshdConfig -Value $lines -Encoding ascii
    $sshdExe = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
    & $sshdExe -t
    if ($LASTEXITCODE -eq 0) {
        Restart-Service sshd
        Write-Host '已移除 AllowUsers 并重启 sshd。'
    } else {
        Write-Warning 'sshd 校验失败，请手工检查 sshd_config（备份在 sshd_config.cage-bak）。'
    }
}

# 3. 移除防火墙规则
& netsh.exe advfirewall firewall delete rule name="Cage approval broker" 2>&1 | Out-Null
Write-Host '已移除审批代理防火墙规则。'

# 4. 停止代理并移除自启
Get-Process cage-approve -ErrorAction SilentlyContinue | Stop-Process -Force
$lnk = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp\Cage approval broker.lnk'
if (Test-Path $lnk) { Remove-Item $lnk -Force; Write-Host '已移除登录自启。' }

# 5. 可选删除账号
if ($RemoveUser) {
    & net.exe user $UserName 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        & net.exe user $UserName /delete 2>&1 | Out-Null
        Write-Host "已删除账号 $UserName（用户目录 C:\Users\$UserName 仍保留）。"
    }
}

Write-Host '吊销完成。' -ForegroundColor Green