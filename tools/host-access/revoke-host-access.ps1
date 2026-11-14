# 吊销 Cage 对宿主机的访问
#
# 以管理员身份运行：
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\revoke-host-access.ps1
#
# 与 setup 脚本一致：32 位 PowerShell 自动改用 64 位重启，原生命令统一封装。

[CmdletBinding()]
param(
    [string]$UserName = 'cageops',
    [int]$BrokerPort = 8642,
    [switch]$RemoveUser,
    [switch]$AlreadyRelaunched
)

$ErrorActionPreference = 'Stop'

if (-not [Environment]::Is64BitProcess -and -not $AlreadyRelaunched) {
    $x64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $x64)) {
        $x64 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    Write-Host '检测到 32 位 PowerShell，正在以 64 位重新启动…' -ForegroundColor Yellow
    & $x64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -AlreadyRelaunched -UserName $UserName -BrokerPort $BrokerPort $(if ($RemoveUser) { '-RemoveUser' })
    exit $LASTEXITCODE
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'need-elevation: 请以管理员身份运行。'
}

function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Exe @Arguments 2>&1
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = (@($output) | Out-String).Trim() }
    } finally {
        $ErrorActionPreference = $previous
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()

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
    $verify = Invoke-Native -Exe $sshdExe -Arguments @('-t')
    if ($verify.ExitCode -eq 0) {
        Restart-Service sshd
        Write-Host '已移除 AllowUsers 并重启 sshd。'
    } else {
        Write-Warning "sshd 校验失败，请手工检查 sshd_config（备份 sshd_config.cage-bak）：$($verify.Output)"
    }
}

# 3. 移除防火墙规则
$removed = Invoke-Native -Exe 'netsh.exe' -Arguments @('advfirewall', 'firewall', 'delete', 'rule', 'name=Cage approval broker')
if ($removed.ExitCode -eq 0) { Write-Host '已移除审批代理防火墙规则。' }

# 4. 停止代理并移除自启
Get-Process cage-approve -ErrorAction SilentlyContinue | Stop-Process -Force
$lnk = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp\Cage approval broker.lnk'
if (Test-Path $lnk) { Remove-Item $lnk -Force; Write-Host '已移除登录自启。' }

# 5. 可选删除账号
if ($RemoveUser) {
    $probe = Invoke-Native -Exe 'net.exe' -Arguments @('user', $UserName)
    if ($probe.ExitCode -eq 0) {
        Invoke-Native -Exe 'net.exe' -Arguments @('user', $UserName, '/delete') | Out-Null
        Write-Host "已删除账号 $UserName（用户目录 C:\Users\$UserName 仍保留）。"
    }
}

Write-Host '吊销完成。' -ForegroundColor Green