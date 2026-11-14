# 吊销 Cage 对宿主机的访问
#
# 以管理员身份运行：
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\revoke-host-access.ps1
#
# 与 setup 脚本一致：32 位自动切 64 位、账号操作走 ADSI、sshd 路径从服务解析。

[CmdletBinding()]
param(
    [string]$UserName = 'cageops',
    [int]$BrokerPort = 8642,
    [switch]$RemoveUser,
    [switch]$AlreadyRelaunched
)

$ErrorActionPreference = 'Stop'
$script:step = '初始化'

trap {
    Write-Host ''
    Write-Host ("[失败] 步骤: " + $script:step) -ForegroundColor Red
    Write-Host ("       " + $_.Exception.Message) -ForegroundColor Red
    exit 1
}

function Step {
    param([string]$Name)
    $script:step = $Name
    Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Name) -ForegroundColor Cyan
}

if (-not [Environment]::Is64BitProcess -and -not $AlreadyRelaunched) {
    $x64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $x64)) {
        $x64 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    Write-Host '检测到 32 位 PowerShell，正在以 64 位重新启动…' -ForegroundColor Yellow
    $extra = @()
    if ($RemoveUser) { $extra += '-RemoveUser' }
    & $x64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -AlreadyRelaunched -UserName $UserName -BrokerPort $BrokerPort @extra
    exit $LASTEXITCODE
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '需要管理员权限：请右键「以管理员身份运行」后再执行。'
}

$computerPath = "WinNT://{0},computer" -f $env:COMPUTERNAME

Step '1/4 清空客机公钥'
$keyFile = Join-Path $env:SystemDrive "Users\$UserName\.ssh\authorized_keys"
if (Test-Path $keyFile) {
    Set-Content -Path $keyFile -Value '' -Encoding ascii
    Write-Host "   已清空 $keyFile"
} else {
    Write-Host '   公钥文件不存在，跳过。'
}

Step '2/4 移除 sshd 白名单'
$sshdConfig = Join-Path $env:ProgramData 'ssh\sshd_config'
if (Test-Path $sshdConfig) {
    $lines = Get-Content $sshdConfig | Where-Object { $_ -notmatch ('^\s*AllowUsers\s+.*' + [regex]::Escape($UserName) + '@') }
    Set-Content -Path $sshdConfig -Value $lines -Encoding ascii
    $service = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue
    if ($service) {
        $sshdExe = ($service.PathName -replace '^"([^"]+)".*$', '$1') -replace '^([^\s]+\.exe).*$', '$1'
        & $sshdExe -t
        if ($LASTEXITCODE -eq 0) {
            Restart-Service sshd
            Write-Host '   已移除并重启 sshd。'
        } else {
            Write-Warning '   sshd 校验失败，请手工检查 sshd_config（备份 sshd_config.cage-bak）。'
        }
    }
}

Step '3/4 移除防火墙规则与登录自启'
& netsh.exe advfirewall firewall delete rule "name=Cage approval broker" | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host '   防火墙规则已移除。' }
Get-Process cage-approve -ErrorAction SilentlyContinue | Stop-Process -Force
$lnk = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp\Cage approval broker.lnk'
if (Test-Path $lnk) { Remove-Item $lnk -Force; Write-Host '   登录自启已移除。' }

Step '4/4 可选删除账号'
if ($RemoveUser) {
    $computer = [ADSI]$computerPath
    $names = @($computer.Children | Where-Object { $_.SchemaClassName -eq 'user' } | ForEach-Object { $_.Name })
    if ($names -contains $UserName) {
        $computer.Delete('User', $UserName)
        Write-Host "   已删除账号 $UserName（用户目录仍保留）。"
    } else {
        Write-Host '   账号不存在，跳过。'
    }
} else {
    Write-Host '   保留账号（如需删除请加 -RemoveUser）。'
}

Write-Host ''
Write-Host '吊销完成。' -ForegroundColor Green