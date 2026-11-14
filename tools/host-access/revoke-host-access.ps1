# 吊销 Cage 对宿主机的访问
# 以管理员身份运行。执行后客机将无法再 SSH 进来，也无法调用审批代理。

[CmdletBinding()]
param(
    [string]$UserName = 'cageops',
    [string]$GuestAddress = '100.65.250.76',
    [int]$BrokerPort = 8642,
    # 连账号一起删掉（默认保留，便于以后再次启用）
    [switch]$RemoveUser
)

$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '请以管理员身份运行。'
}

# 1. 移除公钥
$keyFile = Join-Path $env:SystemDrive "Users\$UserName\.ssh\authorized_keys"
if (Test-Path $keyFile) {
    Set-Content -Path $keyFile -Value '' -Encoding ascii
    Write-Host "已清空 $keyFile"
}

# 2. 移除 AllowUsers 行
$sshdConfig = Join-Path $env:ProgramData 'ssh\sshd_config'
if (Test-Path $sshdConfig) {
    $lines = Get-Content $sshdConfig | Where-Object { $_ -notmatch "^\s*AllowUsers\s+$UserName@" }
    Set-Content -Path $sshdConfig -Value $lines -Encoding ascii
    & "$env:SystemRoot\System32\OpenSSH\sshd.exe" -t
    if ($LASTEXITCODE -eq 0) {
        Restart-Service sshd
        Write-Host '已移除 AllowUsers 并重启 sshd。'
    } else {
        Write-Warning 'sshd 校验失败，请手工检查 sshd_config。'
    }
}

# 3. 移除防火墙规则
Get-NetFirewallRule -DisplayName 'Cage approval broker' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
Write-Host '已移除审批代理防火墙规则。'

# 4. 停止并移除自启
Get-Process cage-approve -ErrorAction SilentlyContinue | Stop-Process -Force
$lnk = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp\Cage approval broker.lnk'
if (Test-Path $lnk) { Remove-Item $lnk -Force; Write-Host '已移除开机自启。' }

# 5. 可选删除账号
if ($RemoveUser) {
    if (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name $UserName
        Write-Host "已删除账号 $UserName（用户目录仍保留在 C:\Users\$UserName）。"
    }
}

Write-Host '吊销完成。' -ForegroundColor Green