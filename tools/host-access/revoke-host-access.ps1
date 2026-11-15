# Revoke only this integration, preserving unrelated SSH keys and policy.
[CmdletBinding()]
param(
    [ValidatePattern('^[a-z_][a-z0-9_-]{0,30}$')][string]$UserName = 'cageops',
    [switch]$RemoveUser,
    [switch]$AlreadyRelaunched
)
$ErrorActionPreference='Stop'
if (-not [Environment]::Is64BitProcess) {
    if ($AlreadyRelaunched) { throw '64-bit relaunch failed.' }
    $x64=Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    $forward=@{UserName=$UserName;AlreadyRelaunched=$true;RemoveUser=[bool]$RemoveUser}
    $params=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([Management.Automation.PSSerializer]::Serialize($forward)))
    $path="'"+$PSCommandPath.Replace("'","''")+"'"
    $code='$p=[Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('''+$params+'''))); & '+$path+' @p; exit $LASTEXITCODE'
    & $x64 -NoProfile -ExecutionPolicy Bypass -OutputFormat Text -InputFormat Text -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code)))
    exit $LASTEXITCODE
}
. (Join-Path $PSScriptRoot 'host-access-common.ps1')
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run in an administrator PowerShell window.' }
if ($UserName -eq $identity.Name.Split('\')[-1].ToLowerInvariant()) { throw 'Refusing to revoke the current host operator.' }
$computer=[ADSI]("WinNT://{0},computer" -f $env:COMPUTERNAME)
$exists=@($computer.Children | Where-Object {$_.SchemaClassName -eq 'user'} | ForEach-Object {[string]$_.Name}) -contains $UserName
if ($exists) {
    $user=[ADSI]("WinNT://{0}/{1},user" -f $env:COMPUTERNAME,$UserName)
    $user.UserFlags.Value=$user.UserFlags.Value -bor 2
    $user.SetInfo()
    Write-Host 'Dedicated account disabled first. Existing SSH sessions are not automatically terminated.'
}
$configPath=Join-Path $env:ProgramData 'ssh\sshd_config'
$content=[IO.File]::ReadAllText($configPath)
$clean=Remove-CageSshBlock $content $UserName
if ($clean -ne $content) { Set-CageSshConfig $configPath $clean (Get-CageSshdExe) }
# Exact dedicated integration key path. Leave unrelated ~/.ssh/authorized_keys untouched.
$keyFile=Join-Path $env:ProgramData "ssh\${UserName}_authorized_keys"
if (Test-Path -LiteralPath $keyFile) { [IO.File]::WriteAllText($keyFile,'',[Text.Encoding]::ASCII) }
Get-NetFirewallRule -DisplayName 'Cage approval broker' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$broker=Join-Path $env:ProgramData 'CageBroker\cage-approve.exe'
Get-CimInstance Win32_Process -Filter "Name='cage-approve.exe'" | Where-Object {$_.ExecutablePath -eq $broker} | ForEach-Object {Stop-Process -Id $_.ProcessId -ErrorAction Stop}
$links=@(
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp\Cage approval broker.lnk'),
    (Join-Path ([Environment]::GetFolderPath('Startup')) 'Cage approval broker.lnk')
)
foreach($link in $links) { if(Test-Path -LiteralPath $link) {Remove-Item -LiteralPath $link -Force} }
if($RemoveUser -and $exists) {$computer.Delete('User',$UserName)}
Write-Host 'Revoked. Dedicated account is disabled (or removed); unrelated SSH policy and keys retained.'
Write-Host 'Broker token/logs remain in the protected directory for audit; rotate the token before re-enabling.'
