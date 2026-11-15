# Cage host access: dedicated standard user + explicit human approval.
# Windows PowerShell 5.1, run as administrator. Deployment values stay local.
[CmdletBinding()]
param(
    [string]$GuestPublicKey,
    [string]$GuestAddress,
    [ValidatePattern('^[a-z_][a-z0-9_-]{0,30}$')][string]$UserName = 'cageops',
    [string]$BrokerAddress,
    [ValidateRange(1024,65535)][int]$BrokerPort = 8642,
    [switch]$AlreadyRelaunched,
    [switch]$CheckOnly
)
$ErrorActionPreference = 'Stop'
$script:step = 'initialization'
trap {
    Write-Host ("[FAILED] {0}: {1} (line {2})" -f $script:step, $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
    exit 1
}
function Step([string]$Name) { $script:step = $Name; Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Name) -ForegroundColor Cyan }

# Preserve every explicitly supplied parameter when switching bitness.
if (-not [Environment]::Is64BitProcess) {
    if ($AlreadyRelaunched) { throw '64-bit PowerShell relaunch failed.' }
    $x64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $x64)) { throw 'Cannot find native 64-bit PowerShell.' }
    $forward = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) { $forward[$entry.Key] = $entry.Value }
    $forward['AlreadyRelaunched'] = $true
    $serialized = [Management.Automation.PSSerializer]::Serialize($forward)
    $encodedParams = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($serialized))
    $literalPath = "'" + $PSCommandPath.Replace("'", "''") + "'"
    $code = '$ProgressPreference=''SilentlyContinue'';$p=[Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''' + $encodedParams + '''))); & ' + $literalPath + ' @p 6>&1 | ForEach-Object {[string]$_}; exit $LASTEXITCODE'
    Write-Host 'Switching to 64-bit Windows PowerShell...'
    & $x64 -NoProfile -ExecutionPolicy Bypass -OutputFormat Text -InputFormat Text -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code)))
    exit $LASTEXITCODE
}
. (Join-Path $PSScriptRoot 'host-access-common.ps1')
$localPath = Join-Path $PSScriptRoot 'host-access.local.psd1'
if (Test-Path -LiteralPath $localPath) {
    $local = Import-PowerShellDataFile -LiteralPath $localPath
    foreach ($name in @('GuestPublicKey','GuestAddress','BrokerAddress')) {
        if (-not (Get-Variable -Name $name -ValueOnly) -and $local.ContainsKey($name)) { Set-Variable -Name $name -Value $local[$name] }
    }
}
foreach ($name in @('GuestPublicKey','GuestAddress','BrokerAddress')) {
    if (-not (Get-Variable -Name $name -ValueOnly)) { throw "Missing $name. Set parameters or create host-access.local.psd1 (see example)." }
}
if ($GuestPublicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]*)?$') { throw 'Expected a single ssh-ed25519 public key.' }
$brokerIP = $null
if (-not [Net.IPAddress]::TryParse($BrokerAddress,[ref]$brokerIP) -or $brokerIP.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'BrokerAddress must be a tailnet IPv4 address.' }
$b = $brokerIP.GetAddressBytes()
if ($b[0] -ne 100 -or $b[1] -lt 64 -or $b[1] -gt 127) { throw 'BrokerAddress must be within 100.64.0.0/10.' }
if (-not (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $BrokerAddress -ErrorAction SilentlyContinue)) { throw 'BrokerAddress is not assigned to this host.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($UserName -eq $identity.Name.Split('\')[-1].ToLowerInvariant()) { throw 'Dedicated user must not be the current host operator.' }
$sshdExe = Get-CageSshdExe
$configPath = Join-Path $env:ProgramData 'ssh\sshd_config'
$oldConfig = [IO.File]::ReadAllText($configPath)
$candidate = New-CageSshConfig $oldConfig $UserName $GuestAddress
if ($CheckOnly) {
    Write-Host 'Read-only preflight OK: parameters, address, sshd path and config transformation.'
    Write-Host 'No accounts, ACLs, firewall rules or services changed. Run tests for sshd candidate validation.'
    exit 0
}
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this script in an administrator PowerShell window.' }
Write-Host '== Cage host access setup =='
Write-Host ('PowerShell {0}; 64-bit={1}' -f $PSVersionTable.PSVersion,[Environment]::Is64BitProcess)

Step "1/6 Dedicated local account: $UserName"
$computer = [ADSI]("WinNT://{0},computer" -f $env:COMPUTERNAME)
$names = @($computer.Children | Where-Object { $_.SchemaClassName -eq 'user' } | ForEach-Object { [string]$_.Name })
if ($names -notcontains $UserName) {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $bytes = New-Object byte[] 32; $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $user = $computer.Create('User',$UserName)
    $user.SetPassword(('aA1!' + [Convert]::ToBase64String($bytes)))
    $user.Put('Description','Cage guest SSH operator (standard user)')
    $user.SetInfo()
    $user.UserFlags.Value = $user.UserFlags.Value -bor 0x10000
    $user.SetInfo()
    Write-Host 'Created with a random password (not displayed).'
} else { Write-Host 'Account exists; password unchanged.' }
$userSid = ([Security.Principal.NTAccount]::new($env:COMPUTERNAME,$UserName)).Translate([Security.Principal.SecurityIdentifier])
$userPath = "WinNT://{0}/{1}" -f $env:COMPUTERNAME,$UserName

Step '2/6 Verify standard-user group membership'
$adminName = (Get-CageSid 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
$admins = [ADSI]("WinNT://{0}/{1},group" -f $env:COMPUTERNAME,$adminName)
if ([bool]$admins.psbase.Invoke('IsMember', @($userPath))) { throw 'Dedicated account is an Administrator. Refusing to grant access; remove membership explicitly first.' }
$usersName = (Get-CageSid 'S-1-5-32-545').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
$users = [ADSI]("WinNT://{0}/{1},group" -f $env:COMPUTERNAME,$usersName)
if (-not [bool]$users.psbase.Invoke('IsMember', @($userPath))) { $users.Add($userPath) }
Write-Host 'Verified: not a direct Administrators member; Users membership present.'

Step '3/6 Public key and SID-based ACL'
$keyFile = Join-Path $env:ProgramData "ssh\${UserName}_authorized_keys"
# This file belongs exclusively to this integration. A from= option also restricts legacy SSH configurations.
$line = 'from="' + $GuestAddress + '",no-agent-forwarding,no-port-forwarding,no-X11-forwarding ' + $GuestPublicKey.Trim()
[IO.File]::WriteAllText($keyFile, ($line + "`r`n"), [Text.Encoding]::ASCII)
Set-Acl -LiteralPath $keyFile -AclObject (New-CageKeyAcl $userSid)
$actualAcl = Get-Acl -LiteralPath $keyFile
if ($actualAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') { throw 'Unexpected public key file owner.' }
Write-Host 'Owner=BUILTIN Administrators SID; write=SYSTEM/Admins; dedicated user=read only.'

Step '4/6 Validate and install dedicated-user sshd rules'
Set-CageSshConfig $configPath $candidate $sshdExe $UserName $GuestAddress
Write-Host 'Candidate and installed config validated; sshd restarted. Existing unrelated SSH rules preserved.'

Step '5/6 Limit broker firewall rule to tailnet endpoints'
$ruleName = 'Cage approval broker'
$rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($rule) { $rule | Remove-NetFirewallRule }
New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $BrokerAddress -LocalPort $BrokerPort -RemoteAddress $GuestAddress -Profile Any | Out-Null
Write-Host 'Firewall limited to the configured host and guest tailnet IPs.'

Step '6/6 Install approval broker with protected directory'
$brokerExe = Join-Path $PSScriptRoot 'cage-approve.exe'
if (-not (Test-Path -LiteralPath $brokerExe)) { throw 'Build cage-approve.exe before setup. SSH configured; broker installation incomplete.' }
$target = Join-Path $env:ProgramData 'CageBroker'
if (Test-Path -LiteralPath $target) {
    if ((Get-Item -LiteralPath $target -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Broker directory must not be a reparse point.' }
} else { New-Item -ItemType Directory -Path $target | Out-Null }
$targetExe = Join-Path $target 'cage-approve.exe'
# Stop ONLY the integration binary at this exact installed path, not arbitrary names.
Get-CimInstance Win32_Process -Filter "Name='cage-approve.exe'" | Where-Object { $_.ExecutablePath -eq $targetExe } | ForEach-Object { Stop-Process -Id $_.ProcessId -ErrorAction Stop }
Set-Acl -LiteralPath $target -AclObject (New-CageBrokerAcl $identity.User)
# Remove legacy broad child permissions; root ACL is inherited by each exact descendant.
$children = @(Get-ChildItem -LiteralPath $target -Recurse -Force)
if (@($children | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Broker contents contain a reparse point; inspect before proceeding.' }
foreach ($item in $children) {
    $childAcl = if ($item.PSIsContainer) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $childAcl.SetOwner((Get-CageSid 'S-1-5-32-544'))
    $childAcl.SetAccessRuleProtection($false,$false)
    Set-Acl -LiteralPath $item.FullName -AclObject $childAcl
}
Copy-Item -LiteralPath $brokerExe -Destination $targetExe -Force
# Replace the old all-users startup entry with an entry only for this trusted operator.
$oldLink = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp\Cage approval broker.lnk'
if (Test-Path -LiteralPath $oldLink) { Remove-Item -LiteralPath $oldLink -Force }
$startup = [Environment]::GetFolderPath('Startup')
$link = Join-Path $startup 'Cage approval broker.lnk'
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($link)
$shortcut.TargetPath = $targetExe
$shortcut.Arguments = '-addr ' + $BrokerAddress + ':' + $BrokerPort + ' -allow-source ' + $GuestAddress
$shortcut.WorkingDirectory = $target
$shortcut.Save()
Write-Host 'Installed for current operator login only. Broker was NOT started from this elevated shell.'
Write-Host 'Start the Cage approval broker shortcut from a NORMAL (non-administrator) desktop session.'
Write-Host ''
Write-Host '== Setup complete; SSH authentication still requires a real guest test =='
Write-Host "User: $UserName; public key: $keyFile; broker: ${BrokerAddress}:$BrokerPort"
