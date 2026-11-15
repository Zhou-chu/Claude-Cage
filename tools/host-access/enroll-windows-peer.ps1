# One-time physical/admin enrollment. Windows PowerShell 5.1; ASCII source.
# Package adjacent to host-access-common.ps1. No broker or firewall changes.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$GuestPublicKey,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$GuestAddress,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$HostAddress,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$')][string]$ExpectedComputerName,
    [ValidatePattern('^[a-z_][a-z0-9_-]{0,30}$')][string]$UserName = 'cageops',
    [switch]$CheckOnly
)
$ErrorActionPreference = 'Stop'

# Fence MUST precede imports, relaunch, account access and every mutation.
if (-not [string]::Equals($env:COMPUTERNAME, $ExpectedComputerName, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Computer-name fence failed. Run only on the explicitly expected laptop.'
}
if (-not [Environment]::Is64BitProcess) {
    if (-not [Environment]::Is64BitOperatingSystem) { throw '64-bit Windows is required.' }
    $x64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $x64 -PathType Leaf)) { throw 'Cannot find native 64-bit Windows PowerShell.' }
    $forward = @{}
    foreach ($entry in $PSBoundParameters.GetEnumerator()) { $forward[$entry.Key] = $entry.Value }
    $serialized = [Management.Automation.PSSerializer]::Serialize($forward)
    $encodedParams = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($serialized))
    $literalPath = "'" + $PSCommandPath.Replace("'", "''") + "'"
    $code = '$ErrorActionPreference=''Stop'';try { if (-not [Environment]::Is64BitProcess) { throw ''Native relaunch failed.'' };$p=[Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''' + $encodedParams + '''))); & ' + $literalPath + ' @p;exit 0 } catch { Write-Error -ErrorRecord $_ -ErrorAction Continue;exit 1 }'
    Write-Host 'Switching to 64-bit Windows PowerShell...'
    & $x64 -NoProfile -ExecutionPolicy Bypass -OutputFormat Text -InputFormat Text -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code)))
    exit $LASTEXITCODE
}
. (Join-Path $PSScriptRoot 'host-access-common.ps1')
# Extend, rather than replace, the common pre-install effective-policy check.
$commonEffectiveValidator = ${function:Assert-CageEffectiveConfig}
function Assert-CageEffectiveConfig {
    param([string[]]$Effective, [string]$UserName, [string]$GuestAddress)
    & $commonEffectiveValidator $Effective $UserName $GuestAddress
    if ($Effective -notcontains 'pubkeyauthentication yes') { throw 'Effective public-key authentication is not enabled; no config installed.' }
}

function Assert-PeerAddress([string]$Value, [string]$Label) {
    $ip = $null
    if ($Value -notmatch '\A100\.(?:[0-9]{1,3}\.)[0-9]{1,3}\.[0-9]{1,3}\z' -or
        -not [Net.IPAddress]::TryParse($Value, [ref]$ip) -or
        $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.ToString() -cne $Value) {
        throw "$Label must be a canonical IPv4 address in 100.64.0.0/10."
    }
    $b = $ip.GetAddressBytes()
    if ($b[0] -ne 100 -or $b[1] -lt 64 -or $b[1] -gt 127) { throw "$Label must be in 100.64.0.0/10." }
}
function Assert-PeerPlainPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'SSH paths must not traverse reparse points.' }
        if ($item -is [IO.DirectoryInfo]) { $item = $item.Parent }
        else { $item = $item.Directory }
    }
}
function Get-PeerMembership($Group, [string]$MemberPath) {
    # Do not cast a null/failed query to false and silently authorize an account.
    $result = $Group.psbase.Invoke('IsMember', @($MemberPath))
    if ($result -isnot [bool]) { throw 'Local group membership query returned no Boolean result.' }
    return $result
}

function Assert-PeerPublicKey([string]$GuestPublicKey) {
    # Exactly one plain public-key line; reject options, CR/LF and controls.
    if ($GuestPublicKey -cnotmatch '\Assh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: [\x20-\x7e]+)?\z') {
        throw 'Expected exactly one ASCII ssh-ed25519 public key line without options.'
    }
    $keyBlob = [Convert]::FromBase64String($Matches[1])
    # SSH wire format: uint32(11), ssh-ed25519, uint32(32), 32 public bytes.
    $prefix = [byte[]]@(0,0,0,11,115,115,104,45,101,100,50,53,53,49,57,0,0,0,32)
    if ($keyBlob.Length -ne 51) { throw 'Invalid Ed25519 public key wire length.' }
    for ($i = 0; $i -lt $prefix.Length; $i++) {
        if ($keyBlob[$i] -ne $prefix[$i]) { throw 'Invalid Ed25519 public key wire structure.' }
    }
}
Assert-PeerAddress $GuestAddress 'GuestAddress'
Assert-PeerAddress $HostAddress 'HostAddress'
if ($HostAddress -eq $GuestAddress) { throw 'Guest and host addresses must differ.' }
Assert-PeerPublicKey $GuestPublicKey
if (-not @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $HostAddress -ErrorAction Stop).Count) {
    throw 'HostAddress is not assigned to this laptop.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($UserName -ieq $identity.Name.Split('\')[-1]) { throw 'Dedicated user must not be the current operator.' }
if (-not $CheckOnly -and -not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Apply requires an administrator Windows PowerShell window.'
}
$service = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
if (-not $service -or $service.State -ne 'Running') { throw 'An installed, running sshd service is required.' }
$sshdExe = Get-CageSshdExe
# Common helpers use the standard config path. Refuse service overrides rather
# than changing a config file that this service might not actually load.
$serviceCommand = $service.PathName.Trim()
if ($serviceCommand -ine $sshdExe -and $serviceCommand -ine ('"' + $sshdExe + '"')) {
    throw 'sshd service has custom arguments; inspect its config path before enrollment.'
}
$configDir = Join-Path $env:ProgramData 'ssh'
$configPath = Join-Path $configDir 'sshd_config'
$keyFile = Join-Path $configDir ($UserName + '_authorized_keys')
$hostKeyFile = Join-Path $configDir 'ssh_host_ed25519_key.pub'
$sshKeygen = Join-Path (Split-Path -Parent $sshdExe) 'ssh-keygen.exe'
Assert-PeerPlainPath $configDir
foreach ($path in @($configPath, $hostKeyFile, $sshKeygen)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file missing: $path" }
    Assert-PeerPlainPath $path
}
$line = 'from="' + $GuestAddress + '",no-agent-forwarding,no-port-forwarding,no-X11-forwarding ' + $GuestPublicKey
if (Test-Path -LiteralPath $keyFile) {
    if (-not (Test-Path -LiteralPath $keyFile -PathType Leaf)) { throw 'Dedicated key path is not a regular file.' }
    Assert-PeerPlainPath $keyFile
    $existing = [IO.File]::ReadAllText($keyFile)
    if ($existing.TrimEnd([char[]]"`r`n") -cne $line) {
        throw 'Existing key file is not exactly compatible. Refusing to erase or replace keys.'
    }
}
$oldConfig = [IO.File]::ReadAllText($configPath)
$candidate = New-CageSshConfig $oldConfig $UserName $GuestAddress
$computer = [ADSI]("WinNT://{0},computer" -f $env:COMPUTERNAME)
$names = @($computer.Children | Where-Object { $_.SchemaClassName -eq 'user' } | ForEach-Object { [string]$_.Name })
$exists = $names -icontains $UserName
$userPath = 'WinNT://{0}/{1}' -f $env:COMPUTERNAME, $UserName
$adminName = (Get-CageSid 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
$usersName = (Get-CageSid 'S-1-5-32-545').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
$admins = [ADSI]("WinNT://{0}/{1},group" -f $env:COMPUTERNAME, $adminName)
$users = [ADSI]("WinNT://{0}/{1},group" -f $env:COMPUTERNAME, $usersName)
# Force both group bindings even for a new account; binding failures are fatal.
if ([string]$admins.SchemaClassName -ne 'Group' -or [string]$users.SchemaClassName -ne 'Group') { throw 'Cannot resolve required local groups.' }
$inUsers = $false
if ($exists) {
    $user = [ADSI]$userPath
    $userSid = (New-Object Security.Principal.NTAccount($env:COMPUTERNAME, $UserName)).Translate([Security.Principal.SecurityIdentifier])
    if ($userSid -eq $identity.User) { throw 'Dedicated account resolves to the current operator.' }
    if (Get-PeerMembership $admins $userPath) { throw 'Dedicated account is an Administrators member; refusing enrollment.' }
    if ([int]$user.UserFlags.Value -band 2) { throw 'Existing dedicated account is disabled; refusing to enable it.' }
    $inUsers = Get-PeerMembership $users $userPath
}
if ($CheckOnly) {
    Write-Host 'Read-only preflight passed; no accounts, keys, ACLs, config, firewall or services changed.'
    Write-Host ("Plan: {0} standard local user {1}; preserve existing password; ensure Users membership." -f $(if ($exists) { 'reuse' } else { 'create' }), $UserName)
    Write-Host 'Plan: install compatible source-restricted key with SID ACL; transactionally validate/install SSH rules and restart sshd.'
    Write-Host 'No firewall, VPN, broker or administrator membership changes are planned.'
    Write-Host 'sshd candidate syntax/effective-policy validation requires apply; no temporary config was written in CheckOnly.'
    return
}
$created = $false
try {
    if (-not $exists) {
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        $bytes = New-Object byte[] 32
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        $user = $computer.Create('User', $UserName)
        try { $user.SetPassword(('aA1!' + [Convert]::ToBase64String($bytes))) }
        finally { [Array]::Clear($bytes, 0, $bytes.Length) }
        $user.Put('Description', 'Cage guest SSH operator (standard user)')
        # Commit disabled; only enable after key/config validation has succeeded.
        $user.Put('UserFlags', (0x200 -bor 0x10000 -bor 2))
        $user.SetInfo()
        $created = $true
        $userSid = (New-Object Security.Principal.NTAccount($env:COMPUTERNAME, $UserName)).Translate([Security.Principal.SecurityIdentifier])
    }
    if (Get-PeerMembership $admins $userPath) { throw 'Dedicated account is an Administrators member.' }
    if (-not (Get-PeerMembership $users $userPath)) { $users.Add($userPath) }
    if (-not (Get-PeerMembership $users $userPath)) { throw 'Users membership verification failed.' }
    # Never replace unknown keys. Recheck immediately before writing.
    if (Test-Path -LiteralPath $keyFile) {
        Assert-PeerPlainPath $keyFile
        if ([IO.File]::ReadAllText($keyFile).TrimEnd([char[]]"`r`n") -cne $line) { throw 'Key file changed during enrollment; refusing replacement.' }
    } else {
        # CreateNew prevents overwriting a file appearing after the preflight.
        $stream = New-Object IO.FileStream($keyFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $data = [Text.Encoding]::ASCII.GetBytes($line + "`r`n"); $stream.Write($data, 0, $data.Length) }
        finally { $stream.Dispose() }
    }
    Set-Acl -LiteralPath $keyFile -AclObject (New-CageKeyAcl $userSid)
    $actual = Get-Acl -LiteralPath $keyFile
    $expectedAcl = New-CageKeyAcl $userSid
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
    if ($actual.GetSecurityDescriptorSddlForm($sections) -cne $expectedAcl.GetSecurityDescriptorSddlForm($sections)) { throw 'Dedicated key ACL verification failed.' }
    if ([IO.File]::ReadAllText($configPath) -cne $oldConfig) { throw 'sshd config changed during enrollment; rerun preflight.' }
    Set-CageSshConfig -Path $configPath -Content $candidate -SshdExe $sshdExe -ValidateUser $UserName -GuestAddress $GuestAddress
    if ((Get-Service -Name sshd -ErrorAction Stop).Status -ne 'Running') { throw 'sshd is not running after restart.' }
    if ($created) { $user.UserFlags.Value = [int]$user.UserFlags.Value -band (-bnot 2); $user.SetInfo() }
    Write-Host 'Public SSH host key (independently verify/pin before connecting):'
    # Read ONLY the public host key; never inspect or print private key material.
    Write-Host ([IO.File]::ReadAllText($hostKeyFile).TrimEnd())
    Invoke-CageNative $sshKeygen @('-l', '-E', 'sha256', '-f', $hostKeyFile)
    Write-Host 'Enrollment complete. Password was not displayed or reset; no broker, firewall or VPN changes made.'
    Write-Host 'Physical acceptance and a separately authorized guest SSH test remain required.'
} catch {
    if ($created) {
        try {
            $user.UserFlags.Value = [int]$user.UserFlags.Value -bor 2
            $user.SetInfo()
            Write-Warning 'Enrollment failed; newly created local account was disabled.'
        } catch { Write-Warning 'CRITICAL: could not disable newly created account; administrator intervention required.' }
    }
    throw
}
