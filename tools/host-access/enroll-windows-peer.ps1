# One-time physical/admin enrollment. Windows PowerShell 5.1; ASCII source.
# Package adjacent to host-access-common.ps1. No broker or firewall changes.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$GuestPublicKey,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$GuestAddress,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$HostAddress,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$')][string]$ExpectedComputerName,
    [ValidatePattern('^[a-z_][a-z0-9_-]{0,30}$')][string]$UserName = 'cageops',
    [switch]$CheckOnly,
    # Physical administrator consent only: the description is not cryptographic provenance.
    [switch]$ResumeFailedEnrollment
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
function Initialize-PeerNativeMembership {
    if ('Cage.PeerLocalGroupsV1' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace Cage {
    public sealed class PeerMembershipPage {
        public uint Status;
        public ulong ResumeHandle;
        public string[] MemberSids;
    }
    public static class PeerLocalGroupsV1 {
        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint NetLocalGroupGetMembers(string server, string group, uint level,
            out IntPtr buffer, uint preferredMaximum, out uint entriesRead, out uint totalEntries, ref UIntPtr resume);
        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint NetLocalGroupAddMembers(string server, string group, uint level,
            ref LOCALGROUP_MEMBERS_INFO_0 member, uint entries);
        [DllImport("Netapi32.dll")]
        private static extern uint NetApiBufferFree(IntPtr buffer);
        [StructLayout(LayoutKind.Sequential)]
        private struct LOCALGROUP_MEMBERS_INFO_0 { public IntPtr Sid; }
        public static PeerMembershipPage ReadPage(string group, ulong resumeHandle) {
            if (String.IsNullOrEmpty(group)) throw new ArgumentException("Local group name is empty.");
            IntPtr buffer = IntPtr.Zero;
            UIntPtr resume = new UIntPtr(resumeHandle);
            uint read, total;
            try {
                uint status = NetLocalGroupGetMembers(null, group, 0, out buffer, 65536, out read, out total, ref resume);
                if (status != 0 && status != 234)
                    throw new Win32Exception((int)status, "NetLocalGroupGetMembers failed (" + status + ").");
                if ((read != 0 && buffer == IntPtr.Zero) || read > Int32.MaxValue / IntPtr.Size)
                    throw new InvalidOperationException("Invalid native local-group page.");
                var members = new List<string>();
                for (int i = 0; i < (int)read; ++i) {
                    IntPtr sid = Marshal.ReadIntPtr(buffer, checked(i * IntPtr.Size));
                    if (sid == IntPtr.Zero) throw new InvalidOperationException("Native member SID is null.");
                    members.Add(new SecurityIdentifier(sid).Value);
                }
                return new PeerMembershipPage { Status = status, ResumeHandle = resume.ToUInt64(), MemberSids = members.ToArray() };
            } finally {
                if (buffer != IntPtr.Zero) {
                    uint freed = NetApiBufferFree(buffer);
                    if (freed != 0) throw new Win32Exception((int)freed, "NetApiBufferFree failed (" + freed + ").");
                }
            }
        }
        // Only the fenced apply path calls this method. Defense in depth: require
        // an actual elevated token, and never permit additions to another group.
        public static void AddUsersMember(string group, string memberSid) {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) {
                if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                    throw new UnauthorizedAccessException("Adding Users membership requires an administrator token.");
            }
            string expected = ((NTAccount)new SecurityIdentifier("S-1-5-32-545").Translate(typeof(NTAccount))).Value;
            expected = expected.Substring(expected.LastIndexOf('\\') + 1);
            if (!String.Equals(group, expected, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Only the built-in Users group may be changed.");
            var sid = new SecurityIdentifier(memberSid);
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            GCHandle pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try {
                var member = new LOCALGROUP_MEMBERS_INFO_0 { Sid = pinned.AddrOfPinnedObject() };
                uint status = NetLocalGroupAddMembers(null, group, 0, ref member, 1);
                // A concurrent/already-present addition is safe only because the
                // caller always performs a fresh authoritative query afterwards.
                if (status != 0 && status != 1378)
                    throw new Win32Exception((int)status, "NetLocalGroupAddMembers failed (" + status + ").");
            } finally { pinned.Free(); }
        }
    }
}
'@
}
function ConvertFrom-PeerGroupAccount([string]$AccountName) {
    # Translation supplies the localized name, not parsed command output.
    if ($AccountName -cnotmatch '\A[^\\\x00-\x1f]+\\([^\\\x00-\x1f]+)\z') { throw 'Cannot resolve required local group name.' }
    return $Matches[1]
}
function Resolve-PeerGroupName([string]$GroupSid) {
    if ($GroupSid -cne 'S-1-5-32-544' -and $GroupSid -cne 'S-1-5-32-545') { throw 'Unexpected built-in group SID.' }
    return ConvertFrom-PeerGroupAccount ((Get-CageSid $GroupSid).Translate([Security.Principal.NTAccount]).Value)
}
function Read-PeerMembershipPage([string]$GroupName, [uint64]$ResumeHandle) {
    return [Cage.PeerLocalGroupsV1]::ReadPage($GroupName, $ResumeHandle)
}
function Get-PeerGroupMemberSids([string]$GroupName) {
    $resume = [uint64]0
    $seen = New-Object 'Collections.Generic.HashSet[uint64]'
    $members = New-Object 'Collections.Generic.List[string]'
    do {
        if (-not $seen.Add($resume)) { throw 'Local-group pagination made no progress.' }
        $page = Read-PeerMembershipPage $GroupName $resume
        if ($null -eq $page -or $null -eq $page.MemberSids) { throw 'Local-group query returned no member page.' }
        if ($page.Status -ne 0 -and $page.Status -ne 234) { throw "Local-group query failed ($($page.Status))." }
        foreach ($sid in $page.MemberSids) {
            if ([string]::IsNullOrEmpty($sid)) { throw 'Local-group query returned an empty SID.' }
            # Validate the complete result before returning any membership verdict.
            $members.Add((New-Object Security.Principal.SecurityIdentifier($sid)).Value)
        }
        if ($page.Status -eq 234 -and @($page.MemberSids).Count -eq 0) { throw 'Local-group pagination returned no members.' }
        $resume = [uint64]$page.ResumeHandle
    } while ($page.Status -eq 234)
    return ,($members.ToArray())
}
function Get-PeerMembership([string]$GroupName, [Security.Principal.SecurityIdentifier]$MemberSid) {
    if ($null -eq $MemberSid) { throw 'Membership requires an account SID.' }
    $members = Get-PeerGroupMemberSids $GroupName
    if ($null -eq $members) { throw 'Local-group membership query returned no result.' }
    return ($members -contains $MemberSid.Value)
}
function Add-PeerUsersMembership([string]$GroupName, [Security.Principal.SecurityIdentifier]$MemberSid) {
    [Cage.PeerLocalGroupsV1]::AddUsersMember($GroupName, $MemberSid.Value)
}
function Assert-PeerExistingAccount {
    param([Security.Principal.SecurityIdentifier]$UserSid, [Security.Principal.SecurityIdentifier]$OperatorSid,
        [bool]$IsAdmin, [int]$UserFlags, [AllowNull()][string]$Description, [bool]$Resume)
    if ($null -eq $UserSid -or $null -eq $OperatorSid) { throw 'Cannot resolve dedicated/operator SID.' }
    if ($UserSid -eq $OperatorSid) { throw 'Dedicated account resolves to the current operator.' }
    if ($IsAdmin) { throw 'Dedicated account is an Administrators member; refusing enrollment.' }
    $disabled = [bool]($UserFlags -band 2)
    if ($disabled) {
        if (-not $Resume) { throw 'Existing dedicated account is disabled; refusing to enable it. Physical administrator may explicitly use -ResumeFailedEnrollment after inspection.' }
        if ($Description -cne 'Cage guest SSH operator (standard user)') { throw 'Disabled account description does not exactly match prior enrollment; refusing recovery.' }
    } elseif ($Resume) { throw 'ResumeFailedEnrollment requires an existing disabled dedicated account.' }
    return $disabled
}
function Set-PeerAccountEnabled($User, [bool]$Enabled) {
    $User.psbase.RefreshCache(@('UserFlags'))
    $flags = [int]$User.UserFlags.Value
    if ($Enabled) { $flags = $flags -band (-bnot 2) } else { $flags = $flags -bor 2 }
    $User.Put('UserFlags', $flags)
    $User.SetInfo()
    $User.psbase.RefreshCache(@('UserFlags'))
    if (([bool]([int]$User.UserFlags.Value -band 2)) -eq $Enabled) { throw 'Local account enabled/disabled state verification failed.' }
}
function Restore-PeerDisabledAccount($User, [bool]$Created, [bool]$Resumed) {
    if ($Created -or $Resumed) { Set-PeerAccountEnabled $User $false }
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
if ((-not $CheckOnly -or $ResumeFailedEnrollment) -and -not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Apply or explicit recovery requires an administrator Windows PowerShell window.'
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
Initialize-PeerNativeMembership
$adminName = Resolve-PeerGroupName 'S-1-5-32-544'
$usersName = Resolve-PeerGroupName 'S-1-5-32-545'
# Authoritative native reads must succeed even when the account is not created yet.
$null = Get-PeerGroupMemberSids $adminName
$null = Get-PeerGroupMemberSids $usersName
$resumed = $false
if ($ResumeFailedEnrollment -and -not $exists) { throw 'ResumeFailedEnrollment requires an existing disabled dedicated account.' }
if ($exists) {
    $user = [ADSI]$userPath
    $user.psbase.RefreshCache(@('UserFlags', 'Description'))
    $userSid = (New-Object Security.Principal.NTAccount($env:COMPUTERNAME, $UserName)).Translate([Security.Principal.SecurityIdentifier])
    $resumed = Assert-PeerExistingAccount -UserSid $userSid -OperatorSid $identity.User `
        -IsAdmin (Get-PeerMembership $adminName $userSid) -UserFlags ([int]$user.UserFlags.Value) `
        -Description ([string]$user.Description.Value) -Resume ([bool]$ResumeFailedEnrollment)
    $null = Get-PeerMembership $usersName $userSid
}
if ($CheckOnly) {
    Write-Host 'Read-only preflight passed; no accounts, keys, ACLs, config, firewall or services changed.'
    Write-Host ("Plan: {0} standard local user {1}; preserve existing password; ensure Users membership by SID." -f $(if ($resumed) { 'explicitly recover disabled' } elseif ($exists) { 'reuse' } else { 'create' }), $UserName)
    if ($resumed) { Write-Host 'Recovery consent: description is not cryptographic provenance; account stays disabled until all validation succeeds.' }
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
    if ($userSid -eq $identity.User) { throw 'Dedicated account resolves to the current operator.' }
    if ($resumed) {
        $user.psbase.RefreshCache(@('UserFlags', 'Description'))
        $null = Assert-PeerExistingAccount -UserSid $userSid -OperatorSid $identity.User `
            -IsAdmin (Get-PeerMembership $adminName $userSid) -UserFlags ([int]$user.UserFlags.Value) `
            -Description ([string]$user.Description.Value) -Resume $true
    }
    if (Get-PeerMembership $adminName $userSid) { throw 'Dedicated account is an Administrators member.' }
    if (-not (Get-PeerMembership $usersName $userSid)) { Add-PeerUsersMembership $usersName $userSid }
    if (-not (Get-PeerMembership $usersName $userSid)) { throw 'Users membership verification failed (authoritative SID query).' }
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
    Write-Host 'Public SSH host key (independently verify/pin before connecting):'
    # Read ONLY the public host key; never inspect or print private key material.
    Write-Host ([IO.File]::ReadAllText($hostKeyFile).TrimEnd())
    Invoke-CageNative $sshKeygen @('-l', '-E', 'sha256', '-f', $hostKeyFile)
    if (Get-PeerMembership $adminName $userSid) { throw 'Dedicated account became an Administrators member.' }
    if (-not (Get-PeerMembership $usersName $userSid)) { throw 'Users membership changed during enrollment.' }
    if ($created -or $resumed) {
        $user.psbase.RefreshCache(@('UserFlags', 'Description'))
        $null = Assert-PeerExistingAccount -UserSid $userSid -OperatorSid $identity.User -IsAdmin (Get-PeerMembership $adminName $userSid) `
            -UserFlags ([int]$user.UserFlags.Value) -Description ([string]$user.Description.Value) -Resume $true
        Set-PeerAccountEnabled $user $true
    }
    Write-Host 'Enrollment complete. Password was not displayed or reset; no broker, firewall or VPN changes made.'
    Write-Host 'Physical acceptance and a separately authorized guest SSH test remain required.'
} catch {
    if ($created -or $resumed) {
        try {
            Restore-PeerDisabledAccount $user $created $resumed
            Write-Warning 'Enrollment failed; newly created or explicitly resumed local account was disabled.'
        } catch { Write-Warning 'CRITICAL: could not disable created/resumed account; administrator intervention required.' }
    }
    throw
}
