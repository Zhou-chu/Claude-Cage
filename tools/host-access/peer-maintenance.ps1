# PS5.1 x64 ASCII definitions only. Embed trusted definitions; never execute Desktop scripts as SYSTEM.
# Requires host-access-common.ps1 (-KeepServiceStopped), sshd-system-validation.ps1 and
# enrollment's native membership, Set-PeerAccountEnabled, Assert-PeerPublicKey/KeyAcl functions.
function Get-CagePmHash([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Assert-CagePmRecovery([string]$Directory) {
    $root = Get-CageSsvRoot
    $null = Assert-CageSsvPlainPath $Directory
    if ([IO.Path]::GetDirectoryName($Directory) -ine $root -or
        [IO.Path]::GetFileName($Directory) -cnotmatch '\Acage-peer-maintenance-(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\z') { throw 'Invalid maintenance recovery location.' }
    Assert-CageSsvSealedPath $Directory $true
}
function Write-CagePmFile([string]$Directory, [string]$Name, [byte[]]$Bytes) {
    Assert-CagePmRecovery $Directory
    if ($Name -cnotin @('original.conf','candidate.conf','result.json')) { throw 'Invalid maintenance output name.' }
    $path = Join-Path $Directory $Name
    $null = Assert-CageSsvPlainPath $path -MissingLeaf
    # CreateNew + security descriptor in the same NTFS create; no unsealed interval/overwrite.
    $stream = New-Object IO.FileStream($path, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, (New-CageSsvAcl $false))
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    Assert-CageSsvSealedPath $path $false
}
function Get-CagePmAccount([string]$UserName) {
    $user = [ADSI]('WinNT://{0}/{1},user' -f [Environment]::MachineName, $UserName)
    $user.psbase.RefreshCache(@('UserFlags','Description','objectSID'))
    $sid = New-Object Security.Principal.SecurityIdentifier([byte[]]$user.objectSID.Value, 0)
    return [pscustomobject]@{ Handle=$user; Sid=$sid; Flags=[int]$user.UserFlags.Value; Description=[string]$user.Description.Value }
}
function Assert-CagePmAccount([string]$UserName, [string]$ExpectedSid, [bool]$Enabled) {
    $account = Get-CagePmAccount $UserName
    if ($account.Sid.Value -cne $ExpectedSid -or $account.Description -cne 'Cage guest SSH operator (standard user)' -or
        ([bool]($account.Flags -band 2)) -eq $Enabled) { throw 'Target SID, description or account state changed.' }
    if ((Get-PeerMembership (Resolve-PeerGroupName 'S-1-5-32-544') $account.Sid) -or
        -not (Get-PeerMembership (Resolve-PeerGroupName 'S-1-5-32-545') $account.Sid)) { throw 'Target must be a nonadministrator Users member.' }
    return $account
}
function Get-CagePmService {
    $services = @(Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop)
    if ($services.Count -ne 1) { throw 'sshd service is not unique.' }
    $service = $services[0]
    $exe = Get-CageSsvServiceExe
    Assert-CageSsvExe $exe
    Assert-CageSsvPrivilegedObject $exe
    if ($service.StartName -cnotin @('LocalSystem','NT AUTHORITY\SYSTEM') -or
        ($service.PathName.Trim() -ine $exe -and $service.PathName.Trim() -ine ('"' + $exe + '"'))) { throw 'sshd must use LocalSystem and the exact executable without overrides.' }
    return [pscustomobject]@{ State=[string]$service.State; ProcessId=[int]$service.ProcessId; Exe=$exe }
}
function Assert-CagePmNoListeners([int]$OriginalPid) {
    if ((Get-CagePmService).State -cne 'Stopped') { throw 'sshd is not stopped.' }
    $ids = @($OriginalPid) + @(Get-CimInstance Win32_Process -Filter "Name='sshd.exe'" -ErrorAction Stop | ForEach-Object { [int]$_.ProcessId })
    if (@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $ids -contains [int]$_.OwningProcess }).Count) { throw 'An sshd process still owns a TCP listener.' }
}
function Stop-CagePmService([int]$OriginalPid) {
    $service = Get-Service -Name sshd -ErrorAction Stop
    if ($service.Status -ne 'Stopped') { Stop-Service -Name sshd -NoWait -ErrorAction Stop }
    # No Force, no dependent-service stop and no process killing.
    (Get-Service -Name sshd -ErrorAction Stop).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(20))
    Assert-CagePmNoListeners $OriginalPid
}
function Wait-CagePmRunning([string]$HostAddress) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        $service = Get-CagePmService
        if ($service.State -ceq 'Running' -and $service.ProcessId -gt 0 -and
            @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { [int]$_.OwningProcess -eq $service.ProcessId -and $_.LocalAddress -in @($HostAddress,'0.0.0.0','::') }).Count) { return $service }
        [Threading.Thread]::Sleep(100)
    } while ($clock.Elapsed.TotalSeconds -lt 20)
    throw 'sshd did not become running and listening within 20 seconds.'
}
function Assert-CagePmKey([string]$Path, [string]$ExpectedHash, [string]$UserSid) {
    $null = Assert-CageSsvPlainPath $Path
    Assert-PeerKeyAcl -Actual (Get-Acl -LiteralPath $Path -ErrorAction Stop) -Expected (New-CageKeyAcl (Get-CageSid $UserSid))
    if ((Get-CagePmHash ([IO.File]::ReadAllBytes($Path))) -cne $ExpectedHash) { throw 'Dedicated public key snapshot changed.' }
}
function Restore-CagePmConfig([string]$Path, [byte[]]$Original, [string]$CandidateHash) {
    $null = Assert-CageSsvPlainPath $Path
    Assert-CageSsvPrivilegedObject $Path
    $originalHash = Get-CagePmHash $Original
    # Compare and restore through one exclusive handle; never clobber an intervening writer.
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        if ($stream.Length -gt 1048576) { throw 'External config size changed.' }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset=0
        while ($offset -lt $bytes.Length) { $read=$stream.Read($bytes,$offset,$bytes.Length-$offset); if ($read -le 0) { throw 'Incomplete config read.' }; $offset+=$read }
        $current = Get-CagePmHash $bytes
        if ($current -cne $originalHash -and $current -cne $CandidateHash) { throw 'External config edit: refusing restoration.' }
        if ($current -cne $originalHash) { $stream.Position=0; $stream.Write($Original,0,$Original.Length); $stream.SetLength($Original.Length); $stream.Flush($true) }
    } finally { $stream.Dispose() }
    if ((Get-CagePmHash ([IO.File]::ReadAllBytes($Path))) -cne $originalHash) { throw 'Original config restoration was not exact.' }
}
function Get-CagePmPublicHostKey([string]$Root) {
    try {
        $path = Join-Path $Root 'ssh_host_ed25519_key.pub'
        $null = Assert-CageSsvPlainPath $path
        if ((Get-Item -LiteralPath $path -Force -ErrorAction Stop).Length -gt 4096) { throw 'Oversized public key.' }
        $line = [IO.File]::ReadAllText($path).TrimEnd([char[]]"`r`n")
        Assert-PeerPublicKey $line
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $fingerprint = 'SHA256:' + [Convert]::ToBase64String($sha.ComputeHash([Convert]::FromBase64String($line.Split(' ')[1]))).TrimEnd('=') }
        finally { $sha.Dispose() }
        return [pscustomobject]@{ PublicKey=$line; Fingerprint=$fingerprint }
    } catch { return $null } # Optional public-only reporting; never read the private host key.
}
function Invoke-CagePeerMaintenanceCore {
    # Internal test seam. Production encoded action MUST use the direct-gated public entry.
    [CmdletBinding()]
    param([string]$ExpectedComputerName, [string]$UserName, [string]$GuestAddress, [string]$HostAddress,
        [string]$ExpectedUserSid, [string]$ExpectedConfigHash, [string]$ExpectedKeyHash, [string]$RecoveryDirectory)
    $ErrorActionPreference = 'Stop'
    if (-not [string]::Equals([Environment]::MachineName, $ExpectedComputerName, [StringComparison]::OrdinalIgnoreCase)) { throw 'Actual computer-name fence failed.' }
    if ($UserName -cne 'cageops' -or $GuestAddress -cne '100.65.250.76' -or $HostAddress -cne '100.112.222.42' -or
        $ExpectedUserSid -cnotmatch '\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z' -or
        $ExpectedConfigHash -cnotmatch '\A[0-9a-f]{64}\z' -or $ExpectedKeyHash -cnotmatch '\A[0-9a-f]{64}\z') { throw 'Noncanonical maintenance identity, addresses or hashes.' }
    Assert-CageSsvContext $UserName $GuestAddress 30
    Assert-CagePmRecovery $RecoveryDirectory
    foreach ($name in @('original.conf','candidate.conf','result.json')) {
        if (Test-Path -LiteralPath (Join-Path $RecoveryDirectory $name)) { throw 'Recovery output collision.' }
    }
    Initialize-PeerNativeMembership
    $null = Assert-CagePmAccount $UserName $ExpectedUserSid $false
    if (-not @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $HostAddress -ErrorAction Stop | Where-Object { $_.IPAddress -ceq $HostAddress }).Count) { throw 'HostAddress is not assigned to this machine.' }
    $service = Get-CagePmService
    if ($service.State -cne 'Running' -or $service.ProcessId -le 0) { throw 'An existing running sshd service is required.' }
    $root = Get-CageSsvRoot
    $path = Join-Path $root 'sshd_config'
    $key = Join-Path $root ($UserName + '_authorized_keys')
    $null = Assert-CageSsvPlainPath $path
    Assert-CageSsvPrivilegedObject $path
    $original = [IO.File]::ReadAllBytes($path)
    if ((Get-CagePmHash $original) -cne $ExpectedConfigHash) { throw 'Active config snapshot changed.' }
    Assert-CagePmKey $key $ExpectedKeyHash $ExpectedUserSid
    $publicHost = Get-CagePmPublicHostKey $root
    $candidateHash = ''
    $proof = @{ Calls=0; Lines=@(); NativeStopped=$true; NativeStatus=$null; Diagnostics=@() }
    $result = [pscustomobject]@{ Success=$false; Machine=[Environment]::MachineName; UserSid=$ExpectedUserSid; SystemSid='S-1-5-18'; AccountEnabled=$false; StandardUser=$false; ServiceState='Unknown'; OriginalConfigHash=$ExpectedConfigHash; CandidateConfigHash=''; ActiveConfigHash=''; PublicHost=$publicHost; Critical=$false; Error=''; Native=$null; Diagnostics=@(); Effective=@() }
    # All preconditions are complete. Snapshot original bytes BEFORE service/account changes.
    Write-CagePmFile $RecoveryDirectory 'original.conf' $original
    try {
        Stop-CagePmService $service.ProcessId
        $account = Assert-CagePmAccount $UserName $ExpectedUserSid $false
        Assert-CagePmKey $key $ExpectedKeyHash $ExpectedUserSid
        Assert-CagePmNoListeners $service.ProcessId
        Set-PeerAccountEnabled $account.Handle $true
        $null = Assert-CagePmAccount $UserName $ExpectedUserSid $true
        $memory = New-Object IO.MemoryStream(,$original)
        $reader = New-Object IO.StreamReader($memory, (New-Object Text.UTF8Encoding($false,$true)), $true)
        try { $content = New-CageSshConfig ($reader.ReadToEnd()) $UserName $GuestAddress } finally { $reader.Dispose() }
        Assert-CageSsvContent $content
        $candidateBytes = (New-Object Text.UTF8Encoding($false,$true)).GetBytes($content)
        $candidateHash = Get-CagePmHash $candidateBytes
        $candidatePath = Join-Path $RecoveryDirectory 'candidate.conf'
        Write-CagePmFile $RecoveryDirectory 'candidate.conf' $candidateBytes
        if ((Get-CagePmHash ([IO.File]::ReadAllBytes($path))) -cne $ExpectedConfigHash) { throw 'External config edit before commit.' }
        # Distinct name avoids dynamic-scope collisions with common setter locals/parameters.
        $pmContext = @{ Proof=$proof; Service=$service; Content=$content; CandidatePath=$candidatePath; CandidateHash=$candidateHash; Path=$path; User=$UserName; Guest=$GuestAddress; OriginalHash=$ExpectedConfigHash }
        $validator = {
            param($ValidationContent, $ValidationUser, $ValidationAddress)
            if ($pmContext.Proof.Calls -ne 0 -or $ValidationContent -cne $pmContext.Content -or $ValidationUser -cne $pmContext.User -or $ValidationAddress -cne $pmContext.Guest) { throw 'Unexpected effective-validation callback context.' }
            $pmContext.Proof.Calls++
            Assert-CagePmNoListeners $pmContext.Service.ProcessId
            Assert-CageSsvSealedPath $pmContext.CandidatePath $false
            if ((Get-CagePmHash ([IO.File]::ReadAllBytes($pmContext.CandidatePath))) -cne $pmContext.CandidateHash) { throw 'Sealed candidate changed.' }
            $pmContext.Proof.NativeStopped = $false
            $native = Invoke-CageSsvNative $pmContext.Service.Exe @('-T','-f',$pmContext.CandidatePath,'-C',("user=" + $pmContext.User + ',host=cage-guest,addr=' + $pmContext.Guest)) 10
            $pmContext.Proof.NativeStopped = [bool]$native.Stopped
            $pmContext.Proof.NativeStatus = ConvertTo-CageSsvStatus $native
            $pmContext.Proof.Diagnostics = @()
            if ($native.PSObject.Properties['Diagnostics']) {
                $pmContext.Proof.Diagnostics = @($native.Diagnostics | Where-Object { $_ -cmatch '\A(get_user_token|ga_init|generate_s4u_user_token|LsaLogonUser)(?: \[code=(?:0x[0-9a-fA-F]{1,8}|[0-9]{1,10})\])?\z' } | Select-Object -First 8)
            }
            if (-not (Test-CageSsvNativeSuccess $native)) { throw 'SYSTEM effective validation failed.' }
            $pmContext.Proof.Lines = @(Select-CageSsvEffective @($native.Lines))
            Assert-CageEffectiveConfig $pmContext.Proof.Lines $pmContext.User $pmContext.Guest
            if ($pmContext.Proof.Lines -cnotcontains 'pubkeyauthentication yes') { throw 'Public-key authentication is not enabled.' }
            if ((Get-CagePmHash ([IO.File]::ReadAllBytes($pmContext.Path))) -cne $pmContext.OriginalHash) { throw 'External config edit during validation.' }
            return $pmContext.Proof.Lines
        }
        Set-CageSshConfig -Path $path -Content $content -SshdExe $service.Exe -ValidateUser $UserName -GuestAddress $GuestAddress -KeepServiceStopped -EffectiveValidator $validator
        if ($proof.Calls -ne 1 -or -not $proof.NativeStopped -or @($proof.Lines).Count -ne 7) { throw 'No complete seven-field validation proof.' }
        $null = Assert-CagePmAccount $UserName $ExpectedUserSid $true
        Assert-CagePmKey $key $ExpectedKeyHash $ExpectedUserSid
        if ((Get-CagePmHash ([IO.File]::ReadAllBytes($path))) -cne $candidateHash -or (Get-CagePmService).Exe -ine $service.Exe) { throw 'Committed config or service executable changed.' }
        Assert-CagePmNoListeners $service.ProcessId
        Start-Service -Name sshd -ErrorAction Stop
        $running = Wait-CagePmRunning $HostAddress
        $null = Assert-CagePmAccount $UserName $ExpectedUserSid $true
        Assert-CagePmKey $key $ExpectedKeyHash $ExpectedUserSid
        if ((Get-CagePmHash ([IO.File]::ReadAllBytes($path))) -cne $candidateHash) { throw 'Active config changed after start.' }
        $result.Success=$true; $result.AccountEnabled=$true; $result.StandardUser=$true; $result.ServiceState=$running.State
        $result.CandidateConfigHash=$candidateHash; $result.ActiveConfigHash=$candidateHash
        $result.Native=$proof.NativeStatus; $result.Diagnostics=@($proof.Diagnostics); $result.Effective=@($proof.Lines); Write-CagePmFile $RecoveryDirectory 'result.json' ([Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 4 -Compress)))
        return $result
    } catch {
        # Common bounded syntax failures propagate this marker, even before our callback.
        if ($_.Exception.Data['CageNativeUnproven']) { $proof.NativeStopped=$false }
        $result.Success=$false; $result.AccountEnabled=$null; $result.Error='MaintenanceFailed'; $result.CandidateConfigHash=$candidateHash
        if (-not $proof.NativeStopped) { $result.Error='NativeTerminationUnproven' }
        $isolated=$false; $disabled=$false; $restored=$false
        # FIRST isolate, even if enable/commit/start threw after partially succeeding.
        try { Stop-CagePmService $service.ProcessId; $isolated=$true } catch { $result.Critical=$true }
        try {
            $account = Get-CagePmAccount $UserName
            if ($account.Sid.Value -cne $ExpectedUserSid) { throw 'Rollback target SID changed.' }
            Set-PeerAccountEnabled $account.Handle $false
            $fresh = Get-CagePmAccount $UserName
            if ($fresh.Sid.Value -cne $ExpectedUserSid -or -not ($fresh.Flags -band 2)) { throw 'Rollback disabled state not proven.' }
            $disabled=$true; $result.AccountEnabled=$false
        } catch { $result.Critical=$true }
        if ($isolated -and $disabled -and $proof.NativeStopped) {
            try {
                $snapshot = Join-Path $RecoveryDirectory 'original.conf'
                Assert-CageSsvSealedPath $snapshot $false
                if ((Get-CagePmHash ([IO.File]::ReadAllBytes($snapshot))) -cne $ExpectedConfigHash) { throw 'Original snapshot changed.' }
                Restore-CagePmConfig $path $original $candidateHash
                $proof.NativeStopped=$false
                $syntax = Invoke-CageSsvNative $service.Exe @('-t','-f',$path) 10
                $proof.NativeStopped=[bool]$syntax.Stopped
                if (-not (Test-CageSsvNativeSuccess $syntax)) { throw 'Restored config syntax not proven.' }
                $fresh = Get-CagePmAccount $UserName
                if ($fresh.Sid.Value -cne $ExpectedUserSid -or -not ($fresh.Flags -band 2)) { throw 'Disabled state changed before original start.' }
                Assert-CagePmNoListeners $service.ProcessId
                if ((Get-CagePmHash ([IO.File]::ReadAllBytes($path))) -cne $ExpectedConfigHash -or (Get-CagePmService).Exe -ine $service.Exe) { throw 'Restoration changed before start.' }
                Start-Service -Name sshd -ErrorAction Stop
                $null = Wait-CagePmRunning $HostAddress
                $fresh = Get-CagePmAccount $UserName
                if ($fresh.Sid.Value -cne $ExpectedUserSid -or -not ($fresh.Flags -band 2) -or (Get-CagePmHash ([IO.File]::ReadAllBytes($path))) -cne $ExpectedConfigHash) { throw 'Restored account/config changed after start.' }
                $restored=$true
            } catch { $result.Critical=$true }
        } else { $result.Critical=$true }
        if (-not $restored) { try { Stop-CagePmService $service.ProcessId } catch { $result.Critical=$true } }
        $result.ServiceState = if ($restored) { 'Running' } else { 'StoppedUnproven' }
        try { $result.ActiveConfigHash=Get-CagePmHash ([IO.File]::ReadAllBytes($path)) } catch { $result.Critical=$true }
        try { $result.Native=$proof.NativeStatus; $result.Diagnostics=@($proof.Diagnostics); $result.Effective=@($proof.Lines); Write-CagePmFile $RecoveryDirectory 'result.json' ([Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 4 -Compress))) } catch { $result.Critical=$true }
        if ($result.Critical) { throw 'CRITICAL: maintenance failed; no restart authorized without verified disable, isolation and config restoration. Inspect retained recovery files.' }
        throw 'Maintenance failed; exact original account disabled and original service/config restored. Inspect retained recovery files.'
    }
}
function Invoke-CagePeerMaintenance {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ExpectedComputerName, [Parameter(Mandatory=$true)][string]$UserName,
        [Parameter(Mandatory=$true)][string]$GuestAddress, [Parameter(Mandatory=$true)][string]$HostAddress,
        [Parameter(Mandatory=$true)][string]$ExpectedUserSid, [Parameter(Mandatory=$true)][string]$ExpectedConfigHash,
        [Parameter(Mandatory=$true)][string]$ExpectedKeyHash, [Parameter(Mandatory=$true)][string]$RecoveryDirectory)
    # Direct, unparameterized identity/platform gates; tests ONLY mock the internal core.
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') { throw 'Maintenance refused non-SYSTEM identity before reading inputs.' }
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess -or [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows PowerShell 5.1 x64 is required.' }
    Invoke-CagePeerMaintenanceCore @PSBoundParameters
}
