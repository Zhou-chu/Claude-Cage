# Shared PS 5.1-compatible helpers. No machine changes when dot-sourced.
Set-StrictMode -Version 2

function Get-CageSid {
    param([Parameter(Mandatory=$true)][string]$Value)
    New-Object System.Security.Principal.SecurityIdentifier($Value)
}

function New-CageKeyAcl {
    param([Parameter(Mandatory=$true)][System.Security.Principal.SecurityIdentifier]$Reader)
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((Get-CageSid 'S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule((Get-CageSid $sid), 'FullControl', 'Allow')
        $acl.AddAccessRule($rule)
    }
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Reader, 'ReadAndExecute', 'Allow')))
    return $acl
}

function New-CageBrokerAcl {
    param([Parameter(Mandatory=$true)][System.Security.Principal.SecurityIdentifier]$Operator)
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((Get-CageSid 'S-1-5-32-544'))
    foreach ($sid in @((Get-CageSid 'S-1-5-18'), (Get-CageSid 'S-1-5-32-544'), $Operator)) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    return $acl
}

function Get-CageSshdExe {
    $service = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
    if (-not $service) { throw 'sshd service is not installed.' }
    if ($service.PathName -match '^"([^"]+\.exe)"(?:\s.*)?$') { $exe = $Matches[1] }
    elseif ($service.PathName -match '^(.+?\.exe)(?:\s.*)?$') { $exe = $Matches[1] }
    else { throw 'Cannot parse sshd service executable.' }
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "sshd executable missing: $exe" }
    return $exe
}

function Invoke-CageNative {
    param([string]$Exe, [string[]]$NativeArguments)
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Exe @NativeArguments | Out-Host
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $saved }
    if ($code -ne 0) { throw "Native command failed ($code): $Exe" }
}

function Remove-CageSshBlock {
    param([string]$Content, [string]$UserName)
    $escaped = [regex]::Escape($UserName)
    # Remove only our delimited block, never an unrelated AllowUsers line.
    $pattern = '(?ms)^# BEGIN CAGE HOST ACCESS ' + $escaped + '\r?\n.*?^# END CAGE HOST ACCESS ' + $escaped + '\r?\n?'
    $clean = [regex]::Replace($Content, $pattern, '')
    # Migration from the two earlier published script versions. Exact paired markers only.
    $legacyAllow = '(?m)^# Cage: dedicated standard user, fixed tailnet source only\r?\nAllowUsers ' + $escaped + '@[^\r\n]+\r?\n?'
    $clean = [regex]::Replace($clean, $legacyAllow, '')
    $legacyKey = '(?m)^# Cage: absolute key path, does not depend on profile resolution\r?\nMatch User ' + $escaped + '\r?\n[ \t]+AuthorizedKeysFile __PROGRAMDATA__/ssh/cageops_authorized_keys\r?\n?'
    $clean = [regex]::Replace($clean, $legacyKey, '')
    return $clean
}

function New-CageSshConfig {
    param([string]$Content, [string]$UserName, [string]$GuestAddress)
    if ($UserName -notmatch '^[a-z_][a-z0-9_-]{0,30}$') { throw 'Use a lower-case dedicated local user name.' }
    $address = $null
    if (-not [System.Net.IPAddress]::TryParse($GuestAddress, [ref]$address) -or $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw 'GuestAddress must be an IPv4 address.' }
    $bytes = $address.GetAddressBytes()
    if ($bytes[0] -ne 100 -or $bytes[1] -lt 64 -or $bytes[1] -gt 127) { throw 'GuestAddress must be a tailnet IPv4 address (100.64.0.0/10).' }
    $clean = Remove-CageSshBlock $Content $UserName
    if ($clean -match ('(?im)^\s*Match\s+User\s+[^\r\n]*\b' + [regex]::Escape($UserName) + '\b')) { throw 'Existing unmanaged Match User for dedicated account; inspect it before installing.' }
    # Append after global settings, but BEFORE all existing Match rules (first-value wins).
    $firstMatch = [regex]::Match($clean, '(?im)^[ \t]*Match\s+')
    $at = if ($firstMatch.Success) { $firstMatch.Index } else { $clean.Length }
    $block = @(
        "# BEGIN CAGE HOST ACCESS $UserName"
        "Match User $UserName"
        "    AuthorizedKeysFile __PROGRAMDATA__/ssh/${UserName}_authorized_keys"
        '    AuthenticationMethods publickey'
        '    PubkeyAuthentication yes'
        '    PasswordAuthentication no'
        '    KbdInteractiveAuthentication no'
        "    AllowUsers $UserName@$GuestAddress"
        '    DisableForwarding yes'
        'Match all'
        "# END CAGE HOST ACCESS $UserName"
    ) -join "`r`n"
    return $clean.Substring(0, $at).TrimEnd("`r", "`n") + "`r`n`r`n" + $block + "`r`n" + $clean.Substring($at)
}

function Assert-CageEffectiveConfig {
    param([string[]]$Effective, [string]$UserName, [string]$GuestAddress)
    foreach ($required in @('passwordauthentication no','kbdinteractiveauthentication no','authenticationmethods publickey','disableforwarding yes',("allowusers $UserName@$GuestAddress"))) {
        if ($Effective -notcontains $required) { throw "Effective sshd rule mismatch: $required. Existing policy may conflict; no config installed." }
    }
    $expected = 'authorizedkeysfile __PROGRAMDATA__/ssh/' + $UserName + '_authorized_keys'
    if ($Effective -notcontains $expected) { throw 'Effective dedicated key path was overridden; no config installed.' }
}

function Set-CageSshConfig {
    param([string]$Path, [string]$Content, [string]$SshdExe, [string]$ValidateUser, [string]$GuestAddress, [scriptblock]$EffectiveValidator)
    if ($EffectiveValidator -and -not $ValidateUser) { throw 'An effective-validator callback requires an explicit target user.' }
    $original = [IO.File]::ReadAllBytes($Path)
    $candidate = $Path + '.cage-' + [guid]::NewGuid().ToString('N')
    # Write a candidate in the same protected directory. It contains config, not credentials.
    try {
        [IO.File]::WriteAllText($candidate, $Content, (New-Object Text.UTF8Encoding($false)))
        Set-Acl -LiteralPath $candidate -AclObject (Get-Acl -LiteralPath $Path)
        Invoke-CageNative $SshdExe @('-t', '-f', $candidate)
        if ($ValidateUser) {
            if ($EffectiveValidator) {
                # The callback receives immutable candidate content, never a user-writable script.
                $effective = @(& $EffectiveValidator $Content $ValidateUser $GuestAddress)
            } else {
                $effective = @(& $SshdExe -T -f $candidate -C "user=$ValidateUser,host=cage-guest,addr=$GuestAddress")
                if ($LASTEXITCODE -ne 0) { throw 'Cannot evaluate candidate sshd user context.' }
            }
            Assert-CageEffectiveConfig $effective $ValidateUser $GuestAddress
        }
        if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($Path)) -cne [Convert]::ToBase64String($original)) {
            throw 'Active sshd config changed during candidate validation; no config installed.'
        }
        if (-not (Test-Path -LiteralPath ($Path + '.cage-bak'))) { [IO.File]::WriteAllBytes(($Path + '.cage-bak'), $original) }
        try {
            [IO.File]::WriteAllText($Path, $Content, (New-Object Text.UTF8Encoding($false)))
            Invoke-CageNative $SshdExe @('-t', '-f', $Path)
            Restart-Service sshd -ErrorAction Stop
        } catch {
            [IO.File]::WriteAllBytes($Path, $original)
            throw
        }
    } finally {
        # Exact, locally created candidate path, verified under the config's directory.
        if (Test-Path -LiteralPath $candidate) { Remove-Item -LiteralPath $candidate -Force }
    }
}
