# Non-elevated PS5.1 tests: isolated files and mocks; NEVER task/service/account writes.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'host-access-common.ps1')
if ($PSVersionTable.PSVersion.Major -ne 5 -or -not [Environment]::Is64BitProcess) { throw 'Run native Windows PowerShell 5.1 x64.' }
$count = 0
function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw "ASSERT: $Message" }; $script:count++ }
$dir = Join-Path (Join-Path $PSScriptRoot '.test-output') ('system-integration-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $dir
$fixture = Join-Path $dir 'isolated_config'
$original = "# isolated original`r`nPort 22`r`n"
$proposed = "# isolated candidate`r`nPort 22`r`n"
$script:restarts = 0
$script:syntaxCalls = 0
$script:failRestart = $false
function Invoke-CageNative { param($Exe, $NativeArguments) $script:syntaxCalls++; if ($NativeArguments[0] -cne '-t') { throw 'Only mocked syntax checking is allowed.' } }
function Restart-Service { [CmdletBinding()] param($Name) $script:restarts++; if ($script:failRestart) { throw 'mock restart failed' } }
$valid = @('passwordauthentication no','kbdinteractiveauthentication no','authenticationmethods publickey','disableforwarding yes','allowusers cageops@100.64.0.10','authorizedkeysfile __PROGRAMDATA__/ssh/cageops_authorized_keys','pubkeyauthentication yes')
$script:callbackCalls = 0
$callback = { param($Content, $User, $Address) $script:callbackCalls++; Assert ($Content -ceq $proposed) 'Callback receives immutable proposed content'; Assert ($User -ceq 'cageops' -and $Address -ceq '100.64.0.10') 'Callback receives exact target context'; return $valid }
[IO.File]::WriteAllText($fixture, $original)
# Deliberately nonexistent binary: any accidental direct admin -T call must fail.
Set-CageSshConfig $fixture $proposed 'C:\CAGE-NO-DIRECT-SSHD.exe' 'cageops' '100.64.0.10' -EffectiveValidator $callback
Assert ($script:callbackCalls -eq 1) 'Validated once via callback, never direct cross-user native execution'
Assert ($script:restarts -eq 1 -and $script:syntaxCalls -eq 2) 'Commit follows validation and syntax checks'
Assert ([IO.File]::ReadAllText($fixture) -ceq $proposed) 'Successful validation commits candidate'
foreach ($mode in @('throw','unsafe','concurrent','restart')) {
    [IO.File]::WriteAllText($fixture, $original)
    $script:restarts = 0
    $script:failRestart = $mode -eq 'restart'
    $validator = { param($Content, $User, $Address)
        if ($mode -eq 'throw') { throw 'mock SYSTEM context unavailable' }
        if ($mode -eq 'unsafe') { return @('passwordauthentication yes') }
        if ($mode -eq 'concurrent') { [IO.File]::WriteAllText($fixture, 'external concurrent update') }
        return $valid
    }
    $failure = ''
    try { Set-CageSshConfig $fixture $proposed 'C:\CAGE-NO-DIRECT-SSHD.exe' 'cageops' '100.64.0.10' -EffectiveValidator $validator } catch { $failure = $_.Exception.Message }
    Assert ($failure.Length -gt 0) ('Failure reported: ' + $mode)
    $wanted = if ($mode -eq 'concurrent') { 'external concurrent update' } else { $original }
    Assert ([IO.File]::ReadAllText($fixture) -ceq $wanted) ('No stale/unsafe configuration survives: ' + $mode)
    Assert ($script:restarts -eq $(if ($mode -eq 'restart') { 1 } else { 0 })) ('No premature service commit: ' + $mode)
}
$failed = $false
try { Set-CageSshConfig 'C:\CAGE-NO-FILE' '' '' -EffectiveValidator {} } catch { $failed = $_.Exception.Message -like '*explicit target user*' }
Assert $failed 'Reject validator without target before any file access'
Write-Host ("PASS: {0} integration assertions; isolated file/ACL writes only; no native sshd, task, account or service operations." -f $count)
