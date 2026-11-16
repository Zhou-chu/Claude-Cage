# Isolated PS5.1 batch. No live SSH, tasks, users, groups, services or privileged ACL writes.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$count=0; $cases=0
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERT: $Message" }
    $script:count++
}
function Rejected([scriptblock]$Action, [string]$Message) {
    $failure=''
    try { & $Action | Out-Null } catch { $failure=$_.Exception.Message }
    Assert (-not [string]::IsNullOrEmpty($failure)) $Message
    return $failure
}
Assert ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1 -and [Environment]::Is64BitProcess) 'PS5.1 x64 batch'
$source=Join-Path $PSScriptRoot 'peer-maintenance.ps1'
$t=$null; $e=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$t,[ref]$e)
Assert ($e.Count -eq 0) 'Production PS5.1 parse'
Assert (@($ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] }).Count -eq 0) 'Definitions only on import'
foreach ($file in @($source,$PSCommandPath)) {
    $null=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$t,[ref]$e)
    Assert ($e.Count -eq 0) 'Test and production parse'
    Assert (@([IO.File]::ReadAllBytes($file) | Where-Object { $_ -gt 127 }).Count -eq 0) 'ASCII source'
}
$forbidden=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and ($n.GetCommandName() -in @('New-LocalUser','Remove-LocalUser','Add-PeerUsersMembership','Register-ScheduledTask','Restart-Service','Stop-Process') -or ($n.GetCommandName() -eq 'Stop-Service' -and $n.Extent.Text -match '-Force\b'))},$true))
Assert ($forbidden.Count -eq 0 -and -not $ast.Extent.Text.Contains('SetPassword')) 'No forbidden account/task/forced service operations'
. (Join-Path $PSScriptRoot 'host-access-common.ps1')
. (Join-Path $PSScriptRoot 'sshd-system-validation.ps1')
$enroll=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'enroll-windows-peer.ps1'),[ref]$t,[ref]$e)
foreach ($name in @('Assert-PeerPublicKey','Get-PeerKeyAclRuleSet','Assert-PeerKeyAcl')) {
    $def=$enroll.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    Assert ($null -ne $def) 'Dependency function exists'
    . ([scriptblock]::Create($def.Extent.Text))
}
. $source
# The real public gate is never mocked, and refuses before ANY helper/input access.
Assert ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') 'Run tests as a non-SYSTEM human'
$gate=@{ExpectedComputerName='unread';UserName='x';GuestAddress='x';HostAddress='x';ExpectedUserSid='x';ExpectedConfigHash='x';ExpectedKeyHash='x';RecoveryDirectory='x'}
$message=Rejected { Invoke-CagePeerMaintenance @gate } 'Actual nonSYSTEM refusal'
Assert ($message -like 'Maintenance refused non-SYSTEM identity*') 'Direct SID gate precedes dependencies'
$originalStop=${function:Stop-CagePmService}
$originalListener=${function:Assert-CagePmNoListeners}
$originalService=${function:Get-CagePmService}
$originalKey=${function:Assert-CagePmKey}
$originalWriter=${function:Write-CagePmFile}
$originalPublic=${function:Get-CagePmPublicHostKey}
$originalRestore=${function:Restore-CagePmConfig}
$originalExeAssert=${function:Assert-CageSsvExe}
# Pure ACL comparator uses only synthetic descriptors, never Set-Acl.
$sidText='S-1-5-21-111-222-333-1001'
$expectedAcl=New-CageKeyAcl (Get-CageSid $sidText)
Assert-PeerKeyAcl $expectedAcl $expectedAcl
Assert $true 'Real existing key comparator accepts intended three-rule protected descriptor'
$badAcl=New-CageKeyAcl (Get-CageSid $sidText)
$badAcl.SetAccessRuleProtection($false,$true)
$null=Rejected { Assert-PeerKeyAcl $badAcl $expectedAcl } 'Unprotected dedicated key ACL rejected'
# All remaining account/service/network/native seams are synthetic. Only fixture bytes are real.
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('cage-peer-maintenance-test-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($testRoot)
function Get-CageSsvRoot { return $script:root }
function Assert-CageSsvSealedPath([string]$Path,[bool]$Directory) {
    Assert ($Path.StartsWith($script:root+'\',[StringComparison]::OrdinalIgnoreCase)) 'Sealed access is isolated fixture only'
    Assert ((Test-Path -LiteralPath $Path) -and [bool](Get-Item -LiteralPath $Path -Force).PSIsContainer -eq $Directory) 'Fixture object type'
    if ($script:scenario -ceq 'BadSeal') { throw 'Synthetic ACL failure.' }
}
function Assert-CageSsvPrivilegedObject { }
function Initialize-PeerNativeMembership { }
function Resolve-PeerGroupName([string]$GroupSid) { return $GroupSid }
function Get-PeerMembership($GroupName,$MemberSid) {
    if ($script:scenario -ceq 'MembershipError') { throw 'Synthetic native membership error.' }
    if ($GroupName -ceq 'S-1-5-32-544') { return $script:admin }
    if ($GroupName -ceq 'S-1-5-32-545') { return $script:users }
    throw 'Unexpected membership query.'
}
function Get-CagePmAccount([string]$UserName) {
    Assert ($UserName -ceq 'cageops') 'Only exact account read'
    return [pscustomobject]@{Handle='original-handle'; Sid=(Get-CageSid $script:currentSid); Flags=$script:flags; Description=$script:description}
}
function Get-NetIPAddress { return [pscustomobject]@{IPAddress=$script:assigned} }
function Get-CagePmService {
    return [pscustomobject]@{State=$script:state;ProcessId=99;Exe=(Join-Path $script:root 'sshd.exe')}
}
function Assert-CagePmNoListeners([int]$OriginalPid) {
    Assert ($OriginalPid -eq 99) 'Original PID always included'
    if ($script:state -cne 'Stopped' -or $script:scenario -ceq 'LingeringListener') { throw 'Synthetic listener isolation failure.' }
    $script:trace.Add('Isolated')
}
function Stop-CagePmService([int]$OriginalPid) {
    $script:trace.Add('Stop')
    if ($script:scenario -ceq 'StopFails') { throw 'Synthetic stop failure.' }
    $script:state='Stopped'
    Assert-CagePmNoListeners $OriginalPid
}
function Set-PeerAccountEnabled($User,[bool]$Enabled) {
    Assert ($User -ceq 'original-handle' -and $script:currentSid -ceq $script:targetSid) 'Mutation exact original SID only'
    if ($Enabled) {
        Assert ($script:state -ceq 'Stopped' -and $script:trace.Contains('Isolated')) 'Enable only in stopped-listener isolation'
        $script:trace.Add('Enable')
        if ($script:scenario -cne 'EnableNoEffect') { $script:flags=512 }
        if ($script:scenario -ceq 'EnableThrows') { throw 'Synthetic partial enable failure.' }
        if ($script:scenario -ceq 'SidReplacement') { $script:currentSid='S-1-5-21-111-222-333-1002' }
    } else {
        $script:trace.Add('Disable')
        Assert ($script:trace.Contains('Stop')) 'Rollback stop attempted before disabling'
        if ($script:scenario -ceq 'DisableFails') { throw 'Synthetic disable failure.' }
        if ($script:scenario -cne 'DisableNoEffect') { $script:flags=514 }
    }
}
function Assert-CagePmKey([string]$Path,[string]$ExpectedHash,[string]$UserSid) {
    if ($script:scenario -ceq 'BadKeyAcl') { throw 'Synthetic ACL mismatch.' }
    if ((Get-CagePmHash ([IO.File]::ReadAllBytes($Path))) -cne $ExpectedHash) { throw 'Synthetic key mismatch.' }
}
function Get-CagePmPublicHostKey { return $null }
function Write-CagePmFile([string]$Directory,[string]$Name,[byte[]]$Bytes) {
    $script:trace.Add('Write-'+$Name)
    if ($Name -ceq 'original.conf' -and $script:scenario -ceq 'SnapshotFails') { throw 'Synthetic snapshot failure.' }
    if ($Name -ceq 'candidate.conf' -and $script:scenario -ceq 'CandidateFails') { throw 'Synthetic candidate failure.' }
    if ($Name -ceq 'result.json' -and $script:scenario -ceq 'ResultFails' -and -not $script:resultFailed) { $script:resultFailed=$true; throw 'Synthetic metadata failure.' }
    Assert ($Directory -ceq $script:recovery) 'Write only isolated recovery'
    $stream=New-Object IO.FileStream((Join-Path $Directory $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($Bytes,0,$Bytes.Length) } finally { $stream.Dispose() }
}
function Invoke-CageSsvNative([string]$SshdExe,[string[]]$Arguments,[int]$TimeoutSeconds) {
    Assert ($TimeoutSeconds -eq 10) 'Native invocation bounded'
    $lines=@($script:effective)
    $code=0; $stopped=$true; $truncated=$false; $timedOut=$false
    if ($Arguments[0] -ceq '-T') {
        $script:trace.Add('Validate')
        Assert ($script:state -ceq 'Stopped' -and -not ($script:flags -band 2)) 'Real target enabled while service isolated for validation'
        Assert (($Arguments -join '|') -ceq ('-T|-f|'+(Join-Path $script:recovery 'candidate.conf')+'|-C|user=cageops,host=cage-guest,addr=100.65.250.76')) 'Exact sealed candidate and actual user context'
        switch -Exact ($script:scenario) {
            'NativeThrows' { throw 'Synthetic native exception.' }
            'NativeUnterminated' { $stopped=$false }
            'NativeTruncated' { $truncated=$true }
            'NativeTimeout' { $timedOut=$true }
            'NativeExit' { $code=1 }
            'MissingField' { $lines=@($lines | Select-Object -Skip 1) }
            'DuplicateField' { $lines+=@($lines[0]) }
            'ExtraField' { $lines+=@('permitrootlogin yes') }
            'BadPubkey' { $lines[6]='pubkeyauthentication no' }
            'BadField' { $lines[$script:badFieldIndex]=$lines[$script:badFieldIndex]+'-wrong' }
            'ConfigDuringValidation' { [IO.File]::WriteAllText($script:active,'External edit') }
            'DisableFails' { $lines[6]='pubkeyauthentication no' }
            'DisableNoEffect' { $lines[6]='pubkeyauthentication no' }
            'RestoreSyntaxFails' { $lines[6]='pubkeyauthentication no' }
        }
    } elseif ($Arguments[0] -ceq '-t') {
        $script:trace.Add('RestoreSyntax')
        Assert (($script:flags -band 2) -ne 0) 'Disable confirmed before restore validation'
        if ($script:scenario -ceq 'RestoreSyntaxFails') { $code=1 }
    } else { throw 'Unexpected native command.' }
    return [pscustomobject]@{ExitCode=$code;Stopped=$stopped;TimedOut=$timedOut;Truncated=$truncated;Lines=$lines}
}
function Set-CageSshConfig {
    param([string]$Path,[string]$Content,[string]$SshdExe,[string]$ValidateUser,[string]$GuestAddress,[switch]$KeepServiceStopped,[scriptblock]$EffectiveValidator)
    Assert ($KeepServiceStopped -and $script:state -ceq 'Stopped') 'Commit never restarts'
    # Deliberately shadow common/core variable names: callback must use its own context.
    $service='shadow'; $candidatePath='shadow'; $candidateHash='shadow'; $original='shadow'
    if ($script:scenario -ceq 'SyntaxUnterminated') { $nativeFailure=New-Object InvalidOperationException('Synthetic bounded syntax termination failure.'); $nativeFailure.Data['CageNativeUnproven']=$true; throw $nativeFailure }
    if ($script:scenario -ceq 'SkipCallback') { [IO.File]::WriteAllText($Path,$Content); return }
    if ($script:scenario -ceq 'WrongCallbackUser') { $null=& $EffectiveValidator $Content 'fakeuser' $GuestAddress; return }
    if ($script:scenario -ceq 'WrongCallbackGuest') { $null=& $EffectiveValidator $Content $ValidateUser '100.65.250.77'; return }
    if ($script:scenario -ceq 'WrongCallbackContent') { $null=& $EffectiveValidator ($Content+'x') $ValidateUser $GuestAddress; return }
    $null=& $EffectiveValidator $Content $ValidateUser $GuestAddress
    if ($script:scenario -ceq 'DuplicateCallback') { $null=& $EffectiveValidator $Content $ValidateUser $GuestAddress }
    $script:trace.Add('Commit')
    [IO.File]::WriteAllText($Path,$Content,(New-Object Text.UTF8Encoding($false)))
    if ($script:scenario -ceq 'CommitThrows') { throw 'Synthetic partial commit failure.' }
    if ($script:scenario -ceq 'ConfigAfterCommit') { [IO.File]::WriteAllText($Path,'External edit') }
    if ($script:scenario -ceq 'KeyAfterCommit') { [IO.File]::WriteAllText($script:key,'changed key') }
}
function Restore-CagePmConfig([string]$Path,[byte[]]$Original,[string]$CandidateHash) {
    $script:trace.Add('Restore')
    Assert (($script:flags -band 2) -ne 0 -and $script:state -ceq 'Stopped') 'Disable and isolation before restore'
    & $script:originalRestore $Path $Original $CandidateHash
}
function Start-Service {
    [CmdletBinding()]param([string]$Name)
    Assert ($Name -ceq 'sshd' -and $script:state -ceq 'Stopped') 'Only stopped sshd can start'
    if ($script:trace.Contains('Disable')) { Assert (($script:flags -band 2) -ne 0 -and $script:trace.Contains('RestoreSyntax')) 'Every rollback start follows verified disable and restored syntax' }
    else { Assert ($script:trace.Contains('Validate') -and $script:trace.Contains('Commit')) 'Normal start only after effective validation/commit' }
    $script:trace.Add('Start'); $script:state='Running'; $script:starts++
    if ($script:scenario -ceq 'StartThrows' -and $script:starts -eq 1) { throw 'Synthetic partial start failure.' }
}
function Wait-CagePmRunning([string]$HostAddress) {
    $script:trace.Add('Running')
    if ($script:scenario -ceq 'ListeningFails' -and $script:starts -eq 1) { throw 'Synthetic bounded listening timeout.' }
    return Get-CagePmService
}
function New-Fixture([string]$Scenario) {
    $script:scenario=$Scenario; $script:cases++; $script:trace=New-Object 'Collections.Generic.List[string]'
    $script:root=Join-Path $script:testRoot ('case-'+$script:cases+'\ssh')
    $script:recovery=Join-Path $script:root ('cage-peer-maintenance-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($script:recovery)
    $script:active=Join-Path $script:root 'sshd_config'; $script:key=Join-Path $script:root 'cageops_authorized_keys'
    $script:originalBytes=[Text.Encoding]::UTF8.GetPreamble()+[Text.Encoding]::UTF8.GetBytes("Port 22`r`nAllowUsers unrelated`r`nMatch Group administrators`r`n    AuthorizedKeysFile admin_keys`r`n")
    [IO.File]::WriteAllBytes($script:active,$script:originalBytes); [IO.File]::WriteAllText($script:key,'synthetic public-only authorized key')
    $script:targetSid=$script:sidText; $script:currentSid=$script:targetSid; $script:flags=514; $script:admin=$false; $script:users=$true
    $script:description='Cage guest SSH operator (standard user)'; $script:assigned='100.112.222.42'; $script:state='Running'; $script:starts=0; $script:resultFailed=$false
    $script:effective=@('passwordauthentication no','kbdinteractiveauthentication no','authenticationmethods publickey','disableforwarding yes','allowusers cageops@100.65.250.76','authorizedkeysfile __PROGRAMDATA__/ssh/cageops_authorized_keys','pubkeyauthentication yes')
    return @{ExpectedComputerName=[Environment]::MachineName;UserName='cageops';GuestAddress='100.65.250.76';HostAddress='100.112.222.42';ExpectedUserSid=$script:targetSid;ExpectedConfigHash=(Get-CagePmHash $script:originalBytes);ExpectedKeyHash=(Get-CagePmHash ([IO.File]::ReadAllBytes($script:key)));RecoveryDirectory=$script:recovery}
}
$p=New-Fixture 'Success'
$result=Invoke-CagePeerMaintenanceCore @p
Assert ($result.Success -and $result.AccountEnabled -and $result.StandardUser -and $result.SystemSid -ceq 'S-1-5-18') 'Structured success receipt'
Assert ($trace.IndexOf('Stop') -lt $trace.IndexOf('Isolated') -and $trace.IndexOf('Isolated') -lt $trace.IndexOf('Enable') -and $trace.IndexOf('Enable') -lt $trace.IndexOf('Validate') -and $trace.IndexOf('Validate') -lt $trace.IndexOf('Start')) 'stop/listeners => enable => validate => start ordering'
Assert (-not $trace.Contains('Disable')) 'Success does not disable'
Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $recovery 'original.conf'))) -ceq [Convert]::ToBase64String($originalBytes)) 'Exact original snapshot including BOM'
Assert (([IO.File]::ReadAllText($active)).Contains('AllowUsers unrelated') -and ([IO.File]::ReadAllText($active)).Contains('Match Group administrators')) 'Unrelated user rules preserved'
Assert ((Get-CagePmHash ([IO.File]::ReadAllBytes($key))) -ceq $p.ExpectedKeyHash) 'Dedicated key bytes unchanged'
Assert ((Get-Content -LiteralPath (Join-Path $recovery 'result.json') -Raw | ConvertFrom-Json).Success) 'Retained success metadata'
foreach ($pre in @('Machine','User','Guest','Host','Sid','ConfigHash','KeyHash','Enabled','Description','Admin','NoUsers','HostNotAssigned','ServiceStopped','BadSeal','BadKeyAcl','MembershipError','RecoveryPrefix','RecoveryRoot','Collision','SnapshotFails')) {
    $p=New-Fixture $pre
    switch ($pre) {
        'Machine' {$p.ExpectedComputerName='Not-'+[Environment]::MachineName}
        'User' {$p.UserName='other'} 'Guest' {$p.GuestAddress='100.65.250.076'} 'Host' {$p.HostAddress='100.112.222.43'}
        'Sid' {$p.ExpectedUserSid='S-1-5-21-111-222-333-1002'} 'ConfigHash' {$p.ExpectedConfigHash=('0'*64)} 'KeyHash' {$p.ExpectedKeyHash=('0'*64)}
        'Enabled' {$script:flags=512} 'Description' {$script:description='other'} 'Admin' {$script:admin=$true} 'NoUsers' {$script:users=$false}
        'HostNotAssigned' {$script:assigned='100.112.222.43'} 'ServiceStopped' {$script:state='Stopped'}
        'RecoveryPrefix' {$p.RecoveryDirectory=$root} 'RecoveryRoot' {$p.RecoveryDirectory=$testRoot}
        'Collision' {[IO.File]::WriteAllText((Join-Path $recovery 'result.json'),'existing')}
    }
    $null=Rejected { Invoke-CagePeerMaintenanceCore @p } ('Precondition '+$pre)
    Assert (-not $trace.Contains('Stop') -and -not $trace.Contains('Enable') -and -not $trace.Contains('Disable') -and -not $trace.Contains('Start')) ('No privileged mutation for '+$pre)
}
foreach ($failure in @('CandidateFails','EnableThrows','EnableNoEffect','NativeThrows','NativeUnterminated','SyntaxUnterminated','NativeTruncated','NativeTimeout','NativeExit','MissingField','DuplicateField','ExtraField','BadPubkey','WrongCallbackUser','WrongCallbackGuest','WrongCallbackContent','DuplicateCallback','SkipCallback','CommitThrows','ConfigDuringValidation','ConfigAfterCommit','KeyAfterCommit','StartThrows','ListeningFails','DisableFails','DisableNoEffect','RestoreSyntaxFails','LingeringListener','StopFails','SidReplacement','ResultFails','BadField0','BadField1','BadField2','BadField3','BadField4','BadField5','BadField6')) {
    $p=New-Fixture $failure
    if ($failure -like 'BadField?') { $script:badFieldIndex=[int]$failure.Substring(8); $script:scenario='BadField' }
    $message=Rejected { Invoke-CagePeerMaintenanceCore @p } ('Injected failure '+$failure)
    Assert ($trace.Contains('Stop')) ('Stop attempted on every entered failure '+$failure)
    if ($failure -ne 'SidReplacement') { Assert ($trace.Contains('Disable')) ('Exact original target disable attempted '+$failure) }
    else { Assert (-not $trace.Contains('Disable')) 'Never disable replaced SID' }
    if ($trace.Contains('Restore')) { Assert ($trace.IndexOf('Disable') -lt $trace.IndexOf('Restore')) ('Disable before restore '+$failure) }
    if ($failure -in @('NativeThrows','NativeUnterminated','SyntaxUnterminated','ConfigDuringValidation','ConfigAfterCommit','DisableFails','DisableNoEffect','RestoreSyntaxFails','LingeringListener','StopFails','SidReplacement')) {
        Assert ($starts -eq 0 -and $message -like 'CRITICAL:*') ('No unsafe restart '+$failure)
    }
    if ($failure -in @('ConfigDuringValidation','ConfigAfterCommit')) { Assert ([IO.File]::ReadAllText($active) -ceq 'External edit') ('External config never overwritten '+$failure) }
    if ($failure -notin @('DisableFails','DisableNoEffect','SidReplacement')) { Assert (($flags -band 2) -ne 0) ('Fresh disabled state '+$failure) }
    if ($state -ceq 'Running' -and $starts -gt 0) {
        Assert ($trace.Contains('Disable') -and $trace.Contains('RestoreSyntax')) ('Original service starts only after disable/restore '+$failure)
        Assert ((Get-CagePmHash ([IO.File]::ReadAllBytes($active))) -ceq $p.ExpectedConfigHash) ('Original config exact after rollback '+$failure)
    }
    $metadata=Get-Content -LiteralPath (Join-Path $recovery 'result.json') -Raw | ConvertFrom-Json
    Assert (-not $metadata.Success) ('No failure claims success '+$failure)
}
Write-Output ('PASS: '+$count+' assertions; '+$cases+' isolated scenarios; PS5.1 x64; no live privileged actions. Fixtures retained: '+$testRoot)
