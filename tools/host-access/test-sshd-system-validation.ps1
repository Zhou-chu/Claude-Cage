# Nonprivileged Windows PowerShell 5.1 x64 regression suite.
# NO live scheduler, sshd, accounts, keys, services, elevation or SSH authentication.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$source = Join-Path $PSScriptRoot 'sshd-system-validation.ps1'
$count = 0
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw ('ASSERT: ' + $Message) }
    $script:count++
}
function Assert-Rejected([scriptblock]$Action, [string]$Message) {
    $messageText = ''
    try { & $Action | Out-Null } catch { $messageText = $_.Exception.Message }
    Assert ($messageText.Length -gt 0) $Message
    return $messageText
}
# Defense in depth: even an accidentally unmocked wrapper cannot reach Scheduler.
function Register-ScheduledTask { throw 'TEST GUARD: live Register-ScheduledTask forbidden' }
function Start-ScheduledTask { throw 'TEST GUARD: live Start-ScheduledTask forbidden' }
function Stop-ScheduledTask { throw 'TEST GUARD: live Stop-ScheduledTask forbidden' }
function Unregister-ScheduledTask { throw 'TEST GUARD: live Unregister-ScheduledTask forbidden' }
function Get-ScheduledTask { throw 'TEST GUARD: live Get-ScheduledTask forbidden' }
Assert ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1 -and [Environment]::Is64BitProcess) 'Windows PowerShell 5.1 x64 test host'
Assert ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') 'Suite must not run as SYSTEM'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
Assert ($errors.Count -eq 0) 'Helper parses in PS5.1'
$null = [Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$tokens, [ref]$errors)
Assert ($errors.Count -eq 0) 'Suite parses in PS5.1'
Assert (@([IO.File]::ReadAllBytes($source) | Where-Object { $_ -gt 127 }).Count -eq 0) 'Source is ASCII'
Assert (@($ast.EndBlock.Statements | Where-Object { $_ -isnot [Management.Automation.Language.FunctionDefinitionAst] }).Count -eq 0) 'Import defines functions only'
. $source
function New-CageSsvScheduler { throw 'TEST GUARD: live COM Scheduler forbidden' }
$definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-CageSshdSystemValidation' }, $true)
Assert ((@($definition.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) -join ',') -ceq 'SshdExe,Content,ValidateUser,GuestAddress,TimeoutSeconds') 'Exact public API'
Assert ($definition.Body.ParamBlock.Parameters[4].DefaultValue.Value -eq 30) 'Bounded timeout defaults to 30 seconds'
Assert (-not ($ast.Extent.Text -match '(?i)Enable-LocalUser|Disable-LocalUser|Set-LocalUser|Start-Service|Restart-Service|Stop-Service|RunAs|ssh\.exe|Set-Content|Out-File')) 'No account, service, authentication, elevation or active-config mutation commands'
foreach ($ip in @('100.64.0.0','100.127.255.255','100.100.100.100')) { Assert-CageSsvContext 'cageops' $ip 30; Assert $true 'Canonical tailnet accepted' }
foreach ($ip in @('100.63.255.255','100.128.0.0','100.64.0.01','100.64.1','127.0.0.1','::1','100.64.0.1/32',"100.64.0.1`n",'100.64.0.1,host=other')) {
    $null = Assert-Rejected { Assert-CageSsvContext 'cageops' $ip 30 } 'Reject unsafe guest address'
}
foreach ($user in @('Cageops','user name','user,host=x','-user','user@host',"user`n",('a' * 21),'')) { $null = Assert-Rejected { Assert-CageSsvContext $user '100.64.0.1' 30 } 'Reject unsafe username' }
foreach ($timeout in @(0,4,121)) { $null = Assert-Rejected { Assert-CageSsvContext 'cageops' '100.64.0.1' $timeout } 'Reject timeout outside hard bound' }
foreach ($text in @('', ' ', ("Port 22`0"), ('x' * 524289))) { $null = Assert-Rejected { Assert-CageSsvContent $text } 'Reject unsafe candidate bounds' }
Assert-CageSsvContent "Port 22`r`n"
Assert ((Assert-CageSsvPlainPath $source) -ieq $source) 'Real read-only ancestor traversal works'
foreach ($path in @('relative','\\host\share\file','C:\x:stream','C:\a\..\b','C:\bad.\file',"C:\bad`n\file",'C:\*\file')) { $null = Assert-Rejected { Assert-CageSsvPlainPath $path -MissingLeaf } 'Reject unsafe local path' }
# Actual worker refusal. Mock input access to prove the direct identity gate precedes it.
& {
    function Assert-CageSsvCapsuleName { throw 'INPUT WAS READ' }
    function Read-CageSsvFile { throw 'INPUT WAS READ' }
    $refusal = Assert-Rejected { Invoke-CageSsvWorker 'Z:\never-read-user-controlled-path' } 'Actual nonSYSTEM worker refuses'
    Assert ($refusal -ceq 'SYSTEM worker refused non-SYSTEM identity before reading inputs.') 'Actual identity refusal precedes any input access'
}
# The fixed encoded action round-trips to exactly the embedded code, and running it
# as the current nonSYSTEM tester also refuses before trying the fictitious capsule.
$capsuleText = 'C:\ProgramData\ssh\cage-sshd-validation-0123456789abcdef0123456789abcdef'
$worker = Get-CageSsvWorkerCode $capsuleText
$null = [Management.Automation.Language.Parser]::ParseInput($worker, [ref]$tokens, [ref]$errors)
Assert ($errors.Count -eq 0) 'Self-contained worker parses'
Assert ($worker -notmatch '(?i)\-File|PSScriptRoot|Import-Module|\.ps1') 'Worker has no operator script dependency'
$actionArguments = Get-CageSsvActionArguments $capsuleText
Assert ($actionArguments -cmatch '\A-NoLogo -NoProfile -NonInteractive -EncodedCommand ([A-Za-z0-9+/=]+)\z') 'Fixed encoded-only argument shape'
$encoded = $matches[1]
Assert ($actionArguments.Length -le 30000) 'Encoded action fits Windows command line'
$bootstrap = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
Assert ($bootstrap -cmatch "FromBase64String\('([A-Za-z0-9+/=]+)'\)") 'Bootstrap contains only embedded payload'
$memory = New-Object IO.MemoryStream(,[Convert]::FromBase64String($matches[1]))
$gzip = New-Object IO.Compression.GZipStream($memory, [IO.Compression.CompressionMode]::Decompress)
$reader = New-Object IO.StreamReader($gzip, [Text.Encoding]::UTF8)
try { Assert ($reader.ReadToEnd() -ceq $worker) 'Compressed embedded worker is exact' } finally { $reader.Dispose(); $memory.Dispose() }
$actionError = ''
try { & ([scriptblock]::Create($bootstrap)) } catch { $actionError = $_.Exception.Message }
Assert ($actionError -ceq 'SYSTEM worker refused non-SYSTEM identity before reading inputs.') 'Actual encoded bootstrap refuses nonSYSTEM without input reads'
# Semantic ACL checks, including NTFS D:P -> D:PAI and harmless ACE ordering.
function New-TestDescriptor([string]$Sddl, [bool]$Directory) {
    if ($Directory) { $d = New-Object Security.AccessControl.DirectorySecurity } else { $d = New-Object Security.AccessControl.FileSecurity }
    $d.SetSecurityDescriptorSddlForm($Sddl)
    return $d
}
foreach ($directory in @($false,$true)) {
    $flags = ''; if ($directory) { $flags = 'OICI' }
    $sddl = 'O:BAD:P(A;' + $flags + ';FA;;;SY)(A;' + $flags + ';FA;;;BA)'
    foreach ($valid in @($sddl, $sddl.Replace('D:P','D:PAI'), ('O:BAD:PAI(A;' + $flags + ';FA;;;BA)(A;' + $flags + ';FA;;;SY)'))) {
        Assert ((Get-CageSsvAclFault (New-TestDescriptor $valid $directory) $directory 'S-1-5-32-544') -ceq '') 'Accept exact semantic ACL despite NTFS normalization/order'
    }
    foreach ($bad in @($sddl.Replace('O:BA','O:SY'), $sddl.Replace('D:P','D:AI'), ($sddl + '(A;;FA;;;WD)'), $sddl.Replace(';FA;;;SY',';FR;;;SY'), $sddl.Replace('(A;','(D;'), $sddl.Replace(';;;SY',';;;WD'), 'O:BAD:P', $sddl.Replace('(A;' + $flags + ';FA;;;SY)',''), $sddl.Replace('(A;' + $flags + ';FA;;;SY)','(A;' + $flags + 'ID;FA;;;SY)'))) {
        Assert ((Get-CageSsvAclFault (New-TestDescriptor $bad $directory) $directory 'S-1-5-32-544') -cne '') 'Reject owner/protection/mask/SID/deny/inherited/extra/missing ACL changes'
    }
    Assert ((Get-CageSsvAclFault (New-CageSsvAcl $directory) $directory 'S-1-5-32-544') -ceq '') 'Constructed ACL is exact'
    Assert ((Get-CageSsvAclFault (New-CageSsvAcl $directory) (-not $directory) 'S-1-5-32-544') -cne '') 'File versus directory flags are exact'
}
Assert ((Get-CageSsvAclFault $null $false 'S-1-5-32-544') -ceq 'MissingAcl') 'Missing ACL rejected'
# Real NTFS fixtures: only their OWNER is overridden to the tester. Production's
# Assert-CageSsvSealedPath still hardcodes BA and rejects this owner.
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('cage-ssv-test-' + [guid]::NewGuid().ToString('N'))
$fixtureRoot = [IO.Path]::GetFullPath($fixtureRoot)
$null = [IO.Directory]::CreateDirectory($fixtureRoot)
$fixtureFile = Join-Path $fixtureRoot 'file.tmp'
$fixtureDirectory = Join-Path $fixtureRoot 'directory'
[IO.File]::WriteAllText($fixtureFile, 'Only a tester-owned semantic ACL fixture.')
$null = [IO.Directory]::CreateDirectory($fixtureDirectory)
$originalFile = Get-Acl -LiteralPath $fixtureFile
$originalDirectory = Get-Acl -LiteralPath $fixtureDirectory
$tester = [Security.Principal.WindowsIdentity]::GetCurrent().User
try {
    foreach ($entry in @(@($fixtureFile,$false), @($fixtureDirectory,$true))) {
        $acl = New-CageSsvAcl ([bool]$entry[1])
        $acl.SetOwner($tester)
        Set-Acl -LiteralPath $entry[0] -AclObject $acl
        $actual = Get-Acl -LiteralPath $entry[0]
        Assert ((Get-CageSsvAclFault $actual ([bool]$entry[1]) $tester.Value) -ceq '') 'Real NTFS file/directory roundtrip retains exact protected explicit rights'
        Assert ((Get-CageSsvAclFault $actual ([bool]$entry[1]) 'S-1-5-32-544') -ceq 'Owner') 'Production owner rule is not weakened by fixture override'
    }
} finally {
    # Fresh access-only descriptors avoid replaying Get-Acl's audit sections,
    # which would request SeSecurityPrivilege on an unelevated tester token.
    $restoreFile = New-Object Security.AccessControl.FileSecurity
    $restoreFile.SetSecurityDescriptorSddlForm($originalFile.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access), [Security.AccessControl.AccessControlSections]::Access)
    [IO.File]::SetAccessControl($fixtureFile, $restoreFile)
    $restoreDirectory = New-Object Security.AccessControl.DirectorySecurity
    $restoreDirectory.SetSecurityDescriptorSddlForm($originalDirectory.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access), [Security.AccessControl.AccessControlSections]::Access)
    [IO.Directory]::SetAccessControl($fixtureDirectory, $restoreDirectory)
    # Exact paths constructed above; never recurse or delete an unchecked target.
    Assert ([IO.Path]::GetDirectoryName($fixtureFile) -ceq $fixtureRoot) 'Fixture deletion target verified'
    Assert ([IO.Path]::GetDirectoryName($fixtureDirectory) -ceq $fixtureRoot) 'Fixture directory deletion target verified'
    [IO.File]::Delete($fixtureFile)
    [IO.Directory]::Delete($fixtureDirectory, $false)
    [IO.Directory]::Delete($fixtureRoot, $false)
}
# Reparse detection via synthetic attributes; no junctions/symlinks are created.
& {
    function Get-Item {
        param($LiteralPath, [switch]$Force, $ErrorAction)
        $attributes = [IO.FileAttributes]::Directory
        if ($LiteralPath -ieq 'C:\parent') { $attributes = $attributes -bor [IO.FileAttributes]::ReparsePoint }
        return [pscustomobject]@{ Attributes=$attributes; PSIsContainer=$true }
    }
    $null = Assert-Rejected { Assert-CageSsvPlainPath 'C:\parent\child' } 'Reject reparse ancestor before opening child'
}
# Service executable parsing and binding, all with synthetic read-only objects.
& {
    $serviceText = '"C:\Program Files\OpenSSH\sshd.exe" -f C:\fixed.conf'
    function Get-CimInstance { param($ClassName,$Filter,$ErrorAction); Assert ($ClassName -ceq 'Win32_Service' -and $Filter -ceq "Name='sshd'") 'Service query is exact and local'; return [pscustomobject]@{PathName=$serviceText} }
    Assert ((Get-CageSsvServiceExe) -ceq 'C:\Program Files\OpenSSH\sshd.exe') 'Quoted service path parsed'
    $serviceText = 'C:\Windows\System32\OpenSSH\sshd.exe'
    Assert ((Get-CageSsvServiceExe) -ceq $serviceText) 'Unquoted no-space service path parsed'
    $serviceText = 'C:\Program Files\OpenSSH\sshd.exe'
    $null = Assert-Rejected { Get-CageSsvServiceExe } 'Ambiguous unquoted service path rejected'
}
& {
    function Assert-CageSsvPlainPath { param($Path); return $Path }
    function Get-Item { param($LiteralPath,[switch]$Force,$ErrorAction); return [pscustomobject]@{PSIsContainer=$false;Name='sshd.exe'} }
    function Get-CageSsvServiceExe { return 'C:\trusted\sshd.exe' }
    Assert-CageSsvExe 'C:\trusted\sshd.exe'
    $null = Assert-Rejected { Assert-CageSsvExe 'C:\untrusted\sshd.exe' } 'Existing different executable is not accepted'
}
$effectiveLines = @('passwordauthentication no','kbdinteractiveauthentication no','authenticationmethods publickey','disableforwarding yes','allowusers cageops@100.64.0.10','authorizedkeysfile __PROGRAMDATA__/ssh/cageops_authorized_keys','pubkeyauthentication yes')
Assert ((@(Select-CageSsvEffective $effectiveLines) -join '|') -ceq ($effectiveLines -join '|')) 'Seven fields returned in exact contract order'
foreach ($bad in @(@($effectiveLines[0..5]), @($effectiveLines + $effectiveLines[0]), @($effectiveLines + 'port 22'), @($effectiveLines[0..5] + 'pubkeyauthentication yes' + "passwordauthentication no`nsecret"))) {
    $null = Assert-Rejected { Select-CageSsvEffective $bad } 'Missing/duplicate/unknown/control-bearing effective output fails closed'
}
# Compile only the stdlib runner, then exercise its private PURE reader using
# in-memory StreamReader. No native executable is started in these tests.
Initialize-CageSsvNative
function Invoke-TestReader([string]$Text, [bool]$Output) {
    $r = New-Object CageSshdValidation.NativeResult
    $list = New-Object 'Collections.Generic.List[string]'
    $m = New-Object IO.MemoryStream(,[Text.Encoding]::UTF8.GetBytes($Text))
    $reader = New-Object IO.StreamReader($m)
    try {
        $method = [CageSshdValidation.Native].GetMethod('Read', [Reflection.BindingFlags]'NonPublic,Static')
        $reflectionArguments = New-Object object[] 4
        $reflectionArguments[0] = $reader.PSObject.BaseObject
        $reflectionArguments[1] = [bool]$Output
        $reflectionArguments[2] = $r.PSObject.BaseObject
        $reflectionArguments[3] = $list.PSObject.BaseObject
        $null = $method.Invoke($null, $reflectionArguments)
        return [pscustomobject]@{ Result=$r; Lines=@($list.ToArray()) }
    } finally { $reader.Dispose(); $m.Dispose() }
}
$filtered = Invoke-TestReader (($effectiveLines -join "`n") + "`nport 22`nsecret secret-token`n") $true
Assert (($filtered.Lines -join '|') -ceq ($effectiveLines -join '|')) 'Native stdout stores only the seven selected fields'
$diagnostics = Invoke-TestReader "debug1: get_user_token: private-user failed: 5 secret`ndebug2: ga_init: secret`ngenerate_s4u_user_token: status 0xC0000072 secret`nLsaLogonUser: code 1326 secret`ndebug3: secret private-key`nnot_get_user_token secret`n" $false
Assert (($diagnostics.Lines -join '|') -ceq 'get_user_token [code=5]|ga_init|generate_s4u_user_token [code=0xC0000072]|LsaLogonUser [code=1326]') 'Only narrow token diagnostics survive, stripped of user/path/secret text'
Assert (-not (($diagnostics.Lines -join '|') -match 'secret|private')) 'Sanitized diagnostic text excludes secrets'
$overflow = Invoke-TestReader ((('debug1: get_user_token: secret' + "`n") * 9)) $false
Assert ($overflow.Result.Truncated -and $overflow.Lines.Count -eq 8) 'Diagnostic count overflow is bounded and fails closed'
$overflow = Invoke-TestReader ('x' * 4097) $true
Assert $overflow.Result.Truncated 'Oversized line fails closed with bounded line buffer'
$overflow = Invoke-TestReader (('ignored' + "`n") * 150000) $true
Assert $overflow.Result.Truncated 'Excess native stream bytes fail closed without retaining output'
# Native runner status/result proof validator.
function New-TestNative {
    return [pscustomobject]@{ExitCode=0;TimedOut=$false;Truncated=$false;Stopped=$true;Lines=@($effectiveLines);Diagnostics=@()}
}
function New-TestResult([string]$Nonce) {
    return [pscustomobject]@{Schema=1;Nonce=$Nonce;SystemSid='S-1-5-18';Success=$true;NativeStopped=$true;Syntax=(ConvertTo-CageSsvStatus (New-TestNative));Effective=(ConvertTo-CageSsvStatus (New-TestNative));Lines=@($effectiveLines);Diagnostics=@();Error='None'}
}
$testNonce = '0123456789abcdef0123456789abcdef'
Assert (@(Assert-CageSsvResult (New-TestResult $testNonce) $testNonce).Count -eq 7) 'Valid SYSTEM envelope emits only seven strings'
foreach ($mutation in @('Nonce','Sid','Schema','SuccessType','Live','SyntaxMissing','Exit','TimedOut','Truncated','Stopped','Diagnostic','DiagnosticString','DiagnosticOverflow','Lines','LineString','Extra','BadStatus','Error')) {
    $r = New-TestResult $testNonce
    switch ($mutation) {
        Nonce { $r.Nonce='f' * 32 }; Sid { $r.SystemSid='S-1-5-32-544' }; Schema { $r.Schema=2 }; SuccessType { $r.Success='true' }; Live { $r.NativeStopped=$false }; SyntaxMissing { $r.Syntax=$null }; Exit { $r.Effective.ExitCode=1 }; TimedOut { $r.Effective.TimedOut=$true }; Truncated { $r.Effective.Truncated=$true }; Stopped { $r.Effective.Stopped=$false }; Diagnostic { $r.Diagnostics=@('get_user_token secret') }; DiagnosticString { $r.Diagnostics='ga_init' }; DiagnosticOverflow { $r.Diagnostics=@('ga_init') * 9 }; Lines { $r.Lines=@($effectiveLines[0..5]) }; LineString { $r.Lines='pubkeyauthentication yes' }; Extra { $r | Add-Member NoteProperty Other 'secret' }; BadStatus { $r.Effective.ExitCode='0' }; Error { $r.Error='secret' }
    }
    $msg = Assert-Rejected { Assert-CageSsvResult $r $testNonce } ('Reject mutated proof: ' + $mutation)
    Assert (-not $msg.Contains('secret')) 'Rejected proof does not echo injected data'
}
$r = New-TestResult $testNonce; $r.Success=$false; $r.Error='EffectiveFailed'; $r.Diagnostics=@('get_user_token [code=5]'); $r.Lines=@(); $r.Effective.ExitCode=255
$msg = Assert-Rejected { Assert-CageSsvResult $r $testNonce } 'Native failure throws sanitized relevant diagnostics'
Assert ($msg -ceq 'SYSTEM sshd preflight EffectiveFailed (get_user_token [code=5]). No account state was changed.') 'Relevant diagnostics remain useful without raw stderr'
# Isolated worker-core simulations require an EXPLICIT TEST-ONLY switch. Production
# Invoke-CageSsvWorker has no such switch and its SID guard remains unmodified.
function Invoke-IsolatedWorkerTest {
    param([Parameter(Mandatory=$true)][switch]$AllowMockSystem, [string]$Mode)
    if (-not $AllowMockSystem) { throw 'Explicit isolated worker simulation required.' }
    & {
        . $source
function New-CageSsvScheduler { throw 'TEST GUARD: live COM Scheduler forbidden' }
        $state = @{ Calls=(New-Object 'Collections.Generic.List[object]'); Result=$null }
        $candidate = "Port 22`r`n"
        $request = [pscustomobject]@{Schema=1;Nonce=$testNonce;CandidateHash=(Get-CageSsvHash $candidate);SshdExe='C:\synthetic\sshd.exe';ValidateUser='cageops';GuestAddress='100.64.0.10';TimeoutSeconds=30}
        if ($Mode -ceq 'Hash') { $request.CandidateHash='0' * 64 }
        if ($Mode -ceq 'User') { $request.ValidateUser='BAD' }
        if ($Mode -ceq 'Request') { $request.Schema=2 }
        function Assert-CageSsvCapsuleName { param($Capsule); if ($Mode -ceq 'Acl') { throw 'secret ACL failure' } }
        function Assert-CageSsvExe { param($SshdExe); if ($Mode -ceq 'Exe') { throw 'secret executable' } }
        function Read-CageSsvFile {
            param($Capsule,$Name,$MaximumBytes)
            if ($Name -ceq 'request.json') { return ($request | ConvertTo-Json -Compress) }
            if ($Mode -ceq 'CandidateRead') { throw 'secret candidate read' }
            return $candidate
        }
        function Write-CageSsvResult { param($Capsule,$Result); $state.Result=$Result; if ($Mode -ceq 'Write') { throw 'secret result write' } }
        function Invoke-CageSsvNative {
            param($SshdExe,$Arguments,$TimeoutSeconds)
            $state.Calls.Add(@($Arguments))
            $n=New-TestNative
            $stage='Effective'; if ($Arguments[0] -ceq '-t') { $stage='Syntax'; $n.Lines=@() }
            if ($Mode -ceq ($stage + 'Exit')) { $n.ExitCode=255; $n.Diagnostics=@('get_user_token [code=5]') }
            if ($Mode -ceq ($stage + 'Timeout')) { $n.TimedOut=$true }
            if ($Mode -ceq ($stage + 'Truncate')) { $n.Truncated=$true }
            if ($Mode -ceq ($stage + 'Live')) { $n.Stopped=$false }
            if ($stage -ceq 'Effective' -and $Mode -ceq 'Missing') { $n.Lines=@($effectiveLines[0..5]) }
            if ($stage -ceq 'Effective' -and $Mode -ceq 'Duplicate') { $n.Lines=@($effectiveLines + $effectiveLines[0]) }
            Assert ($TimeoutSeconds -eq 10) 'Each native invocation has a bounded sub-deadline'
            return $n
        }
        $message=''
        try { Invoke-CageSsvWorkerCore $capsuleText } catch { $message=$_.Exception.Message }
        return [pscustomobject]@{Result=$state.Result;Calls=@($state.Calls.ToArray());Message=$message}
    }
}
$w = Invoke-IsolatedWorkerTest -AllowMockSystem -Mode Success
Assert ($w.Result.Success -and $w.Calls.Count -eq 2) 'Mock worker runs both validation phases'
Assert (($w.Calls[0] -join '|') -ceq ('-t|-f|' + $capsuleText + '\candidate.conf')) 'Worker syntax command is fixed and never listens'
Assert (($w.Calls[1] -join '|') -ceq ('-ddd|-T|-f|' + $capsuleText + '\candidate.conf|-C|user=cageops,host=cage-guest,addr=100.64.0.10')) 'Worker effective command has exact safe context'
foreach ($mode in @('Hash','User','Exe','CandidateRead','SyntaxExit','SyntaxTimeout','SyntaxTruncate','SyntaxLive','EffectiveExit','EffectiveTimeout','EffectiveTruncate','EffectiveLive','Missing','Duplicate')) {
    $w=Invoke-IsolatedWorkerTest -AllowMockSystem -Mode $mode
    Assert ($null -ne $w.Result -and -not $w.Result.Success -and @($w.Result.Lines).Count -eq 0) ('Mock worker fails closed: ' + $mode)
    Assert (-not (($w.Result | ConvertTo-Json -Depth 6 -Compress).Contains('secret'))) 'Worker never serializes exception text'
}
foreach ($mode in @('Request','Acl','Write')) { $w=Invoke-IsolatedWorkerTest -AllowMockSystem -Mode $mode; Assert ($w.Message.Length -gt 0) ('Early/result-write worker failure does not claim success: ' + $mode) }
# The COM registration contract has its own pure-memory suite; never instantiate
# the real COM service here, including after nested helper reloads.
$registerSource = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Register-CageSsvTask' }, $true).Body.Extent.Text
Assert ($registerSource.Contains('RegisterTaskDefinition')) 'Creation uses atomic explicit-security registration'
Assert ($registerSource.Contains("18, 'S-1-5-18'") -and $registerSource.Contains('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')) 'Creation never overwrites and never grants creator-user rights'
Assert ($registerSource.Contains('Assert-CageSsvTaskDescriptor')) 'Task owner/DACL is verified before any start'
Assert (-not $registerSource.Contains('Register-ScheduledTask')) 'No fallback to unsealed default task creation'
$comRefusal = Assert-Rejected { New-CageSsvScheduler } 'Live COM is guarded in test process'
Assert ($comRefusal -ceq 'TEST GUARD: live COM Scheduler forbidden') 'Test COM guard is explicit and deterministic'
function New-TestTask([string]$Name,[string]$Execute,[string]$Arguments,[string]$State='Ready') {
    return [pscustomobject]@{TaskName=$Name;TaskPath='\';Actions=@([pscustomobject]@{Execute=$Execute;Arguments=$Arguments});Triggers=@();Principal=[pscustomobject]@{UserId='S-1-5-18';LogonType='ServiceAccount';RunLevel='Highest'};State=$State}
}
& {
    $name='CageSshdValidate-' + ('a' * 32); $exe='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; $argsText='fixed'
    foreach ($mutation in @('Name','Path','Action','Arguments','Principal','Logon','Level','Trigger')) {
        $t=New-TestTask $name $exe $argsText
        switch ($mutation) { Name {$t.TaskName+='x'}; Path {$t.TaskPath='\other\'}; Action {$t.Actions[0].Execute='other.exe'}; Arguments {$t.Actions[0].Arguments='other'}; Principal {$t.Principal.UserId='Administrator'}; Logon {$t.Principal.LogonType='Interactive'}; Level {$t.Principal.RunLevel='Limited'}; Trigger {$t.Triggers=@('unexpected')} }
        $null=Assert-Rejected { Assert-CageSsvTaskIdentity $t $name $exe $argsText } 'Reject mismatched task before start/cleanup'
    }
    $t=New-TestTask $name $exe $argsText; $t.Triggers=$null
    Assert-CageSsvTaskIdentity $t $name $exe $argsText
    Assert $true 'Null CIM triggers means no triggers'
    foreach ($bad in @('*','CageSshdValidate-*','other','CageSshdValidate-' + ('A' * 32))) { $null=Assert-Rejected { Assert-CageSsvTaskName $bad } 'Task operations reject wildcards/noncanonical names' }
}
# Real wait loop with fake clock, fake state transitions and fake atomic result.
function Invoke-IsolatedWaitTest([string]$Mode) {
    & {
        . $source
function New-CageSsvScheduler { throw 'TEST GUARD: live COM Scheduler forbidden' }
        $fakeClock=@{Tick=0;Poll=0}
        $name='CageSshdValidate-' + ('b' * 32)
        function Get-CageSsvMilliseconds { return $fakeClock.Tick }
        function Wait-CageSsvPoll { $fakeClock.Poll++; $fakeClock.Tick+=1000 }
        function Get-CageSsvTask {
            param($TaskName)
            $s='Ready'
            if ($Mode -ceq 'Race' -and $fakeClock.Poll -eq 1) {$s='Running'}
            if ($Mode -cin @('Running','StopTimeout')) {$s='Running'}
            if ($Mode -ceq 'Unknown') {$s='Unknown'}
            return (New-TestTask $TaskName 'fixed.exe' 'fixed' $s)
        }
        function Test-CageSsvResultExists { param($Capsule); return ($Mode -ceq 'Race' -and $fakeClock.Poll -ge 2) }
        $message=''
        try { Wait-CageSsvTask $name 'fixed.exe' 'fixed' $capsuleText 5 -Stopping:($Mode -cin @('StopReady','StopTimeout')) } catch { $message=$_.Exception.Message }
        return [pscustomobject]@{Message=$message;Polls=$fakeClock.Poll}
    }
}
$wait=Invoke-IsolatedWaitTest Race
Assert ($wait.Message -ceq '' -and $wait.Polls -eq 2) 'Initial Ready does not complete before worker result and final stopped state'
foreach ($mode in @('Ready','Running','Unknown','StopTimeout')) { $wait=Invoke-IsolatedWaitTest $mode; Assert ($wait.Message.Length -gt 0 -and $wait.Polls -le 5) 'Task timeout/uncertain state is bounded and rejected' }
$wait=Invoke-IsolatedWaitTest StopReady
Assert ($wait.Message -ceq '' -and $wait.Polls -eq 0) 'Stopping wait accepts proven stopped task without a result'
# Full function is ONLY invoked within this isolated mock scope. EVERY scheduler,
# IO, executable/platform/admin prerequisite and action builder is mocked first.
function Invoke-IsolatedParentTest([string]$Mode) {
    & {
        . $source
function New-CageSsvScheduler { throw 'TEST GUARD: live COM Scheduler forbidden' }
        $state=@{Task=$null;Files=@{};Calls=(New-Object 'Collections.Generic.List[string]');Capsule='';Removed=$false;Registered=$false}
        function Assert-CageSsvAdministrator { if ($Mode -ceq 'Admin') { throw 'secret admin' } }
        function Assert-CageSsvExe { param($SshdExe); if ($Mode -ceq 'Exe') { throw 'secret executable' } }
        function Get-CageSsvRoot { return 'C:\ProgramData\ssh' }
        function Get-CageSsvPowerShellExe { return 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' }
        function Get-CageSsvActionArguments { param($Capsule); return '-NoLogo -NoProfile -NonInteractive -EncodedCommand Zg==' }
        function New-CageSsvCapsule { param($Capsule,[ref]$Created); $state.Capsule=$Capsule; $state.Calls.Add('Create'); if ($Mode -ceq 'Create') {throw 'secret creation'}; $Created.Value=$true; if ($Mode -ceq 'CreateAcl') {throw 'secret ACL'} }
        function Write-CageSsvFile { param($Capsule,$Name,$Text); $state.Calls.Add('Write:'+$Name); if ($Mode -ceq ('Write:'+$Name)) {throw 'secret write'}; $state.Files[$Name]=$Text }
        function Get-CageSsvTask {
            param($TaskName)
            if ($Mode -ceq 'Collision' -and -not $state.Registered) {return (New-TestTask $TaskName 'other.exe' 'other')}
            if ($Mode -ceq 'GetAfterRegister' -and $state.Registered) {throw 'secret task query'}
            return $state.Task
        }
        function Register-CageSsvTask {
            param($TaskName,$Execute,$Arguments,$TimeoutSeconds)
            $state.Calls.Add('Register'); $state.Registered=$true
            if ($Mode -ceq 'RegisterBefore') {throw 'secret register'}
            $state.Task=New-TestTask $TaskName $Execute $Arguments
            if ($Mode -ceq 'RegisterAfter') {throw 'secret registered error'}
            if ($Mode -ceq 'Identity') {$state.Task.Actions[0].Arguments='foreign'}
        }
        function Start-CageSsvTask { param($TaskName); $state.Calls.Add('Start'); if ($Mode -ceq 'Start') {throw 'secret uncertain start'}; $state.Task.State='Running' }
        function Stop-CageSsvTask { param($TaskName); $state.Calls.Add('Stop'); if ($Mode -ceq 'Stop') {throw 'secret stop'}; $state.Task.State='Ready' }
        function Wait-CageSsvTask {
            param($TaskName,$Execute,$Arguments,$Capsule,$TimeoutSeconds,[switch]$Stopping)
            if ($Stopping) {$state.Calls.Add('WaitStop'); if ($Mode -ceq 'StopWait') {throw 'secret stop wait'}; return}
            $state.Calls.Add('Wait')
            if ($Mode -cin @('Timeout','Stop','StopWait','InitialReadyTimeout')) {if ($Mode -ceq 'InitialReadyTimeout') {$state.Task.State='Ready'}; throw 'secret timeout'}
            $state.Task.State='Ready'
        }
        function Read-CageSsvFile {
            param($Capsule,$Name,$MaximumBytes)
            $state.Calls.Add('ReadResult')
            if ($Mode -ceq 'Read') {throw 'secret read'}
            if ($Mode -ceq 'Json') {return '{secret'}
            $request=$state.Files['request.json'] | ConvertFrom-Json
            $r=New-TestResult $request.Nonce
            switch ($Mode) {
                Nonce {$r.Nonce='0' * 32}; Sid {$r.SystemSid='S-1-5-32-544'}; Schema {$r.Schema=2}; Live {$r.NativeStopped=$false;$r.Effective.Stopped=$false}; Exit {$r.Success=$false;$r.Error='EffectiveFailed';$r.Effective.ExitCode=255;$r.Lines=@();$r.Diagnostics=@('get_user_token [code=5]')}; Missing {$r.Lines=@($effectiveLines[0..5])}; Duplicate {$r.Lines=@($effectiveLines + $effectiveLines[0])}; Diagnostic {$r.Diagnostics=@('secret')}
            }
            if ($Mode -ceq 'LiveAfterProof') { $state.Task.State='Running' }
            return ($r | ConvertTo-Json -Depth 6 -Compress)
        }
        function Unregister-CageSsvTask { param($TaskName); $state.Calls.Add('Unregister'); if ($Mode -ceq 'Unregister') {throw 'secret unregister'}; if ($Mode -cne 'UnregisterRemains') {$state.Task=$null} }
        function Remove-CageSsvCapsule { param($Capsule); $state.Calls.Add('Remove'); Assert ($Capsule -ceq $state.Capsule) 'Cleanup targets only created capsule'; if ($Mode -ceq 'Remove') {throw 'secret remove'}; $state.Removed=$true }
        $output=@();$message=''
        try {$output=@(Invoke-CageSshdSystemValidation -SshdExe 'C:\synthetic\sshd.exe' -Content "Port 22`r`n" -ValidateUser 'cageops' -GuestAddress '100.64.0.10')} catch {$message=$_.Exception.Message}
        return [pscustomobject]@{Output=$output;Message=$message;Calls=@($state.Calls.ToArray());Removed=$state.Removed}
    }
}
$p=Invoke-IsolatedParentTest Success
Assert ($p.Message -ceq '' -and $p.Output.Count -eq 7 -and @($p.Output | Where-Object { $_ -isnot [string] }).Count -eq 0) 'Mocked full function emits only seven strings'
Assert ($p.Removed -and ($p.Calls -join '|') -ceq 'Create|Write:candidate.conf|Write:request.json|Register|Start|Wait|ReadResult|Unregister|Remove') 'Success cleans exact task before exact capsule'
foreach ($mode in @('Admin','Exe','Collision','Create','CreateAcl','Write:candidate.conf','Write:request.json','RegisterBefore','RegisterAfter','Identity','GetAfterRegister','Start','Timeout','Stop','StopWait','InitialReadyTimeout','Read','Json','Nonce','Sid','Schema','Live','LiveAfterProof','Exit','Missing','Duplicate','Diagnostic','Unregister','UnregisterRemains','Remove')) {
    $p=Invoke-IsolatedParentTest $mode
    Assert ($p.Message.Length -gt 0 -and $p.Output.Count -eq 0) ('Parent reports no success: ' + $mode)
    Assert (-not ($p.Message -match 'secret|TEST GUARD')) 'Parent sanitizes all unexpected failures and never reaches live scheduler'
    if ($mode -cin @('Identity','GetAfterRegister','Start','Timeout','Stop','StopWait','InitialReadyTimeout','Read','Json','Nonce','Sid','Schema','Live','LiveAfterProof','Missing','Duplicate','Diagnostic','Unregister','UnregisterRemains')) {
        Assert (-not $p.Removed -and $p.Message.Contains('Retained protected artifacts')) ('Uncertain failure retains protected capsule and exact cleanup names: ' + $mode)
    }
    if ($mode -cin @('Start','Timeout','InitialReadyTimeout')) { Assert ($p.Calls -contains 'Stop' -and $p.Calls -contains 'WaitStop') 'Uncertain start/timeout stops and waits even at initial Ready' }
    if ($mode -cin @('RegisterBefore','RegisterAfter','CreateAcl','Write:candidate.conf','Write:request.json','Exit')) { Assert $p.Removed ('Proven inactive failure is cleaned up: ' + $mode + '; ' + $p.Message + '; ' + ($p.Calls -join '|')) }
    if ($mode -ceq 'Identity') { Assert ($p.Calls -notcontains 'Start' -and $p.Calls -notcontains 'Unregister' -and $p.Calls -notcontains 'Stop') 'Foreign task identity is never started or cleaned up' }
    if ($mode -ceq 'Exit') { Assert $p.Message.Contains('get_user_token [code=5]') 'Parent retains sanitized native diagnostics on failure' }
}
# Real narrow task wrappers with inert cmdlets, including exact lookup and no
# wildcard cleanup. None of these fakes calls a module-qualified live command.
& {
    . $source
function New-CageSsvScheduler { throw 'TEST GUARD: live COM Scheduler forbidden' }
    $wrapperCalls=New-Object 'Collections.Generic.List[string]'
    $exactName='CageSshdValidate-' + ('c' * 32)
    function Start-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction); Assert ($TaskName -ceq $exactName -and $TaskPath -ceq '\') 'Start wrapper targets exact own task'; $wrapperCalls.Add('Start') }
    function Stop-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction); Assert ($TaskName -ceq $exactName -and $TaskPath -ceq '\') 'Stop wrapper targets exact own task'; $wrapperCalls.Add('Stop') }
    function Unregister-ScheduledTask { param($TaskName,$TaskPath,[switch]$Confirm,$ErrorAction); Assert ($TaskName -ceq $exactName -and $TaskPath -ceq '\' -and -not $Confirm) 'Unregister wrapper targets exact own task'; $wrapperCalls.Add('Unregister') }
    function Get-ScheduledTask { param($TaskPath,$ErrorAction); Assert ($TaskPath -ceq '\') 'Lookup is confined to root folder'; New-TestTask 'unrelated' 'other' 'other'; New-TestTask $exactName 'fixed.exe' 'fixed' }
    Start-CageSsvTask $exactName; Stop-CageSsvTask $exactName; Unregister-CageSsvTask $exactName
    Assert ((Get-CageSsvTask $exactName).TaskName -ceq $exactName) 'Exact lookup excludes unrelated tasks'
    foreach ($command in @('Start-CageSsvTask','Stop-CageSsvTask','Unregister-CageSsvTask','Get-CageSsvTask')) { $null=Assert-Rejected { & $command 'CageSshdValidate-*' } 'Wrappers reject wildcard names before cmdlet invocation' }
    Assert (($wrapperCalls -join '|') -ceq 'Start|Stop|Unregister') 'No invalid name reaches scheduler mock'
}
# Pure protected-root/ancestor policy and cleanup refusals. No filesystem mutation.
& {
    . $source
function New-CageSsvScheduler { throw 'TEST GUARD: live COM Scheduler forbidden' }
    $descriptor=New-TestDescriptor 'O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)' $false
    function Get-Acl { param($LiteralPath,$ErrorAction); return $descriptor }
    Assert-CageSsvPrivilegedObject 'C:\synthetic'
    $descriptor=New-TestDescriptor 'O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)' $false
    $null=Assert-Rejected { Assert-CageSsvPrivilegedObject 'C:\synthetic' } 'Unprivileged direct path writes rejected'
    $descriptor=New-TestDescriptor 'O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x40;;;BU)' $false
    $null=Assert-Rejected { Assert-CageSsvPrivilegedObject 'C:\synthetic' -Ancestor } 'Ancestor delete-child rights rejected'
    $descriptor=New-TestDescriptor 'O:S-1-5-21-1-2-3-1001D:P(A;;FA;;;SY)(A;;FA;;;BA)' $false
    $null=Assert-Rejected { Assert-CageSsvPrivilegedObject 'C:\synthetic' -Ancestor } 'Unprivileged ancestor owner rejected'
}
& {
    . $source
function New-CageSsvScheduler { throw 'TEST GUARD: live COM Scheduler forbidden' }
    function Assert-CageSsvCapsuleName { param($Capsule) }
    function Get-ChildItem { param($LiteralPath,[switch]$Force,$ErrorAction); return [pscustomobject]@{Name='foreign.txt';PSIsContainer=$false;FullName='Z:\never-delete\foreign.txt'} }
    $null=Assert-Rejected { Remove-CageSsvCapsule $capsuleText } 'Unknown child prevents any exact-file deletion'
}
foreach ($proofType in @('SidArray','ErrorArray')) {
    $r=New-TestResult $testNonce
    if ($proofType -ceq 'SidArray') {$r.SystemSid=@('S-1-5-18','S-1-5-18')} else {$r.Error=@('None','None')}
    $null=Assert-Rejected { Assert-CageSsvResult $r $testNonce } 'Identity/error proof must be scalar strings'
}
# Real public administrator gate only; no full public invocation outside mocks.
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $null=Assert-Rejected { Assert-CageSsvAdministrator } 'Actual unelevated token rejected without elevation attempt'
}
Write-Host ("PASS: {0} SYSTEM-validation assertions (no privileged actions)." -f $count)
Write-Host 'LIMITATION: real SYSTEM execution and disabled-account token behavior were NOT tested. A disabled-account refusal must fail preflight without enabling the account.'
