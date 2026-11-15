# Nonprivileged Windows PowerShell 5.1 x64 tests; no account/group mutations.
# NEVER run a correctly targeted enrollment, even with CheckOnly, in this suite.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$source = Join-Path $PSScriptRoot 'enroll-windows-peer.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
$count = 0
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERT: $Message" }
    $script:count++
}
function Assert-Rejected([scriptblock]$Action, [string]$Message) {
    $rejected = $false
    try { & $Action } catch { $rejected = $true }
    Assert $rejected $Message
}
Assert ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1) 'Run suite in Windows PowerShell 5.1'
Assert ([Environment]::Is64BitProcess) 'Run suite in native 64-bit process'
Assert ($errors.Count -eq 0) 'Enrollment source parses'
$selfTokens = $null
$selfErrors = $null
$null = [Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$selfTokens, [ref]$selfErrors)
Assert ($selfErrors.Count -eq 0) 'Test source parses'
$bytes = [IO.File]::ReadAllBytes($source)
Assert (@($bytes | Where-Object { $_ -gt 127 }).Count -eq 0) 'Enrollment source is ASCII'
$names = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
Assert (($names -join ',') -ceq 'GuestPublicKey,GuestAddress,HostAddress,ExpectedComputerName,UserName,CheckOnly,ResumeFailedEnrollment') 'Exact seven declared parameters; recovery is seventh'
$metadata = New-Object Management.Automation.CommandMetadata (Get-Command -Name $source)
foreach ($name in @('GuestPublicKey','GuestAddress','HostAddress','ExpectedComputerName')) {
    Assert $metadata.Parameters[$name].ParameterSets['__AllParameterSets'].IsMandatory "$name is mandatory"
}
Assert ($ast.ParamBlock.Parameters[4].DefaultValue.Value -ceq 'cageops') 'Default dedicated user'
foreach ($name in @('CheckOnly','ResumeFailedEnrollment')) {
    Assert ($metadata.Parameters[$name].ParameterType -eq [Management.Automation.SwitchParameter]) "$name switch type"
    Assert ($null -eq $ast.ParamBlock.Parameters[$names.IndexOf($name)].DefaultValue) "$name defaults to false"
}
$statements = @($ast.EndBlock.Statements)
Assert ($statements[1] -is [Management.Automation.Language.IfStatementAst]) 'Host fence is the first action after error policy'
Assert ($statements[1].Extent.Text.Contains('Computer-name fence failed.')) 'First action fences COMPUTERNAME'
Assert (-not $statements[1].Extent.Text.Contains('Get-')) 'Host fence has no host queries'
$wrongHost = 'CAGE-NEVER-TEST'
if ($env:COMPUTERNAME -ieq $wrongHost) { $wrongHost = 'CAGE-OTHER-TEST' }
$arguments = @{
    GuestPublicKey = 'synthetic-not-a-real-key'
    GuestAddress = '100.64.0.10'
    HostAddress = '100.64.0.11'
    ExpectedComputerName = $wrongHost
}
foreach ($check in @($false, $true)) {
    foreach ($resume in @($false, $true)) {
        $message = ''
        try { & $source @arguments -CheckOnly:$check -ResumeFailedEnrollment:$resume } catch { $message = $_.Exception.Message }
        Assert ($message -like 'Computer-name fence failed.*') 'Wrong host rejected before import/key/account access for every switch combination'
    }
}
Assert-Rejected { & $source @arguments -UserName 'bad user' } 'Reject unsafe user parameter before execution'
Assert-Rejected { & $source -GuestPublicKey x -GuestAddress x -HostAddress x -ExpectedComputerName 'bad/name' } 'Reject unsafe expected name'
# Load only function ASTs; never execute the enrollment body/import/apply.
foreach ($name in @('Assert-PeerAddress','Assert-PeerPublicKey','Assert-PeerPlainPath',
    'Initialize-PeerNativeMembership','ConvertFrom-PeerGroupAccount','Resolve-PeerGroupName',
    'Read-PeerMembershipPage','Get-PeerGroupMemberSids','Get-PeerMembership','Assert-PeerExistingAccount',
    'Set-PeerAccountEnabled','Restore-PeerDisabledAccount','Get-PeerKeyAclRuleSet','Assert-PeerKeyAcl')) {
    $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    Assert ($null -ne $definition) "Isolated function $name exists"
    . ([scriptblock]::Create($definition.Extent.Text))
}
foreach ($ip in @('100.64.0.0','100.127.255.255')) {
    Assert-PeerAddress $ip 'test'
    Assert $true 'Accept canonical range boundary'
}
foreach ($ip in @('100.63.255.255','100.128.0.0','192.0.2.1','100.64.0.01','100.64.1','::1',"100.64.0.10`n",'100.64.0.10/32','100.64.0.10,100.64.0.11')) {
    Assert-Rejected { Assert-PeerAddress $ip 'test' } 'Reject noncanonical/out-of-range/injected address'
}
# Synthetic wire-format bytes only: no generated private keys or live key files.
$blob = New-Object byte[] 51
$prefix = [byte[]]@(0,0,0,11,115,115,104,45,101,100,50,53,53,49,57,0,0,0,32)
[Array]::Copy($prefix, $blob, $prefix.Length)
for ($i = 19; $i -lt 51; $i++) { $blob[$i] = [byte]$i }
$key = 'ssh-ed25519 ' + [Convert]::ToBase64String($blob)
Assert-PeerPublicKey $key
Assert-PeerPublicKey ($key + ' synthetic-test-comment')
Assert $true 'Accept exact Ed25519 public wire data and ASCII comment'
foreach ($bad in @(($key + "`n"), ($key + "`r`n" + $key), ('from="*" ' + $key), $key.Replace('ssh-ed25519','ssh-rsa'), 'ssh-ed25519 AAAA', ($key + "`tcomment"))) {
    Assert-Rejected { Assert-PeerPublicKey $bad } 'Reject malformed/multiline/options public key'
}
$blob[3] = 12
Assert-Rejected { Assert-PeerPublicKey ('ssh-ed25519 ' + [Convert]::ToBase64String($blob)) } 'Reject incorrect Ed25519 wire header'
Assert-PeerPlainPath $source
Assert $true 'Read-only ancestor traversal handles FileInfo and DirectoryInfo under strict mode'
. (Join-Path $PSScriptRoot 'host-access-common.ps1')
# Compare access facts rather than NTFS AutoInherited history/ACE order.
function New-TestKeyDescriptor([string]$Sddl) {
    $descriptor = New-Object Security.AccessControl.FileSecurity
    $descriptor.SetSecurityDescriptorSddlForm($Sddl)
    return $descriptor
}
$aclReader = New-Object Security.Principal.SecurityIdentifier('S-1-5-21-1-2-3-1001')
$aclExpected = New-CageKeyAcl $aclReader
$sidText = $aclReader.Value
$normalSddl = 'O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;' + $sidText + ')'
foreach ($sddl in @($normalSddl, $normalSddl.Replace('D:P','D:PAI'),
    ('O:BAD:PAI(A;;0x1200a9;;;' + $sidText + ')(A;;FA;;;BA)(A;;FA;;;SY)'))) {
    Assert-PeerKeyAcl -Actual (New-TestKeyDescriptor $sddl) -Expected $aclExpected
    Assert $true 'Exact permissions accept NTFS AutoInherited normalization and harmless allow-entry order'
}
$badAcls = @(
    $normalSddl.Replace('O:BA','O:SY'),
    $normalSddl.Replace('D:P','D:AI'),
    ($normalSddl + '(A;;FA;;;WD)'),
    $normalSddl.Replace('0x1200a9','FA'),
    $normalSddl.Replace('0x1200a9','0x1301bf'),
    $normalSddl.Replace('(A;;FA;;;SY)','(A;ID;FA;;;SY)'),
    $normalSddl.Replace('(A;;FA;;;SY)','(D;;FA;;;SY)'),
    $normalSddl.Replace('(A;;FA;;;SY)',''),
    $normalSddl.Replace($sidText,'S-1-5-21-1-2-3-1002'),
    'O:BAD:P'
)
foreach ($sddl in $badAcls) {
    Assert-Rejected { Assert-PeerKeyAcl -Actual (New-TestKeyDescriptor $sddl) -Expected $aclExpected } 'Reject changed owner/protection/SID/mask, extra/missing/inherited/deny entries or empty DACL'
}
Assert-Rejected { Assert-PeerKeyAcl -Actual $null -Expected $aclExpected } 'Reject missing actual descriptor'
# Actual NTFS roundtrip, owner=current tester only so no elevation is required.
$fixtureRoot = Join-Path $PSScriptRoot '.test-output'
$null = New-Item -ItemType Directory -Path $fixtureRoot -Force
$fixture = Join-Path $fixtureRoot ('acl-semantic-test-' + [guid]::NewGuid().ToString('N') + '.tmp')
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$fixtureAcl = New-CageKeyAcl $currentSid
$fixtureAcl.SetOwner($currentSid)
[IO.File]::WriteAllText($fixture, 'Isolated ACL normalization fixture')
Set-Acl -LiteralPath $fixture -AclObject $fixtureAcl
$fixtureActual = Get-Acl -LiteralPath $fixture
Assert-PeerKeyAcl -Actual $fixtureActual -Expected $fixtureAcl
Assert $fixtureActual.AreAccessRulesProtected 'Real file roundtrip retains protection and exact three permissions despite normalization'
$original = "Port 22`r`nAllowUsers unrelated`r`nMatch Group administrators`r`n    AuthorizedKeysFile admin_keys`r`n"
$candidate = New-CageSshConfig $original 'cageops' '100.64.0.10'
Assert ($candidate.Contains('AllowUsers unrelated')) 'Preserve unrelated allowlist'
Assert ($candidate.Contains("Match Group administrators`r`n    AuthorizedKeysFile admin_keys")) 'Preserve unrelated Match rule'
Assert ($candidate -ceq (New-CageSshConfig $candidate 'cageops' '100.64.0.10')) 'Managed config is idempotent'
$commonEffectiveValidator = ${function:Assert-CageEffectiveConfig}
$definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-CageEffectiveConfig' }, $true)
. ([scriptblock]::Create($definition.Extent.Text))
$effective = @('passwordauthentication no','kbdinteractiveauthentication no','authenticationmethods publickey','disableforwarding yes','allowusers cageops@100.64.0.10','authorizedkeysfile __PROGRAMDATA__/ssh/cageops_authorized_keys','pubkeyauthentication yes')
Assert-CageEffectiveConfig $effective 'cageops' '100.64.0.10'
Assert $true 'Extended effective validator accepts exact intended policy'
Assert-Rejected { Assert-CageEffectiveConfig @($effective | Where-Object { $_ -ne 'pubkeyauthentication yes' }) 'cageops' '100.64.0.10' } 'Reject unusable public-key authentication before install'
Assert-Rejected { Assert-CageEffectiveConfig @($effective | Where-Object { $_ -ne 'disableforwarding yes' }) 'cageops' '100.64.0.10' } 'Common forwarding validation retained'
# Parser-only CheckOnly coverage: reporting/return only; apply remains after it.
$checkBranch = @($statements | Where-Object { $_ -is [Management.Automation.Language.IfStatementAst] -and $_.Clauses[0].Item1.Extent.Text -eq '$CheckOnly' })
Assert ($checkBranch.Count -eq 1) 'Single explicit CheckOnly fence'
$checkCommands = @($checkBranch[0].FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))
Assert (@($checkCommands | Where-Object { $_.GetCommandName() -ne 'Write-Host' }).Count -eq 0) 'CheckOnly branch contains reporting only'
Assert ($checkBranch[0].Clauses[0].Item2.Statements[-1] -is [Management.Automation.Language.ReturnStatementAst]) 'CheckOnly returns before apply'
$apply = @($statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })
Assert ($apply.Count -eq 1 -and $apply[0].Extent.StartOffset -gt $checkBranch[0].Extent.EndOffset) 'Apply transaction follows CheckOnly return'
$body = $ast.Extent.Text
Assert ($body.Contains('foreach ($entry in $PSBoundParameters.GetEnumerator())')) 'Relaunch forwards every bound parameter'
Assert ($body.Contains('$PSCommandPath.Replace')) 'Relaunch targets generic source path'
Assert ($body.Contains('-ValidateUser $UserName -GuestAddress $GuestAddress')) 'Common transaction receives exact user/source validation context'
Assert (-not ($body -match '(?i)New-NetFirewallRule|Set-NetFirewallRule|Remove-NetFirewallRule|Add-LocalGroupMember|Start-Process|tailscale\.exe')) 'No firewall, elevation or VPN mutation commands'
Assert (-not ($body -match 'ADsPath|\.IsMember|Invoke\(''IsMember''|\$users\.Add')) 'No ADSI path-based membership query/add remains'
Assert ($body.Contains('(-not $CheckOnly -or $ResumeFailedEnrollment)')) 'Recovery CheckOnly also requires explicit administrator token'
Assert ($body.Contains('$ResumeFailedEnrollment -and -not $exists')) 'Recovery rejects absent accounts before apply'
Assert ($body.Contains('description is not cryptographic provenance')) 'Physical consent limitation documented in source and preflight'
Assert ($body.Contains('Existing key file is not exactly compatible.')) 'Existing incompatible dedicated key refusal retained'
Assert ($body.Contains('Dedicated key ACL verification failed.')) 'Dedicated key ACL verification retained'
Assert ($body.Contains('HostAddress is not assigned to this laptop.')) 'Assigned host-IP fence retained'
# Exercise relaunch serialization against an inert binding target only.
function Test-SyntheticForward {
    param([string]$GuestPublicKey, [string]$GuestAddress, [string]$HostAddress, [string]$ExpectedComputerName, [string]$UserName, [switch]$CheckOnly, [switch]$ResumeFailedEnrollment)
    return [pscustomobject]@{ Bound = $PSBoundParameters; Check = [bool]$CheckOnly; Resume = [bool]$ResumeFailedEnrollment }
}
foreach ($check in @($false, $true)) {
    foreach ($resume in @($false, $true)) {
        $forward = @{
            GuestPublicKey = ($key + " synthetic 'quoted' comment")
            GuestAddress = '100.64.0.10'
            HostAddress = '100.64.0.11'
            ExpectedComputerName = 'CAGE-SYNTHETIC'
            UserName = 'synthetic_ops'
            CheckOnly = [Management.Automation.SwitchParameter]$check
            ResumeFailedEnrollment = [Management.Automation.SwitchParameter]$resume
        }
        $serialized = [Management.Automation.PSSerializer]::Serialize($forward)
        $encodedParams = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($serialized))
        $roundTrip = [Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedParams)))
        $result = Test-SyntheticForward @roundTrip
        Assert ($result.Bound.Count -eq 7) 'All seven bound relaunch parameters survive serialization'
        Assert ($result.Check -eq $check -and $result.Resume -eq $resume) 'Explicit true/false switch values survive relaunch serialization'
        foreach ($name in @('GuestPublicKey','GuestAddress','HostAddress','ExpectedComputerName','UserName')) {
            Assert ($result.Bound[$name] -ceq $forward[$name]) 'Relaunch preserves exact string value'
        }
    }
}
# SID translation parsing is locale-independent; never parse net.exe output.
Assert ((ConvertFrom-PeerGroupAccount 'BUILTIN\Users') -ceq 'Users') 'Parse translated group account'
$localized = [string][char]0x7528 + [char]0x6237
Assert ((ConvertFrom-PeerGroupAccount ('BUILTIN\' + $localized)) -ceq $localized) 'Preserve localized group name from SID translation'
foreach ($invalid in @('', 'Users', '\Users', 'BUILTIN\', 'BUILTIN\Users\extra', "BUILTIN\Users`n")) {
    Assert-Rejected { ConvertFrom-PeerGroupAccount $invalid } 'Reject malformed group translation'
}
Assert-Rejected { Resolve-PeerGroupName 'S-1-5-32-546' } 'Only the two required built-in group SIDs are accepted'
$member = Get-CageSid 'S-1-5-21-111-222-333-1001'
$operatorSid = Get-CageSid 'S-1-5-21-111-222-333-1002'
$other = $operatorSid.Value
# Mock only the read-only page seam. Production native imports are private.
$nativePageReader = ${function:Read-PeerMembershipPage}
function Read-PeerMembershipPage([string]$GroupName, [uint64]$ResumeHandle) {
    if ($script:pageError) { throw (New-Object ComponentModel.Win32Exception(5)) }
    $script:pageRequests.Add($ResumeHandle)
    if (-not $script:pages.ContainsKey($ResumeHandle)) { throw 'Unexpected resume handle.' }
    return $script:pages[$ResumeHandle]
}
function Set-MockPages([hashtable]$Values) {
    $script:pages = $Values
    $script:pageError = $false
    $script:pageRequests = New-Object 'Collections.Generic.List[uint64]'
}
try {
    Set-MockPages @{ ([uint64]0) = [pscustomobject]@{ Status=0; ResumeHandle=0; MemberSids=[string[]]@() } }
    Assert (-not (Get-PeerMembership 'synthetic group' $member)) 'Empty authoritative group is not membership'
    Set-MockPages @{ ([uint64]0) = [pscustomobject]@{ Status=0; ResumeHandle=0; MemberSids=@($member.Value, $other) } }
    Assert (Get-PeerMembership 'synthetic group' $member) 'Membership matches SID, not path or name'
    Assert (-not (Get-PeerMembership 'synthetic group' (Get-CageSid 'S-1-5-21-111-222-333-1003'))) 'Different account SID is not a member'
    Set-MockPages @{
        ([uint64]0) = [pscustomobject]@{ Status=234; ResumeHandle=42; MemberSids=@($other) }
        ([uint64]42) = [pscustomobject]@{ Status=0; ResumeHandle=0; MemberSids=@($member.Value) }
    }
    Assert (Get-PeerMembership 'synthetic group' $member) 'Pagination includes later page SID'
    Assert (($script:pageRequests -join ',') -ceq '0,42') 'Native continuation handle is forwarded exactly'
    foreach ($invalidPage in @(
        $null,
        [pscustomobject]@{ Status=5; ResumeHandle=0; MemberSids=@() },
        [pscustomobject]@{ Status=0; ResumeHandle=0; MemberSids=$null },
        [pscustomobject]@{ Status=0; ResumeHandle=0; MemberSids=@('not-a-sid') },
        [pscustomobject]@{ Status=0; ResumeHandle=0; MemberSids=@($member.Value, '') },
        [pscustomobject]@{ Status=234; ResumeHandle=42; MemberSids=@() },
        [pscustomobject]@{ Status=234; ResumeHandle=0; MemberSids=@($other) },
        [pscustomobject]@{ Status=0; MemberSids=@($other) }
    )) {
        Set-MockPages @{ ([uint64]0) = $invalidPage }
        Assert-Rejected { Get-PeerMembership 'synthetic group' $member } 'Malformed/failed/nonprogressing query fails closed'
    }
    Set-MockPages @{
        ([uint64]0) = [pscustomobject]@{ Status=234; ResumeHandle=42; MemberSids=@($member.Value) }
        ([uint64]42) = [pscustomobject]@{ Status=5; ResumeHandle=0; MemberSids=@() }
    }
    Assert-Rejected { Get-PeerMembership 'synthetic group' $member } 'Earlier positive SID does not mask later query error'
    Set-MockPages @{
        ([uint64]0) = [pscustomobject]@{ Status=234; ResumeHandle=42; MemberSids=@($other) }
        ([uint64]42) = [pscustomobject]@{ Status=234; ResumeHandle=0; MemberSids=@($other) }
    }
    Assert-Rejected { Get-PeerMembership 'synthetic group' $member } 'Pagination cycle fails closed'
    $script:pageError = $true
    Assert-Rejected { Get-PeerMembership 'synthetic group' $member } 'Native Win32 exception is not coerced to false'
    Assert-Rejected { Get-PeerMembership 'synthetic group' $null } 'Null account SID fails closed'
} finally { ${function:Read-PeerMembershipPage} = $nativePageReader }
# Actual READONLY native binding test: compile production C# and enumerate only.
Initialize-PeerNativeMembership
foreach ($sid in @('S-1-5-32-544','S-1-5-32-545')) {
    $groupName = Resolve-PeerGroupName $sid
    $actualMembers = Get-PeerGroupMemberSids $groupName
    Assert ($null -ne $actualMembers) 'Native level0 enumeration returns a complete SID array'
    foreach ($value in $actualMembers) {
        Assert ((Get-CageSid $value).Value -ceq $value) 'Native member has valid canonical SID'
    }
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    Assert ((Get-PeerMembership $groupName $currentSid) -eq ($actualMembers -contains $currentSid.Value)) 'Fresh native SID membership agrees with authoritative enumeration'
}
$nativeFailure = $null
try { $null = [Cage.PeerLocalGroupsV1]::ReadPage(('CAGE-READONLY-' + [guid]::NewGuid().ToString('N')), 0) }
catch {
    $nativeFailure = $_.Exception
    while ($null -ne $nativeFailure.InnerException) { $nativeFailure = $nativeFailure.InnerException }
}
Assert ($nativeFailure -is [ComponentModel.Win32Exception]) 'Native missing-group query preserves Win32 failure, never empty membership'
Assert ($nativeFailure.NativeErrorCode -ne 0) 'Native query error exposes nonzero Win32 status'
Assert (-not $body.Contains('-IsAdmin $false')) 'Production account validator always receives real administrator membership verdict'
$privateStatic = [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static
foreach ($nativeName in @('NetLocalGroupGetMembers','NetLocalGroupAddMembers','NetApiBufferFree')) {
    Assert ($null -ne [Cage.PeerLocalGroupsV1].GetMethod($nativeName, $privateStatic)) 'Native import is private, not directly callable by enrollment'
}
Assert ($body.Contains('Marshal.ReadIntPtr(buffer, checked(i * IntPtr.Size))')) 'Level0 SID pointer entries use native pointer width'
Assert ($body.Contains('new SecurityIdentifier(sid).Value')) 'Native SID bytes converted to canonical SID, not ADsPath'
Assert ($body.Contains('NetLocalGroupAddMembers(null, group, 0, ref member, 1)')) 'Add uses binary SID at level0'
Assert ($body.Contains('if (status != 0 && status != 1378)')) 'Only success/already-member accepted before fresh verification'
Assert ($body.Contains('if (freed != 0) throw new Win32Exception')) 'Buffer free errors fail closed'
# Recovery decision tests: exact description plus explicit consent is necessary,
# but neither substitutes for SID/admin/operator/host/key fences.
$description = 'Cage guest SSH operator (standard user)'
Assert (-not (Assert-PeerExistingAccount $member $operatorSid $false 512 'unrelated description' $false)) 'Normal enabled standard account remains reusable'
Assert (Assert-PeerExistingAccount $member $operatorSid $false 514 $description $true) 'Explicit switch permits exact disabled prior-creator description'
Assert-Rejected { Assert-PeerExistingAccount $member $operatorSid $false 514 $description $false } 'Disabled account refused by default even with matching description'
Assert-Rejected { Assert-PeerExistingAccount $member $operatorSid $false 512 $description $true } 'Recovery does not target enabled accounts'
foreach ($badDescription in @($null, '', 'unrelated', $description.ToUpperInvariant(), ($description + ' '), ($description + "`n"))) {
    Assert-Rejected { Assert-PeerExistingAccount $member $operatorSid $false 514 $badDescription $true } 'Recovery description must match exactly, without trimming/case folding'
}
foreach ($resume in @($false, $true)) {
    Assert-Rejected { Assert-PeerExistingAccount $member $operatorSid $true 514 $description $resume } 'Recovery never bypasses administrator membership fence'
    Assert-Rejected { Assert-PeerExistingAccount $member $member $false 514 $description $resume } 'Recovery never bypasses operator SID fence'
}
Assert-Rejected { Assert-PeerExistingAccount $null $operatorSid $false 514 $description $true } 'Missing account SID refuses recovery'
# In-memory ADSI-shaped mock: Put/SetInfo/RefreshCache never touch a real user.
Add-Type -TypeDefinition @'
namespace CageTest {
    public sealed class FlagValue { public int Value; }
    public sealed class Account {
        public FlagValue UserFlags = new FlagValue();
        public int Commits;
        public bool ThrowAfterEnable;
        public bool ThrowOnCommit;
        private int pending;
        public void RefreshCache(string[] names) { }
        public void Put(string name, int value) { pending = value; }
        public void SetInfo() {
            if (ThrowOnCommit) throw new System.InvalidOperationException("mock commit failure");
            UserFlags.Value = pending;
            ++Commits;
            if (ThrowAfterEnable && (pending & 2) == 0) throw new System.InvalidOperationException("mock failure after enable");
        }
    }
}
'@
$user = New-Object CageTest.Account
$user.UserFlags.Value = 0x10202
Set-PeerAccountEnabled $user $true
Assert ($user.UserFlags.Value -eq 0x10200) 'Enable preserves every unrelated account flag'
Set-PeerAccountEnabled $user $false
Assert ($user.UserFlags.Value -eq 0x10202) 'Disable preserves every unrelated account flag'
# Execute the actual source catch block with in-memory accounts and deliberate
# failures. This checks both rollback flags without running any enrollment body.
$rollbackText = $apply[0].CatchClauses[0].Body.Extent.Text
$rollbackHarness = [scriptblock]::Create('param([scriptblock]$Fail) try { & $Fail } catch ' + $rollbackText)
$savedWarningPreference = $WarningPreference
$WarningPreference = 'SilentlyContinue'
try {
    foreach ($created in @($false, $true)) {
        foreach ($resumed in @($false, $true)) {
            $user = New-Object CageTest.Account
            $user.UserFlags.Value = 512
            $failure = ''
            try { & $rollbackHarness { throw 'synthetic later enrollment failure' } } catch { $failure = $_.Exception.Message }
            Assert ($failure -ceq 'synthetic later enrollment failure') 'Rollback preserves original enrollment error'
            Assert (($user.UserFlags.Value -band 2) -eq $(if ($created -or $resumed) { 2 } else { 0 })) 'Actual catch disables only newly created or explicitly resumed accounts'
            Assert ($user.Commits -eq $(if ($created -or $resumed) { 1 } else { 0 })) 'Ordinary reused accounts are never disabled by rollback'
        }
    }
    $created = $false
    $resumed = $true
    $user = New-Object CageTest.Account
    $user.UserFlags.Value = 514
    $user.ThrowAfterEnable = $true
    $failure = ''
    try { & $rollbackHarness { Set-PeerAccountEnabled $user $true } } catch { $failure = $_.Exception.Message }
    Assert ($failure -like '*mock failure after enable*') 'Enable commit failure is reported'
    Assert (($user.UserFlags.Value -band 2) -eq 2 -and $user.Commits -eq 2) 'Resumed account is disabled again when enabling fails after committing'
    $user = New-Object CageTest.Account
    $user.ThrowOnCommit = $true
    $failure = ''
    try { & $rollbackHarness { throw 'original failure with failed rollback' } } catch { $failure = $_.Exception.Message }
    Assert ($failure -ceq 'original failure with failed rollback') 'Critical rollback failure does not conceal original error'
} finally { $WarningPreference = $savedWarningPreference }
$applyCommands = @($apply[0].Body.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))
$enables = @($applyCommands | Where-Object { $_.GetCommandName() -eq 'Set-PeerAccountEnabled' })
Assert ($enables.Count -eq 1 -and $enables[0].Extent.Text -ceq 'Set-PeerAccountEnabled $user $true') 'Single success-only enable operation'
foreach ($name in @('Set-CageSshConfig','Set-Acl','Invoke-CageNative')) {
    $validation = @($applyCommands | Where-Object { $_.GetCommandName() -eq $name })
    Assert ($validation.Count -gt 0 -and $validation[-1].Extent.EndOffset -lt $enables[0].Extent.StartOffset) 'Enable follows key ACL, SSH config/restart and fingerprint validation'
}
Assert ($apply[0].Body.Extent.Text.Contains('$created -or $resumed')) 'Final enable is restricted to created or explicitly resumed accounts'
Assert ($body.Contains("`$user.Put('UserFlags', (0x200 -bor 0x10000 -bor 2))")) 'New accounts are committed disabled'
Write-Host ("PASS: {0} assertions; PowerShell {1}; x64; isolated helpers/mocks/readonly native SID queries; no account/group/key/service writes." -f $count, $PSVersionTable.PSVersion)
Write-Host 'Remaining physical acceptance: ZC_LAPTOP CheckOnly/explicit recovery, real key ACL and sshd validation/restart, account state/rollback, Sysnative relaunch and independent host-key pinning. No live SSH authentication or enrollment was attempted.'
