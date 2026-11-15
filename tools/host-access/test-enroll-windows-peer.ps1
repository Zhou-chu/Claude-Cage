# Nonprivileged PS 5.1 tests: AST, pure validators, wrong-host fence only.
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
Assert ($errors.Count -eq 0) 'Enrollment source parses'
$selfTokens = $null
$selfErrors = $null
$null = [Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$selfTokens, [ref]$selfErrors)
Assert ($selfErrors.Count -eq 0) 'Test source parses'
$bytes = [IO.File]::ReadAllBytes($source)
Assert (@($bytes | Where-Object { $_ -gt 127 }).Count -eq 0) 'Enrollment source is ASCII'
$names = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
Assert (($names -join ',') -ceq 'GuestPublicKey,GuestAddress,HostAddress,ExpectedComputerName,UserName,CheckOnly') 'Exact six declared parameters'
$metadata = New-Object Management.Automation.CommandMetadata (Get-Command -Name $source)
foreach ($name in @('GuestPublicKey','GuestAddress','HostAddress','ExpectedComputerName')) {
    Assert $metadata.Parameters[$name].ParameterSets['__AllParameterSets'].IsMandatory "$name is mandatory"
}
Assert ($ast.ParamBlock.Parameters[4].DefaultValue.Value -ceq 'cageops') 'Default dedicated user'
Assert ($metadata.Parameters['CheckOnly'].ParameterType -eq [Management.Automation.SwitchParameter]) 'CheckOnly switch type'
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
    $message = ''
    try { & $source @arguments -CheckOnly:$check } catch { $message = $_.Exception.Message }
    Assert ($message -like 'Computer-name fence failed.*') 'Wrong host rejected before key validation/import in apply and CheckOnly'
}
Assert-Rejected { & $source @arguments -UserName 'bad user' } 'Reject unsafe user parameter before execution'
Assert-Rejected { & $source -GuestPublicKey x -GuestAddress x -HostAddress x -ExpectedComputerName 'bad/name' } 'Reject unsafe expected name'
# Load only selected pure function ASTs; never execute the enrollment body.
foreach ($name in @('Assert-PeerAddress','Assert-PeerPublicKey','Assert-PeerPlainPath')) {
    $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    Assert ($null -ne $definition) "Pure function $name exists"
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
# Parser-only CheckOnly coverage: its direct branch has reporting and return
# only; all apply-side mutations are in the subsequent top-level try block.
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
# Exercise the relaunch serialization against an inert binding target only.
function Test-SyntheticForward {
    param([string]$GuestPublicKey, [string]$GuestAddress, [string]$HostAddress, [string]$ExpectedComputerName, [string]$UserName, [switch]$CheckOnly)
    return [pscustomobject]@{ Bound = $PSBoundParameters; Check = [bool]$CheckOnly }
}
foreach ($check in @($false, $true)) {
    $forward = @{
        GuestPublicKey = ($key + " synthetic 'quoted' comment")
        GuestAddress = '100.64.0.10'
        HostAddress = '100.64.0.11'
        ExpectedComputerName = 'CAGE-SYNTHETIC'
        UserName = 'synthetic_ops'
        CheckOnly = [Management.Automation.SwitchParameter]$check
    }
    $serialized = [Management.Automation.PSSerializer]::Serialize($forward)
    $encodedParams = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($serialized))
    $roundTrip = [Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedParams)))
    $result = Test-SyntheticForward @roundTrip
    Assert ($result.Bound.Count -eq 6) 'All six bound relaunch parameters survive serialization'
    Assert ($result.Check -eq $check) 'Explicit switch value survives relaunch serialization'
    foreach ($name in @('GuestPublicKey','GuestAddress','HostAddress','ExpectedComputerName','UserName')) {
        Assert ($result.Bound[$name] -ceq $forward[$name]) 'Relaunch preserves exact string value'
    }
}
Write-Host ("PASS: {0} assertions; PowerShell {1}; AST/pure helpers/wrong-host fence; no business mutations." -f $count, $PSVersionTable.PSVersion)
Write-Host 'Remaining physical acceptance: correct laptop CheckOnly/apply, existing sshd effective policy/restart, ADSI groups, key ACL, failure cleanup, Sysnative relaunch and independent host-key pinning. No live SSH authentication was attempted.'
