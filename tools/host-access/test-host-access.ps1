# Standalone, non-admin PS 5.1 tests. No services/accounts/firewall are changed.
[CmdletBinding()]
param([string]$SshdExe)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'host-access-common.ps1')
if (-not $SshdExe) { $SshdExe = Get-CageSshdExe }
$count=0
function Assert([bool]$Condition,[string]$Message) {
    if(-not $Condition) {throw "ASSERT: $Message"}
    $script:count++
}
$reader=Get-CageSid 'S-1-5-21-1-2-3-1001'
$acl=New-CageKeyAcl $reader
Assert ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544') 'SID owner conversion'
Assert $acl.AreAccessRulesProtected 'No inherited key ACL'
$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
Assert ($rules.Count -eq 3) 'Exact key ACL contains three principals'
$readRule=@($rules | Where-Object {$_.IdentityReference.Value -eq $reader.Value})
Assert (($readRule[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -eq 0) 'Guest cannot write key file'
$rootAcl=New-CageBrokerAcl ([Security.Principal.WindowsIdentity]::GetCurrent().User)
Assert $rootAcl.AreAccessRulesProtected 'Broker inheritance blocked'
Assert ($rootAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544') 'Broker owner SID'
$original=@'
Port 22
AuthorizedKeysFile .ssh/authorized_keys
Subsystem sftp sftp-server.exe
AllowUsers existingoperator
Match Group administrators
    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys

# Cage: dedicated standard user, fixed tailnet source only
AllowUsers cageops@100.64.0.10 oldoperator
'@
$result=New-CageSshConfig $original 'cageops' '100.64.0.10'
Assert ($result.Contains('AllowUsers existingoperator')) 'Unrelated global policy preserved'
Assert ($result.IndexOf('Match User cageops') -lt $result.IndexOf('Match Group administrators')) 'Dedicated rule precedes broad Match'
Assert (-not $result.Contains('oldoperator')) 'Exact legacy managed policy removed'
Assert ($result.Contains('PasswordAuthentication no')) 'Password login disabled'
Assert ($result -eq (New-CageSshConfig $result 'cageops' '100.64.0.10')) 'Config update is idempotent'
$revoked=Remove-CageSshBlock $result 'cageops'
Assert (-not $revoked.Contains('Match User cageops')) 'Revoke removes only own Match'
Assert ($revoked.Contains('AllowUsers existingoperator')) 'Revoke preserves unrelated allowlist'
foreach($bad in @('192.168.1.1','100.128.0.1','100.63.255.255',"100.64.0.10`nMatch all")) {
    $rejected=$false
    try{$null=New-CageSshConfig '' 'cageops' $bad}catch{$rejected=$true}
    Assert $rejected 'Reject invalid or non-tailnet source'
}
$startMatch="Match Group administrators`r`n AuthorizedKeysFile admin_keys`r`n"
Assert ((New-CageSshConfig $startMatch 'cageops' '100.64.0.10').Contains('Match Group administrators')) 'Match at character zero preserved'
$legacyKey=@'
Port 22
# Cage: absolute key path, does not depend on profile resolution
Match User cageops
    AuthorizedKeysFile __PROGRAMDATA__/ssh/cageops_authorized_keys
Match Group administrators
    AuthorizedKeysFile admin_keys
'@
Assert (@([regex]::Matches((New-CageSshConfig $legacyKey 'cageops' '100.64.0.10'),'Match User cageops')).Count -eq 1) 'Migrate earlier key block once'
$unknown=$false
try{$null=New-CageSshConfig "Match User cageops`n PasswordAuthentication yes" 'cageops' '100.64.0.10'}catch{$unknown=$true}
Assert $unknown 'Do not overwrite unmanaged user rules'
# Verify the exact native sshd parser/effective values without reading real host private keys.
if(-not(Test-Path -LiteralPath $SshdExe)){throw 'Provide -SshdExe for real validation.'}
$outRoot=Join-Path $PSScriptRoot '.test-output'
New-Item -ItemType Directory -Path $outRoot -Force | Out-Null
$dir=Join-Path $outRoot ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
$key=Join-Path $dir 'temporary_host_key'
$keygen=Join-Path (Split-Path $SshdExe -Parent) 'ssh-keygen.exe'
$info=New-Object Diagnostics.ProcessStartInfo
$info.FileName=$keygen
$info.Arguments='-q -t ed25519 -N "" -f "'+$key+'"'
$info.UseShellExecute=$false
$info.CreateNoWindow=$true
$p=[Diagnostics.Process]::Start($info)
if(-not $p.WaitForExit(10000)){$p.Kill();throw 'ssh-keygen timed out'}
Assert ($p.ExitCode -eq 0) 'Generated isolated test host key'
$testConfig=New-CageSshConfig "AuthorizedKeysFile .ssh/authorized_keys`r`nMatch Group administrators`r`n AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys`r`n" 'cageops' '100.64.0.10'
$config=Join-Path $dir 'sshd_config'
[IO.File]::WriteAllText($config,$testConfig,(New-Object Text.UTF8Encoding($false)))
& $SshdExe -t -f $config -h $key
Assert ($LASTEXITCODE -eq 0) 'Native sshd -t accepts managed config'
$effective=@(& $SshdExe -T -f $config -h $key -C 'user=cageops,host=guest,addr=100.64.0.10')
Assert ($LASTEXITCODE -eq 0) 'Native sshd -T expands dedicated user context'
Assert ($effective -contains 'passwordauthentication no') 'Effective password auth disabled'
Assert ($effective -contains 'kbdinteractiveauthentication no') 'Effective interactive auth disabled'
Assert ($effective -contains 'authenticationmethods publickey') 'Effective public key only'
Assert ($effective -contains 'allowusers cageops@100.64.0.10') 'Effective source-limited AllowUsers'
Assert ($effective -contains 'disableforwarding yes') 'Effective forwarding disabled'
Assert ([bool]($effective -match '^authorizedkeysfile .*ssh/cageops_authorized_keys$')) 'Effective absolute key path'
Assert-CageEffectiveConfig $effective 'cageops' '100.64.0.10'
$conflict = $false
try { Assert-CageEffectiveConfig @('passwordauthentication yes') 'cageops' '100.64.0.10' } catch { $conflict = $true }
Assert $conflict 'Fail closed when existing policy overrides the intended rules'
$other=@(& $SshdExe -T -f $config -h $key -C 'user=unrelatedoperator,host=guest,addr=100.64.0.11')
Assert ($LASTEXITCODE -eq 0) 'Native sshd expands unrelated user context'
Assert ($other -contains 'passwordauthentication yes') 'Unrelated user auth unchanged'
# Failure-injection tests: only local test files and mocked commands/services.
$fixture=Join-Path $dir 'rollback_config'
$bytes=[Text.Encoding]::UTF8.GetBytes("# original bytes`r`nPort 22`r`n")
[IO.File]::WriteAllBytes($fixture,$bytes)
$before=[Convert]::ToBase64String($bytes)
function Invoke-CageNative { param([string]$Exe,[string[]]$NativeArguments) if($script:rejectCandidate){throw 'injected candidate failure'} }
function Restart-Service { [CmdletBinding()]param([string]$Name) throw 'injected restart failure, no service touched' }
$script:rejectCandidate=$false
$failed=$false
try { Set-CageSshConfig $fixture "Port 2222`r`n" $SshdExe } catch { $failed=$true }
Assert $failed 'Restart failure is surfaced'
Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes($fixture)) -eq $before) 'Restart failure restores exact original bytes'
$script:rejectCandidate=$true
$failed=$false
try { Set-CageSshConfig $fixture "Port 2223`r`n" $SshdExe } catch { $failed=$true }
Assert $failed 'Candidate validation failure is surfaced'
Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes($fixture)) -eq $before) 'Candidate validation failure never changes live config'
Write-Host ("PASS: {0} assertions; native sshd and failure-injection tests; no admin changes." -f $count)
