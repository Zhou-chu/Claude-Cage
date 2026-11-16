# Operator-side deployment over the EXISTING trusted administrator SSH connection.
# No private keys/tokens are read, copied or embedded. SYSTEM loads sealed hash-pinned code.
[CmdletBinding()]
param([ValidateSet('Prepare','Probe','Start','Collect','Cleanup')][string]$Action='Prepare',
    [string]$StatePath='')
$ErrorActionPreference='Stop'
if(-not $StatePath){$StatePath=Join-Path $PSScriptRoot '.test-output\laptop-maintenance-state.json'}
$ssh='C:\Program Files\OpenSSH\ssh.exe'
$sshArgs=@('-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ConnectTimeout=10','-o','ConnectionAttempts=1','-o','NumberOfPasswordPrompts=0','-o','IdentitiesOnly=yes','-i','C:\Users\Zhouchu\.ssh\id_ed25519','-l','zhouc','-p','22','100.112.222.42')
function Get-Source([string]$Name){[IO.File]::ReadAllText((Join-Path $PSScriptRoot $Name))}
function Get-Digest([byte[]]$Bytes){$s=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($s.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
function Get-Compressed([string]$Text){$m=New-Object IO.MemoryStream;$g=New-Object IO.Compression.GZipStream($m,[IO.Compression.CompressionMode]::Compress,$true);try{$b=[Text.Encoding]::UTF8.GetBytes($Text);$g.Write($b,0,$b.Length)}finally{$g.Dispose()};try{return ,$m.ToArray()}finally{$m.Dispose()}}
function Invoke-Laptop([string]$Code,$Data){
    $prefix='$ErrorActionPreference=''Stop'';$ProgressPreference=''SilentlyContinue'';[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false);if($env:COMPUTERNAME -cne ''ZC_LAPTOP''){throw ''Wrong computer''};'
    $dataText=if($null -eq $Data){''}else{[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Data|ConvertTo-Json -Depth 10 -Compress)))}
    $executableCode=$Code.Replace('[Console]::In.ReadToEnd().Trim()','$stagedBase64')
    $envelope=@{Data=$dataText;Code=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($executableCode))}
    $inputText=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($envelope|ConvertTo-Json -Compress)))
    $id=[guid]::NewGuid().ToString('N');$base=Join-Path (Join-Path $PSScriptRoot '.test-output') ('ssh-transfer-'+$id)
    $inputPath=$base+'.input';$outputPath=$base+'.output';$errorPath=$base+'.error';$requestPath=$base+'.json'
    [IO.File]::WriteAllText($inputPath,$inputText,(New-Object Text.UTF8Encoding($false)))
    $remotePath='C:\Users\zhouc\AppData\Local\Temp\cage-input-'+$id+'.txt'
    $copyArgs=@('-B','-q','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ConnectTimeout=10','-o','IdentitiesOnly=yes','-i','C:\Users\Zhouchu\.ssh\id_ed25519','-P','22',$inputPath,('zhouc@100.112.222.42:/C:/Users/zhouc/AppData/Local/Temp/cage-input-'+$id+'.txt'))
    & 'C:\Program Files\OpenSSH\scp.exe' @copyArgs
    if($LASTEXITCODE -ne 0){throw 'SFTP staging failed; no remote execution attempted.'}
    $digest=Get-Digest ([IO.File]::ReadAllBytes($inputPath))
    $stage='$stageBytes=[IO.File]::ReadAllBytes('''+$remotePath+''');$sha=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($sha.ComputeHash($stageBytes))).Replace(''-'','''').ToLowerInvariant()}finally{$sha.Dispose()};if($hash -cne '''+$digest+'''){throw ''Staged input hash mismatch''};$envelope=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Text.Encoding]::UTF8.GetString($stageBytes).Trim()))|ConvertFrom-Json;$stagedBase64=[string]$envelope.Data;$executableCode=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($envelope.Code));'
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($prefix+$stage+'& ([scriptblock]::Create($executableCode))'))
    $cmd='powershell.exe -NoLogo -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand '+$encoded
    $request=@{argv=(@($ssh)+$sshArgs+@($cmd));output=$outputPath;error=$errorPath}
    [IO.File]::WriteAllText($requestPath,($request|ConvertTo-Json -Depth 5 -Compress),(New-Object Text.UTF8Encoding($false)))
    $runner=@'
import json,subprocess,sys
r=json.load(open(sys.argv[1],encoding='utf-8-sig'))
try:
 with open(r['output'],'wb') as o,open(r['error'],'wb') as e:
  p=subprocess.run(r['argv'],stdin=subprocess.DEVNULL,stdout=o,stderr=e,timeout=60)
 sys.exit(p.returncode)
except subprocess.TimeoutExpired:
 sys.exit(124)
'@
    & 'D:\Programme Files\Python\python.exe' -I -c $runner $requestPath
    $exit=$LASTEXITCODE
    if($exit -ne 0){$diagnostic=[IO.File]::ReadAllText($errorPath);throw ('SSH command incomplete; do not repeat Start. Exit='+$exit+' '+$diagnostic)}
    [IO.File]::ReadAllText($outputPath).Trim()
}
function Get-TaskLoader([string]$Root,[string]$Leaf,[string]$Digest){
    $loader=@'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or -not [Environment]::Is64BitProcess -or $PSVersionTable.PSVersion.Major -ne 5 -or [Environment]::MachineName -cne 'ZC_LAPTOP'){throw 'SYSTEM loader context refused'}
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
function Test-Seal([string]$p,[bool]$dir){
 $a=Get-Acl -LiteralPath $p;$r=New-Object Security.AccessControl.RawSecurityDescriptor($a.GetSecurityDescriptorBinaryForm(),0)
 if($r.Owner.Value -cne 'S-1-5-32-544' -or -not $a.AreAccessRulesProtected -or $r.DiscretionaryAcl.Count -ne 2){throw 'Loader ACL refused'}
 $seen=@{};foreach($x in $r.DiscretionaryAcl){$f=if($dir){3}else{0};if($x -isnot [Security.AccessControl.CommonAce] -or $x.IsCallback -or $x.AceQualifier -ne 'AccessAllowed' -or [int]$x.AceFlags -ne $f -or $x.AccessMask -ne 2032127 -or $x.SecurityIdentifier.Value -cnotin @('S-1-5-18','S-1-5-32-544') -or $seen.ContainsKey($x.SecurityIdentifier.Value)){throw 'Loader ACE refused'};$seen[$x.SecurityIdentifier.Value]=$true}
}
$root='__ROOT__';$path=Join-Path $root '__LEAF__';$cursor=$path
while($cursor){$i=Get-Item -LiteralPath $cursor -Force;if($i.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Loader reparse refused'};$parent=[IO.Directory]::GetParent($cursor);if($null -eq $parent){break};$cursor=$parent.FullName}
Test-Seal $root $true;Test-Seal $path $false
if((Get-Item -LiteralPath $path).Length -gt 1048576){throw 'Loader payload bound'}
$b=[IO.File]::ReadAllBytes($path);$s=[Security.Cryptography.SHA256]::Create();try{$h=([BitConverter]::ToString($s.ComputeHash($b))).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}
if($h -cne '__DIGEST__'){throw 'Loader hash mismatch'}
$m=New-Object IO.MemoryStream(,$b);$g=New-Object IO.Compression.GZipStream($m,[IO.Compression.CompressionMode]::Decompress);$reader=New-Object IO.StreamReader($g,(New-Object Text.UTF8Encoding($false,$true)))
try{$code=$reader.ReadToEnd();if($code.Length -gt 524288){throw 'Expanded payload bound'}}finally{$reader.Dispose();$m.Dispose()}
& ([scriptblock]::Create($code))
'@
    $loader=$loader.Replace('__ROOT__',$Root).Replace('__LEAF__',$Leaf).Replace('__DIGEST__',$Digest)
    '-NoLogo -NoProfile -NonInteractive -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($loader))
}
$remotePrelude=@'
$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()))|ConvertFrom-Json
$me=[Security.Principal.WindowsIdentity]::GetCurrent();if(-not(New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Existing SSH administrator token required'}
. ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p.Helpers))))
Assert-CageSsvAdministrator
if([IO.Path]::GetDirectoryName($p.Root) -ine (Get-CageSsvRoot) -or [IO.Path]::GetFileName($p.Root) -cnotmatch '\Acage-peer-maintenance-[0-9a-f]{32}\z'){throw 'Invalid deployment root'}
'@
if($Action -eq 'Prepare'){
    if(Test-Path -LiteralPath $StatePath){throw 'Existing deployment state; Collect/Cleanup it first, never blindly prepare again.'}
    $common=Get-Source 'host-access-common.ps1';$ssv=Get-Source 'sshd-system-validation.ps1';$maintenance=Get-Source 'peer-maintenance.ps1'
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput((Get-Source 'enroll-windows-peer.ps1'),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Enrollment definitions parse failed'}
    $peer=(@($ast.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -cne 'Assert-CageEffectiveConfig'}|ForEach-Object{$_.Extent.Text}) -join "`n")
    $defs=$common+"`n"+$ssv+"`n"+$peer+"`n"+$maintenance
    $id=[guid]::NewGuid().ToString('N');$root='C:\ProgramData\ssh\cage-peer-maintenance-'+$id
    $state=[ordered]@{Root=$root;Primary=('CageSshdValidate-'+$id);Guardian=('CageSshdValidate-'+[guid]::NewGuid().ToString('N'));Helpers=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ssv));ExpectedConfigHash='796f518d1f4bb03d775da710c259b518eb770d123133dbd6429ca7e14d3c224b';ExpectedUserSid='S-1-5-21-1048963097-555537751-3702992147-1008';ExpectedGuestKey='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHUyxOBrXtTacXxJ0eTYbp2ijdeeYb1cqHZiiGLLCuI'}
    $probe=$remotePrelude+@'
$c=Get-FileHash -LiteralPath 'C:\ProgramData\ssh\sshd_config';if($c.Hash.ToLowerInvariant() -cne $p.ExpectedConfigHash){throw 'Active config changed from investigated snapshot'}
$u=Get-LocalUser cageops;if($u.Enabled -or $u.SID.Value -cne $p.ExpectedUserSid){throw 'Account snapshot mismatch'}
$key=[IO.File]::ReadAllText('C:\ProgramData\ssh\cageops_authorized_keys').Trim();$lines=@($key -split '\r?\n'|Where-Object{$_ -and -not $_.StartsWith('#')})
if($lines.Count -ne 1 -or -not $lines[0].Contains($p.ExpectedGuestKey) -or -not $lines[0].StartsWith('from="100.65.250.76",no-agent-forwarding,no-port-forwarding,no-X11-forwarding ')){throw 'Expected exact guest key and source restriction not installed'}
[pscustomobject]@{KeyHash=(Get-FileHash -LiteralPath 'C:\ProgramData\ssh\cageops_authorized_keys').Hash.ToLowerInvariant();PowerShell=Get-CageSsvPowerShellExe}|ConvertTo-Json -Compress
'@
    $probeData=(Invoke-Laptop $probe $state)|ConvertFrom-Json
    $state.ExpectedKeyHash=$probeData.KeyHash;$state.Execute=$probeData.PowerShell
    $parameters=@{ExpectedComputerName='ZC_LAPTOP';UserName='cageops';GuestAddress='100.65.250.76';HostAddress='100.112.222.42';ExpectedUserSid=$state.ExpectedUserSid;ExpectedConfigHash=$state.ExpectedConfigHash;ExpectedKeyHash=$state.ExpectedKeyHash;RecoveryDirectory=$root}
    $encodedParams=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($parameters|ConvertTo-Json -Compress)))
    $entry=@'
$argsFixed=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PARAMS__'))|ConvertFrom-Json
$bound=@{};foreach($v in $argsFixed.PSObject.Properties){$bound[$v.Name]=$v.Value}
Assert-CagePmRecovery $bound.RecoveryDirectory
$tracePath=Join-Path $bound.RecoveryDirectory 'trace.log'
$traceStream=New-Object IO.FileStream($tracePath,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::None,(New-CageSsvAcl $false));$traceStream.Dispose()
Assert-CageSsvSealedPath $tracePath $false
Start-Transcript -Path $tracePath -Append -Force | Out-Null
Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class CageMaintenanceAwake { [DllImport("kernel32.dll", SetLastError=true)] public static extern uint SetThreadExecutionState(uint flags); }' | Out-Null
try {
    if([CageMaintenanceAwake]::SetThreadExecutionState([uint32]2147483649) -eq 0){throw 'Unable to request bounded maintenance wakefulness.'}
    Set-PSDebug -Trace 1
    Invoke-CagePeerMaintenance @bound | Out-Null
} finally {
    Set-PSDebug -Off
    [void][CageMaintenanceAwake]::SetThreadExecutionState([uint32]2147483648)
    Stop-Transcript | Out-Null
}
'@
    $entry="`n"+$entry.Replace('__PARAMS__',$encodedParams)
    $worker=Get-Compressed ($defs+$entry)
    $guardian=@'
$root='__ROOT__';$primary='__PRIMARY__';Assert-CagePmRecovery $root
$result=Join-Path $root 'result.json';if(Test-Path -LiteralPath $result){Assert-CageSsvSealedPath $result $false;$r=[IO.File]::ReadAllText($result)|ConvertFrom-Json;if($r.Success -eq $true -and $r.SystemSid -ceq 'S-1-5-18' -and $r.UserSid -ceq '__SID__'){exit 0}}
$original=Join-Path $root 'original.conf';if(-not(Test-Path -LiteralPath $original)){exit 0};Assert-CageSsvSealedPath $original $false
$task=Get-CageSsvTask $primary;if($task){Assert-CageSsvTaskIdentity $task $primary '__EXE__' '__ARGS__';if([string]$task.State -eq 'Running'){Stop-CageSsvTask $primary;$clock=[Diagnostics.Stopwatch]::StartNew();do{$task=Get-CageSsvTask $primary;if($null -eq $task -or [string]$task.State -ne 'Running'){break};Start-Sleep -Milliseconds 100}while($clock.Elapsed.TotalSeconds -lt 15);if($task -and [string]$task.State -eq 'Running'){throw 'Primary termination not proven'}}}
Initialize-PeerNativeMembership;$svc=Get-CagePmService;Stop-CagePmService $svc.ProcessId
$a=Get-CagePmAccount 'cageops';if($a.Sid.Value -cne '__SID__'){throw 'Rollback SID mismatch'};Set-PeerAccountEnabled $a.Handle $false;$a=Get-CagePmAccount 'cageops';if($a.Sid.Value -cne '__SID__' -or -not($a.Flags -band 2)){throw 'Rollback disable not proven'}
if(Test-Path -LiteralPath $result){Assert-CageSsvSealedPath $result $false;$prior=[IO.File]::ReadAllText($result)|ConvertFrom-Json;if($prior.Error -ceq 'NativeTerminationUnproven'){throw 'Native termination remains unproven; keep account disabled and service stopped'}}
$bytes=[IO.File]::ReadAllBytes($original);if((Get-CagePmHash $bytes) -cne '__CONFIG__'){throw 'Rollback original hash mismatch'}
$candidate=Join-Path $root 'candidate.conf';$candidateHash='';if(Test-Path -LiteralPath $candidate){Assert-CageSsvSealedPath $candidate $false;$candidateHash=Get-CagePmHash ([IO.File]::ReadAllBytes($candidate))}
$path=Join-Path (Get-CageSsvRoot) 'sshd_config';Restore-CagePmConfig $path $bytes $candidateHash
$native=Invoke-CageSsvNative $svc.Exe @('-t','-f',$path) 10;if(-not(Test-CageSsvNativeSuccess $native)){throw 'Rollback syntax/termination not proven'}
$a=Get-CagePmAccount 'cageops';if(-not($a.Flags -band 2)){throw 'Disabled state changed'};Start-Service sshd -ErrorAction Stop;$null=Wait-CagePmRunning '100.112.222.42'
Write-CagePmFile $root 'result.json' ([Text.Encoding]::UTF8.GetBytes('{"Success":false,"GuardianRollback":true,"AccountEnabled":false,"ServiceState":"Running"}'))
'@
    $state.PrimaryArgs=Get-TaskLoader $root 'worker.gz' (Get-Digest $worker)
    $guardian=$guardian.Replace('__ROOT__',$root).Replace('__PRIMARY__',$state.Primary).Replace('__SID__',$state.ExpectedUserSid).Replace('__EXE__',$state.Execute).Replace('__ARGS__',$state.PrimaryArgs).Replace('__CONFIG__',$state.ExpectedConfigHash)
    $guardBytes=Get-Compressed ($defs+"`n"+$guardian)
    $state.GuardianArgs=Get-TaskLoader $root 'guardian.gz' (Get-Digest $guardBytes)
    $probeSource=@'
$root='__ROOT__';Assert-CagePmRecovery $root;Initialize-PeerNativeMembership
$null=Assert-CagePmAccount 'cageops' '__SID__' $false
$service=Get-CagePmService;if($service.State -cne 'Running'){throw 'Probe requires original running service'}
Assert-CagePmKey 'C:\ProgramData\ssh\cageops_authorized_keys' '__KEYHASH__' '__SID__'
$networkClock=[Diagnostics.Stopwatch]::StartNew();$listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop);$sshdProcesses=@(Get-CimInstance Win32_Process -Filter "Name='sshd.exe'" -ErrorAction Stop)
if(-not @($listeners|Where-Object{[int]$_.OwningProcess -eq $service.ProcessId}).Count -or $sshdProcesses.Count -lt 1){throw 'Expected sshd listener/process missing from SYSTEM network query'}
$networkQueryMs=$networkClock.ElapsedMilliseconds
$native=Invoke-CageSsvNative $service.Exe @('-t','-f','C:\ProgramData\ssh\sshd_config') 10
if(-not(Test-CageSsvNativeSuccess $native)){throw 'Probe native syntax/termination failed'}
$data=[Text.Encoding]::UTF8.GetBytes(([pscustomobject]@{Success=$true;SystemSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Computer=[Environment]::MachineName;UserDisabled=$true;ServiceState=$service.State;NativeSyntaxExit=$native.ExitCode;NetworkQueryMs=$networkQueryMs;ListenerCount=$listeners.Count;SshdProcessCount=$sshdProcesses.Count}|ConvertTo-Json -Compress))
$path=Join-Path $root 'probe.json';$stream=New-Object IO.FileStream($path,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::None,(New-CageSsvAcl $false));try{$stream.Write($data,0,$data.Length);$stream.Flush($true)}finally{$stream.Dispose()};Assert-CageSsvSealedPath $path $false
'@
    $probeSource=$probeSource.Replace('__ROOT__',$root).Replace('__SID__',$state.ExpectedUserSid).Replace('__KEYHASH__',$state.ExpectedKeyHash)
    $probeBytes=Get-Compressed ($defs+"`n"+$probeSource)
    $state.Probe=('CageSshdValidate-'+[guid]::NewGuid().ToString('N'));$state.ProbeArgs=Get-TaskLoader $root 'probe.gz' (Get-Digest $probeBytes)
    $state.Worker=[Convert]::ToBase64String($worker);$state.GuardianCode=[Convert]::ToBase64String($guardBytes);$state.ProbeCode=[Convert]::ToBase64String($probeBytes)
    $prepare=$remotePrelude+@'
$created=$false;New-CageSsvCapsule $p.Root ([ref]$created)
foreach($item in @(@('worker.gz',$p.Worker),@('guardian.gz',$p.GuardianCode),@('probe.gz',$p.ProbeCode))){$path=Join-Path $p.Root $item[0];$stream=New-Object IO.FileStream($path,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::None,(New-CageSsvAcl $false));try{$b=[Convert]::FromBase64String($item[1]);$stream.Write($b,0,$b.Length);$stream.Flush($true)}finally{$stream.Dispose()};Assert-CageSsvSealedPath $path $false}
[pscustomobject]@{Prepared=$true;Root=$p.Root;NoAccountOrServiceChanges=$true}|ConvertTo-Json -Compress
'@
    $output=Invoke-Laptop $prepare $state
    [IO.File]::WriteAllText($StatePath,($state|ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))
    $output;return
}
if(-not(Test-Path -LiteralPath $StatePath)){throw 'No prepared deployment state.'}
$state=[IO.File]::ReadAllText($StatePath)|ConvertFrom-Json
if($Action -eq 'Probe'){
    $probeCommand=$remotePrelude+@'
Assert-CageSsvSealedPath $p.Root $true
if(Get-CageSsvTask $p.Probe){throw 'Probe task already exists; Collect rather than repeat'}
Register-CageSsvTask $p.Probe $p.Execute $p.ProbeArgs 80
Assert-CageSsvTaskIdentity (Get-CageSsvTask $p.Probe) $p.Probe $p.Execute $p.ProbeArgs
Start-CageSsvTask $p.Probe
[pscustomobject]@{ProbeStarted=$true;NoAccountOrServiceChanges=$true}|ConvertTo-Json -Compress
'@
    Invoke-Laptop $probeCommand $state;return
}
if($Action -eq 'Start'){
    $start=$remotePrelude+@'
Assert-CageSsvSealedPath $p.Root $true
$probePath=Join-Path $p.Root 'probe.json';Assert-CageSsvSealedPath $probePath $false;$probeResult=[IO.File]::ReadAllText($probePath)|ConvertFrom-Json
if($probeResult.Success -ne $true -or $probeResult.SystemSid -cne 'S-1-5-18' -or $probeResult.Computer -cne 'ZC_LAPTOP' -or $probeResult.UserDisabled -ne $true){throw 'Real SYSTEM probe required'}
if((Get-CageSsvTask $p.Primary) -or (Get-CageSsvTask $p.Guardian)){throw 'Task collision; never repeat Start'}
if((Get-FileHash 'C:\ProgramData\ssh\sshd_config').Hash.ToLowerInvariant() -cne $p.ExpectedConfigHash -or (Get-LocalUser cageops).Enabled){throw 'Maintenance snapshot changed'}
# Guardian is armed before starting primary; protected DACL from creation.
$scheduler=New-CageSsvScheduler;$scheduler.Connect();$definition=$scheduler.NewTask(0);$definition.RegistrationInfo.Description='Cage bounded one-time rollback guardian'
$definition.Principal.UserId='S-1-5-18';$definition.Principal.LogonType=5;$definition.Principal.RunLevel=1
$definition.Settings.ExecutionTimeLimit='PT120S';$definition.Settings.MultipleInstances=2;$definition.Settings.StartWhenAvailable=$true;$definition.Settings.DisallowStartIfOnBatteries=$false;$definition.Settings.StopIfGoingOnBatteries=$false
$trigger=$definition.Triggers.Create(1);$trigger.StartBoundary=[DateTime]::UtcNow.AddSeconds(120).ToString('yyyy-MM-ddTHH:mm:ssZ');$trigger.Enabled=$true
$action=$definition.Actions.Create(0);$action.Path=$p.Execute;$action.Arguments=$p.GuardianArgs
$registered=$scheduler.GetFolder('\').RegisterTaskDefinition($p.Guardian,$definition,18,'S-1-5-18',$null,5,'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)');Assert-CageSsvTaskDescriptor ($registered.GetSecurityDescriptor(5))
$primaryDefinition=$scheduler.NewTask(0);$primaryDefinition.RegistrationInfo.Description='Cage approved one-time isolated SSH account maintenance with rollback'
$primaryDefinition.Principal.UserId='S-1-5-18';$primaryDefinition.Principal.LogonType=5;$primaryDefinition.Principal.RunLevel=1
$primaryDefinition.Settings.ExecutionTimeLimit='PT90S';$primaryDefinition.Settings.MultipleInstances=2;$primaryDefinition.Settings.DisallowStartIfOnBatteries=$false;$primaryDefinition.Settings.StopIfGoingOnBatteries=$false
$primaryAction=$primaryDefinition.Actions.Create(0);$primaryAction.Path=$p.Execute;$primaryAction.Arguments=$p.PrimaryArgs
$primaryRegistered=$scheduler.GetFolder('\').RegisterTaskDefinition($p.Primary,$primaryDefinition,18,'S-1-5-18',$null,5,'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)');Assert-CageSsvTaskDescriptor ($primaryRegistered.GetSecurityDescriptor(5))
Assert-CageSsvTaskIdentity (Get-CageSsvTask $p.Primary) $p.Primary $p.Execute $p.PrimaryArgs
Start-CageSsvTask $p.Primary
[pscustomobject]@{Started=$true;Primary=$p.Primary;Guardian=$p.Guardian;ReadOnlyCollectNext=$true}|ConvertTo-Json -Compress
'@
    Invoke-Laptop $start $state;return
}
$collect=$remotePrelude+@'
Assert-CageSsvSealedPath $p.Root $true
$result=$null;$path=Join-Path $p.Root 'result.json';if(Test-Path -LiteralPath $path){Assert-CageSsvSealedPath $path $false;$result=[IO.File]::ReadAllText($path)|ConvertFrom-Json}
$probe=$null;$probePath=Join-Path $p.Root 'probe.json';if(Test-Path -LiteralPath $probePath){Assert-CageSsvSealedPath $probePath $false;$probe=[IO.File]::ReadAllText($probePath)|ConvertFrom-Json}
$tasks=@();foreach($name in @($p.Primary,$p.Guardian,$p.Probe)){$t=Get-CageSsvTask $name;if($t){$info=Get-ScheduledTaskInfo -TaskName $name -TaskPath '\';$tasks+=[pscustomobject]@{Name=$t.TaskName;State=[string]$t.State;LastResult=$info.LastTaskResult}}}
[pscustomobject]@{Result=$result;Probe=$probe;Tasks=$tasks;AccountEnabled=(Get-LocalUser cageops).Enabled;ServiceState=[string](Get-Service sshd).Status;ConfigHash=(Get-FileHash 'C:\ProgramData\ssh\sshd_config').Hash.ToLowerInvariant()}|ConvertTo-Json -Depth 8 -Compress
'@
if($Action -eq 'Collect'){Invoke-Laptop $collect $state;return}
if($Action -eq 'Cleanup'){
    $cleanup=$remotePrelude+@'
Assert-CageSsvSealedPath $p.Root $true
$resultPath=Join-Path $p.Root 'result.json'
if(Test-Path -LiteralPath $resultPath){
 Assert-CageSsvSealedPath $resultPath $false;$r=[IO.File]::ReadAllText($resultPath)|ConvertFrom-Json
 if($r.Success -ne $true -and -not($r.AccountEnabled -eq $false -and $r.ServiceState -eq 'Running')){throw 'Unsettled outcome; retain guardian and all artifacts'}
} elseif((Test-Path -LiteralPath (Join-Path $p.Root 'original.conf')) -or (Get-CageSsvTask $p.Primary) -or (Get-CageSsvTask $p.Guardian)) {throw 'Missing maintenance result; retain all tasks and recovery files'}
foreach($name in @($p.Primary,$p.Guardian,$p.Probe)){$t=Get-CageSsvTask $name;if($t){$argsExpected=if($name -ceq $p.Primary){$p.PrimaryArgs}elseif($name -ceq $p.Guardian){$p.GuardianArgs}else{$p.ProbeArgs};if($t.TaskPath -cne '\' -or @($t.Actions).Count -ne 1 -or $t.Actions[0].Execute -ine $p.Execute -or $t.Actions[0].Arguments -cne $argsExpected -or $t.Principal.UserId -cnotin @('S-1-5-18','SYSTEM','NT AUTHORITY\SYSTEM') -or [string]$t.State -eq 'Running'){throw 'Cleanup task identity/state mismatch'};Unregister-CageSsvTask $name;if(Get-CageSsvTask $name){throw 'Task removal not proven'}}}
[pscustomobject]@{TasksRemoved=$true;RecoveryRetained=$p.Root}|ConvertTo-Json -Compress
'@
    Invoke-Laptop $cleanup $state
}
