# Pure memory tests; no real COM scheduler, tasks, accounts, keys or services.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'sshd-system-validation.ps1')
$count = 0
function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw "ASSERT: $Message" }; $script:count++ }
function Rejected([scriptblock]$Code, [string]$Message) { $rejected=$false; try { & $Code } catch { $rejected=$true }; Assert $rejected $Message }
$sealed = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
foreach ($good in @($sealed,'O:BAG:BAD:PAI(A;;FA;;;BA)(A;;FA;;;SY)')) {
    Assert-CageSsvTaskDescriptor $good
    Assert $true 'Accept exact protected task access facts, harmless order/history allowed'
}
foreach ($bad in @(
    'O:SYG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)',
    'O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)',
    'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)',
    'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;SY)',
    'O:BAG:BAD:P(A;ID;FA;;;SY)(A;;FA;;;BA)',
    'O:BAG:BAD:P(D;;FA;;;SY)(A;;FA;;;BA)',
    'O:BAG:BAD:P(A;;FR;;;SY)(A;;FA;;;BA)',
    'O:BAG:BAD:P(A;;FA;;;SY)',
    'O:BAG:BAD:P',
    'O:BAG:BAD:NO_ACCESS_CONTROL'
)) { Rejected { Assert-CageSsvTaskDescriptor $bad } 'Reject wrong owner, open/inherited/foreign/deny/duplicate/missing/expanded task access' }
$script:actualSddl = $sealed
$script:registered = New-Object PSObject
$script:registered | Add-Member ScriptMethod GetSecurityDescriptor { param($sections) Assert ($sections -eq 5) 'Read owner/DACL only, never SACL'; return $script:actualSddl }
$script:action = [pscustomobject]@{ Path=''; Arguments='' }
$actions = New-Object PSObject
$actions | Add-Member ScriptMethod Create { param($type) Assert ($type -eq 0) 'Fixed EXEC action'; return $script:action }
$script:definition = [pscustomobject]@{
    RegistrationInfo=[pscustomobject]@{Description=''}
    Principal=[pscustomobject]@{UserId='';LogonType=0;RunLevel=0}
    Settings=[pscustomobject]@{ExecutionTimeLimit='';MultipleInstances=0;AllowDemandStart=$false;DisallowStartIfOnBatteries=$true;StopIfGoingOnBatteries=$true;Enabled=$false;Hidden=$true}
    Actions=$actions
}
$script:folder = New-Object PSObject
$script:folder | Add-Member ScriptMethod RegisterTaskDefinition {
    param($name,$definition,$flags,$user,$password,$logon,$sddl)
    $script:request=[pscustomobject]@{Name=$name;Definition=$definition;Flags=$flags;User=$user;Password=$password;Logon=$logon;Sddl=$sddl}
    return $script:registered
}
$script:scheduler = New-Object PSObject
$script:scheduler | Add-Member ScriptMethod Connect { }
$script:scheduler | Add-Member ScriptMethod NewTask { param($flags) Assert ($flags -eq 0) 'New definition only'; return $script:definition }
$script:scheduler | Add-Member ScriptMethod GetFolder { param($path) Assert ($path -ceq '\') 'Only local root task folder'; return $script:folder }
function New-CageSsvScheduler { return $script:scheduler }
$name='CageSshdValidate-0123456789abcdef0123456789abcdef'
Register-CageSsvTask $name 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' '-NoProfile -EncodedCommand FIXED' 30
Assert ($script:request.Flags -eq 18) 'Atomic CREATE only + no automatically appended principal ACE'
Assert ($script:request.Name -ceq $name -and $script:request.User -ceq 'S-1-5-18') 'Exact GUID task, exact SYSTEM identity'
Assert ($null -eq $script:request.Password -and $script:request.Logon -eq 5) 'ServiceAccount without passwords'
Assert ($script:request.Sddl -ceq $sealed) 'Protected SY/BA-only descriptor supplied at creation, no creator SID'
Assert ($script:definition.Principal.LogonType -eq 5 -and $script:definition.Principal.RunLevel -eq 1) 'SYSTEM service/highest principal'
Assert ($script:definition.Settings.ExecutionTimeLimit -ceq 'PT40S' -and $script:definition.Settings.MultipleInstances -eq 2) 'Bounded duration, no parallel duplicate runs'
Assert ($script:definition.Settings.AllowDemandStart -and -not $script:definition.Settings.Hidden) 'Explicit manual start, visible to administrator'
Assert ($script:action.Arguments -ceq '-NoProfile -EncodedCommand FIXED') 'No file script dependency in action'
$script:actualSddl = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)'
Rejected { Register-CageSsvTask $name 'fixed' 'fixed' 30 } 'Refuse unexpectedly permissive descriptor returned by scheduler'
$script:queryMode='found'
function Get-ScheduledTask {
    [CmdletBinding()] param($TaskName,$TaskPath)
    Assert ($TaskName -ceq $name -and $TaskPath -ceq '\') 'Never enumerate unrelated task definitions'
    if ($script:queryMode -eq 'missing') { Write-Error -Message 'isolated not found' -Category ObjectNotFound -ErrorAction Stop }
    if ($script:queryMode -eq 'denied') { throw 'isolated access denied' }
    return [pscustomobject]@{TaskName=$name}
}
Assert ($null -ne (Get-CageSsvTask $name)) 'Exact task found'
$script:queryMode='missing'
Assert ($null -eq (Get-CageSsvTask $name)) 'Only typed not-found is absence'
$script:queryMode='denied'
Rejected { Get-CageSsvTask $name } 'Query error is not treated as task absence'
Write-Host ("PASS: {0} task-security assertions; pure memory/COM and cmdlet substitutes only; no privileged operations." -f $count)
