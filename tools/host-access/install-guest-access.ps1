# Install guest-only client without changing Windows accounts, services or policy.
# Token travels over Cage stdin, never argv/logs/temporary scripts.
[CmdletBinding()]
param(
    [string]$CageExe,
    [string]$UserName = 'cageops',
    [int]$BrokerPort = 8642,
    [string]$BrokerAddress
)
$ErrorActionPreference='Stop'
if (-not [Environment]::Is64BitProcess) {
    $x64=Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $x64)) { throw '64-bit Windows PowerShell is required.' }
    $forward=@{}
    foreach($entry in $PSBoundParameters.GetEnumerator()) { $forward[$entry.Key]=$entry.Value }
    $params=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([Management.Automation.PSSerializer]::Serialize($forward)))
    $path="'"+$PSCommandPath.Replace("'","''")+"'"
    $code='$ProgressPreference=''SilentlyContinue'';$p=[Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('''+$params+'''))); & '+$path+' @p 6>&1 | ForEach-Object {[string]$_}; exit $LASTEXITCODE'
    & $x64 -NoProfile -ExecutionPolicy Bypass -OutputFormat Text -InputFormat Text -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code)))
    exit $LASTEXITCODE
}
if (-not $CageExe) { $CageExe=Join-Path $PSScriptRoot '..\..\_output\windows-amd64\app\resources\cage.exe' }
$localPath=Join-Path $PSScriptRoot 'host-access.local.psd1'
if(-not $BrokerAddress){$BrokerAddress=(Import-PowerShellDataFile -LiteralPath $localPath).BrokerAddress}
if(-not $BrokerAddress){throw 'Specify BrokerAddress or local deployment parameters.'}
# Verify keyscan speaks to the installed local sshd service, independently of guest/tailnet.
$service=Get-CimInstance Win32_Service -Filter "Name='sshd'"
$pidBefore=$service.ProcessId
if(-not (Get-NetTCPConnection -State Listen -LocalPort 22 | Where-Object {$_.OwningProcess -eq $pidBefore})){throw 'Local SSH listener does not belong to the expected sshd service.'}
. (Join-Path $PSScriptRoot 'host-access-common.ps1')
$keyscan=Join-Path (Split-Path (Get-CageSshdExe) -Parent) 'ssh-keyscan.exe'
$saved=$ErrorActionPreference
try{
    $ErrorActionPreference='Continue'
    $scan=@(& $keyscan -T 5 -t ed25519 127.0.0.1 2>$null)
    $scanExit=$LASTEXITCODE
}finally{$ErrorActionPreference=$saved}
$keyLines=@($scan | Where-Object {$_ -match '^127\.0\.0\.1 ssh-ed25519 [A-Za-z0-9+/]+=*(?: .*)?$'})
if($scanExit -ne 0 -or $keyLines.Count -ne 1 -or (Get-CimInstance Win32_Service -Filter "Name='sshd'").ProcessId -ne $pidBefore){throw 'Cannot independently verify local SSH host public key.'}
$hostKey=($keyLines[0] -split ' ')[1..2] -join ' '
$tokenPath=Join-Path $env:ProgramData 'CageBroker\token'
$token=[IO.File]::ReadAllText($tokenPath).Trim()
if($token -notmatch '^[a-f0-9]{64}$'){throw 'Invalid broker token file (contents withheld).'}
$files=@{}
foreach($name in @('cage-host','cage_host.py','cage_host_native.py')) {
    $files[$name]=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot "guest\$name")))
}
$payload=@{
    files=$files
    config=@{
        version=1;host=$BrokerAddress;ssh_user=$UserName;ssh_port=22;broker_port=$BrokerPort
        identity_file='~/.ssh/id_ed25519';known_hosts_file='~/.config/cage-host/known_hosts'
        broker_token_file='~/.config/cage-host/token';connect_timeout=10;broker_timeout=300
    }
    token=$token
    hostkey=($BrokerAddress+' '+$hostKey+"`n")
}
# Only this fixed bootstrap is in argv; the deployment data is standard input.
$bootstrap=@'
import base64,json,os,pathlib,stat,subprocess,sys,tempfile
p=json.loads(base64.b64decode(sys.stdin.buffer.read(262144)))
home=pathlib.Path.home()
def directory(path):
    if path.is_symlink(): raise RuntimeError('symlink directory refused')
    path.mkdir(exist_ok=True)
    st=path.stat()
    if st.st_uid!=os.geteuid() or not stat.S_ISDIR(st.st_mode): raise RuntimeError('unsafe install directory')
    path.chmod(0o700)
for d in (home/'.local',home/'.local/bin',home/'.config',home/'.config/cage-host'): directory(d)
def store(path,data,mode):
    if path.is_symlink(): raise RuntimeError('symlink target refused')
    fd,name=tempfile.mkstemp(prefix='.install-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f: f.write(data)
        os.chmod(name,mode)
        os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)
for name,data in p['files'].items():
    if name not in ('cage-host','cage_host.py','cage_host_native.py'): raise RuntimeError('unexpected install member')
    store(home/'.local/bin'/name,base64.b64decode(data),0o700)
root=home/'.config/cage-host'
store(root/'config.json',json.dumps(p['config']).encode(),0o600)
store(root/'token',p['token'].encode(),0o600)
store(root/'known_hosts',p['hostkey'].encode(),0o600)
subprocess.run(['/usr/bin/python3','-I',str(home/'.local/bin/cage_host_native.py')],check=True)
print('Installed ~/.local/bin/cage-host; private config/token; independently pinned host key.')
'@
$encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($payload|ConvertTo-Json -Compress -Depth 5)))
$encoded | & $CageExe run /usr/bin/python3 -I -c $bootstrap
if($LASTEXITCODE -ne 0){throw 'Guest client installation failed (token not printed).'}
Write-Host 'Guest client installed. No broker execution/approval request was submitted.'
