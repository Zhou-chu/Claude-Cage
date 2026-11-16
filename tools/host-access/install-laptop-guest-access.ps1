# Add only the independently authorized laptop SSH target. Never copy an approval token.
[CmdletBinding()]
param([string]$StatePath='',[string]$CageExe='')
$ErrorActionPreference='Stop'
if(-not $StatePath){$StatePath=Join-Path $PSScriptRoot '.test-output\laptop-maintenance-state.json'}
if(-not $CageExe){$CageExe=Join-Path $PSScriptRoot '..\..\_output\windows-amd64\app\resources\cage.exe'}
$state=[IO.File]::ReadAllText($StatePath)|ConvertFrom-Json
$raw=& (Join-Path $PSScriptRoot 'invoke-laptop-maintenance.ps1') -Action Collect -StatePath $StatePath
$proof=$raw|ConvertFrom-Json;$r=$proof.Result
if($null -eq $r -or $r.Success -ne $true -or $r.SystemSid -cne 'S-1-5-18' -or $r.Machine -cne 'ZC_LAPTOP' -or $r.UserSid -cne $state.ExpectedUserSid -or $r.StandardUser -ne $true -or $r.AccountEnabled -ne $true -or $proof.AccountEnabled -ne $true -or $proof.ServiceState -cne 'Running' -or $proof.ConfigHash -cne $r.CandidateConfigHash){throw 'Verified live maintenance success required before registering guest target.'}
$key=([string]$r.PublicHost.PublicKey -split '\s+')[0..1] -join ' ';$fingerprint=[string]$r.PublicHost.Fingerprint
if($key -cnotmatch '\Assh-ed25519 [A-Za-z0-9+/]+=*\z' -or $fingerprint -cnotmatch '\ASHA256:[A-Za-z0-9+/]+\z'){throw 'Authenticated public host-key evidence missing.'}
$payload=@{key=$key;fingerprint=$fingerprint}
$bootstrap=@'
import base64,hashlib,importlib.util,json,os,pathlib,stat,subprocess,sys,tempfile
p=json.loads(base64.b64decode(sys.stdin.buffer.read(65536)))
if set(p)!={'key','fingerprint'}: raise RuntimeError('unexpected installation input')
parts=p['key'].split()
if len(parts)!=2 or parts[0]!='ssh-ed25519': raise RuntimeError('not an Ed25519 public key')
fp='SHA256:'+base64.b64encode(hashlib.sha256(base64.b64decode(parts[1],validate=True)).digest()).decode().rstrip('=')
if fp!=p['fingerprint']: raise RuntimeError('authenticated public-key fingerprint mismatch')
home=pathlib.Path.home();root=home/'.config/cage-host'
for d in (home/'.config',root):
 st=os.lstat(d)
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o022: raise RuntimeError('unsafe client directory')
module=home/'.local/bin/cage_host.py'
spec=importlib.util.spec_from_file_location('_peer_transport',module);host=importlib.util.module_from_spec(spec);sys.modules[spec.name]=host;spec.loader.exec_module(host)
primary=host.strict_json(host.private_read(root/'config.json'),'primary client configuration')
registry=root/'mcp_targets.json'
try: old=host.private_read(registry)
except host.ClientError:
 if registry.exists() or registry.is_symlink(): raise
 old=None
if old is None: data={'version':1,'targets':{}}
else: data=host.strict_json(old,'existing targets registry')
if set(data)!={'version','targets'} or data['version']!=1 or not isinstance(data['targets'],dict): raise RuntimeError('unknown existing target registry; preserve it')
config_path=root/'laptop.json';known_path=root/'known_hosts_laptop'
if 'laptop' in data['targets'] and host.absolute_path(data['targets']['laptop'])!=str(config_path): raise RuntimeError('unmanaged laptop target; preserve it')
config=dict(primary);config.update(host='100.112.222.42',ssh_user='cageops',ssh_port=22,known_hosts_file=str(known_path),broker_token_file=str(root/'laptop-no-broker-token'))
# No broker token is created/read/shared. Only the existing guest SSH identity path is reused.
outputs={known_path:('100.112.222.42 '+p['key']+'\n').encode(),config_path:json.dumps(config,separators=(',',':')).encode()}
for path,wanted in outputs.items():
 if path.exists() or path.is_symlink():
  if host.private_read(path)!=wanted: raise RuntimeError('existing target file differs; no silent host-key rotation/overwrite')
def store(path,contents):
 fd,name=tempfile.mkstemp(prefix='.peer-install-',dir=root)
 try:
  with os.fdopen(fd,'wb') as f: f.write(contents);f.flush();os.fsync(f.fileno())
  os.chmod(name,0o600);os.replace(name,path)
 finally:
  if os.path.exists(name): os.unlink(name)
for path,wanted in outputs.items(): store(path,wanted)
if old is not None and not (root/'mcp_targets.before-laptop.json').exists(): store(root/'mcp_targets.before-laptop.json',old)
data['targets']['laptop']=str(config_path)
store(registry,json.dumps(data,separators=(',',':')).encode())
loaded=host.load_config(str(config_path))
if loaded.host!='100.112.222.42' or loaded.ssh_user!='cageops': raise RuntimeError('installed target metadata mismatch')
print(json.dumps({'registered_target':'laptop','host':loaded.host,'user':loaded.ssh_user,'host_key_fingerprint':fp,'files_mode':'0600','broker_token_shared':False,'existing_targets_preserved':True}))
'@
$encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($payload|ConvertTo-Json -Compress)))
$encoded | & $CageExe run /usr/bin/python3 -I -c $bootstrap
if($LASTEXITCODE -ne 0){throw 'Guest target registration failed; no automatic authentication retry.'}
