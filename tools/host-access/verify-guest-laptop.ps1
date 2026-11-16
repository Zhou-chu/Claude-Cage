# Read-only real JSON-RPC acceptance through a fresh copy of the installed guest MCP server.
[CmdletBinding()]
param([string]$StatePath='',[string]$CageExe='')
$ErrorActionPreference='Stop'
if(-not $StatePath){$StatePath=Join-Path $PSScriptRoot '.test-output\laptop-maintenance-awake-state.json'}
if(-not $CageExe){$CageExe=Join-Path $PSScriptRoot '..\..\_output\windows-amd64\app\resources\cage.exe'}
$state=[IO.File]::ReadAllText($StatePath)|ConvertFrom-Json
$identityCommand=@'
$i=[Security.Principal.WindowsIdentity]::GetCurrent()
$p=New-Object Security.Principal.WindowsPrincipal($i)
[pscustomobject]@{Computer=$env:COMPUTERNAME;User=$i.Name;Sid=$i.User.Value;Admin=$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);System=$i.IsSystem}|ConvertTo-Json -Compress
'@
$payload=@{sid=$state.ExpectedUserSid;identityCommand=$identityCommand}
$bootstrap=@'
import base64,json,pathlib,subprocess,sys
p=json.loads(base64.b64decode(sys.stdin.buffer.read(65536)))
server=pathlib.Path.home()/'.local/bin/cage_host_mcp.py'
def rpc(i,method,params): return {'jsonrpc':'2.0','id':i,'method':method,'params':params}
def call(i,name,args): return rpc(i,'tools/call',{'name':name,'arguments':args})
requests=[rpc(1,'initialize',{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'cage-peer-acceptance','version':'1'}}),{'jsonrpc':'2.0','method':'notifications/initialized','params':{}},rpc(2,'tools/list',{}),call(3,'cage_ssh_targets',{}),call(4,'cage_ssh_execute',{'target':'laptop','shell':'powershell','command':p['identityCommand'],'timeout_seconds':20}),call(5,'cage_ssh_execute',{'target':'laptop','shell':'powershell','command':'exit 19','timeout_seconds':20}),call(6,'cage_ssh_execute',{'target':'windows-host','shell':'powershell','command':p['identityCommand'],'timeout_seconds':20}),call(7,'cage_ssh_execute',{'target':'unregistered-proof-target','shell':'powershell','command':'Write-Output SHOULD_NOT_EXECUTE','timeout_seconds':20})]
wire=b''.join((json.dumps(x,separators=(',',':'))+'\n').encode() for x in requests)
result=subprocess.run(['/usr/bin/python3','-I',str(server)],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=100)
if result.returncode!=0: raise RuntimeError('MCP server did not exit cleanly')
responses=[json.loads(x) for x in result.stdout.splitlines() if x.strip()]
by_id={x['id']:x for x in responses}
if len(responses)!=7 or set(by_id)!=set(range(1,8)): raise RuntimeError('MCP response framing/id mismatch')
if any('error' in x for x in responses): raise RuntimeError('MCP protocol error')
names={t['name'] for t in by_id[2]['result']['tools']}
if not {'cage_ssh_targets','cage_ssh_execute'}<=names: raise RuntimeError('SSH tools missing')
def tool(i):
 envelope=by_id[i]['result']
 return json.loads(envelope['content'][0]['text']),bool(envelope.get('isError',False))
targets,bad=tool(3)
if bad or not {'laptop','windows-host'}<={x['alias'] for x in targets['targets']}: raise RuntimeError('authorized target registry incomplete')
laptop,bad=tool(4)
if bad or laptop['execution_outcome']!='succeeded' or laptop['exit_code']!=0: raise RuntimeError('laptop MCP execution failed: '+json.dumps(laptop))
identity=json.loads(laptop['stdout'].strip())
if identity['Computer']!='ZC_LAPTOP' or identity['Sid']!=p['sid'] or identity['Admin'] or identity['System']: raise RuntimeError('laptop identity/standard-user proof mismatch')
exit_test,bad=tool(5)
if not bad or exit_test['exit_code']!=19 or exit_test['execution_outcome']!='failed': raise RuntimeError('nonzero remote status was not preserved')
desktop,bad=tool(6)
if bad or desktop['exit_code']!=0 or desktop['execution_outcome']!='succeeded': raise RuntimeError('existing desktop target regression: '+json.dumps(desktop))
desktop_identity=json.loads(desktop['stdout'].strip())
if desktop_identity['Computer']!='DESKTOP-UQ2EMAP' or desktop_identity['Admin'] or desktop_identity['System']: raise RuntimeError('desktop standard-user identity mismatch')
rejected,bad=tool(7)
if not bad or rejected['execution_outcome']!='not_started' or rejected['error']['code']!='tool_rejected': raise RuntimeError('unregistered target was not rejected before execution')
print(json.dumps({'mcp_protocol':'passed','authorized_targets':sorted(x['alias'] for x in targets['targets']),'laptop_identity':identity,'remote_exit_19_preserved':True,'unregistered_target_rejected_before_execution':True,'existing_desktop_target':'passed','desktop_identity':desktop_identity,'fresh_stdio_server':True}))
'@
$encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($payload|ConvertTo-Json -Compress)))
$encoded | & $CageExe run /usr/bin/python3 -I -c $bootstrap
if($LASTEXITCODE -ne 0){throw 'Read-only guest MCP acceptance failed; no authentication retry or state-changing command was used.'}
