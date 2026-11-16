# Windows PowerShell 5.1 x64. Dot-source only; importing performs no privileged actions.
# Native sshd token initialization requires SYSTEM even when an administrator is elevated.
# Never change the target account state to make validation succeed.

function Assert-CageSsvPlatform {
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) {
        throw 'Windows PowerShell 5.1 x64 is required.'
    }
}

function Assert-CageSsvAdministrator {
    Assert-CageSsvPlatform
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'An already elevated administrator token is required; no elevation was attempted.'
    }
}

function Assert-CageSsvContext {
    param([string]$ValidateUser, [string]$GuestAddress, [int]$TimeoutSeconds)
    if ($ValidateUser -cnotmatch '\A[a-z][a-z0-9_-]{0,19}\z') { throw 'Invalid validation username.' }
    if ($GuestAddress -cnotmatch '\A100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.(?:0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.(?:0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])\z') {
        throw 'A canonical tailnet IPv4 address is required.'
    }
    if ($TimeoutSeconds -lt 5 -or $TimeoutSeconds -gt 120) { throw 'TimeoutSeconds must be between 5 and 120.' }
}

function Assert-CageSsvContent {
    param([string]$Content)
    if ([string]::IsNullOrWhiteSpace($Content) -or $Content.Length -gt 524288 -or $Content.IndexOf([char]0) -ge 0 -or [Text.Encoding]::UTF8.GetByteCount($Content) -gt 1048576) {
        throw 'Candidate content is empty, oversized or invalid.'
    }
}

function Assert-CageSsvPlainPath {
    param([string]$Path, [switch]$MissingLeaf)
    if ([string]::IsNullOrEmpty($Path) -or $Path -notmatch '\A[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or $Path -match '[\x00-\x1f"*?<>|]') { throw 'Unsafe local path.' }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.TrimEnd('\') -ine $Path.TrimEnd('\')) { throw 'Noncanonical local path.' }
    $root = [IO.Path]::GetPathRoot($full)
    $parts = @($full.Substring($root.Length).TrimEnd('\').Split('\') | Where-Object { $_ -ne '' })
    $paths = @($root)
    $cursor = $root
    foreach ($part in $parts) {
        if ($part -match '[ .]\z') { throw 'Ambiguous path component.' }
        $cursor = Join-Path $cursor $part
        $paths += $cursor
    }
    for ($i = 0; $i -lt $paths.Count; $i++) {
        if ($MissingLeaf -and $i -eq $paths.Count - 1 -and -not (Test-Path -LiteralPath $paths[$i])) { continue }
        $item = Get-Item -LiteralPath $paths[$i] -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse paths are forbidden.' }
        if ($i -lt $paths.Count - 1 -and -not $item.PSIsContainer) { throw 'Invalid path ancestor.' }
    }
    return $full
}

function Get-CageSsvAclFault {
    # Pure semantic comparator. ExpectedOwnerSid is explicit so tests can use their own
    # owner on a real NTFS fixture; production ALWAYS supplies Builtin Administrators.
    param($Actual, [bool]$Directory, [string]$ExpectedOwnerSid)
    if ($null -eq $Actual) { return 'MissingAcl' }
    if ($Actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $ExpectedOwnerSid) { return 'Owner' }
    if (-not $Actual.AreAccessRulesProtected) { return 'Protection' }
    $rules = @($Actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { return 'RuleCount' }
    $expectedFlags = 0
    if ($Directory) { $expectedFlags = 3 }
    $seen = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if ($sid -cne 'S-1-5-18' -and $sid -cne 'S-1-5-32-544') { return 'ForeignSid' }
        if ($seen.ContainsKey($sid)) { return 'DuplicateSid' }
        $seen[$sid] = $true
        if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or [int]$rule.FileSystemRights -ne 2032127 -or [int]$rule.InheritanceFlags -ne $expectedFlags -or [int]$rule.PropagationFlags -ne 0) { return 'Rule' }
    }
    return ''
}

function New-CageSsvAcl {
    param([bool]$Directory)
    if ($Directory) { $acl = New-Object Security.AccessControl.DirectorySecurity }
    else { $acl = New-Object Security.AccessControl.FileSecurity }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::None
    if ($Directory) { $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' }
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        $null = $acl.AddAccessRule($rule)
    }
    return $acl
}

function Assert-CageSsvSealedPath {
    param([string]$Path, [bool]$Directory)
    $null = Assert-CageSsvPlainPath $Path
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ([bool]$item.PSIsContainer -ne $Directory) { throw 'Capsule object type mismatch.' }
    $fault = Get-CageSsvAclFault -Actual (Get-Acl -LiteralPath $Path -ErrorAction Stop) -Directory $Directory -ExpectedOwnerSid 'S-1-5-32-544'
    if ($fault) { throw ('Capsule ACL verification failed: ' + $fault + '.') }
}

function Assert-CageSsvPrivilegedObject {
    param([string]$Path, [switch]$Ancestor)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($trusted -cnotcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'Untrusted path owner.' }
    # On an ancestor, creating unrelated children does not permit replacement of the
    # existing protected child. DELETE_CHILD / DELETE / WRITE_DAC / WRITE_OWNER do.
    $mask = 852310
    if ($Ancestor) { $mask = 852032 }
    foreach ($rule in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and ($trusted -cnotcontains $rule.IdentityReference.Value) -and (([int]$rule.FileSystemRights -band $mask) -ne 0)) { throw 'Unprivileged path mutation rights.' }
    }
}

function Get-CageSsvRoot {
    $common = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    $root = Join-Path $common 'ssh'
    $null = Assert-CageSsvPlainPath $root
    if (-not (Get-Item -LiteralPath $root -Force).PSIsContainer) { throw 'SSH data directory is missing.' }
    Assert-CageSsvPrivilegedObject $root
    $parent = [IO.Directory]::GetParent($root)
    while ($null -ne $parent) {
        Assert-CageSsvPrivilegedObject $parent.FullName -Ancestor
        $parent = $parent.Parent
    }
    return $root
}

function Assert-CageSsvCapsuleName {
    param([string]$Capsule)
    $root = Get-CageSsvRoot
    if ([IO.Path]::GetDirectoryName($Capsule) -ine $root -or [IO.Path]::GetFileName($Capsule) -cnotmatch '\Acage-sshd-validation-[0-9a-f]{32}\z') { throw 'Invalid private capsule location.' }
    Assert-CageSsvSealedPath $Capsule $true
}

function Get-CageSsvServiceExe {
    $services = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'" -ErrorAction Stop)
    if ($services.Count -ne 1) { throw 'Local sshd service was not uniquely resolved.' }
    $command = [string]$services[0].PathName
    if ($command -match '\A"([^"\r\n]+\.exe)"(?:\s+[^\r\n]*)?\z') { return $matches[1] }
    if ($command -match '\A([^\s"\r\n]+\.exe)(?:\s+[^\r\n]*)?\z') { return $matches[1] }
    throw 'Local sshd service executable is ambiguous.'
}

function Assert-CageSsvExe {
    param([string]$SshdExe)
    $full = Assert-CageSsvPlainPath $SshdExe
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Name -ine 'sshd.exe') { throw 'Expected an existing sshd.exe.' }
    $serviceExe = Get-CageSsvServiceExe
    $null = Assert-CageSsvPlainPath $serviceExe
    if ($full -ine $serviceExe) { throw 'Executable is not bound to the local sshd service.' }
}

function Get-CageSsvPowerShellExe {
    $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $exe = Join-Path $windows 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $null = Assert-CageSsvPlainPath $exe
    Assert-CageSsvPrivilegedObject $exe
    $parent = [IO.Directory]::GetParent($exe)
    while ($null -ne $parent) {
        Assert-CageSsvPrivilegedObject $parent.FullName -Ancestor
        $parent = $parent.Parent
    }
    return $exe
}

function New-CageSsvCapsule {
    param([string]$Capsule, [ref]$Created)
    $null = Assert-CageSsvPlainPath $Capsule -MissingLeaf
    if (Test-Path -LiteralPath $Capsule) { throw 'Private capsule collision.' }
    $null = [IO.Directory]::CreateDirectory($Capsule, (New-CageSsvAcl $true))
    $Created.Value = $true
    Assert-CageSsvSealedPath $Capsule $true
}

function Write-CageSsvFile {
    param([string]$Capsule, [string]$Name, [string]$Text)
    Assert-CageSsvCapsuleName $Capsule
    if ($Name -cnotin @('request.json','candidate.conf','result.tmp')) { throw 'Invalid capsule write name.' }
    $path = Join-Path $Capsule $Name
    $null = Assert-CageSsvPlainPath $path -MissingLeaf
    if (Test-Path -LiteralPath $path) { throw 'Capsule output collision.' }
    # The owner must be BA on creation, not the creating human's SID (WRITE_DAC).
    $stream = [IO.File]::Create($path, 4096, [IO.FileOptions]::None, (New-CageSsvAcl $false))
    try {
        $bytes = (New-Object Text.UTF8Encoding($false, $true)).GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    Assert-CageSsvSealedPath $path $false
}

function Read-CageSsvFile {
    param([string]$Capsule, [string]$Name, [int]$MaximumBytes)
    Assert-CageSsvCapsuleName $Capsule
    if ($Name -cnotin @('request.json','candidate.conf','result.json')) { throw 'Invalid capsule read name.' }
    $path = Join-Path $Capsule $Name
    Assert-CageSsvSealedPath $path $false
    if ((Get-Item -LiteralPath $path -Force).Length -gt $MaximumBytes) { throw 'Capsule file exceeds its bound.' }
    return [IO.File]::ReadAllText($path, (New-Object Text.UTF8Encoding($false, $true)))
}

function Get-CageSsvHash {
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-CageSsvFields {
    return @('passwordauthentication','kbdinteractiveauthentication','authenticationmethods','disableforwarding','allowusers','authorizedkeysfile','pubkeyauthentication')
}

function Select-CageSsvEffective {
    param([string[]]$Lines)
    $fields = @(Get-CageSsvFields)
    $found = @{}
    foreach ($line in $Lines) {
        if ($null -eq $line -or $line.Length -gt 2048 -or $line -match '[\x00-\x1f\x7f]') { throw 'Invalid effective-config line.' }
        if ($line -cmatch '\A([a-z]+) (.+)\z' -and $fields -ccontains $matches[1]) {
            $key = $matches[1]
            if ($found.ContainsKey($key)) { throw 'Ambiguous effective-config field.' }
            $found[$key] = $line
        } else { throw 'Unexpected effective-config field.' }
    }
    if ($found.Count -ne 7) { throw 'Missing effective-config fields.' }
    foreach ($field in $fields) { [string]$found[$field] }
}

function Initialize-CageSsvNative {
    if ('CageSshdValidation.Native' -as [type]) { return }
    # Bounded character readers, not ReadToEnd or DataReceived's unbounded line buffer.
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
namespace CageSshdValidation {
 public sealed class NativeResult {
  public int ExitCode = -1;
  public bool TimedOut, Truncated, Stopped;
  public string[] Lines = new string[0], Diagnostics = new string[0];
 }
 public static class Native {
  static readonly Regex Field = new Regex(@"^(passwordauthentication|kbdinteractiveauthentication|authenticationmethods|disableforwarding|allowusers|authorizedkeysfile|pubkeyauthentication) .+$", RegexOptions.CultureInvariant);
  static readonly Regex Diagnostic = new Regex(@"^(?:debug[123]:\s*)?(get_user_token|ga_init|generate_s4u_user_token|LsaLogonUser)(?:[: (\t]|$)", RegexOptions.CultureInvariant);
  static readonly Regex Code = new Regex(@"(?:error|status|code|failed)[^0-9a-f]{0,8}(0x[0-9a-fA-F]{1,8}|[0-9]{1,10})(?:[^0-9a-fA-F]|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
  static void Read(System.IO.StreamReader reader, bool output, NativeResult result, List<string> saved) {
   char[] buffer = new char[1024]; StringBuilder line = new StringBuilder(); int total = 0, n;
   Action emit = delegate {
    string text = line.ToString().TrimEnd('\r'); line.Clear();
    if (output) {
     if (Field.IsMatch(text)) { if (text.Length > 2048 || saved.Count >= 14) result.Truncated = true; else saved.Add(text); }
    } else {
     Match match = Diagnostic.Match(text);
     if (match.Success) {
      if (saved.Count >= 8) { result.Truncated = true; return; }
      string safe = match.Groups[1].Value; Match code = Code.Match(text);
      if (code.Success) safe += " [code=" + code.Groups[1].Value + "]";
      saved.Add(safe);
     }
    }
   };
   while ((n = reader.Read(buffer, 0, buffer.Length)) > 0) {
    total += n; if (total > 1048576) result.Truncated = true;
    for (int i = 0; i < n; i++) {
     if (buffer[i] == '\n') emit();
     else if (line.Length < 4096) line.Append(buffer[i]);
     else result.Truncated = true;
    }
   }
   if (line.Length > 0) emit();
  }
  public static NativeResult Run(string exe, string arguments, int timeoutMilliseconds) {
   NativeResult result = new NativeResult(); List<string> lines = new List<string>(), diagnostics = new List<string>();
   using (Process process = new Process()) {
    process.StartInfo = new ProcessStartInfo(exe, arguments);
    process.StartInfo.UseShellExecute = false; process.StartInfo.CreateNoWindow = true;
    process.StartInfo.RedirectStandardOutput = true; process.StartInfo.RedirectStandardError = true;
    bool launched = false;
    try {
     process.Start(); launched = true;
     Task stdout = Task.Factory.StartNew(delegate { Read(process.StandardOutput, true, result, lines); });
     Task stderr = Task.Factory.StartNew(delegate { Read(process.StandardError, false, result, diagnostics); });
     if (!process.WaitForExit(timeoutMilliseconds)) {
      result.TimedOut = true;
      try { process.Kill(); } catch { }
      result.Stopped = process.WaitForExit(1000);
     } else result.Stopped = true;
     if (result.Stopped) result.ExitCode = process.ExitCode;
     if (!Task.WaitAll(new Task[] { stdout, stderr }, 1000)) { result.Truncated = true; result.Stopped = false; }
     else { result.Lines = lines.ToArray(); result.Diagnostics = diagnostics.ToArray(); }
    } catch {
     result.Truncated = true;
     result.Stopped = !launched;
     if (launched) {
      try { if (!process.HasExited) process.Kill(); result.Stopped = process.WaitForExit(1000); } catch { result.Stopped = false; }
     }
    }
   }
   return result;
  }
 }
}
'@ -ErrorAction Stop
}

function Invoke-CageSsvNative {
    param([string]$SshdExe, [string[]]$Arguments, [int]$TimeoutSeconds)
    Initialize-CageSsvNative
    # All arguments are fixed flags, canonical local paths, or validated ASCII context.
    $quoted = @()
    foreach ($argument in $Arguments) {
        if ($argument -match '["\r\n\x00]' -or $argument.EndsWith('\')) { throw 'Invalid native argument.' }
        $quoted += ('"' + $argument + '"')
    }
    return [CageSshdValidation.Native]::Run($SshdExe, ($quoted -join ' '), ($TimeoutSeconds * 1000))
}

function ConvertTo-CageSsvStatus {
    param($Native)
    return [pscustomobject]@{ ExitCode = [int]$Native.ExitCode; TimedOut = [bool]$Native.TimedOut; Truncated = [bool]$Native.Truncated; Stopped = [bool]$Native.Stopped }
}

function Test-CageSsvNativeSuccess {
    param($Native)
    return ($Native.Stopped -and -not $Native.TimedOut -and -not $Native.Truncated -and $Native.ExitCode -eq 0)
}

function Write-CageSsvResult {
    param([string]$Capsule, $Result)
    Write-CageSsvFile $Capsule 'result.tmp' ($Result | ConvertTo-Json -Depth 6 -Compress)
    $source = Join-Path $Capsule 'result.tmp'
    $target = Join-Path $Capsule 'result.json'
    $null = Assert-CageSsvPlainPath $target -MissingLeaf
    if (Test-Path -LiteralPath $target) { throw 'Result collision.' }
    [IO.File]::Move($source, $target)
    Assert-CageSsvSealedPath $target $false
}

function Invoke-CageSsvWorkerCore {
    # Internal worker implementation. The fixed scheduled action ONLY enters through
    # Invoke-CageSsvWorker, whose actual SYSTEM identity check precedes every read.
    param([string]$Capsule)
    Assert-CageSsvCapsuleName $Capsule
    $request = (Read-CageSsvFile $Capsule 'request.json' 8192) | ConvertFrom-Json -ErrorAction Stop
    $properties = @($request.PSObject.Properties.Name | Sort-Object)
    if (($properties -join ',') -cne 'CandidateHash,GuestAddress,Nonce,Schema,SshdExe,TimeoutSeconds,ValidateUser' -or $request.Schema -isnot [int] -or $request.Schema -ne 1 -or $request.Nonce -isnot [string] -or $request.Nonce -cnotmatch '\A[0-9a-f]{32}\z' -or $request.CandidateHash -isnot [string] -or $request.CandidateHash -cnotmatch '\A[0-9a-f]{64}\z' -or $request.TimeoutSeconds -isnot [int] -or $request.ValidateUser -isnot [string] -or $request.GuestAddress -isnot [string] -or $request.SshdExe -isnot [string]) { throw 'Invalid capsule request.' }
    $result = [pscustomobject]@{ Schema = 1; Nonce = $request.Nonce; SystemSid = 'S-1-5-18'; Success = $false; NativeStopped = $true; Syntax = $null; Effective = $null; Lines = @(); Diagnostics = @(); Error = 'PreflightFailed' }
    try {
        Assert-CageSsvContext $request.ValidateUser $request.GuestAddress $request.TimeoutSeconds
        Assert-CageSsvExe $request.SshdExe
        $candidate = Read-CageSsvFile $Capsule 'candidate.conf' 1048576
        Assert-CageSsvContent $candidate
        if ((Get-CageSsvHash $candidate) -cne $request.CandidateHash) { throw 'Candidate digest mismatch.' }
        $path = Join-Path $Capsule 'candidate.conf'
        $nativeTimeout = [Math]::Max(1, [Math]::Floor($request.TimeoutSeconds / 3))
        $result.Error = 'SyntaxFailed'
        $syntax = Invoke-CageSsvNative $request.SshdExe @('-t','-f',$path) $nativeTimeout
        $result.Syntax = ConvertTo-CageSsvStatus $syntax
        $result.NativeStopped = [bool]$syntax.Stopped
        $result.Diagnostics = @($syntax.Diagnostics)
        if (-not (Test-CageSsvNativeSuccess $syntax)) { throw 'Syntax validation failed.' }
        $result.Error = 'EffectiveFailed'
        $effective = Invoke-CageSsvNative $request.SshdExe @('-ddd','-T','-f',$path,'-C',("user=" + $request.ValidateUser + ',host=cage-guest,addr=' + $request.GuestAddress)) $nativeTimeout
        $result.Effective = ConvertTo-CageSsvStatus $effective
        $result.NativeStopped = [bool]$effective.Stopped
        $result.Diagnostics = @($effective.Diagnostics)
        if (-not (Test-CageSsvNativeSuccess $effective)) { throw 'Effective validation failed.' }
        $result.Error = 'EffectiveFieldsInvalid'
        $result.Lines = @(Select-CageSsvEffective @($effective.Lines))
        $result.Success = $true
        $result.Error = 'None'
    } catch {
        # Never serialize exception text, paths, candidate contents or unfiltered stderr.
        $result.Success = $false
        $result.Lines = @()
    }
    Write-CageSsvResult $Capsule $result
}

function Invoke-CageSsvWorker {
    param([string]$Capsule)
    # Deliberately direct and not parameterized/mocked by production configuration.
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') { throw 'SYSTEM worker refused non-SYSTEM identity before reading inputs.' }
    Assert-CageSsvPlatform
    Invoke-CageSsvWorkerCore $Capsule
}

function Get-CageSsvWorkerCode {
    param([string]$Capsule)
    # Parent has already established the fixed path; quote defensively anyway.
    if ($Capsule -match "['\r\n\x00]") { throw 'Unsafe encoded capsule path.' }
    $names = @('Assert-CageSsvPlatform','Assert-CageSsvContext','Assert-CageSsvContent','Assert-CageSsvPlainPath','Get-CageSsvAclFault','New-CageSsvAcl','Assert-CageSsvSealedPath','Assert-CageSsvPrivilegedObject','Get-CageSsvRoot','Assert-CageSsvCapsuleName','Get-CageSsvServiceExe','Assert-CageSsvExe','Write-CageSsvFile','Read-CageSsvFile','Get-CageSsvHash','Get-CageSsvFields','Select-CageSsvEffective','Initialize-CageSsvNative','Invoke-CageSsvNative','ConvertTo-CageSsvStatus','Test-CageSsvNativeSuccess','Write-CageSsvResult','Invoke-CageSsvWorkerCore','Invoke-CageSsvWorker')
    $definitions = foreach ($name in $names) {
        $command = Get-Command -Name $name -CommandType Function -ErrorAction Stop
        'function ' + $name + " {`r`n" + $command.Definition + "`r`n}"
    }
    return ("$" + "ErrorActionPreference = 'Stop'`r`nSet-StrictMode -Version 2`r`n" + ($definitions -join "`r`n") + "`r`nInvoke-CageSsvWorker -Capsule '" + $Capsule + "'")
}

function Get-CageSsvActionArguments {
    param([string]$Capsule)
    # Gzip only compresses embedded trusted code; no external script is loaded.
    $code = Get-CageSsvWorkerCode $Capsule
    $memory = New-Object IO.MemoryStream
    $gzip = New-Object IO.Compression.GZipStream($memory, [IO.Compression.CompressionMode]::Compress, $true)
    try { $bytes = [Text.Encoding]::UTF8.GetBytes($code); $gzip.Write($bytes, 0, $bytes.Length) }
    finally { $gzip.Dispose() }
    try { $payload = [Convert]::ToBase64String($memory.ToArray()) } finally { $memory.Dispose() }
    $bootstrap = '$ErrorActionPreference=''Stop'';$m=New-Object IO.MemoryStream(,[Convert]::FromBase64String(''' + $payload + '''));$g=New-Object IO.Compression.GZipStream($m,[IO.Compression.CompressionMode]::Decompress);$r=New-Object IO.StreamReader($g,[Text.Encoding]::UTF8);try{$s=$r.ReadToEnd()}finally{$r.Dispose();$m.Dispose()};& ([scriptblock]::Create($s))'
    $arguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
    if ($arguments.Length -gt 30000) { throw 'Embedded action exceeds its safe command-line bound.' }
    return $arguments
}

function Assert-CageSsvTaskName {
    param([string]$TaskName)
    if ($TaskName -cnotmatch '\ACageSshdValidate-[0-9a-f]{32}\z') { throw 'Invalid task identity.' }
}

function Get-CageSsvTask {
    param([string]$TaskName)
    Assert-CageSsvTaskName $TaskName
    # Query only our validated literal GUID name; never enumerate unrelated tasks.
    try { $tasks = @(Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop | Where-Object { $_.TaskName -ceq $TaskName }) }
    catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) { return $null }
        throw
    }
    if ($tasks.Count -gt 1) { throw 'Ambiguous task identity.' }
    if ($tasks.Count -eq 1) { return $tasks[0] }
    return $null
}

function New-CageSsvScheduler {
    return (New-Object -ComObject 'Schedule.Service')
}

function Assert-CageSsvTaskDescriptor {
    param([string]$Sddl)
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    if ($null -eq $raw.Owner -or $raw.Owner.Value -cne 'S-1-5-32-544' -or
        -not ($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -or
        -not ($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -or
        $null -eq $raw.DiscretionaryAcl -or $raw.DiscretionaryAcl.Count -ne 2) { throw 'Task security descriptor is not sealed.' }
    $seen = @{}
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or
            $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed -or
            $ace.AceFlags -ne [Security.AccessControl.AceFlags]::None -or $ace.AccessMask -ne 2032127 -or
            $ace.SecurityIdentifier.Value -cnotin @('S-1-5-18','S-1-5-32-544') -or $seen.ContainsKey($ace.SecurityIdentifier.Value)) {
            throw 'Task contains unexpected permission entries.'
        }
        $seen[$ace.SecurityIdentifier.Value] = $true
    }
}

function Register-CageSsvTask {
    param([string]$TaskName, [string]$Execute, [string]$Arguments, [int]$TimeoutSeconds)
    Assert-CageSsvTaskName $TaskName
    # Register atomically with explicit protected owner/DACL, not a creator-user ACL.
    # TASK_CREATE | TASK_DONT_ADD_PRINCIPAL_ACE; never overwrite an existing task.
    $scheduler = New-CageSsvScheduler
    $scheduler.Connect()
    $definition = $scheduler.NewTask(0)
    $definition.RegistrationInfo.Description = 'Cage one-time read-only sshd policy validation; no account/config/service changes.'
    $definition.Principal.UserId = 'S-1-5-18'
    $definition.Principal.LogonType = 5
    $definition.Principal.RunLevel = 1
    $definition.Settings.ExecutionTimeLimit = 'PT' + ($TimeoutSeconds + 10) + 'S'
    $definition.Settings.MultipleInstances = 2
    $definition.Settings.AllowDemandStart = $true
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $definition.Settings.Enabled = $true
    $definition.Settings.Hidden = $false
    $action = $definition.Actions.Create(0)
    $action.Path = $Execute
    $action.Arguments = $Arguments
    $folder = $scheduler.GetFolder('\')
    $registered = $folder.RegisterTaskDefinition($TaskName, $definition, 18, 'S-1-5-18', $null, 5, 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    Assert-CageSsvTaskDescriptor ($registered.GetSecurityDescriptor(5))
}

function Start-CageSsvTask {
    param([string]$TaskName)
    Assert-CageSsvTaskName $TaskName
    $null = Start-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
}

function Stop-CageSsvTask {
    param([string]$TaskName)
    Assert-CageSsvTaskName $TaskName
    $null = Stop-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
}

function Unregister-CageSsvTask {
    param([string]$TaskName)
    Assert-CageSsvTaskName $TaskName
    $null = Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
}

function Assert-CageSsvTaskIdentity {
    param($Task, [string]$TaskName, [string]$Execute, [string]$Arguments)
    if ($null -eq $Task -or $Task.TaskName -cne $TaskName -or $Task.TaskPath -cne '\' -or @($Task.Actions).Count -ne 1 -or @($Task.Triggers | Where-Object { $null -ne $_ }).Count -ne 0 -or $Task.Actions[0].Execute -ine $Execute -or $Task.Actions[0].Arguments -cne $Arguments -or $Task.Principal.UserId -cnotin @('S-1-5-18','SYSTEM','NT AUTHORITY\SYSTEM') -or [string]$Task.Principal.LogonType -cne 'ServiceAccount' -or [string]$Task.Principal.RunLevel -cne 'Highest') { throw 'Registered task identity mismatch.' }
}

function Get-CageSsvMilliseconds { return [Environment]::TickCount }
function Wait-CageSsvPoll { Start-Sleep -Milliseconds 100 }
function Test-CageSsvElapsed {
    param([int]$Started, [int]$Seconds)
    # TickCount is signed and wraps; unsigned elapsed modulo 2^32 is bounded.
    $elapsed = ([long](Get-CageSsvMilliseconds) - [long]$Started + 4294967296L) % 4294967296L
    return ($elapsed -ge ([long]$Seconds * 1000))
}
function Test-CageSsvResultExists {
    param([string]$Capsule)
    Assert-CageSsvCapsuleName $Capsule
    return (Test-Path -LiteralPath (Join-Path $Capsule 'result.json'))
}

function Wait-CageSsvTask {
    param([string]$TaskName, [string]$Execute, [string]$Arguments, [string]$Capsule, [int]$TimeoutSeconds, [switch]$Stopping)
    $started = Get-CageSsvMilliseconds
    do {
        $task = Get-CageSsvTask $TaskName
        Assert-CageSsvTaskIdentity $task $TaskName $Execute $Arguments
        $state = [string]$task.State
        if ($state -cin @('Ready','Disabled')) {
            if ($Stopping) { return }
            # Initial Ready is not completion. Only an atomic result plus a stopped
            # task proves completion; otherwise keep waiting until the deadline.
            if (Test-CageSsvResultExists $Capsule) { return }
        } elseif ($state -cnotin @('Running','Queued')) { throw 'Task state is uncertain.' }
        if (Test-CageSsvElapsed $started $TimeoutSeconds) { throw 'Task wait timed out.' }
        Wait-CageSsvPoll
    } while ($true)
}

function Assert-CageSsvResult {
    param($Result, [string]$Nonce)
    $names = @($Result.PSObject.Properties.Name | Sort-Object)
    if (($names -join ',') -cne 'Diagnostics,Effective,Error,Lines,NativeStopped,Nonce,Schema,Success,Syntax,SystemSid' -or $Result.Schema -isnot [int] -or $Result.Schema -ne 1 -or $Result.Nonce -isnot [string] -or $Result.Nonce -cne $Nonce -or $Result.SystemSid -isnot [string] -or $Result.SystemSid -cne 'S-1-5-18' -or $Result.Success -isnot [bool] -or $Result.NativeStopped -isnot [bool] -or $Result.Error -isnot [string] -or $Result.Error -cnotin @('None','PreflightFailed','SyntaxFailed','EffectiveFailed','EffectiveFieldsInvalid')) { throw 'Invalid SYSTEM result envelope.' }
    if ($null -eq $Result.Diagnostics -or $Result.Diagnostics -is [string] -or @($Result.Diagnostics).Count -gt 8) { throw 'Invalid SYSTEM diagnostics.' }
    foreach ($line in @($Result.Diagnostics)) {
        if ($line -isnot [string] -or $line -cnotmatch '\A(get_user_token|ga_init|generate_s4u_user_token|LsaLogonUser)(?: \[code=(?:0x[0-9a-fA-F]{1,8}|[0-9]{1,10})\])?\z') { throw 'Invalid SYSTEM diagnostics.' }
    }
    foreach ($status in @($Result.Syntax,$Result.Effective)) {
        if ($null -eq $status) { continue }
        if ((@($status.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'ExitCode,Stopped,TimedOut,Truncated' -or $status.ExitCode -isnot [int] -or $status.Stopped -isnot [bool] -or $status.TimedOut -isnot [bool] -or $status.Truncated -isnot [bool]) { throw 'Invalid native status.' }
    }
    if (-not $Result.NativeStopped -or @(@($Result.Syntax,$Result.Effective) | Where-Object { $null -ne $_ -and -not $_.Stopped }).Count -gt 0) { throw 'Native process termination is unproven.' }
    if (-not $Result.Success) {
        $detail = ''
        if (@($Result.Diagnostics).Count -gt 0) { $detail = ' (' + (@($Result.Diagnostics) -join '; ') + ')' }
        if ($Result.Error -ceq 'None') { throw 'Inconsistent native failure proof.' }
        $safeFailure = New-Object InvalidOperationException('SYSTEM sshd preflight ' + $Result.Error + $detail + '. No account state was changed.')
        $safeFailure.Data['CageSsvValidatedNativeFailure'] = $true
        throw $safeFailure
    }
    if ($Result.Error -cne 'None' -or $null -eq $Result.Syntax -or $null -eq $Result.Effective -or -not (Test-CageSsvNativeSuccess $Result.Syntax) -or -not (Test-CageSsvNativeSuccess $Result.Effective) -or $null -eq $Result.Lines -or $Result.Lines -is [string]) { throw 'Inconsistent native success proof.' }
    return @(Select-CageSsvEffective @($Result.Lines))
}

function Remove-CageSsvCapsule {
    param([string]$Capsule)
    Assert-CageSsvCapsuleName $Capsule
    $children = @(Get-ChildItem -LiteralPath $Capsule -Force -ErrorAction Stop)
    foreach ($child in $children) {
        if ($child.Name -cnotin @('request.json','candidate.conf','result.tmp','result.json') -or $child.PSIsContainer) { throw 'Unexpected capsule child; retained for inspection.' }
        Assert-CageSsvSealedPath $child.FullName $false
    }
    # No recursion or wildcards. Check every exact child before deleting any child.
    foreach ($child in $children) { [IO.File]::Delete($child.FullName) }
    Assert-CageSsvSealedPath $Capsule $true
    [IO.Directory]::Delete($Capsule, $false)
    if (Test-Path -LiteralPath $Capsule) { throw 'Capsule cleanup incomplete.' }
}

function Invoke-CageSshdSystemValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$SshdExe,
        [Parameter(Mandatory=$true)][string]$Content,
        [Parameter(Mandatory=$true)][string]$ValidateUser,
        [Parameter(Mandatory=$true)][string]$GuestAddress,
        [ValidateRange(5,120)][int]$TimeoutSeconds = 30
    )
    $ErrorActionPreference = 'Stop'
    try {
        Assert-CageSsvAdministrator
        Assert-CageSsvContext $ValidateUser $GuestAddress $TimeoutSeconds
        Assert-CageSsvContent $Content
        Assert-CageSsvExe $SshdExe
        $root = Get-CageSsvRoot
        $execute = Get-CageSsvPowerShellExe
    } catch { throw 'SYSTEM sshd validation prerequisites failed: require an already elevated Windows PowerShell 5.1 x64 administrator, canonical inputs, trusted local sshd service executable and protected SSH data directory. No changes were made.' }
    $id = [guid]::NewGuid().ToString('N')
    $taskName = 'CageSshdValidate-' + $id
    $capsule = Join-Path $root ('cage-sshd-validation-' + $id)
    $nonce = [guid]::NewGuid().ToString('N')
    try {
        if ($null -ne (Get-CageSsvTask $taskName)) { throw 'Generated task name collision.' }
        $arguments = Get-CageSsvActionArguments $capsule
    } catch { throw 'Unable to reserve a unique validation task and bounded encoded action; no changes were made.' }
    $created = $false
    $taskMayExist = $false
    $startAttempted = $false
    $resultReceived = $false
    $retain = $false
    $failure = ''
    $cleanupFailure = $false
    $lines = @()
    try {
        New-CageSsvCapsule $capsule ([ref]$created)
        Write-CageSsvFile $capsule 'candidate.conf' $Content
        $request = [pscustomobject]@{ Schema = 1; Nonce = $nonce; CandidateHash = Get-CageSsvHash $Content; SshdExe = $SshdExe; ValidateUser = $ValidateUser; GuestAddress = $GuestAddress; TimeoutSeconds = $TimeoutSeconds }
        Write-CageSsvFile $capsule 'request.json' ($request | ConvertTo-Json -Compress)
        $taskMayExist = $true
        Register-CageSsvTask $taskName $execute $arguments $TimeoutSeconds
        Assert-CageSsvTaskIdentity (Get-CageSsvTask $taskName) $taskName $execute $arguments
        $startAttempted = $true
        Start-CageSsvTask $taskName
        Wait-CageSsvTask $taskName $execute $arguments $capsule $TimeoutSeconds
        $result = (Read-CageSsvFile $capsule 'result.json' 32768) | ConvertFrom-Json -ErrorAction Stop
        if ($result.NativeStopped -isnot [bool] -or -not $result.NativeStopped) { $retain = $true }
        foreach ($status in @($result.Syntax,$result.Effective)) { if ($null -ne $status -and ($status.Stopped -isnot [bool] -or -not $status.Stopped)) { $retain = $true } }
        $lines = @(Assert-CageSsvResult $result $nonce)
        $resultReceived = $true
    } catch {
        # Only the validated result validator emits relevant sanitized native detail.
        if ($_.Exception.Data['CageSsvValidatedNativeFailure'] -eq $true) {
            $failure = $_.Exception.Message
            $resultReceived = $true
        } else { $failure = 'SYSTEM sshd validation failed closed; no account state was changed.' }
    } finally {
        if ($taskMayExist) {
            try {
                $task = Get-CageSsvTask $taskName
                if ($null -ne $task) {
                    Assert-CageSsvTaskIdentity $task $taskName $execute $arguments
                    # Stop even an initial Ready after an uncertain Start request.
                    if (($startAttempted -and -not $resultReceived) -or [string]$task.State -cnotin @('Ready','Disabled')) {
                        Stop-CageSsvTask $taskName
                        Wait-CageSsvTask $taskName $execute $arguments $capsule 5 -Stopping
                        # A prior result cannot prove exit of a newly live instance.
                        $retain = $true
                    }
                    if ($startAttempted -and -not $resultReceived) { $retain = $true }
                    if (-not $retain) {
                        Unregister-CageSsvTask $taskName
                        if ($null -ne (Get-CageSsvTask $taskName)) { throw 'Task cleanup incomplete.' }
                    }
                } elseif ($startAttempted -and -not $resultReceived) { $retain = $true }
            } catch { $retain = $true; $cleanupFailure = $true }
        }
        if ($created -and -not $retain) {
            try { Remove-CageSsvCapsule $capsule } catch { $retain = $true; $cleanupFailure = $true }
        }
    }
    if ($retain -or $cleanupFailure) {
        throw ('SYSTEM sshd validation has unproven termination or incomplete cleanup. Retained protected artifacts; inspect only task "' + $taskName + '" and capsule "' + $capsule + '" manually. No success is reported.')
    }
    if ($failure) { throw $failure }
    return $lines
}
