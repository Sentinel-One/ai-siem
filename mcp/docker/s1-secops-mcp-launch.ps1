<#
.SYNOPSIS
  Run a bundled MCP server from the sentinelone/secops-mcps image with
  credentials from Windows Credential Manager.

.DESCRIPTION
  Reads Generic credentials written by `s1-secops-mcp setup` (or by this
  script's `setup` command) and hands them to the container over stdin
  (entrypoint S1_SECRETS_STDIN=1). Secrets never appear on a command line, in
  the MCP client config, or in `docker inspect`.

  Credential naming matches @napi-rs/keyring (keyring-rs) on Windows:
    TargetName = "<profile>:<NAME>.sentinelone-mcp", UserName = "<profile>:<NAME>",
    Type = CRED_TYPE_GENERIC, blob = UTF-16LE.

  Usage:
    s1-secops-mcp-launch.ps1 [-Image IMG] [-Profile P] <server> [server args...]
      server: s1-secops-mcp | purple-mcp | virustotal-mcp
    s1-secops-mcp-launch.ps1 setup  [-Profile P]
    s1-secops-mcp-launch.ps1 status [-Profile P]
    s1-secops-mcp-launch.ps1 versions | help      image versions / entrypoint help

  Environment: S1_MCP_IMAGE, S1_PROFILE, S1_OUTPUT_DIR (mounted at /output),
  S1_CLAUDE_MD_PATH (host CLAUDE.md, mounted read-only). S1_SCOPE is
  <accountId> or <accountId>:<siteId>.

  MCP client config example (no secrets):
    "s1-secops-mcp": { "command": "powershell.exe",
      "args": ["-NoProfile","-ExecutionPolicy","Bypass","-File","C:\\path\\s1-secops-mcp-launch.ps1","s1-secops-mcp"] }

  Requires FullLanguage mode (Add-Type). Under AppLocker/WDAC constrained
  language mode, use the native server with `s1-secops-mcp setup` instead.
#>
param(
  [string]$Image = $(if ($env:S1_MCP_IMAGE) { $env:S1_MCP_IMAGE } else { 'sentinelone/secops-mcps:1.5.2' }),
  [Alias('Profile')][string]$KeyProfile = $(if ($env:S1_PROFILE) { $env:S1_PROFILE } else { 'default' }),
  [Parameter(Position = 0, Mandatory = $true)][string]$Command,
  [Parameter(Position = 1, ValueFromRemainingArguments = $true)][string[]]$ServerArgs
)
$ErrorActionPreference = 'Stop'
$Service = 'sentinelone-mcp'
if ($KeyProfile -notmatch '^[A-Za-z0-9_.-]{1,64}$') { throw "invalid profile name: $KeyProfile" }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class S1Cred {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct CREDENTIAL {
    public int Flags; public int Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public int CredentialBlobSize; public IntPtr CredentialBlob; public int Persist;
    public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;
  }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredReadW(string target, int type, int flags, out IntPtr cred);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CredWriteW(ref CREDENTIAL cred, int flags);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr p);
  public static string Read(string target) {
    IntPtr p;
    if (!CredReadW(target, 1, 0, out p)) {
      int e = Marshal.GetLastWin32Error();
      if (e == 1168) return null; // ERROR_NOT_FOUND
      throw new System.ComponentModel.Win32Exception(e);
    }
    try {
      var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
      if (c.CredentialBlobSize == 0) return "";
      return Marshal.PtrToStringUni(c.CredentialBlob, c.CredentialBlobSize / 2);
    } finally { CredFree(p); }
  }
  public static void Write(string target, string user, string value) {
    byte[] b = System.Text.Encoding.Unicode.GetBytes(value);
    var c = new CREDENTIAL();
    c.Type = 1; c.TargetName = target; c.UserName = user; c.Persist = 3; // CRED_PERSIST_ENTERPRISE, as keyring-rs
    c.CredentialBlobSize = b.Length;
    c.CredentialBlob = Marshal.AllocHGlobal(b.Length);
    try {
      Marshal.Copy(b, 0, c.CredentialBlob, b.Length);
      if (!CredWriteW(ref c, 0)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    } finally { Marshal.FreeHGlobal(c.CredentialBlob); }
  }
}
'@

function Get-Target([string]$Name) { "${KeyProfile}:${Name}.$Service" }
function Get-Kc([string]$Name) { [S1Cred]::Read((Get-Target $Name)) }
function Set-Kc([string]$Name, [string]$Value) {
  [S1Cred]::Write((Get-Target $Name), "${KeyProfile}:${Name}", $Value)
  if ((Get-Kc $Name) -cne $Value) { throw "write for $Name did not read back" }
}
# Errors and warnings go to stderr explicitly: under `powershell.exe -File`,
# Write-Warning / Write-Host can land on stdout and corrupt the JSON-RPC stream.
function Write-Err([string]$m) { [Console]::Error.WriteLine($m) }

$AllNames = 'S1_CONSOLE_URL','S1_CONSOLE_API_TOKEN','S1_HEC_INGEST_URL','S1_HEC_TOKEN','S1_SCOPE','VIRUSTOTAL_API_KEY'
function Test-Secret([string]$n) { $n -match 'TOKEN|KEY' }

# Same validation as `s1-secops-mcp setup` and the sh launcher. Returns an error or $null.
function Test-Value([string]$n, [string]$v) {
  if ($n -in 'S1_CONSOLE_URL','S1_HEC_INGEST_URL') { if ($v -notmatch '^https://[A-Za-z0-9.-]+(:\d+)?$') { return 'must be an https:// origin' } }
  elseif ($n -eq 'S1_SCOPE') { if ($v -notmatch '^\d+(:\d+)?$') { return 'must be <accountId> or <accountId>:<siteId>' } }
  elseif (Test-Secret $n) { if ($v -match '\s') { return 'contains whitespace' }; if ($v.Length -lt 16) { return 'is too short to be a real token' } }
  return $null
}

# Windows command-line quoting (CommandLineToArgvW rules), for the .NET Framework
# Arguments string: backslashes before a quote and at the end are doubled.
function ConvertTo-WinArg([string]$a) {
  if ($a -ne '' -and $a -notmatch '[\s"]') { return $a }
  '"' + ([regex]::Replace($a, '(\\*)"', { param($m) $m.Groups[1].Value * 2 + '\"' }) -replace '(\\+)$', '$1$1') + '"'
}

switch -Regex ($Command) {
  '^setup$' {
    if ([Console]::IsInputRedirected) { throw 'setup must run in an interactive console (or use: s1-secops-mcp setup, which reads NAME=value lines on stdin)' }
    Write-Host "Profile: $KeyProfile. Press Enter to keep a value. Secrets are not echoed."
    foreach ($n in $AllNames) {
      $cur = Get-Kc $n
      $hint = if (-not $cur) { 'not set' } elseif (Test-Secret $n) { "set, $($cur.Length) chars" } else { $cur }
      if (Test-Secret $n) {
        $ss = Read-Host -AsSecureString "$n [$hint]"
        $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
        try { $v = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
      } else { $v = Read-Host "$n [$hint]" }
      if (-not $v) { continue }
      if ($n -like '*URL') { $v = $v.TrimEnd('/') }
      $problem = Test-Value $n $v
      if ($problem) { Write-Host "  skip ${n}: $problem"; continue }
      Set-Kc $n $v; Write-Host "  stored $n"
    }
    exit 0
  }
  '^status$' {
    foreach ($n in $AllNames) {
      $v = Get-Kc $n
      $s = if (-not $v) { '-' } elseif (Test-Secret $n) { "set ($($v.Length) chars)" } else { $v }
      '{0,-34} {1}' -f $n, $s
    }
    exit 0
  }
  '^(versions|help)$' { & docker run --rm $Image $Command; exit $LASTEXITCODE }
  '^(s1-secops-mcp|s1)$' { $Names = 'S1_CONSOLE_URL','S1_CONSOLE_API_TOKEN','S1_HEC_INGEST_URL','S1_HEC_TOKEN','S1_SCOPE' }
  '^(purple-mcp|purple)$' { $Names = 'S1_CONSOLE_URL','S1_CONSOLE_API_TOKEN','VIRUSTOTAL_API_KEY' }  # VT key -> PURPLEMCP_VT_API_KEY
  '^(virustotal-mcp|virustotal|vt)$' { $Names = @('VIRUSTOTAL_API_KEY') }
  default { throw "unknown server '$Command'" }
}

$payload = New-Object System.Text.StringBuilder
$missing = @()
foreach ($n in $Names) { $v = Get-Kc $n; if ($v) { [void]$payload.Append("$n=$v`n") } else { $missing += $n } }
[void]$payload.Append("`n")
# Warn only for what a server cannot run without (as the sh launcher does).
$required = $missing | Where-Object { $_ -in 'S1_CONSOLE_API_TOKEN','VIRUSTOTAL_API_KEY' }
if ($required) { Write-Err "s1-secops-mcp-launch: warning: not in Credential Manager for profile ${KeyProfile}: $($required -join ', ') (run: s1-secops-mcp-launch.ps1 setup)" }

$cname = "s1mcp-$PID-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
$dargs = @('run','-i','--rm','--name',$cname,'-e','S1_SECRETS_STDIN=1')
if ($env:S1_OUTPUT_DIR) {
  if (-not (Test-Path -LiteralPath $env:S1_OUTPUT_DIR -PathType Container)) { throw "S1_OUTPUT_DIR $($env:S1_OUTPUT_DIR) is not a directory" }
  # Windows paths cannot be mirrored inside a Linux container, so the directory is
  # mounted at /output: pass outputFile as /output/<name>.
  $dargs += @('-v', "$($env:S1_OUTPUT_DIR):/output", '-e', 'S1_OUTPUT_DIRS=/output')
}
if ($env:S1_CLAUDE_MD_PATH -and (Test-Path -LiteralPath $env:S1_CLAUDE_MD_PATH -PathType Leaf)) {
  $dargs += @('-v', "$($env:S1_CLAUDE_MD_PATH):/workspace/CLAUDE.md:ro", '-e', 'S1_CLAUDE_MD_PATH=/workspace/CLAUDE.md')
}
$dargs += @($Image, $Command)
if ($ServerArgs) { $dargs += $ServerArgs }   # passed through as given, empty strings included

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'docker'
if ($psi.PSObject.Properties.Name -contains 'ArgumentList' -and $null -ne $psi.ArgumentList) {
  foreach ($a in $dargs) { [void]$psi.ArgumentList.Add($a) }          # PowerShell 7 (.NET Core)
} else {
  # Windows PowerShell 5.1 (.NET Framework): one string. None of these values is
  # a secret; they are docker options, the image and the server name.
  $psi.Arguments = ($dargs | ForEach-Object { ConvertTo-WinArg $_ }) -join ' '
}
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
# No UTF-8 BOM in front of the payload (.NET Framework can write one when the
# console input code page is 65001); the entrypoint also strips one defensively.
try { [Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
$proc = [System.Diagnostics.Process]::Start($psi)
$utf8 = New-Object System.Text.UTF8Encoding($false)
$bytes = $utf8.GetBytes($payload.ToString())
$proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
$proc.StandardInput.BaseStream.Flush()
# Relay the client's stdin to docker until either side closes.
$stdin = [Console]::OpenStandardInput()
$copy = $stdin.CopyToAsync($proc.StandardInput.BaseStream)
try {
  while (-not $proc.HasExited) {
    if ($copy.IsCompleted) { $proc.StandardInput.Close(); $copy = [System.Threading.Tasks.Task]::Delay(-1) }
    Start-Sleep -Milliseconds 100
  }
} finally {
  if (-not $proc.HasExited) { try { & docker kill $cname *> $null } catch { } }
}
exit $proc.ExitCode
