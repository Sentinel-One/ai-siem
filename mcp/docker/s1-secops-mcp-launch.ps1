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
    s1-secops-mcp-launch.ps1 install [options]   copy to $HOME\bin, pull the image, add the
                                                 three servers to the Claude Desktop config
                                                 (backup kept), then run setup if no token
    s1-secops-mcp-launch.ps1 config  [options]   print the mcpServers JSON with this
                                                 script's absolute path (other clients)
      options: -Image IMG  -Profile P  -OutputDir DIR  -ClaudeMd FILE
               -ConfigPath FILE (install only; default %APPDATA%\Claude\claude_desktop_config.json)

  Environment: S1_MCP_IMAGE, S1_PROFILE, S1_OUTPUT_DIR (mounted at /output),
  S1_CLAUDE_MD_PATH (host CLAUDE.md, mounted read-only). S1_SCOPE is
  <accountId> or <accountId>:<siteId>.

  MCP client config example (no secrets; JSON does not expand %USERPROFILE%,
  which is why install and config write the real path):
    "s1-secops-mcp": { "command": "powershell.exe",
      "args": ["-NoProfile","-ExecutionPolicy","Bypass","-File","C:\\path\\s1-secops-mcp-launch.ps1","s1-secops-mcp"] }

  Requires FullLanguage mode (Add-Type). Under AppLocker/WDAC constrained
  language mode, use the native server with `s1-secops-mcp setup` instead.
#>
param(
  [string]$Image = $(if ($env:S1_MCP_IMAGE) { $env:S1_MCP_IMAGE } else { 'sentinelone/secops-mcps:1.5.3' }),
  [Alias('Profile')][string]$KeyProfile = $(if ($env:S1_PROFILE) { $env:S1_PROFILE } else { 'default' }),
  [string]$OutputDir,
  [string]$ClaudeMd,
  [string]$ConfigPath,
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
// Forwards the MCP client's stdin to docker one read at a time, flushing every
// chunk. Stream.CopyToAsync into Process.StandardInput leaves each message in
// that stream's write buffer until it fills or closes, so the server never saw
// a request until the client gave up and closed stdin.
public static class S1Relay {
  public static System.Threading.Thread Start(System.IO.Stream input, System.IO.Stream output) {
    var t = new System.Threading.Thread(() => {
      var buf = new byte[65536];
      try {
        int n;
        while ((n = input.Read(buf, 0, buf.Length)) > 0) { output.Write(buf, 0, n); output.Flush(); }
      } catch (Exception) { }
      try { output.Close(); } catch (Exception) { }
    });
    t.IsBackground = true;
    t.Start();
    return t;
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

# The three Claude Desktop entries for launcher $Launcher. No secrets: paths and names only.
function New-S1Entries([string]$Launcher) {
  $pre = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Launcher, '-Image', $Image)
  if ($KeyProfile -ne 'default') { $pre += @('-Profile', $KeyProfile) }
  $s1 = [ordered]@{ command = 'powershell.exe'; args = @($pre + 's1-secops-mcp') }
  $envMap = [ordered]@{}
  if ($OutputDir) { $envMap['S1_OUTPUT_DIR'] = $OutputDir }
  if ($ClaudeMd) { $envMap['S1_CLAUDE_MD_PATH'] = $ClaudeMd }
  if ($envMap.Count) { $s1['env'] = $envMap }
  [ordered]@{
    's1-secops-mcp' = $s1
    'purple-mcp'    = [ordered]@{ command = 'powershell.exe'; args = @($pre + 'purple-mcp') }
    'virustotal'    = [ordered]@{ command = 'powershell.exe'; args = @($pre + 'virustotal-mcp') }
  }
}

if ($Command -in 'install', 'config') {
  if (-not $PSCommandPath) { throw "cannot find this script on disk. Save it to a file first, then run: powershell -NoProfile -ExecutionPolicy Bypass -File <file> $Command" }
  if ($ConfigPath -and $Command -ne 'install') { throw '-ConfigPath is for install only' }
  if ($OutputDir) {
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    $OutputDir = (Resolve-Path -LiteralPath $OutputDir).ProviderPath
  }
  if ($ClaudeMd) {
    if (-not (Test-Path -LiteralPath $ClaudeMd -PathType Leaf)) { throw "-ClaudeMd $ClaudeMd is not a file" }
    $ClaudeMd = (Resolve-Path -LiteralPath $ClaudeMd).ProviderPath
  }
  if ($Command -eq 'config') {
    [ordered]@{ mcpServers = (New-S1Entries $PSCommandPath) } | ConvertTo-Json -Depth 10
    exit 0
  }

  # install
  $binDir = Join-Path $HOME 'bin'
  $dest = Join-Path $binDir 's1-secops-mcp-launch.ps1'
  New-Item -ItemType Directory -Force -Path $binDir | Out-Null
  if ([IO.Path]::GetFullPath($PSCommandPath) -ne [IO.Path]::GetFullPath($dest)) { Copy-Item -LiteralPath $PSCommandPath -Destination $dest -Force }
  if (Get-Command Unblock-File -ErrorAction SilentlyContinue) { Unblock-File -LiteralPath $dest }
  Write-Err "Launcher installed: $dest"

  # Which config Claude Desktop reads depends on how it was installed. The
  # claude.ai installer now ships an MSIX package (Claude_<publisher id>): a
  # fresh install reads its file-system-virtualized copy under
  # %LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude, while an install
  # that found a real %APPDATA%\Claude from an earlier version keeps reading that
  # one (and Settings > Developer > Edit config always opens the %APPDATA% copy).
  # So write every location that applies; each is merged on its own.
  if ($ConfigPath) { $targets = @($ConfigPath) } else {
    if (-not $env:APPDATA) { throw 'APPDATA is not set; pass -ConfigPath <path to claude_desktop_config.json>' }
    $targets = @(Join-Path (Join-Path $env:APPDATA 'Claude') 'claude_desktop_config.json')
    if ($env:LOCALAPPDATA -and (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'Packages'))) {
      Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'Packages') -Directory -Filter 'Claude_*' -ErrorAction SilentlyContinue |
        ForEach-Object { $targets += Join-Path (Join-Path (Join-Path (Join-Path $_.FullName 'LocalCache') 'Roaming') 'Claude') 'claude_desktop_config.json' }
    }
  }
  $new = New-S1Entries $dest
  # Merge every target first, so one invalid file stops the run before any file is written.
  $merged = @()
  foreach ($t in $targets) {
    $cfg = [pscustomobject]@{}
    if (Test-Path -LiteralPath $t -PathType Leaf) {
      $raw = [IO.File]::ReadAllText($t)
      if ($raw.Trim()) {
        try { $cfg = $raw | ConvertFrom-Json } catch { throw "config not changed: invalid JSON in ${t}: $($_.Exception.Message)" }
      }
    }
    if ($cfg -isnot [System.Management.Automation.PSCustomObject]) { throw "config not changed: $t is not a JSON object" }
    $servers = $cfg.mcpServers
    if ($servers -isnot [System.Management.Automation.PSCustomObject]) { $servers = [pscustomobject]@{} }
    # Keep every other server and setting, replace our three entries, and drop
    # older entries that ran this launcher under another name (e.g. "virustotal-mcp").
    foreach ($p in @($servers.PSObject.Properties)) {
      if (-not $new.Contains($p.Name) -and (($p.Value | ConvertTo-Json -Depth 20 -Compress) -match 's1-secops-mcp-launch')) {
        $servers.PSObject.Properties.Remove($p.Name); Write-Err "removed old entry $($p.Name) from $t"
      }
    }
    foreach ($k in $new.Keys) { $servers | Add-Member -NotePropertyName $k -NotePropertyValue $new[$k] -Force }
    $cfg | Add-Member -NotePropertyName mcpServers -NotePropertyValue $servers -Force
    $merged += , @($t, ($cfg | ConvertTo-Json -Depth 20))
  }
  foreach ($m in $merged) {
    $t = $m[0]
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $t) | Out-Null
    if (Test-Path -LiteralPath $t -PathType Leaf) {
      $bak = "$t.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
      Copy-Item -LiteralPath $t -Destination $bak
      Write-Err "Backup of your previous config: $bak"
    }
    [IO.File]::WriteAllText($t, $m[1] + "`n", (New-Object System.Text.UTF8Encoding($false)))
    $kind = if ($t -match '[\\/]Packages[\\/]Claude_') { ' (MSIX install: the file Claude Desktop reads)' } else { '' }
    Write-Err "Claude Desktop config updated: $t$kind"
  }

  # Windows PowerShell 5.1 turns a native command's redirected stderr into
  # error records, which 'Stop' makes fatal (docker info prints warnings and,
  # with Docker stopped, errors there). Run docker under 'Continue' and judge
  # by exit code only.
  $dockerUp = $false
  $pullRc = 0
  if (Get-Command docker -ErrorAction SilentlyContinue) {
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
      & docker info *> $null; $dockerUp = ($LASTEXITCODE -eq 0)
      if ($dockerUp) {
        Write-Err "Pulling $Image ..."
        & docker pull $Image 2>&1 | ForEach-Object { Write-Err "$_" }
        $pullRc = $LASTEXITCODE
      }
    } catch { $dockerUp = $false } finally { $ErrorActionPreference = $eap }
  }
  if (-not $dockerUp) { Write-Err 's1-secops-mcp-launch: warning: Docker is not running. Start Docker Desktop before you open Claude Desktop.' }
  elseif ($pullRc -ne 0) { Write-Err 's1-secops-mcp-launch: warning: pull failed; the first start will retry it' }

  $hasToken = $true
  try { $hasToken = [bool](Get-Kc 'S1_CONSOLE_API_TOKEN') } catch { Write-Err "s1-secops-mcp-launch: warning: Credential Manager unavailable: $($_.Exception.Message)" }
  if (-not $hasToken) {
    if (-not [Console]::IsInputRedirected) {
      Write-Err "S1_CONSOLE_API_TOKEN is not stored for profile $KeyProfile. Starting setup: press Enter to keep any value already stored."
      & (Get-Process -Id $PID).Path -NoProfile -ExecutionPolicy Bypass -File $dest -Profile $KeyProfile setup
      $still = $true; try { $still = -not (Get-Kc 'S1_CONSOLE_API_TOKEN') } catch { }
      if ($still) { Write-Err "s1-secops-mcp-launch: warning: S1_CONSOLE_API_TOKEN is still not stored. Run: powershell -NoProfile -ExecutionPolicy Bypass -File `"$dest`" setup  (paste with right-click if Ctrl+V does nothing)" }
    }
    else { Write-Err "Next: store your credentials with: powershell -NoProfile -ExecutionPolicy Bypass -File `"$dest`" setup" }
  }
  Write-Err 'Done. Quit Claude Desktop completely (also from the system tray) and open it again: it starts the three MCPs itself. Nothing needs starting in Docker Desktop.'
  exit 0
}

switch -Regex ($Command) {
  '^setup$' {
    if ([Console]::IsInputRedirected) { throw 'setup must run in an interactive console (or use: s1-secops-mcp setup, which reads NAME=value lines on stdin)' }
    Write-Host "Profile: $KeyProfile. Press Enter to keep a value. Secrets are not echoed."
    Write-Host "Tip: if Ctrl+V does not paste into a hidden prompt, right-click to paste."
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
# Relay the client's stdin to docker, flushing each read, until the client
# closes stdin (the relay then closes docker's stdin) or docker exits.
$relay = [S1Relay]::Start([Console]::OpenStandardInput(), $proc.StandardInput.BaseStream)
try {
  while (-not $proc.WaitForExit(200)) { }
} finally {
  if (-not $proc.HasExited) { try { & docker kill $cname *> $null } catch { } }
}
exit $proc.ExitCode
