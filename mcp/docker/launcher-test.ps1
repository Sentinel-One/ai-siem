<#
  launcher-test.ps1: hermetic tests for `s1-secops-mcp-launch.ps1 install` and
  `config`. Runs each case in a child PowerShell whose HOME, USERPROFILE and
  APPDATA point at a temp directory, so the real Claude Desktop config is never
  touched. Needs no network; Credential Manager is only read.

  Usage: pwsh -NoProfile -File docker/launcher-test.ps1
         (Windows PowerShell 5.1: powershell -NoProfile -ExecutionPolicy Bypass -File ...)
#>
$ErrorActionPreference = 'Stop'
$launcher = Join-Path $PSScriptRoot 's1-secops-mcp-launch.ps1'
$psExe = (Get-Process -Id $PID).Path
$root = Join-Path ([IO.Path]::GetTempPath()) ("s1launch-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$script:pass = 0; $script:fail = 0
function Ok([string]$m) { $script:pass++; Write-Host "  ok   $m" }
function Bad([string]$m, [string]$detail) { $script:fail++; Write-Host "  FAIL $m"; if ($detail) { Write-Host "       $detail" } }

$homeDir = Join-Path $root 'home with space'
$appData = Join-Path $homeDir 'AppData'
New-Item -ItemType Directory -Force -Path $homeDir, $appData | Out-Null
$cfg = Join-Path (Join-Path $appData 'Claude') 'claude_desktop_config.json'
$dest = Join-Path (Join-Path $homeDir 'bin') 's1-secops-mcp-launch.ps1'

# Run the launcher in a child PowerShell with a temp HOME. Returns stdout; stderr lands in $root\err.txt.
function Invoke-Launcher([string]$Script, [string[]]$LauncherArgs) {
  $saved = @{ HOME = $env:HOME; USERPROFILE = $env:USERPROFILE; APPDATA = $env:APPDATA }
  $env:HOME = $homeDir; $env:USERPROFILE = $homeDir; $env:APPDATA = $appData
  try {
    $out = & $psExe -NoProfile -ExecutionPolicy Bypass -File $Script @LauncherArgs 2> (Join-Path $root 'err.txt')
    $script:rc = $LASTEXITCODE
    ($out | Out-String)
  } finally { foreach ($k in $saved.Keys) { Set-Item "env:$k" $saved[$k] } }
}
function ErrText { Get-Content -Raw (Join-Path $root 'err.txt') -ErrorAction SilentlyContinue }

try {
  # config: three entries, absolute path, powershell.exe -File <launcher>
  $j = Invoke-Launcher $launcher @('config') | ConvertFrom-Json
  $names = @($j.mcpServers.PSObject.Properties.Name)
  $a = $j.mcpServers.'s1-secops-mcp'.args
  if (($names -join ',') -eq 's1-secops-mcp,purple-mcp,virustotal' -and $j.mcpServers.virustotal.command -eq 'powershell.exe' -and $a[4] -eq $launcher -and $a[-1] -eq 's1-secops-mcp' -and $j.mcpServers.virustotal.args[-1] -eq 'virustotal-mcp') {
    Ok 'config: three entries, absolute path' } else { Bad 'config' (ErrText) }

  # config options
  $md = Join-Path $root 'CLAUDE.md'; Set-Content -Path $md -Value '# x'
  $out = Join-Path $root 'out dir'
  $j = Invoke-Launcher $launcher @('config', '-Profile', 'prod', '-OutputDir', $out, '-ClaudeMd', $md, '-Image', 'sentinelone/secops-mcps:9.9.9') | ConvertFrom-Json
  $e = $j.mcpServers.'s1-secops-mcp'.env
  if ((Test-Path $out) -and $e.S1_OUTPUT_DIR -eq (Resolve-Path $out).ProviderPath -and $e.S1_CLAUDE_MD_PATH -eq (Resolve-Path $md).ProviderPath -and
      ($j.mcpServers.'purple-mcp'.args -join ' ') -match '-Image sentinelone/secops-mcps:9\.9\.9 -Profile prod purple-mcp$' -and -not $j.mcpServers.virustotal.env) {
    Ok 'config: -Profile -OutputDir -ClaudeMd -Image' } else { Bad 'config options' (ErrText) }

  # install, fresh
  [void](Invoke-Launcher $launcher @('install'))
  $j = Get-Content -Raw $cfg | ConvertFrom-Json
  $cmds = @($j.mcpServers.PSObject.Properties | ForEach-Object { $_.Value.args[4] } | Select-Object -Unique)
  if ($rc -eq 0 -and (Test-Path $dest) -and ($cmds -join '') -eq $dest -and -not (Get-ChildItem "$cfg.bak-*" -ErrorAction SilentlyContinue)) {
    Ok 'install: fresh config under APPDATA, launcher copied to HOME\bin' } else { Bad "install fresh (rc=$rc)" (ErrText) }
  if ((ErrText) -match 'Quit Claude Desktop completely') { Ok 'install: restart instruction' } else { Bad 'install messages' (ErrText) }

  # install merge
  $orig = @'
{"globalShortcut": "Alt+Space",
 "mcpServers": {
   "other": {"command": "node", "args": ["x.js"]},
   "virustotal-mcp": {"command": "powershell.exe", "args": ["-File", "C:\\old\\s1-secops-mcp-launch.ps1", "virustotal-mcp"]},
   "s1-secops-mcp": {"command": "docker", "args": ["run", "sentinelone/secops-mcps:1.4.0"]}},
 "preferences": {"a": 1}}
'@
  [IO.File]::WriteAllText($cfg, $orig)
  [void](Invoke-Launcher $launcher @('install'))
  $j = Get-Content -Raw $cfg | ConvertFrom-Json
  $names = @($j.mcpServers.PSObject.Properties.Name | Sort-Object)
  if ($j.globalShortcut -eq 'Alt+Space' -and $j.preferences.a -eq 1 -and $j.mcpServers.other.command -eq 'node' -and
      ($names -join ',') -eq 'other,purple-mcp,s1-secops-mcp,virustotal' -and $j.mcpServers.'s1-secops-mcp'.args[4] -eq $dest) {
    Ok 'install: merge keeps others, replaces ours, drops old entry' } else { Bad 'install merge' (ErrText) }
  $bak = @(Get-ChildItem "$cfg.bak-*" -ErrorAction SilentlyContinue)
  if ($bak.Count -eq 1 -and [IO.File]::ReadAllText($bak[0].FullName) -eq $orig -and (ErrText) -match 'removed old entry virustotal-mcp') {
    Ok 'install: backup identical to previous config' } else { Bad 'install backup' (ErrText) }
  $bak | Remove-Item

  # idempotent from the installed copy
  $before = [IO.File]::ReadAllText($cfg)
  [void](Invoke-Launcher $dest @('install'))
  if ([IO.File]::ReadAllText($cfg) -eq $before) { Ok 'install: idempotent from the installed copy' } else { Bad 'install idempotent' }
  Get-ChildItem "$cfg.bak-*" -ErrorAction SilentlyContinue | Remove-Item

  # UTF-8 without BOM
  $bytes = [IO.File]::ReadAllBytes($cfg)
  if (-not ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB)) { Ok 'install: config written as UTF-8 without BOM' } else { Bad 'install BOM' }

  # invalid JSON left untouched
  [IO.File]::WriteAllText($cfg, '{ "mcpServers": ')
  [void](Invoke-Launcher $launcher @('install'))
  if ($rc -ne 0 -and [IO.File]::ReadAllText($cfg) -eq '{ "mcpServers": ' -and (ErrText) -match 'config not changed' -and -not (Get-ChildItem "$cfg.bak-*" -ErrorAction SilentlyContinue)) {
    Ok "install: invalid JSON left untouched (rc=$rc)" } else { Bad 'install invalid JSON' (ErrText) }

  # -ConfigPath
  $alt = Join-Path $root 'alt\c.json'
  [void](Invoke-Launcher $launcher @('install', '-ConfigPath', $alt))
  if (@((Get-Content -Raw $alt | ConvertFrom-Json).mcpServers.PSObject.Properties).Count -eq 3) { Ok 'install: -ConfigPath' } else { Bad 'install -ConfigPath' (ErrText) }

  # -ConfigPath is install-only
  [void](Invoke-Launcher $launcher @('config', '-ConfigPath', $alt))
  if ($rc -ne 0) { Ok 'config: rejects -ConfigPath' } else { Bad 'config -ConfigPath accepted' }
} finally { Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue }

Write-Host ''
Write-Host "launcher-test.ps1: $($script:pass) passed, $($script:fail) failed (PowerShell $($PSVersionTable.PSVersion))"
if ($script:fail) { exit 1 }
