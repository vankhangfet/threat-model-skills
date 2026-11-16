<#
.SYNOPSIS
  Install the threat-modeling skills into a project repo for one or more coding agents (Windows-friendly).
.DESCRIPTION
  Copies the skills into each selected agent's project skills folder. Always copies (no symlinks),
  so it works without admin rights or Developer Mode.
.PARAMETER Repo
  Path to the project repo.
.PARAMETER Agents
  Comma-separated agents or "all" (default). Supported: claude, codex, copilot, cline, opencode, kiro, pi
.PARAMETER Uninstall
  Remove the skills from the selected agent folders.
.PARAMETER List
  List supported agents and their folders.
.EXAMPLE
  ./install.ps1 C:\work\my-service
  ./install.ps1 -Agents claude,kiro C:\work\my-service
  ./install.ps1 -Agents codex,copilot -WhatIf C:\work\my-service
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Position = 0)][string]$Repo,
  [string[]]$Agents = @('all'),
  [switch]$Uninstall,
  [switch]$List
)
$ErrorActionPreference = 'Stop'

$AgentDirs = [ordered]@{
  claude   = '.claude/skills'
  codex    = '.agents/skills'   # also read by OpenCode, Cline, Pi and others
  copilot  = '.github/skills'
  cline    = '.cline/skills'
  opencode = '.opencode/skills'
  kiro     = '.kiro/skills'
  pi       = '.pi/skills'
}
$Skills = 'threat-model-draft', 'threat-to-requirements', 'threat-check'
$Src = $PSScriptRoot

if ($List) { $AgentDirs.GetEnumerator() | ForEach-Object { '{0,-9} {1}' -f $_.Key, $_.Value }; return }
if (-not $Repo) { Get-Help $PSCommandPath -Examples | Out-String | Write-Host; throw 'Repo path is required.' }
if (-not (Test-Path -LiteralPath $Repo -PathType Container)) { throw "Repo path does not exist: $Repo" }
$Repo = (Resolve-Path -LiteralPath $Repo).Path
foreach ($s in $Skills) { if (-not (Test-Path (Join-Path $Src "skills/$s/SKILL.md"))) { throw "Missing source skill: $s" } }

$want = @($Agents | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
if ($want -contains 'all') { $want = @($AgentDirs.Keys) }
$dirs = [System.Collections.Generic.List[string]]::new()
foreach ($a in $want) {
  if (-not $AgentDirs.Contains($a)) { throw "Unsupported agent: $a (supported: $($AgentDirs.Keys -join ', '))" }
  if (-not $dirs.Contains($AgentDirs[$a])) { $dirs.Add($AgentDirs[$a]) }
}
if ($dirs.Count -eq 0) { throw 'No agents selected.' }

foreach ($d in $dirs) {
  $base = Join-Path $Repo $d
  if ($Uninstall) {
    foreach ($s in $Skills) {
      $t = Join-Path $base $s
      if (Test-Path -LiteralPath $t) {
        if ($PSCmdlet.ShouldProcess($t, 'Remove')) { Remove-Item -LiteralPath $t -Recurse -Force; "removed   $d/$s" }
      }
    }
    if ((Test-Path $base) -and -not (Get-ChildItem -Force $base) -and $PSCmdlet.ShouldProcess($base, 'Remove empty folder')) {
      Remove-Item $base; $parent = Split-Path $base
      if (-not (Get-ChildItem -Force $parent)) { Remove-Item $parent }
    }
    continue
  }
  if ($PSCmdlet.ShouldProcess($base, 'Install skills')) {
    New-Item -ItemType Directory -Force -Path $base | Out-Null
    foreach ($s in $Skills) {
      $t = Join-Path $base $s
      if (Test-Path -LiteralPath $t) { Remove-Item -LiteralPath $t -Recurse -Force }
      Copy-Item -Recurse -LiteralPath (Join-Path $Src "skills/$s") -Destination $t
    }
    "installed (copy) $d"
  }
}

if ($Uninstall) { 'Uninstalled. threat-model/ (your models and config) was left untouched.'; return }

$cfgDir = Join-Path $Repo 'threat-model'
$cfg = Join-Path $cfgDir 'config.json'
if (Test-Path $cfg) { 'kept existing threat-model/config.json' }
elseif ($PSCmdlet.ShouldProcess($cfg, 'Create config')) {
  New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
  Copy-Item (Join-Path $Src 'config.example.json') $cfg
  'created threat-model/config.json'
}
''
'Done. Commit these folders so the whole team uses the same skill version.'
