$ErrorActionPreference = 'Stop'
$log = 'Microsoft-Windows-PowerShell/Operational'

$outDir = Join-Path ([Environment]::GetFolderPath('Desktop')) 'papa'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$outFile = Join-Path $outDir 'PWSHOperational.txt'

function _s([int[]]$c) { -join ($c | ForEach-Object { [char]$_ }) }

# Defender module autogen vs real tamper (short user call — keep)
function Test-IsDefenderModuleNoise {
  param([string]$Script)
  if ([string]::IsNullOrWhiteSpace($Script)) { return $false }

  # Real invocation — do not filter
  if ($Script.Length -lt 6000) {
    if ($Script -match '(?im)^\s*(Set-MpPreference|Add-MpPreference|Remove-MpPreference)\s+') { return $false }
    if ($Script -match '(?i)(Set|Add)-MpPreference[^`{]{0,500}?(-DisableRealtimeMonitoring|-ExclusionPath|-ExclusionProcess)\s+\$?(true|\w|:)') { return $false }
  }

  if ($Script -match '__cmdletization|MSFT_MpPreference|GeneratedTypes\.MpPreference') { return $true }
  if ($Script -match 'function\s+(Set|Remove|Add|Get)-MpPreference\s*\{') { return $true }
  if ($Script -match 'Microsoft\.PowerShell\.Cmdletization\.MethodParameter') { return $true }
  if ($Script -match "Parameter\(ParameterSetName='(Remove2|Set0|Add1)'\)" -and $Script -match '\$\{DisableRealtimeMonitoring\}' -and $Script -match '\[ValidateNotNull') { return $true }

  $paramBlocks = ([regex]::Matches($Script, '\[Parameter\(')).Count
  if ($paramBlocks -ge 6 -and $Script -match 'DisableRealtimeMonitoring' -and $Script -match '(ExclusionPath|DisableScriptScanning)') { return $true }

  return $false
}

function Test-IsWindowsMaintenanceNoise {
  param([string]$Script)
  if ($Script -match 'CL_LocalizationData|Get-UserTSHistoryPath|Update-DiagReport|Import-LocalizedData.*CL_Localization') { return $true }
  if ($Script -match 'Copyright \(c\) Microsoft Corporation' -and $Script -match 'Get-FolderSize|Delete-OldFolders') { return $true }
  return $false
}

function Get-BlockVerdict {
  param([string]$Script, [int]$Score)
  if (Test-IsDefenderModuleNoise -Script $Script) { return 'NOISE-DEFENDER' }
  if (Test-IsWindowsMaintenanceNoise -Script $Script) { return 'NOISE-WINDOWS' }
  if ($Script.Length -lt 150 -and $Script -match '(?i)^\s*(\$[mg]\=|New-Object System\.IO\.(MemoryStream|Compression\.GzipStream))') { return 'NOISE-FRAG' }
  if ($Script -match '(?i)Y-ClipBoard|MemScan::Dump|cbdhsvc|Done sweety') { return 'YOUR-TOOL' }
  if ($Script -match 'amsiInitFailed') {
    $evasion = ($Script -match '(?i)EtwEventWrite|EnableScriptBlockLogging|PSEtwLogProvider')
    $load = ($Script -match '(?i)DownloadData') -or ($Script -match 'Assembly' -and $Script -match '::Load')
    if ($evasion -and $load) { return 'CRITICAL-LOADER' }
  }
  if (($Script -match '(?i)-bxor') -and ($Script -match 'GzipStream') -and ($Script -match 'ScriptBlock' -and $Script -match '::Create')) { return 'FILELESS-STAGER' }
  if ($Script -match '(?i)clicker\.exe|Sapphire/raw') { return 'CHEAT-CLICKER' }
  if ($Score -ge 20) { return 'REVIEW-HIGH' }
  if ($Score -ge 10) { return 'REVIEW' }
  return 'LOW'
}

# packed rules: weight + tokens (no plaintext labels in report)
$rules = @(
  @{ W = 5; P = @(
      (_s 70,114,111,109,66,97,115,101,54,52,83,116,114,105,110,103)
      (_s 71,122,105,112,83,116,114,101,97,109)
      (_s 68,101,102,108,97,116,101,83,116,114,101,97,109)
      (_s 98,120,111,114)
      (_s 73,110,118,111,107,101,45,69,120,112,114,101,115,115,105,111,110)
      (_s 92,98,73,69,88,92,98)
      (_s 73,110,118,111,107,101,45,67,111,109,109,97,110,100)
      (_s 69,110,99,111,100,101,100,67,111,109,109,97,110,100)
      (_s 45,101,110,99,92,98)
      (_s 73,79,92,46,77,101,109,111,114,121,83,116,114,101,97,109)
      (_s 67,111,110,118,101,114,116,92,93,58,58,70,114,111,109,66,97,115,101,54,52)
      (_s 73,79,92,46,67,111,109,112,114,101,115,115,105,111,110)
      (_s 45,98,120,111,114)
      (_s 105,99,109,92,98)
      (_s 45,69,110,99,111,100,101,100,67,111,109,109,97,110,100)
      (_s 45,101,92,115,43,91,65,45,90,97,45,122,48,45,57,43,47,61,93,123,52,48,44,125)
    ) }
  @{ W = 5; P = @(
      (_s 78,101,116,92,46,87,101,98,67,108,105,101,110,116)
      (_s 87,101,98,67,108,105,101,110,116)
      (_s 68,111,119,110,108,111,97,100,83,116,114,105,110,103)
      (_s 68,111,119,110,108,111,97,100,70,105,108,101)
      (_s 68,111,119,110,108,111,97,100,68,97,116,97)
      (_s 73,110,118,111,107,101,45,87,101,98,82,101,113,117,101,115,116)
      (_s 73,110,118,111,107,101,45,82,101,115,116,77,101,116,104,111,100)
      (_s 92,98,105,119,114,92,98)
      (_s 92,98,105,114,109,92,98)
      (_s 84,99,112,67,108,105,101,110,116)
      (_s 66,105,116,115,84,114,97,110,115,102,101,114)
      (_s 83,116,97,114,116,45,66,105,116,115,84,114,97,110,115,102,101,114)
      (_s 104,116,116,112,58,47,47)
      (_s 104,116,116,112,115,58,47,47)
      (_s 119,103,101,116,92,98)
      (_s 99,117,114,108,92,98)
      (_s 87,101,98,82,101,113,117,101,115,116)
    ) }
  @{ W = 8; P = @(
      (_s 65,109,115,105,85,116,105,108,115)
      (_s 97,109,115,105,73,110,105,116,70,97,105,108,101,100)
      (_s 97,109,115,105,67,111,110,116,101,120,116)
      (_s 97,109,115,105,83,101,115,115,105,111,110)
      (_s 69,116,119,69,118,101,110,116,87,114,105,116,101)
      (_s 80,83,69,116,119,76,111,103,80,114,111,118,105,100,101,114)
      (_s 82,101,102,108,101,99,116,105,111,110,92,46,69,109,105,116)
      (_s 101,116,119,80,114,111,118,105,100,101,114)
    ) }
  @{ W = 8; P = @(
      (_s 86,105,114,116,117,97,108,65,108,108,111,99)
      (_s 86,105,114,116,117,97,108,80,114,111,116,101,99,116)
      (_s 87,114,105,116,101,80,114,111,99,101,115,115,77,101,109,111,114,121)
      (_s 67,114,101,97,116,101,82,101,109,111,116,101,84,104,114,101,97,100)
      (_s 67,114,101,97,116,101,84,104,114,101,97,100)
      (_s 78,116,67,114,101,97,116,101,84,104,114,101,97,100,69,120)
      (_s 79,112,101,110,80,114,111,99,101,115,115)
      (_s 81,117,101,117,101,85,115,101,114,65,80,67)
      (_s 107,101,114,110,101,108,51,50,92,46,100,108,108)
      (_s 110,116,100,108,108,92,46,100,108,108)
      (_s 68,108,108,73,109,112,111,114,116)
      (_s 85,110,109,97,110,97,103,101,100,70,117,110,99,116,105,111,110,80,111,105,110,116,101,114)
    ) }
  @{ W = 6; P = @(
      (_s 65,100,100,45,84,121,112,101)
      (_s 82,101,102,108,101,99,116,105,111,110,92,46,65,115,115,101,109,98,108,121)
      (_s 65,115,115,101,109,98,108,121,93,58,58,76,111,97,100)
      (_s 76,111,97,100,92,40)
      (_s 76,111,97,100,70,105,108,101)
      (_s 76,111,97,100,70,114,111,109)
      (_s 71,101,116,68,101,108,101,103,97,116,101,70,111,114,70,117,110,99,116,105,111,110,80,111,105,110,116,101,114)
      (_s 68,121,110,97,109,105,99,73,110,118,111,107,101)
      (_s 77,97,114,115,104,97,108,58,58)
    ) }
  @{ W = 6; P = @(
      (_s 78,101,119,45,83,101,114,118,105,99,101)
      (_s 115,99,104,116,97,115,107,115)
      (_s 83,99,104,101,100,117,108,101,100,84,97,115,107)
      (_s 82,101,103,105,115,116,101,114,45,83,99,104,101,100,117,108,101,100,84,97,115,107)
      (_s 67,117,114,114,101,110,116,86,101,114,115,105,111,110,92,92,82,117,110)
      (_s 83,101,116,45,77,80,80,114,101,102,101,114,101,110,99,101)
      (_s 68,105,115,97,98,108,101,82,101,97,108,116,105,109,101,77,111,110,105,116,111,114,105,110,103)
      (_s 69,120,99,108,117,115,105,111,110,80,97,116,104)
      (_s 67,111,109,109,97,110,100,76,105,110,101,69,118,101,110,116,67,111,110,115,117,109,101,114)
      (_s 95,95,69,118,101,110,116,70,105,108,116,101,114)
      (_s 78,101,119,45,78,101,116,70,105,114,101,119,97,108,108,82,117,108,101)
    ) }
  @{ W = 4; P = @(
      (_s 77,105,109,105,107,97,116,122)
      (_s 73,110,118,111,107,101,45,77,105,109,105,107,97,116,122)
      (_s 115,101,107,117,114,108,115,97)
      (_s 108,115,97,100,117,109,112)
      (_s 80,111,119,101,114,86,105,101,119)
      (_s 83,104,97,114,112,72,111,117,110,100)
      (_s 66,108,111,111,100,72,111,117,110,100)
      (_s 82,117,98,101,117,115)
      (_s 83,97,102,101,116,121,75,97,116,122)
      (_s 71,101,116,45,65,68,85,115,101,114)
      (_s 71,101,116,45,68,111,109,97,105,110)
      (_s 119,104,111,97,109,105,92,115,43,47,97,108,108)
    ) }
  @{ W = 5; P = @(
      (_s 109,115,104,116,97)
      (_s 114,117,110,100,108,108,51,50)
      (_s 114,101,103,115,118,114,51,50)
      (_s 99,101,114,116,117,116,105,108)
      (_s 98,105,116,115,97,100,109,105,110)
      (_s 119,109,105,99,92,98)
      (_s 99,109,115,116,112)
      (_s 73,110,115,116,97,108,108,85,116,105,108)
      (_s 77,83,66,117,105,108,100)
      (_s 45,110,111,112,92,98)
      (_s 45,119,92,115,43,104,105,100,100,101,110)
      (_s 45,87,105,110,100,111,119,83,116,121,108,101,92,115,43,72,105,100,100,101,110)
      (_s 83,116,97,114,116,45,80,114,111,99,101,115,115)
      (_s 99,109,100,92,46,101,120,101,92,115,43,47,99)
      (_s 99,109,100,92,115,43,47,99)
    ) }
  @{ W = 4; P = @(
      (_s 92,91,99,104,97,114,92,93,92,115,42,92,100,43)
      (_s 45,106,111,105,110,92,115,42,92,40)
      (_s 66,105,116,67,111,110,118,101,114,116,101,114)
      (_s 84,101,120,116,92,46,69,110,99,111,100,105,110,103)
      (_s 71,101,116,83,116,114,105,110,103,92,40)
      (_s 83,101,99,117,114,101,83,116,114,105,110,103,84,111,66,83,84,82)
      (_s 80,116,114,84,111,83,116,114,105,110,103,65,117,116,111)
      (_s 84,111,66,121,116,101)
      (_s 84,111,73,110,116,49,54)
    ) }
)

$all = foreach ($r in $rules) { $r.P }
$rx = ($all | Select-Object -Unique) -join '|'

# console text via char-codes so file encoding cannot break it
Write-Host (_s 1087,1080,1088,1089,1080,1090,32,1087,1080,1084,1103,1090,1100,46,46,46) -ForegroundColor Cyan
Write-Host 'love bypass by BypassMagister' -ForegroundColor Magenta

$daysBack = 30
$cutoff = (Get-Date).AddDays(-$daysBack)

$events = @(Get-WinEvent -LogName $log -FilterXPath '*[System[EventID=4104]]' -ErrorAction SilentlyContinue |
  Where-Object { $_.TimeCreated -ge $cutoff })
if ($events.Count -eq 0) {
  [IO.File]::WriteAllText($outFile, ('empty (last {0} days)' -f $daysBack), [Text.UTF8Encoding]::new($false))
  return
}

$sha = [Security.Cryptography.SHA256]::Create()
$byHash = @{}  # hash -> list of hits

foreach ($e in $events) {
  if ($e.Properties.Count -ge 3 -and $e.Properties[2].Value) {
    $script = [string]$e.Properties[2].Value
  } else {
    $script = [string]$e.Message
  }
  if ([string]::IsNullOrWhiteSpace($script)) { continue }
  if (Test-IsDefenderModuleNoise -Script $script) { continue }
  if (Test-IsWindowsMaintenanceNoise -Script $script) { continue }
  # skip this hunt tool (4104 logs it too) and old $pattern=@(...) hunters
  if ($script -match '(?i)BypassMagister|PWSHOperational|hunt-ps4104') { continue }
  if ($script -match '(?i)Get-WinEvent' -and $script -match '4104' -and $script -match 'FilterXPath') { continue }
  if ($script -match '\$pattern\s*=\s*@\(' -and $script -match 'FromBase64String') { continue }
  if ($script -match 'function _s' -and $script -match 'byHash') { continue }
  if ($script -match '(?i)Y-ClipBoard|MemScan::Dump') { continue }
  if ($script -notmatch $rx) { continue }

  $score = 0
  foreach ($r in $rules) {
    $gRx = ($r.P -join '|')
    if ($script -match ("(?i){0}" -f $gRx)) { $score += [int]$r.W }
  }

  $a = _s 70,114,111,109,66,97,115,101,54,52,83,116,114,105,110,103
  $b = (_s 71,122,105,112,83,116,114,101,97,109) + '|' + (_s 68,101,102,108,97,116,101,83,116,114,101,97,109) + '|' + (_s 98,120,111,114) + '|' + (_s 92,98,73,69,88,92,98) + '|' + (_s 73,110,118,111,107,101,45,69,120,112,114,101,115,115,105,111,110)
  if ($script -match ("(?i){0}" -f $a) -and $script -match ("(?i){0}" -f $b)) { $score += 10 }
  $c = (_s 65,109,115,105,85,116,105,108,115) + '|' + (_s 97,109,115,105,73,110,105,116,70,97,105,108,101,100)
  if ($script -match ("(?i){0}" -f $c)) { $score += 10 }
  $d = (_s 86,105,114,116,117,97,108,65,108,108,111,99) + '|' + (_s 87,114,105,116,101,80,114,111,99,101,115,115,77,101,109,111,114,121) + '|' + (_s 67,114,101,97,116,101,82,101,109,111,116,101,84,104,114,101,97,100)
  if ($script -match ("(?i){0}" -f $d)) { $score += 10 }

  $norm = ($script -replace '\s+', ' ').Trim()
  if ($norm.Length -gt 4000) { $norm = $norm.Substring(0, 4000) }
  $hash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($norm))).Replace('-', '').Substring(0, 16)

  $matched = @([regex]::Matches($script, $rx, 'IgnoreCase') | ForEach-Object { $_.Value } | Sort-Object -Unique)
  $hitsLine = $matched -join ', '
  $verdict = Get-BlockVerdict -Script $script -Score $score
  if ($verdict -like 'NOISE*') { continue }

  $item = [pscustomobject]@{
    TimeCreated = [datetime]$e.TimeCreated
    Score       = [int]$score
    Verdict     = [string]$verdict
    Hash        = [string]$hash
    Hits        = [string]$hitsLine
    Script      = [string]$script
  }

  if (-not $byHash.ContainsKey($hash)) {
    $byHash[$hash] = New-Object System.Collections.Generic.List[object]
  }
  $byHash[$hash].Add($item)
}

if ($byHash.Count -eq 0) {
  [IO.File]::WriteAllText($outFile, 'no hits', [Text.UTF8Encoding]::new($false))
  Write-Host 'done' -ForegroundColor Yellow
  return
}

$summary = New-Object System.Collections.Generic.List[object]
foreach ($key in $byHash.Keys) {
  $g = $byHash[$key]
  $maxScore = 0
  $first = $g[0].TimeCreated
  $last  = $g[0].TimeCreated
  $scriptText = $g[0].Script
  $scriptTextHits = $g[0].Hits
  foreach ($item in $g) {
    if ($item.Score -gt $maxScore) { $maxScore = $item.Score }
    if ($item.TimeCreated -lt $first) { $first = $item.TimeCreated }
    if ($item.TimeCreated -gt $last) {
      $last = $item.TimeCreated
      $scriptText = $item.Script
      $scriptTextHits = $item.Hits
    }
  }
  $verdict = Get-BlockVerdict -Script $scriptText -Score $maxScore
  $summary.Add([pscustomobject]@{
      Count     = $g.Count
      Score     = $maxScore
      Verdict   = $verdict
      FirstSeen = $first
      LastSeen  = $last
      Hash      = $key
      Hits      = $scriptTextHits
      Script    = $scriptText
    })
}

# sort: score desc, then lastseen desc (manual — avoids Sort-Object type bugs)
$sorted = @($summary.ToArray() | Sort-Object -Property Score -Descending)
for ($i = 0; $i -lt $sorted.Length; ) {
  $j = $i
  while ($j -lt $sorted.Length -and $sorted[$j].Score -eq $sorted[$i].Score) { $j++ }
  if ($j - $i -gt 1) {
    $chunk = @($sorted[$i..($j - 1)] | Sort-Object -Property LastSeen -Descending)
    for ($k = 0; $k -lt $chunk.Length; $k++) { $sorted[$i + $k] = $chunk[$k] }
  }
  $i = $j
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('love bypass by BypassMagister')
[void]$sb.AppendLine(("host {0} | {1:yyyy-MM-dd HH:mm:ss} | window last {2} days | blocks {3}" -f $env:COMPUTERNAME, (Get-Date), $daysBack, $sorted.Length))
[void]$sb.AppendLine('verdict: CRITICAL-LOADER / FILELESS-STAGER / CHEAT-CLICKER = real alert | REVIEW* = check | NOISE* filtered out')
[void]$sb.AppendLine('')

[void]$sb.AppendLine('=== Alerts (review first) ===')
foreach ($s in $sorted) {
  if ($s.Verdict -notmatch '^(CRITICAL|FILELESS|CHEAT|REVIEW)') { continue }
  [void]$sb.AppendLine((
      '[{0}] x{1} score={2} | {3:yyyy-MM-dd HH:mm} .. {4:yyyy-MM-dd HH:mm} | {5}' -f
      $s.Verdict, $s.Count, $s.Score, $s.FirstSeen, $s.LastSeen, $s.Hits
    ))
}
[void]$sb.AppendLine('')
[void]$sb.AppendLine('=== All kept blocks ===')
foreach ($s in $sorted) {
  [void]$sb.AppendLine((
      '[{0}] x{1} score={2} | {3:yyyy-MM-dd HH:mm} .. {4:yyyy-MM-dd HH:mm} | {5}' -f
      $s.Verdict, $s.Count, $s.Score, $s.FirstSeen, $s.LastSeen, $s.Hits
    ))
}
[void]$sb.AppendLine('')
[void]$sb.AppendLine('=== Full script blocks (alerts + stagers only) ===')
[void]$sb.AppendLine('')

foreach ($s in $sorted) {
  if ($s.Verdict -notmatch '^(CRITICAL|FILELESS|CHEAT|REVIEW-HIGH)') { continue }
  [void]$sb.AppendLine(('=' * 72))
  [void]$sb.AppendLine(("verdict {0} | score {1} | x{2} | {3:yyyy-MM-dd HH:mm:ss} .. {4:yyyy-MM-dd HH:mm:ss} | {5}" -f $s.Verdict, $s.Score, $s.Count, $s.FirstSeen, $s.LastSeen, $s.Hash))
  [void]$sb.AppendLine($s.Script)
  [void]$sb.AppendLine('')
}

[IO.File]::WriteAllText($outFile, $sb.ToString(), [Text.UTF8Encoding]::new($false))
Write-Host ''
Write-Host ("=== last {0} days ===" -f $daysBack) -ForegroundColor Cyan
foreach ($s in $sorted) {
  if ($s.Verdict -notmatch '^(CRITICAL|FILELESS|CHEAT|REVIEW)') { continue }
  Write-Host ('[{0}] x{1} score={2} | {3:yyyy-MM-dd HH:mm} .. {4:yyyy-MM-dd HH:mm} | {5}' -f $s.Verdict, $s.Count, $s.Score, $s.FirstSeen, $s.LastSeen, $s.Hits)
}
Write-Host ("blocks {0} | {1}" -f $sorted.Length, $outFile) -ForegroundColor Green
