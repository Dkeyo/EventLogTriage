<#
    Show-Pipeline.ps1 — traces one event through the whole EventLogTriage pipeline
    (collection -> prompt -> raw model reply -> validation -> MITRE mapping) and prints
    each stage. Run from the repo root with Ollama running:

        .\docs\Show-Pipeline.ps1

    The input is a representative sample event (a hidden, encoded PowerShell process) so
    the demo runs without the lab. The classification and MITRE validation are real: the
    prompt goes to the live local model and every returned ID is checked against the allowlist.
#>
[CmdletBinding()]
param(
    [string]$Model = 'llama3.1:8b-instruct-q4_K_M',
    [string]$Uri   = 'http://localhost:11434'
)

$moduleRoot = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $moduleRoot 'EventLogTriage.psd1') -Force

function Hdr($t) { Write-Host "`n$t" -ForegroundColor Cyan }

Write-Host "============================================================" -ForegroundColor DarkCyan
Write-Host " EventLogTriage - full pipeline trace (one sample event)"     -ForegroundColor White
Write-Host "============================================================" -ForegroundColor DarkCyan

$event = [PSCustomObject]@{
    Computer='WIN11-EP01'; TimeCreated=(Get-Date); EventId=1; RecordId=9773
    EventTask='Process Create (rule: ProcessCreate)'
    Data=@{ Image='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; CommandLine='powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwA'; ParentImage='C:\Windows\System32\cmd.exe'; User='RENOMA\Administrator' }
}

Hdr "[1] SAMPLE EVENT   (shape produced by Get-RecentSysmonEvents; see docs/real-detection.png for a live capture)"
Write-Host ("    Computer     : {0}" -f $event.Computer)
Write-Host ("    EventId      : {0} (Process Create)    RecordId : {1}" -f $event.EventId, $event.RecordId)
Write-Host ("    CommandLine  : {0}" -f $event.Data.CommandLine) -ForegroundColor Yellow
Write-Host ("    ParentImage  : {0}" -f $event.Data.ParentImage)

$p = $event | Format-EventForLLM
Hdr "[2] PROMPT   (Format-EventForLLM -> what the model sees)"
($p.User -split "`n") | ForEach-Object { Write-Host "    $_" }
$techCount = ([regex]::Matches($p.System,'T\d{4}')).Count
Write-Host ("    (system prompt embeds {0} MITRE techniques + strict-JSON rule)" -f $techCount) -ForegroundColor DarkGray

Hdr "[3] OLLAMA RAW REPLY   (untrusted model output)"
$body = @{ model=$Model; system=$p.System; prompt=$p.User; format='json'; stream=$false; options=@{temperature=0.1} } | ConvertTo-Json
$raw = (Invoke-RestMethod -Uri "$Uri/api/generate" -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 120).response
Write-Host "    $raw" -ForegroundColor Yellow

Hdr "[4] VALIDATED VERDICT   (Invoke-EventClassification)"
$r = $event | Invoke-EventClassification -Model $Model -Uri $Uri
Write-Host ("    Status: {0}   Classification: {1}" -f $r.Status, $r.Classification) -ForegroundColor Green
Write-Host ("    MitreTechniques: {{{0}}}   RejectedTechniques: {{{1}}}   HallucinationDetected: {2}" -f ($r.MitreTechniques -join ','), ($r.RejectedTechniques -join ','), $r.HallucinationDetected)

Hdr "[5] MITRE ATT&CK MAPPING"
$allow = Get-Content (Join-Path $moduleRoot 'Data\valid-mitre-techniques.json') -Raw | ConvertFrom-Json
foreach ($id in $r.MitreTechniques) {
    $t = $allow.techniques.$id
    Write-Host ("    {0} = {1}   [tactic: {2}]   [Sysmon Event: {3}]" -f $id, $t.name, ($t.tactics -join ','), ($t.sysmonEvents -join ',')) -ForegroundColor Green
}
Write-Host ""
