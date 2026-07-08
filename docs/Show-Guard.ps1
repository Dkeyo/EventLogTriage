<#
    Show-Guard.ps1 — demonstrates the validation layer rejecting fabricated MITRE IDs.
    The model's reply is mocked (via Pester) so this runs without Ollama: it forces a reply
    that mixes one real ID with two fabricated ones and shows the guard keeping only the real
    one. Run from the repo root:

        .\docs\Show-Guard.ps1
#>
[CmdletBinding()]
param()

$moduleRoot = Split-Path $PSScriptRoot -Parent

$container = New-PesterContainer -ScriptBlock {
    param($ModuleRoot)

    BeforeAll { Import-Module (Join-Path $ModuleRoot 'EventLogTriage.psd1') -Force }

    Describe 'Hallucination guard' {
        It 'keeps the real ID and rejects the fabricated ones' {
            Mock -ModuleName EventLogTriage Invoke-RestMethod {
                [PSCustomObject]@{ response = '{"Classification":"MALICIOUS","MitreTechniques":["T1059.001","T1337","T9999"],"Reasoning":"Hidden encoded PowerShell, likely malicious."}' }
            }
            $ev = [PSCustomObject]@{
                Computer='WIN11-EP01'; TimeCreated=(Get-Date); EventId=1; RecordId=9773
                EventTask='Process Create'
                Data=@{ Image='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; CommandLine='powershell.exe -nop -w hidden -enc SQBFAFgA' }
            }
            $r = $ev | Invoke-EventClassification

            Write-Host ""
            Write-Host "  Model returned        : T1059.001, T1337, T9999" -ForegroundColor Yellow
            Write-Host ("  Classification        : {0}" -f $r.Classification)
            Write-Host ("  MitreTechniques       : {0}   (kept, real)" -f ($r.MitreTechniques -join ', ')) -ForegroundColor Green
            Write-Host ("  RejectedTechniques    : {0}   (fabricated, blocked)" -f ($r.RejectedTechniques -join ', ')) -ForegroundColor Red
            Write-Host ("  HallucinationDetected : {0}" -f $r.HallucinationDetected) -ForegroundColor Red
            Write-Host ""

            $r.RejectedTechniques | Should -Contain 'T9999'
            $r.RejectedTechniques | Should -Contain 'T1337'
            $r.MitreTechniques    | Should -Contain 'T1059.001'
            $r.HallucinationDetected | Should -BeTrue
        }
    }
} -Data @{ ModuleRoot = $moduleRoot }

Write-Host "============================================================" -ForegroundColor DarkCyan
Write-Host " EventLogTriage - validation guard (fabricated IDs rejected)" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor DarkCyan

$cfg = New-PesterConfiguration
$cfg.Run.Container = $container
$cfg.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $cfg | Out-Null
