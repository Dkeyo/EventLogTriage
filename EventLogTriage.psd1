@{
    RootModule        = 'EventLogTriage.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '7c9e6a2b-4f3d-4a1e-9b8c-2d5f6a1e3c4d'
    Author            = 'Dawid Kowal'
    CompanyName       = ''
    Copyright         = '(c) 2026 Dawid Kowal. All rights reserved.'
    Description       = 'AI-assisted SOC triage for Sysmon events. Classifies endpoint telemetry with a local LLM (Ollama) and validates the model''s MITRE ATT&CK output against a curated allowlist to catch hallucinated technique IDs.'

    PowerShellVersion = '5.1'

    # Only functions that currently exist are exported. Get-MitreAllowlist is a private
    # helper (Private/), dot-sourced but deliberately not exported.
    FunctionsToExport = @('Get-RecentSysmonEvents', 'Test-WinRMConnection', 'Test-OllamaConnection', 'Format-EventForLLM', 'Invoke-EventClassification')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    RequiredModules   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Security', 'SOC', 'MITRE', 'ATTACK', 'Sysmon', 'Ollama', 'LLM', 'Triage', 'DFIR')
            ProjectUri   = 'https://github.com/Dkeyo/EventLogTriage'
            LicenseUri   = 'https://github.com/Dkeyo/EventLogTriage/blob/main/LICENSE'
            ReleaseNotes = 'Sysmon event collection (local and WinRM remote), tri-state WinRM and Ollama diagnostics, and the LLM triage layer: constrained-choice prompt building plus classification with every MITRE ATT&CK ID validated against a curated allowlist to catch hallucinated techniques. Pester v5 coverage across all functions.'
        }
    }
}
