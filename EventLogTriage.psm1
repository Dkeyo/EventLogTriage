#requires -Version 5.1

# ---------------------------------------------------------------------------
# Module-scoped constants. Centralised here so no function carries magic
# values, and so collection behaviour can be tuned in one place.
# ---------------------------------------------------------------------------
$script:SysmonLogName         = 'Microsoft-Windows-Sysmon/Operational'
$script:DefaultMaxEvents      = 100
$script:DefaultHoursBack      = 1
$script:DefaultSysmonEventIds = @(1, 3, 7, 10, 11, 22)

# Names that mean "this machine" -> collect locally with Get-WinEvent instead of WinRM.
$script:LocalComputerNames    = @('localhost', '127.0.0.1', '::1', '.', $env:COMPUTERNAME)

# WinRM diagnostics (Test-WinRMConnection).
$script:WinRMDefaultPort      = 5985
$script:TrustedHostsPath      = 'WSMan:\localhost\Client\TrustedHosts'

# Ollama diagnostics (Test-OllamaConnection).
$script:OllamaDefaultUri      = 'http://localhost:11434'
$script:OllamaDefaultModel    = 'llama3.1:8b-instruct-q4_K_M'

# ---------------------------------------------------------------------------
# Dot-source public and private function files.
# ---------------------------------------------------------------------------
$public  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter '*.ps1' -ErrorAction SilentlyContinue)
$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in @($public + $private)) {
    try {
        . $file.FullName
    }
    catch {
        throw "Failed to import function file '$($file.FullName)': $($_.Exception.Message)"
    }
}

# Export only the public functions. The manifest's FunctionsToExport is the
# authoritative gate; this keeps direct dot-sourcing of the .psm1 consistent.
Export-ModuleMember -Function $public.BaseName
