#Requires -Modules Pester

# Package-level smoke test. Unlike the per-function suites (which dot-source individual
# files), this imports the real module through the manifest and asserts it packages and
# exports what it claims. A broken manifest, a bad Export-ModuleMember, or a psm1
# dot-source regression would otherwise ship green.

BeforeAll {
    $script:ManifestPath = "$PSScriptRoot/../EventLogTriage.psd1"
    Import-Module $script:ManifestPath -Force
}

AfterAll {
    Remove-Module EventLogTriage -Force -ErrorAction SilentlyContinue
}

Describe 'Module packaging' {

    It 'has a valid manifest' {
        { Test-ModuleManifest -Path $script:ManifestPath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'imports and is loaded' {
        Get-Module EventLogTriage | Should -Not -BeNullOrEmpty
    }

    It 'exports exactly the five public functions' {
        $exported = (Get-Command -Module EventLogTriage -CommandType Function).Name | Sort-Object
        $expected = @(
            'Format-EventForLLM'
            'Get-RecentSysmonEvents'
            'Invoke-EventClassification'
            'Test-OllamaConnection'
            'Test-WinRMConnection'
        ) | Sort-Object
        $exported | Should -Be $expected
    }

    It 'does not export the private Get-MitreAllowlist helper' {
        Get-Command Get-MitreAllowlist -Module EventLogTriage -ErrorAction SilentlyContinue |
            Should -BeNullOrEmpty
    }

    It 'exposes comment-based help on every public function' {
        foreach ($name in (Get-Command -Module EventLogTriage -CommandType Function).Name) {
            (Get-Help $name).Synopsis | Should -Not -BeNullOrEmpty -Because "$name should have a .SYNOPSIS"
        }
    }
}
