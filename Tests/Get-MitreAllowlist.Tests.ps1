#Requires -Modules Pester

BeforeAll {
    . "$PSScriptRoot/../Private/Get-MitreAllowlist.ps1"

    # Re-declare the module-scoped constants the loader reads, pointing MitreAllowlistPath
    # at the REAL allowlist so the genuine 37-technique list loads, and starting from an
    # empty cache so runs are independent. Mirrors the dot-source + re-declare pattern used
    # by the other suites (no Import-Module, no InModuleScope).
    $script:MitreAllowlistPath  = "$PSScriptRoot/../Data/valid-mitre-techniques.json"
    $script:MitreAllowlistCache = @{}
}

Describe 'Get-MitreAllowlist' {

    Context 'Loading the real allowlist' {
        BeforeEach {
            $script:MitreAllowlistPath  = "$PSScriptRoot/../Data/valid-mitre-techniques.json"
            $script:MitreAllowlistCache = @{}
        }

        It 'returns a single parsed object, not an array' {
            $allowlist = Get-MitreAllowlist
            # A stray pipeline emission in the loader would make this an Object[] and break
            # every downstream '$allowlist.techniques' access, so pin the cardinality.
            @($allowlist).Count | Should -Be 1
            $allowlist          | Should -Not -BeNullOrEmpty
        }

        It 'exposes the top-level verificationStatus and schemaVersion from the file' {
            $allowlist = Get-MitreAllowlist
            $allowlist.verificationStatus | Should -BeLike 'preliminary*'
            $allowlist.schemaVersion      | Should -Be '1.0'
        }

        It 'returns exactly 37 techniques keyed by ID' {
            $allowlist = Get-MitreAllowlist
            $ids = $allowlist.techniques.PSObject.Properties.Name
            @($ids).Count | Should -Be 37
        }

        It 'keys techniques by their ID with a canonical name value' {
            $allowlist = Get-MitreAllowlist
            $allowlist.techniques.PSObject.Properties.Name | Should -Contain 'T1059.001'
            $allowlist.techniques.'T1059.001'.name         | Should -Be 'Command and Scripting Interpreter: PowerShell'
            $allowlist.techniques.'T1003.001'.name         | Should -Be 'OS Credential Dumping: LSASS Memory'
        }
    }

    Context 'Caching' {
        It 'serves the second call from cache after the source file is deleted' {
            # Load once from a temp file, delete the file, then call again for the SAME path.
            # A cache hit returns the parse without touching the (now absent) file; a cache
            # miss would throw 'allowlist not found'. This proves the load is cached per path.
            $tempPath = Join-Path $TestDrive 'cache-me.json'
            $body = [ordered]@{
                schemaVersion      = '1.0'
                verificationStatus = 'verified-2026-07-01'
                techniques         = [ordered]@{
                    T1059 = [ordered]@{ name = 'Command and Scripting Interpreter'; tactics = @('Execution'); sysmonEvents = @(1) }
                }
            }
            $body | ConvertTo-Json -Depth 6 | Set-Content -Path $tempPath -Encoding UTF8

            $savedPath = $script:MitreAllowlistPath
            try {
                $script:MitreAllowlistPath  = $tempPath
                $script:MitreAllowlistCache = @{}

                $first = Get-MitreAllowlist
                $first.verificationStatus | Should -Be 'verified-2026-07-01'

                Remove-Item -LiteralPath $tempPath -Force
                { Get-MitreAllowlist } | Should -Not -Throw

                $second = Get-MitreAllowlist
                $second.verificationStatus | Should -Be 'verified-2026-07-01'
                # Same cached instance, not a re-parse.
                [object]::ReferenceEquals($first, $second) | Should -BeTrue
            }
            finally {
                $script:MitreAllowlistPath  = $savedPath
                $script:MitreAllowlistCache = @{}
            }
        }

        It 'keys the cache by path so repointing the constant loads the new file' {
            $savedPath = $script:MitreAllowlistPath
            try {
                $script:MitreAllowlistCache = @{}

                # First load: the real preliminary allowlist.
                $script:MitreAllowlistPath = "$PSScriptRoot/../Data/valid-mitre-techniques.json"
                $real = Get-MitreAllowlist
                $real.verificationStatus | Should -BeLike 'preliminary*'
                @($real.techniques.PSObject.Properties.Name).Count | Should -Be 37

                # Repoint at a different file. A path-keyed cache treats this as a miss and
                # loads the new file rather than returning the stale preliminary parse.
                $tempPath = Join-Path $TestDrive 'other.json'
                $body = [ordered]@{
                    schemaVersion      = '1.0'
                    verificationStatus = 'verified-2026-07-01'
                    techniques         = [ordered]@{ T9000 = [ordered]@{ name = 'Only In Temp File'; tactics = @('Execution'); sysmonEvents = @(1) } }
                }
                $body | ConvertTo-Json -Depth 6 | Set-Content -Path $tempPath -Encoding UTF8

                $script:MitreAllowlistPath = $tempPath
                $other = Get-MitreAllowlist
                $other.verificationStatus | Should -Be 'verified-2026-07-01'
                @($other.techniques.PSObject.Properties.Name) | Should -Be 'T9000'
            }
            finally {
                $script:MitreAllowlistPath  = $savedPath
                $script:MitreAllowlistCache = @{}
            }
        }
    }

    Context 'Misconfiguration throws with actionable messages' {
        It 'throws when the path constant is empty' {
            $savedPath = $script:MitreAllowlistPath
            try {
                $script:MitreAllowlistPath  = ''
                $script:MitreAllowlistCache = @{}
                { Get-MitreAllowlist } | Should -Throw -ExpectedMessage '*path is not configured*'
            }
            finally {
                $script:MitreAllowlistPath  = $savedPath
                $script:MitreAllowlistCache = @{}
            }
        }

        It 'throws a clear error when the allowlist file is missing' {
            $savedPath = $script:MitreAllowlistPath
            try {
                $script:MitreAllowlistPath  = Join-Path $TestDrive 'does-not-exist.json'
                $script:MitreAllowlistCache = @{}
                { Get-MitreAllowlist } | Should -Throw -ExpectedMessage '*allowlist not found*'
            }
            finally {
                $script:MitreAllowlistPath  = $savedPath
                $script:MitreAllowlistCache = @{}
            }
        }

        It 'throws a clear error when the allowlist file is not valid JSON' {
            $badPath = Join-Path $TestDrive 'broken.json'
            Set-Content -Path $badPath -Value '{ this is not json' -Encoding UTF8
            $savedPath = $script:MitreAllowlistPath
            try {
                $script:MitreAllowlistPath  = $badPath
                $script:MitreAllowlistCache = @{}
                { Get-MitreAllowlist } | Should -Throw -ExpectedMessage '*could not be parsed as JSON*'
            }
            finally {
                $script:MitreAllowlistPath  = $savedPath
                $script:MitreAllowlistCache = @{}
            }
        }
    }
}