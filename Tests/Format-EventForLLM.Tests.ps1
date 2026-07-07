#Requires -Modules Pester

BeforeAll {
    # Format-EventForLLM now loads the allowlist through the shared Get-MitreAllowlist
    # helper, so dot-source BOTH: the private dependency first, then the function under
    # test. This mirrors how Test-WinRMConnection.Tests.ps1 / Test-OllamaConnection.Tests.ps1
    # re-declare $script: constants in BeforeAll and dot-source functions directly
    # (no Import-Module, no InModuleScope).
    . "$PSScriptRoot/../Private/Get-MitreAllowlist.ps1"
    . "$PSScriptRoot/../Public/Format-EventForLLM.ps1"

    # Re-declare the module-scoped constant the loader reads, pointing at the REAL
    # allowlist so the genuine 37-technique list and its preliminary status load.
    $script:MitreAllowlistPath = "$PSScriptRoot/../Data/valid-mitre-techniques.json"

    # Clear any cache carried over from a previous dot-source so runs are independent.
    $script:MitreAllowlistCache = @{}

    function New-ProcessCreateEvent {
        [PSCustomObject]@{
            Computer    = 'WIN11-EP01'
            TimeCreated = (Get-Date)
            EventId     = 1
            RecordId    = 1
            EventTask   = 'Process Create (rule: ProcessCreate)'
            Data        = @{
                Image             = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
                CommandLine       = 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA='
                ParentImage       = 'C:\Windows\System32\cmd.exe'
                ParentCommandLine = 'cmd.exe /c start'
                User              = 'RENOMA\Administrator'
            }
        }
    }

    # A realistic SwiftOnSecurity ProcessCreate event: the curated fields plus the
    # ~12 noise fields Sysmon emits per event. Used to prove noise exclusion.
    function New-NoisyProcessCreateEvent {
        [PSCustomObject]@{
            Computer    = 'WIN11-EP01'
            TimeCreated = (Get-Date)
            EventId     = 1
            RecordId    = 9
            EventTask   = 'Process Create (rule: ProcessCreate)'
            Data        = @{
                Image             = 'C:\Windows\System32\cmd.exe'
                CommandLine       = 'cmd.exe /c whoami'
                User              = 'RENOMA\Administrator'
                ProcessGuid       = '{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}'
                LogonGuid         = '{11111111-2222-3333-4444-555555555555}'
                IntegrityLevel    = 'Medium'
                Company           = 'Microsoft Corporation'
                Description       = 'Windows Command Processor'
                Product           = 'Microsoft Windows Operating System'
                FileVersion       = '10.0.26200.1'
                OriginalFileName  = 'Cmd.Exe'
                RuleName          = 'technique_id=T1059'
                UtcTime           = '2026-07-06 09:00:00.000'
                LogonId           = '0x3e7'
                TerminalSessionId = '1'
            }
        }
    }

    # Only EventId + Computer; empty Data hashtable, no TimeCreated, no EventTask.
    function New-SparseEvent {
        [PSCustomObject]@{
            Computer = 'WIN11-EP01'
            EventId  = 3
            Data     = @{}
        }
    }
}

Describe 'Format-EventForLLM' {

    Context 'Return shape' {
        It 'returns a hashtable with non-empty System and User strings' {
            $r = Format-EventForLLM -Event (New-ProcessCreateEvent)
            ($r -is [hashtable]) | Should -BeTrue
            $r.System            | Should -BeOfType [string]
            $r.User              | Should -BeOfType [string]
            $r.System            | Should -Not -BeNullOrEmpty
            $r.User              | Should -Not -BeNullOrEmpty
        }
    }

    Context 'System prompt (constrained choice and strict JSON)' {
        BeforeEach {
            $system = (Format-EventForLLM -Event (New-ProcessCreateEvent)).System
        }

        It 'names the SOC L1 triage role and the never-invent-IDs rule' {
            $system | Should -BeLike '*SOC L1 triage assistant*'
            $system | Should -BeLike '*NEVER invent*'
            $system | Should -BeLike '*ONLY*'
            $system | Should -BeLike '*Valid MITRE technique IDs*'
        }

        It 'embeds a real technique line built from the allowlist (id and canonical name)' {
            $system | Should -BeLike '*T1059*'
            $system | Should -BeLike '*Command and Scripting Interpreter*'
            $system | Should -BeLike '*T1059: Command and Scripting Interpreter*'
        }

        It 'lists many techniques, not just one' {
            # The real allowlist has 37 entries; assert several distinct IDs are present
            # so the block is clearly the whole list, not a single stray line.
            $system | Should -BeLike '*T1003*'
            $system | Should -BeLike '*T1071.004*'
            $system | Should -BeLike '*T1566.001*'
        }

        It 'specifies the strict-JSON response shape with all three fields' {
            $system | Should -BeLike '*STRICT JSON*'
            $system | Should -BeLike '*Classification*'
            $system | Should -BeLike '*MitreTechniques*'
            $system | Should -BeLike '*Reasoning*'
        }

        It 'constrains Classification to the three allowed labels' {
            $system | Should -BeLike '*BENIGN*'
            $system | Should -BeLike '*SUSPICIOUS*'
            $system | Should -BeLike '*MALICIOUS*'
        }
    }

    Context 'System prompt (preliminary caution)' {
        It 'includes the preliminary caution when the loaded allowlist is preliminary' {
            # The real Data file ships verificationStatus 'preliminary-2026-06-17'.
            $system = (Format-EventForLLM -Event (New-ProcessCreateEvent)).System
            $system | Should -BeLike '*CAUTION*'
            $system | Should -BeLike '*preliminary*'
            $system | Should -BeLike '*sanity-check*'
        }

        It 'omits the caution when the loaded allowlist status is not preliminary' {
            # Point the constant at a temp allowlist whose status is verified. The
            # path-keyed cache treats this new path as a miss, so the caution branch
            # is genuinely off rather than returning the real (preliminary) parse.
            $tempPath = Join-Path $TestDrive 'verified-mitre.json'
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
                $script:MitreAllowlistPath = $tempPath
                $system = (Format-EventForLLM -Event (New-ProcessCreateEvent)).System
                $system | Should -BeLike '*T1059: Command and Scripting Interpreter*'
                $system | Should -Not -BeLike '*CAUTION*'
                $system | Should -Not -BeLike '*preliminary*'
            }
            finally {
                $script:MitreAllowlistPath = $savedPath
            }
        }
    }

    Context 'User content (ProcessCreate)' {
        BeforeEach {
            $user = (Format-EventForLLM -Event (New-ProcessCreateEvent)).User
        }

        It 'contains the human EventId label and the event CommandLine and Image' {
            $user | Should -BeLike '*Process Create*'
            $user | Should -BeLike '*Event ID 1*'
            $user | Should -BeLike '*powershell.exe*'
            $user | Should -BeLike '*powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=*'
        }

        It 'includes the host, parent process, and user' {
            $user | Should -BeLike '*WIN11-EP01*'
            $user | Should -BeLike '*cmd.exe*'
            $user | Should -BeLike '*RENOMA\Administrator*'
        }

        It 'includes the event timestamp' {
            $user | Should -BeLike '*Time:*'
        }
    }

    Context 'User content (curated fields only, no hashtable dump)' {
        It 'keeps the curated fields and omits SwiftOnSecurity noise fields' {
            $user = (Format-EventForLLM -Event (New-NoisyProcessCreateEvent)).User
            $user | Should -BeLike '*cmd.exe /c whoami*'   # curated field kept
            $user | Should -Not -BeLike '*ProcessGuid*'
            $user | Should -Not -BeLike '*LogonGuid*'
            $user | Should -Not -BeLike '*IntegrityLevel*'
            $user | Should -Not -BeLike '*OriginalFileName*'
            $user | Should -Not -BeLike '*RuleName*'
            $user | Should -Not -BeLike '*UtcTime*'
            $user | Should -Not -BeLike '*TerminalSessionId*'
            $user | Should -Not -BeLike '*FileVersion*'
        }
    }

    Context 'User content (opt-in event types)' {
        It 'renders registry TargetObject and Details for a Registry Value Set event' {
            $regEvent = [PSCustomObject]@{
                Computer    = 'WIN11-EP01'
                TimeCreated = (Get-Date)
                EventId     = 13
                RecordId    = 20
                EventTask   = 'Registry value set (rule: RegistryEvent)'
                Data        = @{
                    Image        = 'C:\Windows\System32\reg.exe'
                    TargetObject = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run\evil'
                    Details      = 'C:\Users\Public\payload.exe'
                    EventType    = 'SetValue'
                    ProcessGuid  = '{deadbeef-0000-0000-0000-000000000000}'
                }
            }
            $user = (Format-EventForLLM -Event $regEvent).User
            $user | Should -BeLike '*Registry Value Set*'
            $user | Should -BeLike '*HKLM\Software\Microsoft\Windows\CurrentVersion\Run\evil*'
            $user | Should -BeLike '*C:\Users\Public\payload.exe*'
            $user | Should -Not -BeLike '*ProcessGuid*'
        }

        It 'renders StartModule and StartFunction for a CreateRemoteThread event' {
            $crtEvent = [PSCustomObject]@{
                Computer    = 'WIN11-EP01'
                TimeCreated = (Get-Date)
                EventId     = 8
                RecordId    = 21
                EventTask   = 'CreateRemoteThread detected (rule: CreateRemoteThread)'
                Data        = @{
                    SourceImage   = 'C:\malware\injector.exe'
                    TargetImage   = 'C:\Windows\System32\lsass.exe'
                    StartModule   = 'C:\Windows\System32\ntdll.dll'
                    StartFunction = 'RtlUserThreadStart'
                }
            }
            $user = (Format-EventForLLM -Event $crtEvent).User
            $user | Should -BeLike '*CreateRemoteThread*'
            $user | Should -BeLike '*C:\Windows\System32\ntdll.dll*'
            $user | Should -BeLike '*RtlUserThreadStart*'
            $user | Should -BeLike '*lsass.exe*'
        }

        It 'renders Data values that contain literal braces without throwing (GUID / CLSID path)' {
            # Sysmon values routinely carry braces (GUIDs, registry CLSID paths). The
            # formatter must not treat them as format-string placeholders. This is the
            # regression test for the -f FormatException fixed by using interpolation.
            $braceEvent = [PSCustomObject]@{
                Computer    = 'WIN11-EP01'
                TimeCreated = (Get-Date)
                EventId     = 13
                Data        = @{
                    TargetObject = 'HKLM\Software\Classes\CLSID\{00021401-0000-0000-C000-000000000046}'
                    Image        = 'C:\Windows\regedit.exe'
                }
            }
            { Format-EventForLLM -Event $braceEvent } | Should -Not -Throw
            $r = Format-EventForLLM -Event $braceEvent
            $r.User | Should -BeLike '*{00021401-0000-0000-C000-000000000046}*'
        }
    }

    Context 'User content (unusual EventId and blank values)' {
        It 'uses a generic label for an unmapped EventId and does not throw' {
            $unknown = [PSCustomObject]@{
                Computer    = 'WIN11-EP01'
                TimeCreated = (Get-Date)
                EventId     = 255
                Data        = @{ Image = 'C:\Windows\System32\rare.exe' }
            }
            { Format-EventForLLM -Event $unknown } | Should -Not -Throw
            $user = (Format-EventForLLM -Event $unknown).User
            $user | Should -BeLike '*Sysmon Event 255*'
            $user | Should -BeLike '*rare.exe*'
        }

        It 'skips a curated field whose value is null or whitespace rather than emitting a blank line' {
            $blanky = [PSCustomObject]@{
                Computer    = 'WIN11-EP01'
                TimeCreated = (Get-Date)
                EventId     = 1
                Data        = @{
                    Image       = 'C:\Windows\System32\cmd.exe'
                    CommandLine = $null
                    User        = '   '
                }
            }
            { Format-EventForLLM -Event $blanky } | Should -Not -Throw
            $user = (Format-EventForLLM -Event $blanky).User
            $user | Should -BeLike '*cmd.exe*'
            $user | Should -Not -BeLike '*CommandLine:*'
            $user | Should -Not -BeLike '*User:*'
        }
    }

    Context 'Pipeline input' {
        It 'accepts a single event from the pipeline and returns the hashtable' {
            $r = New-ProcessCreateEvent | Format-EventForLLM
            ($r -is [hashtable]) | Should -BeTrue
            $r.System            | Should -Not -BeNullOrEmpty
            $r.User              | Should -BeLike '*Process Create*'
        }

        It 'processes every event when a collection is piped (not just the last)' {
            # Two items so the process{} block is genuinely exercised: a single piped
            # item would pass even if only the last were bound.
            $results = @( (New-ProcessCreateEvent), (New-SparseEvent) | Format-EventForLLM )
            $results.Count | Should -Be 2
            $results[0]    | Should -BeOfType [hashtable]
            $results[1]    | Should -BeOfType [hashtable]
        }
    }

    Context 'Sparse and missing Data' {
        It 'does not throw on an event with only EventId + Computer and empty Data' {
            { Format-EventForLLM -Event (New-SparseEvent) } | Should -Not -Throw
        }

        It 'still labels the event and names the host for a sparse event' {
            $r = Format-EventForLLM -Event (New-SparseEvent)
            $r.System | Should -Not -BeNullOrEmpty
            $r.User   | Should -BeLike '*Network Connection*'
            $r.User   | Should -BeLike '*WIN11-EP01*'
        }

        It 'does not throw when Data is null' {
            $bare = [PSCustomObject]@{
                Computer    = 'WIN11-EP01'
                TimeCreated = (Get-Date)
                EventId     = 1
                RecordId    = 3
                EventTask   = $null
                Data        = $null
            }
            { Format-EventForLLM -Event $bare } | Should -Not -Throw
        }
    }

    Context 'Allowlist caching' {
        It 'reuses the cached parse on the second call without re-reading the file' {
            # Load once from a temp allowlist, then delete the file. A second call for
            # the same path must still return a valid prompt, proving the cache avoids
            # a re-read. The System string is byte-identical across the two calls.
            $tempPath = Join-Path $TestDrive 'cache-probe.json'
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
                $script:MitreAllowlistPath = $tempPath
                $first = (Format-EventForLLM -Event (New-ProcessCreateEvent)).System

                Remove-Item -LiteralPath $tempPath -Force
                { Format-EventForLLM -Event (New-ProcessCreateEvent) } | Should -Not -Throw
                $second = (Format-EventForLLM -Event (New-ProcessCreateEvent)).System

                $second | Should -Be $first
            }
            finally {
                $script:MitreAllowlistPath = $savedPath
            }
        }
    }

    Context 'Allowlist misconfiguration' {
        It 'throws a clear error when the allowlist file is missing' {
            $savedPath = $script:MitreAllowlistPath
            try {
                $script:MitreAllowlistPath = Join-Path $TestDrive 'does-not-exist.json'
                { Format-EventForLLM -Event (New-ProcessCreateEvent) } |
                    Should -Throw -ExpectedMessage '*allowlist not found*'
            }
            finally {
                $script:MitreAllowlistPath = $savedPath
            }
        }

        It 'throws a clear error when the allowlist file is not valid JSON' {
            $badPath = Join-Path $TestDrive 'broken.json'
            Set-Content -Path $badPath -Value '{ this is not json' -Encoding UTF8
            $savedPath = $script:MitreAllowlistPath
            try {
                $script:MitreAllowlistPath = $badPath
                { Format-EventForLLM -Event (New-ProcessCreateEvent) } |
                    Should -Throw -ExpectedMessage '*could not be parsed as JSON*'
            }
            finally {
                $script:MitreAllowlistPath = $savedPath
            }
        }
    }
}