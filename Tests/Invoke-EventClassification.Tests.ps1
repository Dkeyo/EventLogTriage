#Requires -Modules Pester

BeforeAll {
    # Invoke-EventClassification depends on Format-EventForLLM (prompt build) and
    # Get-MitreAllowlist (validation), so dot-source all three. Mirrors the existing
    # pattern: dot-source the functions directly, re-declare $script: constants, Mock
    # Invoke-RestMethod directly. No Import-Module, no InModuleScope.
    . "$PSScriptRoot/../Private/Get-MitreAllowlist.ps1"
    . "$PSScriptRoot/../Public/Format-EventForLLM.ps1"
    . "$PSScriptRoot/../Public/Invoke-EventClassification.ps1"

    # Ollama defaults so -Model / -Uri resolve without a real module load.
    $script:OllamaDefaultUri   = 'http://localhost:11434'
    $script:OllamaDefaultModel = 'llama3.1:8b-instruct-q4_K_M'

    # Point at the REAL allowlist so validation runs against the genuine 37 IDs
    # (T1059.001 and T1105 are present; T9999 and T1160 are not). Empty cache so runs
    # are independent.
    $script:MitreAllowlistPath  = "$PSScriptRoot/../Data/valid-mitre-techniques.json"
    $script:MitreAllowlistCache = @{}

    # A normalised ProcessCreate event shaped like Get-RecentSysmonEvents output.
    function New-ProcessCreateEvent {
        [PSCustomObject]@{
            Computer    = 'WIN11-EP01'
            TimeCreated = [datetime]'2026-07-06T09:00:00'
            EventId     = 1
            RecordId    = 4242
            EventTask   = 'Process Create (rule: ProcessCreate)'
            Data        = @{
                Image             = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
                CommandLine       = 'powershell -enc SQBFAFgA'
                ParentImage       = 'C:\Windows\System32\cmd.exe'
                ParentCommandLine = 'cmd.exe /c start'
                User              = 'RENOMA\Administrator'
            }
        }
    }

    # Wrap a model answer the way Ollama /api/generate does: { response = '<json string>' }.
    function New-GenerateResponse {
        param([string]$Json)
        [PSCustomObject]@{ response = $Json }
    }
}

Describe 'Invoke-EventClassification' {

    BeforeEach {
        $script:MitreAllowlistPath  = "$PSScriptRoot/../Data/valid-mitre-techniques.json"
        $script:MitreAllowlistCache = @{}
    }

    Context 'Model returns a valid technique ID' {
        BeforeEach {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json '{"Classification":"SUSPICIOUS","MitreTechniques":["T1059.001"],"Reasoning":"Encoded PowerShell command."}'
            }
        }

        It 'keeps the ID, flags no hallucination, and reports Classified' {
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.Status                | Should -Be 'Classified'
            $r.Classification        | Should -Be 'SUSPICIOUS'
            $r.MitreTechniques       | Should -Contain 'T1059.001'
            @($r.MitreTechniques).Count | Should -Be 1
            $r.RejectedTechniques    | Should -BeNullOrEmpty
            $r.HallucinationDetected | Should -BeFalse
            $r.Reasoning             | Should -BeLike '*Encoded PowerShell*'
            $r.Error                 | Should -BeNullOrEmpty
        }

        It 'POSTs to /api/generate with the generous timeout, json format, and no-stream body' {
            $null = Invoke-EventClassification -Event (New-ProcessCreateEvent) -TimeoutSec 120
            Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'http://localhost:11434/api/generate' -and
                $Method -eq 'Post' -and
                $TimeoutSec -eq 120 -and
                $ContentType -eq 'application/json' -and
                $Body -is [string] -and
                $Body -like '*"format":*json*' -and
                $Body -like '*"stream":*false*' -and
                $Body -like '*"model":*'
            }
        }

        It 'does not produce a double slash when -Uri carries a trailing slash' {
            $null = Invoke-EventClassification -Event (New-ProcessCreateEvent) -Uri 'http://localhost:11434/'
            Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'http://localhost:11434/api/generate'
            }
        }

        It 'echoes the requested model onto the result and into the body' {
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent) -Model 'qwen2.5:14b-instruct-q4_K_M'
            $r.Model | Should -Be 'qwen2.5:14b-instruct-q4_K_M'
            Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Body -like '*qwen2.5:14b-instruct-q4_K_M*'
            }
        }
    }

    Context 'Model fabricates a technique ID (the hallucination guard)' {
        BeforeEach {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json '{"Classification":"MALICIOUS","MitreTechniques":["T9999"],"Reasoning":"Invented technique."}'
            }
        }

        It 'moves the fake ID to RejectedTechniques, excludes it from MitreTechniques, and flags hallucination' {
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.Status                | Should -Be 'Classified'
            $r.MitreTechniques       | Should -Not -Contain 'T9999'
            $r.MitreTechniques       | Should -BeNullOrEmpty
            $r.RejectedTechniques    | Should -Contain 'T9999'
            $r.HallucinationDetected | Should -BeTrue
        }
    }

    Context 'Model returns a mix of real and fabricated IDs' {
        BeforeEach {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json '{"Classification":"MALICIOUS","MitreTechniques":["T1059.001","T1160","T1105"],"Reasoning":"Mixed."}'
            }
        }

        It 'keeps the real IDs and rejects only the fabricated one' {
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            # T1059.001 and T1105 are real; T1160 is the exact ID Llama 3.1 8B fabricated.
            $r.MitreTechniques       | Should -Contain 'T1059.001'
            $r.MitreTechniques       | Should -Contain 'T1105'
            $r.MitreTechniques       | Should -Not -Contain 'T1160'
            $r.RejectedTechniques    | Should -Contain 'T1160'
            $r.RejectedTechniques    | Should -Not -Contain 'T1059.001'
            $r.HallucinationDetected | Should -BeTrue
            @($r.MitreTechniques).Count    | Should -Be 2
            @($r.RejectedTechniques).Count | Should -Be 1
        }
    }

    Context 'Model returns an empty technique array (no technique applies)' {
        BeforeEach {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json '{"Classification":"BENIGN","MitreTechniques":[],"Reasoning":"Routine activity."}'
            }
        }

        It 'is Classified with no techniques and no hallucination' {
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.Status                      | Should -Be 'Classified'
            $r.Classification              | Should -Be 'BENIGN'
            @($r.MitreTechniques).Count    | Should -Be 0
            @($r.RejectedTechniques).Count | Should -Be 0
            $r.HallucinationDetected       | Should -BeFalse
        }
    }

    Context 'Model reply surrounded by noise (tolerant JSON extraction)' {
        BeforeEach {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json "Sure, here is the classification:`n`n{`"Classification`":`"SUSPICIOUS`",`"MitreTechniques`":[`"T1059.001`"],`"Reasoning`":`"ok`"}`n`nHope that helps."
            }
        }

        It 'extracts the embedded JSON object from leading and trailing text' {
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.Status          | Should -Be 'Classified'
            $r.Classification  | Should -Be 'SUSPICIOUS'
            $r.MitreTechniques | Should -Contain 'T1059.001'
        }
    }

    Context 'Model returns junk (no JSON object)' {
        BeforeEach {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json 'I am not going to answer that.'
            }
        }

        It 'reports Status Error without throwing and preserves the raw reply for audit' {
            { Invoke-EventClassification -Event (New-ProcessCreateEvent) } | Should -Not -Throw
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.Status         | Should -Be 'Error'
            $r.Classification | Should -BeNullOrEmpty
            $r.Error          | Should -Not -BeNullOrEmpty
            $r.RawResponse    | Should -BeLike '*not going to answer*'
        }
    }

    Context 'Model returns a brace-matched but unparseable JSON reply' {
        BeforeEach {
            Mock Invoke-RestMethod {
                # Has braces (so extraction matches) but the content between them is invalid JSON.
                New-GenerateResponse -Json '{ Classification: MALICIOUS, oops }'
            }
        }

        It 'reports Status Error and does not throw' {
            { Invoke-EventClassification -Event (New-ProcessCreateEvent) } | Should -Not -Throw
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.Status | Should -Be 'Error'
            $r.Error  | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Model returns a bare JSON array (non-object)' {
        BeforeEach {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json '["T1059.001"]'
            }
        }

        It 'reports Status Error because a non-object reply is not a classification' {
            { Invoke-EventClassification -Event (New-ProcessCreateEvent) } | Should -Not -Throw
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.Status | Should -Be 'Error'
        }
    }

    Context 'Ollama is unreachable (Invoke-RestMethod throws)' {
        BeforeEach {
            Mock Invoke-RestMethod { throw 'Unable to connect to the remote server' }
        }

        It 'returns Status Error, populates Error, and does not throw' {
            { Invoke-EventClassification -Event (New-ProcessCreateEvent) } | Should -Not -Throw
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.Status         | Should -Be 'Error'
            $r.Error          | Should -BeLike '*Unable to connect*'
            $r.Classification | Should -BeNullOrEmpty
            @($r.MitreTechniques).Count | Should -Be 0
        }

        It 'still carries event provenance on the error result so the caller can pivot back' {
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.Computer | Should -Be 'WIN11-EP01'
            $r.EventId  | Should -Be 1
            $r.RecordId | Should -Be 4242
            $r.Model    | Should -Be 'llama3.1:8b-instruct-q4_K_M'
        }
    }

    Context 'Preliminary allowlist populates MitreNote' {
        BeforeEach {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json '{"Classification":"BENIGN","MitreTechniques":[],"Reasoning":"Routine."}'
            }
        }

        It 'sets MitreNote from the preliminary verificationStatus (CLAUDE.md decision 1)' {
            # The real Data file ships verificationStatus 'preliminary-2026-06-17'.
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.MitreNote | Should -Not -BeNullOrEmpty
            $r.MitreNote | Should -BeLike '*preliminary*'
        }

        It 'leaves MitreNote empty when the loaded allowlist is verified, not preliminary' {
            # Repoint at a verified temp allowlist; path-keyed cache treats it as a miss.
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
                $script:MitreAllowlistCache = @{}
                $script:MitreAllowlistPath  = $tempPath
                $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
                $r.MitreNote | Should -BeNullOrEmpty
            }
            finally {
                $script:MitreAllowlistPath = $savedPath
            }
        }
    }

    Context 'Event provenance is copied onto the successful result' {
        BeforeEach {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json '{"Classification":"SUSPICIOUS","MitreTechniques":["T1059.001"],"Reasoning":"x"}'
            }
        }

        It 'copies Computer, TimeCreated, EventId and RecordId from the source event' {
            $event = New-ProcessCreateEvent
            $r = Invoke-EventClassification -Event $event
            $r.Computer    | Should -Be 'WIN11-EP01'
            $r.EventId     | Should -Be 1
            $r.RecordId    | Should -Be 4242
            $r.TimeCreated | Should -Be ([datetime]'2026-07-06T09:00:00')
        }
    }

    Context 'Pipeline processes a batch' {
        BeforeEach {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json '{"Classification":"BENIGN","MitreTechniques":[],"Reasoning":"Routine."}'
            }
        }

        It 'returns one result per piped event' {
            $e1 = New-ProcessCreateEvent
            $e2 = New-ProcessCreateEvent
            $e2.RecordId = 5555

            $results = @($e1, $e2 | Invoke-EventClassification)
            @($results).Count    | Should -Be 2
            $results[0].RecordId | Should -Be 4242
            $results[1].RecordId | Should -Be 5555
            $results[0].Status   | Should -Be 'Classified'
            $results[1].Status   | Should -Be 'Classified'
            Should -Invoke Invoke-RestMethod -Times 2 -Exactly
        }

        It 'keeps going when one event fails mid-batch (non-throwing per event)' {
            # First call throws (Ollama hiccup), second succeeds. The batch must yield two
            # results: one Error, one Classified. This is the property that lets a caller
            # pipe a hundred events and filter failures afterwards.
            $script:callCount = 0
            Mock Invoke-RestMethod {
                $script:callCount++
                if ($script:callCount -eq 1) { throw 'transient network blip' }
                New-GenerateResponse -Json '{"Classification":"BENIGN","MitreTechniques":[],"Reasoning":"ok"}'
            }

            $e1 = New-ProcessCreateEvent
            $e2 = New-ProcessCreateEvent
            $results = @($e1, $e2 | Invoke-EventClassification)
            @($results).Count | Should -Be 2
            @($results | Where-Object { $_.Status -eq 'Error' }).Count      | Should -Be 1
            @($results | Where-Object { $_.Status -eq 'Classified' }).Count | Should -Be 1
        }
    }

    Context 'Classification label validation' {
        It 'normalises a lower-case valid label to upper-case with no hallucination flag' {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json '{"Classification":"malicious","MitreTechniques":[],"Reasoning":"ok"}'
            }
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.Classification        | Should -Be 'MALICIOUS'
            $r.HallucinationDetected | Should -BeFalse
        }

        It 'flags an out-of-set Classification label as a hallucination but keeps the value' {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json '{"Classification":"DANGEROUS","MitreTechniques":[],"Reasoning":"ok"}'
            }
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.Status                | Should -Be 'Classified'
            $r.Classification        | Should -Be 'DANGEROUS'
            $r.HallucinationDetected | Should -BeTrue
        }

        It 'flags a reply whose Classification field is absent' {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json '{"MitreTechniques":["T1059.001"],"Reasoning":"ok"}'
            }
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.Status                | Should -Be 'Classified'
            $r.Classification        | Should -BeNullOrEmpty
            $r.HallucinationDetected | Should -BeTrue
            # A valid technique is still validated and kept.
            $r.MitreTechniques       | Should -Contain 'T1059.001'
        }
    }

    Context 'Technique ID normalisation and de-duplication' {
        It 'keeps a wrong-case real ID, normalised to the allowlist canonical casing, with no flag' {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json '{"Classification":"SUSPICIOUS","MitreTechniques":["t1059.001"],"Reasoning":"ok"}'
            }
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.MitreTechniques       | Should -Contain 'T1059.001'
            # Stored as the exact canonical casing (-Contain is case-insensitive, so assert
            # the literal string with -ceq to prove the lowercased input was normalised).
            ($r.MitreTechniques[0] -ceq 'T1059.001') | Should -BeTrue
            $r.HallucinationDetected | Should -BeFalse
            @($r.MitreTechniques).Count | Should -Be 1
        }

        It 'de-duplicates a repeated valid ID so the count is not inflated' {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json '{"Classification":"MALICIOUS","MitreTechniques":["T1105","T1105","t1105"],"Reasoning":"ok"}'
            }
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            @($r.MitreTechniques).Count | Should -Be 1
            $r.MitreTechniques          | Should -Contain 'T1105'
        }

        It 'accepts MitreTechniques returned as a bare string rather than an array' {
            Mock Invoke-RestMethod {
                New-GenerateResponse -Json '{"Classification":"SUSPICIOUS","MitreTechniques":"T1059.001","Reasoning":"ok"}'
            }
            $r = Invoke-EventClassification -Event (New-ProcessCreateEvent)
            $r.MitreTechniques          | Should -Contain 'T1059.001'
            @($r.MitreTechniques).Count | Should -Be 1
            $r.HallucinationDetected    | Should -BeFalse
        }
    }
}