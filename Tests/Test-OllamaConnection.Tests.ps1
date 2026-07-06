#Requires -Modules Pester

BeforeAll {
    . "$PSScriptRoot/../Public/Test-OllamaConnection.ps1"

    $script:OllamaDefaultUri   = 'http://localhost:11434'
    $script:OllamaDefaultModel = 'llama3.1:8b-instruct-q4_K_M'

    # Mirrors the real GET /api/tags shape: { models: [ { name = '...' }, ... ] }.
    function New-TagsResponse {
        param([string[]]$Names)
        [PSCustomObject]@{
            models = @($Names | ForEach-Object { [PSCustomObject]@{ name = $_ } })
        }
    }
}

Describe 'Test-OllamaConnection' {

    Context 'Requested model is installed' {
        BeforeEach {
            Mock Invoke-RestMethod {
                New-TagsResponse -Names @(
                    'llama3.1:8b-instruct-q4_K_M',
                    'SpeakLeash/bielik-11b-v2.3-instruct:Q4_K_M',
                    'qwen2.5:14b-instruct-q4_K_M'
                )
            }
        }

        It 'reports Status Healthy for a present model' {
            $r = Test-OllamaConnection -Model 'llama3.1:8b-instruct-q4_K_M'
            $r.Status         | Should -Be 'Healthy'
            $r.OverallSuccess | Should -BeTrue
            $r.ModelAvailable | Should -BeTrue
            $r.ApiResponding  | Should -BeTrue
            $r.Recommendation | Should -BeLike '*is installed*'
        }

        It 'uses the script default Uri and Model when none are supplied' {
            $r = Test-OllamaConnection
            $r.Uri    | Should -Be 'http://localhost:11434'
            $r.Model  | Should -Be 'llama3.1:8b-instruct-q4_K_M'
            $r.Status | Should -Be 'Healthy'
        }

        It 'hits only GET /api/tags with the short timeout and never /api/generate' {
            $null = Test-OllamaConnection -Model 'llama3.1:8b-instruct-q4_K_M'
            Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'http://localhost:11434/api/tags' -and
                $Method -eq 'Get' -and
                $TimeoutSec -eq 10
            }
            Should -Invoke Invoke-RestMethod -Times 0 -Exactly -ParameterFilter { $Uri -like '*generate*' }
        }

        It 'populates AvailableModels with every returned name' {
            $r = Test-OllamaConnection -Model 'llama3.1:8b-instruct-q4_K_M'
            $r.AvailableModels.Count | Should -Be 3
            $r.AvailableModels       | Should -Contain 'qwen2.5:14b-instruct-q4_K_M'
        }

        It 'matches the model name case-insensitively' {
            $r = Test-OllamaConnection -Model 'LLAMA3.1:8B-INSTRUCT-Q4_K_M'
            $r.Status         | Should -Be 'Healthy'
            $r.ModelAvailable | Should -BeTrue
        }
    }

    Context 'API responds but the requested model is absent' {
        BeforeEach {
            Mock Invoke-RestMethod {
                New-TagsResponse -Names @('qwen2.5:14b-instruct-q4_K_M')
            }
        }

        It 'is Inconclusive and recommends an ollama pull command' {
            $r = Test-OllamaConnection -Model 'llama3.1:8b-instruct-q4_K_M' -WarningAction SilentlyContinue
            $r.ApiResponding  | Should -BeTrue
            $r.ModelAvailable | Should -BeFalse
            $r.Status         | Should -Be 'Inconclusive'
            $r.OverallSuccess | Should -BeFalse
            $r.Recommendation | Should -BeLike '*pull*'
            $r.Recommendation | Should -BeLike '*ollama pull llama3.1:8b-instruct-q4_K_M*'
        }

        It 'matches the model name exactly, not as a prefix' {
            $r = Test-OllamaConnection -Model 'qwen2.5' -WarningAction SilentlyContinue
            $r.ModelAvailable | Should -BeFalse
            $r.Status         | Should -Be 'Inconclusive'
        }
    }

    Context 'API is unreachable' {
        BeforeEach {
            Mock Invoke-RestMethod { throw 'Unable to connect to the remote server' }
        }

        It 'reports Failed without throwing' {
            { Test-OllamaConnection -WarningAction SilentlyContinue } | Should -Not -Throw
        }

        It 'sets Status Failed, ApiResponding false, and steers toward starting Ollama' {
            $r = Test-OllamaConnection -WarningAction SilentlyContinue
            $r.Status         | Should -Be 'Failed'
            $r.OverallSuccess | Should -BeFalse
            $r.ApiResponding  | Should -BeFalse
            $r.ModelAvailable | Should -BeFalse
            $r.Recommendation | Should -BeLike '*ollama serve*'
            $r.ApiError       | Should -BeLike '*Unable to connect*'
        }

        It 'returns an empty AvailableModels array' {
            $r = Test-OllamaConnection -WarningAction SilentlyContinue
            $r.AvailableModels       | Should -BeNullOrEmpty
            $r.AvailableModels.Count | Should -Be 0
        }
    }

    Context 'API responds with an empty model list' {
        BeforeEach {
            Mock Invoke-RestMethod { [PSCustomObject]@{ models = @() } }
        }

        It 'is Inconclusive, does not throw, and still recommends a pull' {
            { Test-OllamaConnection -WarningAction SilentlyContinue } | Should -Not -Throw
            $r = Test-OllamaConnection -WarningAction SilentlyContinue
            $r.ApiResponding         | Should -BeTrue
            $r.Status                | Should -Be 'Inconclusive'
            $r.OverallSuccess        | Should -BeFalse
            $r.AvailableModels.Count | Should -Be 0
            $r.Recommendation        | Should -BeLike '*pull*'
        }
    }

    Context 'API responds with a null models property' {
        BeforeEach {
            Mock Invoke-RestMethod { [PSCustomObject]@{ models = $null } }
        }

        It 'is Inconclusive and does not throw' {
            { Test-OllamaConnection -WarningAction SilentlyContinue } | Should -Not -Throw
            $r = Test-OllamaConnection -WarningAction SilentlyContinue
            $r.ApiResponding         | Should -BeTrue
            $r.Status                | Should -Be 'Inconclusive'
            $r.AvailableModels.Count | Should -Be 0
        }
    }

    Context 'API responds with a malformed body (no models property)' {
        BeforeEach {
            Mock Invoke-RestMethod { [PSCustomObject]@{ unexpected = 'shape' } }
        }

        It 'is Inconclusive and does not throw on the missing property' {
            { Test-OllamaConnection -WarningAction SilentlyContinue } | Should -Not -Throw
            $r = Test-OllamaConnection -WarningAction SilentlyContinue
            $r.ApiResponding         | Should -BeTrue
            $r.Status                | Should -Be 'Inconclusive'
            $r.AvailableModels.Count | Should -Be 0
        }
    }

    Context 'API responds with model entries missing a name (defensive parse)' {
        BeforeEach {
            Mock Invoke-RestMethod {
                [PSCustomObject]@{
                    models = @(
                        [PSCustomObject]@{ model = 'no-name-field' },
                        [PSCustomObject]@{ name  = 'llama3.1:8b-instruct-q4_K_M' }
                    )
                }
            }
        }

        It 'skips nameless entries and still finds the present model' {
            $r = Test-OllamaConnection -Model 'llama3.1:8b-instruct-q4_K_M' -WarningAction SilentlyContinue
            $r.Status                | Should -Be 'Healthy'
            $r.ModelAvailable        | Should -BeTrue
            $r.AvailableModels.Count | Should -Be 1
        }
    }

    Context 'Single-model response stays an array' {
        BeforeEach {
            Mock Invoke-RestMethod {
                New-TagsResponse -Names @('llama3.1:8b-instruct-q4_K_M')
            }
        }

        It 'keeps AvailableModels as a string[] with a working .Count for one model' {
            $r = Test-OllamaConnection -Model 'llama3.1:8b-instruct-q4_K_M'
            $r.AvailableModels.Count | Should -Be 1
            $r.AvailableModels       | Should -Contain 'llama3.1:8b-instruct-q4_K_M'
            $r.Status                | Should -Be 'Healthy'
        }
    }

    Context 'Trailing slash on -Uri' {
        BeforeEach {
            Mock Invoke-RestMethod {
                New-TagsResponse -Names @('llama3.1:8b-instruct-q4_K_M')
            }
        }

        It 'does not produce a double slash in the request URI' {
            $null = Test-OllamaConnection -Uri 'http://localhost:11434/' -WarningAction SilentlyContinue
            Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
                $Uri -eq 'http://localhost:11434/api/tags'
            }
        }
    }
}
