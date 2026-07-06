function Test-OllamaConnection {
    <#
    .SYNOPSIS
        Diagnoses connectivity to the local Ollama runtime and confirms a specific
        model is installed, suggesting the exact remediation command when something is wrong.

    .DESCRIPTION
        A non-throwing diagnostic for the classification path of the module.
        Invoke-EventClassification depends on a running Ollama HTTP API (default
        http://localhost:11434) with the requested model already pulled. The usual failure
        causes are: the Ollama service or app is not running, or the model has never been
        pulled onto this machine. Each is reported as a structured result with a concrete
        Recommendation. The function never throws on a failed check.

        Only the lightweight GET /api/tags metadata endpoint is called, with a short timeout.
        The heavy /api/generate endpoint is deliberately NOT touched: a cold-start generate can
        take over a minute while the model loads into VRAM, which is too slow for a connectivity
        probe. Listing tags proves the API is up and reports the installed models without paying
        that cost.

        Status is tri-state:
          Healthy      - the API responded AND the requested -Model is present in the model list.
          Inconclusive - the API responded (even with an empty or malformed body) but the
                         requested -Model is NOT among the returned names. Recommendation includes
                         the exact 'ollama pull <model>' command.
          Failed       - the request threw (service down, connection refused, DNS failure, timeout).
                         Recommendation steers toward starting the Ollama service or app.

    .PARAMETER Uri
        Base URI of the Ollama HTTP API. Default $script:OllamaDefaultUri (http://localhost:11434).
        A trailing slash is tolerated. The probe requests {Uri}/api/tags.

    .PARAMETER Model
        Model name to confirm is installed, matched exactly against the names returned by
        /api/tags (for example 'llama3.1:8b-instruct-q4_K_M'). Default $script:OllamaDefaultModel.

    .EXAMPLE
        Test-OllamaConnection

        Probes the default local endpoint for the default model and returns a structured result.

    .EXAMPLE
        Test-OllamaConnection -Model 'qwen2.5:14b-instruct-q4_K_M' -Verbose

        Confirms a specific model is installed, with step-by-step verbose output. If the model is
        missing the Recommendation contains the exact 'ollama pull qwen2.5:14b-instruct-q4_K_M' command.

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .NOTES
        Model matching is exact-value (not substring) and case-insensitive, using -contains against
        the returned names: 'llama3.1:8b' does NOT match 'llama3.1:8b-instruct-q4_K_M'. A response
        with an empty or non-conforming body is treated as Inconclusive rather than Failed: the API
        is up, but the model cannot be confirmed present.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri = $script:OllamaDefaultUri,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Model = $script:OllamaDefaultModel
    )

    # Tolerate a user-supplied trailing slash so we never build '.../api//api/tags'.
    $base    = $Uri.TrimEnd('/')
    $tagsUri = "$base/api/tags"

    # Short probe timeout (seconds). Kept as a commented literal rather than a third module
    # constant: the module defines exactly two Ollama constants (Uri, Model), and
    # Test-WinRMConnection inlines its own numeric literal (ValidateRange 1..65535) the same way.
    # A dead endpoint fails fast here instead of hanging; /api/generate is never touched
    # (cold-start is ~78s).
    $timeoutSec = 10

    Write-Verbose "Querying Ollama model metadata at '$tagsUri' (timeout ${timeoutSec}s)."

    $apiResponding   = $false
    $apiError        = $null
    $availableModels = @()
    try {
        # -ErrorAction Stop routes any HTTP/transport error into the catch (-> Failed).
        $response      = Invoke-RestMethod -Uri $tagsUri -Method Get -TimeoutSec $timeoutSec -ErrorAction Stop
        # The endpoint answered. ApiResponding reflects reachability ONLY and must not depend on
        # payload shape: a response with a broken body still means the service is up
        # (-> Inconclusive, never Failed).
        $apiResponding = $true

        # Defensive extraction. Do not assume 'models' exists, is non-null, or that each entry
        # carries a 'name'. ForEach-Object { $_.name } tolerates missing members (Select-Object
        # -ExpandProperty would throw); Where-Object drops nulls/blanks; @() keeps it a string[]
        # for zero, one, or many models.
        if ($response -and $response.PSObject.Properties['models'] -and $response.models) {
            $availableModels = @(
                $response.models |
                    ForEach-Object { $_.name } |
                    Where-Object { $_ }
            )
        }
        else {
            Write-Verbose 'API responded but the payload contained no usable model list.'
        }
        Write-Verbose "API responded with $($availableModels.Count) model(s)."
    }
    catch {
        $apiError = $_.Exception.Message
        Write-Verbose "Ollama /api/tags request failed: $apiError"
    }

    # -contains is exact-value (not substring) and case-insensitive, which matches "EXACT match"
    # as the caller means it: the whole name must equal a returned name.
    $modelAvailable = $availableModels -contains $Model

    # Tri-state. Reachability first (Failed), then model presence (Inconclusive), else Healthy.
    # if/elseif/else as an assigned expression is 5.1-safe; no ternary is used.
    $status = if (-not $apiResponding) { 'Failed' } elseif (-not $modelAvailable) { 'Inconclusive' } else { 'Healthy' }
    $overallSuccess = $status -eq 'Healthy'

    if ($status -eq 'Healthy') {
        $recommendation = "Ollama is reachable and model '$Model' is installed."
    }
    elseif ($status -eq 'Inconclusive') {
        if ($availableModels.Count -gt 0) {
            $recommendation = "Ollama is reachable but model '$Model' is not installed. Installed: $($availableModels -join ', '). Pull it with: ollama pull $Model"
        }
        else {
            $recommendation = "Ollama is reachable but reported no installed models. Pull the model with: ollama pull $Model"
        }
    }
    else {
        $detail = if ($apiError) { " Error: $apiError" } else { '' }
        $recommendation = "Cannot reach the Ollama API at '$base'. Start the Ollama service or app (run 'ollama serve', or launch the Ollama desktop app) and confirm it is listening on '$base'.$detail"
    }

    if (-not $overallSuccess) {
        Write-Warning "Ollama diagnostics for '$base' [$status]. $recommendation"
    }

    [PSCustomObject]@{
        Uri             = $base
        Model           = $Model
        ApiResponding   = $apiResponding
        ApiError        = $apiError
        ModelAvailable  = $modelAvailable
        AvailableModels = $availableModels
        Status          = $status
        OverallSuccess  = $overallSuccess
        Recommendation  = $recommendation
    }
}
