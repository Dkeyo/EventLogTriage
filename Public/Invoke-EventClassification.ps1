function Invoke-EventClassification {
    <#
    .SYNOPSIS
        Classifies one normalised Sysmon event with a local Ollama model and validates
        the model's MITRE ATT&CK technique IDs against the curated allowlist.

    .DESCRIPTION
        The core of the LLM layer. For each event it builds the constrained-choice
        prompt with Format-EventForLLM, POSTs it to a local Ollama /api/generate
        endpoint, parses the model's JSON reply, and then does the thing the whole
        design turns on: it VALIDATES every technique ID the model returned against the
        allowlist loaded by Get-MitreAllowlist (CLAUDE.md decision 1, "never trust the
        model's MITRE field"). An ID that is not in the allowlist is treated as a
        hallucination: it is moved out of MitreTechniques into RejectedTechniques and
        HallucinationDetected is set. This is the second line of defence behind the
        constrained-choice system prompt (decision 2), which is why it runs even though
        the prompt already tells the model to choose only from the list.

        Membership is case-insensitive, matching the module idiom in
        Test-OllamaConnection, and a surviving ID is normalised to the allowlist's
        canonical casing so downstream exact-compares and technique-name lookups line
        up. Kept IDs are de-duplicated, so a model that repeats an ID does not inflate
        the count. Classification is checked against the three allowed labels
        (BENIGN, SUSPICIOUS, MALICIOUS): a value that is missing, empty, or outside the
        set also sets HallucinationDetected, since it is the model ignoring the closed
        set; an out-of-set value is preserved (uppercased) so the analyst sees exactly
        what the model said.

        When the allowlist declares a preliminary verificationStatus, MitreNote carries
        a caution so the caller knows the surviving IDs are valid to emit but their
        names and tactics have not been cross-checked character-by-character (CLAUDE.md
        decision 1, mirrored by the allowlist's own verificationNotes). This is a
        data-quality note about the allowlist, separate from HallucinationDetected,
        which is about the model.

        The function is non-throwing per event so a piped batch survives failures. A
        network error, HTTP failure, timeout, or an unparseable model reply does NOT
        throw: the event's result comes back with Status 'Error' and a populated Error
        field, and the provenance fields (Computer, TimeCreated, EventId, RecordId) are
        still copied from the source event so a caller piping a hundred events keeps
        going and can filter the failures afterwards. A genuine module misconfiguration
        (a missing or unparseable allowlist file) is the one exception that DOES throw,
        because it is not a property of any single event and would fail every event
        identically; it surfaces once, up front, from the begin block.

        The request timeout defaults to 120 seconds because a cold-start generate can
        take over a minute while the model loads into VRAM. A warm request returns in a
        few seconds. This is the opposite of Test-OllamaConnection, which uses a short
        timeout and only lists tags, because a connectivity probe must fail fast.

    .PARAMETER Event
        One normalised Sysmon event as returned by Get-RecentSysmonEvents: a
        PSCustomObject with Computer, TimeCreated, EventId, RecordId, EventTask and a
        Data hashtable. Accepted from the pipeline, so a collection of events can be
        piped straight in and each yields one result object.

    .PARAMETER Model
        Ollama model to classify with, sent as the request's 'model' field. Default
        $script:OllamaDefaultModel (llama3.1:8b-instruct-q4_K_M). The chosen model is
        echoed back on every result object, success or error.

    .PARAMETER Uri
        Base URI of the Ollama HTTP API. Default $script:OllamaDefaultUri
        (http://localhost:11434). A trailing slash is tolerated. The request goes to
        {Uri}/api/generate.

    .PARAMETER TimeoutSec
        Per-request timeout in seconds. Default 120, range 1..600. The default is
        deliberately generous: a cold-start generate can take over a minute while the
        model loads into VRAM, so a short timeout would spuriously fail the first event
        of a run.

    .EXAMPLE
        Get-RecentSysmonEvents -HoursBack 1 | Invoke-EventClassification

        Classifies the last hour of Sysmon events. Each result carries the validated
        MitreTechniques, any RejectedTechniques, and the event provenance for pivoting
        back to the source event.

    .EXAMPLE
        $results = Get-RecentSysmonEvents | Invoke-EventClassification
        $results | Where-Object HallucinationDetected
        $results | Where-Object { $_.Status -eq 'Error' }

        Collects a batch, then filters for events where the model fabricated a technique
        ID and for events the classifier could not process (Ollama down, bad reply).

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .NOTES
        The result shape is stable across success and error: the same set of fields is
        present either way. On error, Classification is $null, MitreTechniques and
        RejectedTechniques are empty, Status is 'Error', and Error carries the message.
        On success Status is 'Classified'. RawResponse always carries the raw model text
        (or the raw failure detail) for audit. Validating an ID confirms it EXISTS in
        the allowlist, not that it was applied to the correct behaviour: to catch
        semantic mis-assignment, compare Reasoning against the technique's canonical name.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [psobject]$Event,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Model = $script:OllamaDefaultModel,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri = $script:OllamaDefaultUri,

        [Parameter(Position = 3)]
        [ValidateRange(1, 600)]
        [int]$TimeoutSec = 120
    )

    begin {
        # The three allowed classification labels. A value that is missing, empty, or
        # outside this set flags HallucinationDetected the same way a bad technique ID
        # does: it is the model ignoring the closed set.
        $validClassifications = @('BENIGN', 'SUSPICIOUS', 'MALICIOUS')

        # Tolerate a caller-supplied trailing slash so we never build '.../api//api/generate'.
        $base        = $Uri.TrimEnd('/')
        $generateUri = "$base/api/generate"

        # Load the allowlist ONCE for the whole invocation. This is the one place a
        # genuine module misconfiguration (missing path, missing file, unparseable JSON)
        # is allowed to throw: it is not a per-event condition, it would fail every event
        # identically, and letting it surface here (before any event is processed) is
        # clearer than burying the same error on every result object. Because this call
        # primes the cache, Format-EventForLLM's own Get-MitreAllowlist call in process{}
        # hits the cache and cannot re-throw for a per-event reason.
        $allowlist = Get-MitreAllowlist

        # Case-insensitive lookup keyed by the lowercased ID, mapping to the allowlist's
        # canonical casing. techniques is a JSON object, so it is a PSCustomObject after
        # ConvertFrom-Json: iterate its properties (.Name is the ID). A wrong-case real ID
        # (e.g. 't1059.001') then still matches and is normalised to 'T1059.001', rather
        # than being false-flagged as a hallucination over a casing slip. This matches the
        # case-insensitive -contains idiom Test-OllamaConnection documents.
        $canonicalIdByLower = @{}
        foreach ($id in $allowlist.techniques.PSObject.Properties.Name) {
            $canonicalIdByLower[$id.ToLowerInvariant()] = $id
        }

        # Preliminary caution surfaced onto every result (CLAUDE.md decision 1, mirrored by
        # the JSON's verificationNotes). -like is null-safe: a missing or non-preliminary
        # status leaves MitreNote $null. Computed once; identical for every event in the batch.
        if ($allowlist.verificationStatus -like 'preliminary*') {
            $mitreNote = "MITRE allowlist is preliminary (verificationStatus '$($allowlist.verificationStatus)'): a returned ID is confirmed to EXIST, but its name and tactic mapping have not been cross-checked against attack.mitre.org. Sanity-check the technique against the Reasoning before acting."
        }
        else {
            $mitreNote = $null
        }

        Write-Verbose "Classifying with model '$Model' via '$generateUri' (timeout ${TimeoutSec}s); $($canonicalIdByLower.Count) valid technique IDs loaded."
    }

    process {
        # Gather provenance FIRST, before anything that can fail. Every result object,
        # success or error, carries these so an analyst can always pivot back to the exact
        # source event even when the classification itself failed. Guard each property so a
        # sparse event that lacks one never throws here.
        $computer    = if ($Event.PSObject.Properties['Computer'])    { $Event.Computer }    else { $null }
        $timeCreated = if ($Event.PSObject.Properties['TimeCreated']) { $Event.TimeCreated } else { $null }
        $eventId     = if ($Event.PSObject.Properties['EventId'])     { $Event.EventId }     else { $null }
        $recordId    = if ($Event.PSObject.Properties['RecordId'])    { $Event.RecordId }    else { $null }

        # Result fields, all initialised to their success/error defaults so the emitted
        # shape is identical on both paths. Model and MitreNote are known regardless of
        # outcome, so they are populated even when the request or parse fails.
        $classification        = $null
        $mitreTechniques       = @()
        $rejectedTechniques    = @()
        $hallucinationDetected = $false
        $reasoning             = $null
        $status                = 'Error'
        $errorMessage          = $null
        $rawResponse           = $null

        try {
            # Build the constrained-choice prompt. Format-EventForLLM's Get-MitreAllowlist
            # call hits the cache primed in begin{}, so this does not re-read the file.
            $prompt = Format-EventForLLM -Event $Event

            # Ollama /api/generate contract (empirically confirmed): POST the model, the
            # system + user prompt, format 'json' to force a JSON body, stream $false for a
            # single response object, and a low temperature for deterministic triage. The
            # body is serialised to a JSON string and sent with an explicit content type.
            $body = @{
                model   = $Model
                system  = $prompt.System
                prompt  = $prompt.User
                format  = 'json'
                stream  = $false
                options = @{ temperature = 0.1 }
            } | ConvertTo-Json -Depth 5

            Write-Verbose "POST $generateUri for EventId=$eventId RecordId=$recordId."

            # -ErrorAction Stop routes any HTTP/transport/timeout failure into the catch, so
            # Ollama being down returns an Error result instead of throwing out of the batch.
            $response = Invoke-RestMethod -Uri $generateUri -Method Post -Body $body -ContentType 'application/json' -TimeoutSec $TimeoutSec -ErrorAction Stop

            # The generate endpoint wraps the model's answer in a 'response' string. Keep the
            # raw text for audit BEFORE parsing, so a junk reply is still recorded on the
            # result object.
            $rawText = ''
            if ($response -and $response.PSObject.Properties['response'] -and $null -ne $response.response) {
                $rawText = [string]$response.response
            }
            $rawResponse = $rawText

            # Tolerant JSON extraction. The model sometimes wraps the object in whitespace,
            # newlines, or stray prose. Pull the first '{' to the last '}' with a
            # single-line-dot-all regex before parsing, so leading/trailing noise does not
            # break ConvertFrom-Json. No braces at all is a parse failure. Requiring braces
            # also means a bare array, string, or number reply falls into the error path.
            $match = [regex]::Match($rawText, '(?s)\{.*\}')
            if (-not $match.Success) {
                throw "Model reply contained no JSON object. Raw reply: $rawText"
            }

            try {
                $parsed = $match.Value | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                throw "Model reply was not parseable as JSON: $($_.Exception.Message)"
            }

            # ConvertFrom-Json on a JSON object yields a PSCustomObject. A brace-matched but
            # non-object reply (rare) would not, so reject it into the error path rather than
            # walking properties that do not exist.
            if ($parsed -isnot [System.Management.Automation.PSCustomObject]) {
                throw 'Model reply parsed to a non-object JSON value.'
            }

            # Classification: uppercase-normalise, then check membership. A value that is
            # missing, empty, or outside the three allowed labels flags HallucinationDetected
            # (the model ignoring the closed set). An out-of-set value is kept as-is
            # (uppercased) so the caller sees exactly what the model returned.
            if ($parsed.PSObject.Properties['Classification'] -and $parsed.Classification) {
                $classification = ([string]$parsed.Classification).Trim().ToUpperInvariant()
                if ($validClassifications -notcontains $classification) {
                    $hallucinationDetected = $true
                    Write-Verbose "Model returned an out-of-set Classification '$classification'."
                }
            }
            else {
                $hallucinationDetected = $true
                Write-Verbose 'Model reply had no usable Classification field.'
            }

            # Reasoning: free text, taken as-is when present.
            if ($parsed.PSObject.Properties['Reasoning'] -and $null -ne $parsed.Reasoning) {
                $reasoning = [string]$parsed.Reasoning
            }

            # The validation core. Coerce MitreTechniques to an array first: the model may
            # return it missing, null, a bare string, or an array. Then partition each ID:
            # in the allowlist -> keep (normalised to canonical casing, de-duplicated);
            # not in the allowlist -> reject and flag. Blank entries are skipped rather than
            # counted as rejections.
            $returnedTechniques = @()
            if ($parsed.PSObject.Properties['MitreTechniques'] -and $null -ne $parsed.MitreTechniques) {
                $returnedTechniques = @($parsed.MitreTechniques)
            }

            $kept        = [System.Collections.Generic.List[string]]::new()
            $keptSeen    = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $rejected    = [System.Collections.Generic.List[string]]::new()
            $rejectSeen  = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($rawId in $returnedTechniques) {
                if ($null -eq $rawId) { continue }
                $id = ([string]$rawId).Trim()
                if ($id.Length -eq 0) { continue }

                $lower = $id.ToLowerInvariant()
                if ($canonicalIdByLower.ContainsKey($lower)) {
                    $canonical = $canonicalIdByLower[$lower]
                    if ($keptSeen.Add($canonical)) {
                        $kept.Add($canonical)
                    }
                }
                else {
                    if ($rejectSeen.Add($id)) {
                        $rejected.Add($id)
                    }
                    $hallucinationDetected = $true
                    Write-Verbose "Rejected fabricated technique ID '$id' (not in allowlist)."
                }
            }

            $mitreTechniques    = $kept.ToArray()
            $rejectedTechniques = $rejected.ToArray()
            $status             = 'Classified'
        }
        catch {
            # Any failure in prompt build, HTTP, or parse lands here. Record the message and
            # leave the fields at their Error defaults. Never rethrow: the batch continues.
            $status       = 'Error'
            $errorMessage = $_.Exception.Message
            if ($null -eq $rawResponse) { $rawResponse = $errorMessage }
            Write-Verbose "Classification failed for EventId=$eventId RecordId=${recordId}: $errorMessage"
        }

        [PSCustomObject]@{
            Computer              = $computer
            TimeCreated           = $timeCreated
            EventId               = $eventId
            RecordId              = $recordId
            Classification        = $classification
            MitreTechniques       = $mitreTechniques
            RejectedTechniques    = $rejectedTechniques
            HallucinationDetected = $hallucinationDetected
            Reasoning             = $reasoning
            MitreNote             = $mitreNote
            Model                 = $Model
            Status                = $status
            Error                 = $errorMessage
            RawResponse           = $rawResponse
        }
    }
}