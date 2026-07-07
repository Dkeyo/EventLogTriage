function Format-EventForLLM {
    <#
    .SYNOPSIS
        Turns one normalised Sysmon event into the system/user prompt pair that
        Invoke-EventClassification hands to a local Ollama model.

    .DESCRIPTION
        The prompt builder for the LLM layer. It takes a single event object as
        produced by Get-RecentSysmonEvents and returns a hashtable with two strings:
        a System prompt and a User prompt.

        The System prompt implements the constrained-choice design (CLAUDE.md decision
        2). It embeds the full list of valid MITRE ATT&CK technique IDs and canonical
        names loaded from the module allowlist, one per line, and instructs the model
        to pick MitreTechniques ONLY from that list, never to invent an ID, and to
        answer with strict JSON of a fixed shape. Giving the model a closed set to
        choose from is what curbs the ID hallucination seen during model evaluation
        (Llama 3.1 8B fabricated a non-existent T1160).

        When the allowlist declares a preliminary verificationStatus, a short caution
        line is appended to the System prompt so downstream reasoning treats the
        technique names and tactics as not yet fully cross-checked (CLAUDE.md decision
        1, mirrored by the JSON's own verificationNotes).

        The User prompt renders the salient event fields readably: a human EventId
        label (for example "Process Create"), the host, the timestamp, and the Data
        fields that matter for triage (Image, CommandLine, ParentImage,
        ParentCommandLine, User, plus fields specific to the event type). Absent Data
        keys are skipped rather than printed as blanks, so a sparse event still formats
        cleanly and never throws. The field set is a curated allowlist, so the
        SwiftOnSecurity noise fields (ProcessGuid, LogonGuid, IntegrityLevel, RuleName,
        UtcTime and so on) never reach the model.

        The allowlist is loaded through the shared Get-MitreAllowlist helper, which
        reads and parses the JSON once per resolved path and caches it module-scoped,
        so classifying a batch of events does not re-read the file for every event, and
        Invoke-EventClassification shares the exact same parse for its validation step.
        The load is lazy (nothing touches the filesystem until the first event is
        formatted), which keeps the function safe to dot-source in tests before
        $script:MitreAllowlistPath is set.

    .PARAMETER Event
        One normalised Sysmon event as returned by Get-RecentSysmonEvents: a
        PSCustomObject with Computer, TimeCreated, EventId, RecordId, EventTask and a
        Data hashtable of raw Sysmon EventData fields. Accepted from the pipeline, so a
        collection of events can be piped straight in.

    .EXAMPLE
        $events = Get-RecentSysmonEvents -HoursBack 1
        $prompt = $events[0] | Format-EventForLLM
        $prompt.System   # the constrained-choice system prompt
        $prompt.User     # the formatted event

        Builds the prompt pair for the first collected event.

    .EXAMPLE
        Get-RecentSysmonEvents | Format-EventForLLM | ForEach-Object { Invoke-EventClassification -Prompt $_ }

        Streams a batch of events through the prompt builder. The allowlist is parsed
        once and reused for every event in the batch.

    .OUTPUTS
        System.Collections.Hashtable

    .NOTES
        Well-formed events with sparse Data never throw: absent fields are simply
        omitted from the User prompt. A missing or unparseable allowlist file DOES
        throw, because that is a module misconfiguration the caller must fix, not a
        property of the event.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNull()]
        [psobject]$Event
    )

    begin {
        # Human-readable labels for the Sysmon Event IDs this module collects
        # ($script:DefaultSysmonEventIds = 1,3,7,10,11,22), plus the adjacent IDs the
        # allowlist maps techniques to (8 CreateRemoteThread, 12/13 registry) that a
        # caller can opt into via Get-RecentSysmonEvents -EventIds. Kept function-local:
        # the map is used nowhere else, so it does not earn a module constant, and
        # staying local means the tests do not have to re-declare it. Unknown IDs fall
        # back to a generic label below, so this map never needs to be exhaustive.
        $eventLabels = @{
            1  = 'Process Create'
            3  = 'Network Connection'
            7  = 'Image Loaded'
            8  = 'CreateRemoteThread'
            10 = 'Process Access'
            11 = 'File Create'
            12 = 'Registry Object Added/Deleted'
            13 = 'Registry Value Set'
            22 = 'DNS Query'
        }

        # Field render order for the User prompt, and the allowlist of fields worth showing
        # the model. Common process fields lead; then the fields that only appear on specific
        # event types (file create, registry, create-remote-thread, process access, image
        # load, network, DNS). Any Data key present is printed in this order; any absent key
        # is skipped. Rendering from this fixed set, rather than dumping the hashtable, keeps
        # the prompt stable and drops the SwiftOnSecurity noise fields (ProcessGuid, LogonGuid,
        # IntegrityLevel, RuleName, UtcTime, Company, OriginalFileName, and so on). Covers every
        # collectable Sysmon event type, so opting into registry (12/13) or CreateRemoteThread
        # (8) still surfaces the triage signal (TargetObject, Details, StartModule) rather than
        # silently dropping it.
        $fieldOrder = @(
            'Image', 'CommandLine', 'CurrentDirectory', 'ParentImage', 'ParentCommandLine', 'User',
            'TargetFilename', 'CreationUtcTime',
            'TargetObject', 'Details', 'EventType',
            'SourceImage', 'TargetImage', 'GrantedAccess', 'CallTrace',
            'StartAddress', 'StartModule', 'StartFunction',
            'ImageLoaded', 'Signed', 'Signature', 'SignatureStatus',
            'Protocol', 'SourceIp', 'SourcePort', 'DestinationIp', 'DestinationHostname', 'DestinationPort',
            'QueryName', 'QueryStatus', 'QueryResults',
            'Hashes'
        )

        # Load the MITRE allowlist through the shared loader. Get-MitreAllowlist reads
        # and parses the file once per resolved path and caches it module-scoped, so
        # classifying a batch does not re-read the JSON per event, and
        # Invoke-EventClassification's validation shares the exact same parse. The load
        # is lazy (first call only) and throws an actionable error on a missing path,
        # missing file or unparseable JSON, which is why this function stays safe to
        # dot-source before the path constant is set.
        $allowlist = Get-MitreAllowlist

        # Build the "T1059: Command and Scripting Interpreter" lines once per call.
        # techniques is a JSON OBJECT, so after ConvertFrom-Json it is a PSCustomObject:
        # iterate its properties (.Name is the ID, .Value.name the canonical name), not
        # hashtable keys. Windows PowerShell 5.1 preserves declaration order, so the
        # lines come out in allowlist file order.
        $techniqueLines = foreach ($property in $allowlist.techniques.PSObject.Properties) {
            "$($property.Name): $($property.Value.name)"
        }
        $techniqueBlock = $techniqueLines -join [Environment]::NewLine

        # Static instruction block. Single-quoted here-string so the literal JSON braces,
        # quotes and the {"Classification":...} example are not treated as PowerShell.
        $instructions = @'
You are a SOC L1 triage assistant. You are given one Windows Sysmon endpoint event.
Classify it and map it to MITRE ATT&CK techniques.

Rules:
1. Choose MitreTechniques ONLY from the "Valid MITRE technique IDs" list below.
   Use the exact IDs as written. NEVER invent, guess, or modify a technique ID.
   If no technique in the list applies, return an empty array [].
2. Classification must be exactly one of: BENIGN, SUSPICIOUS, MALICIOUS.
3. Respond with STRICT JSON only. No markdown, no code fences, no commentary
   before or after. Output exactly this shape and nothing else:
{"Classification":"BENIGN|SUSPICIOUS|MALICIOUS","MitreTechniques":["Txxxx"],"Reasoning":"one concise sentence"}
'@

        $systemParts = [System.Collections.Generic.List[string]]::new()
        $systemParts.Add($instructions)
        $systemParts.Add('')
        $systemParts.Add('Valid MITRE technique IDs (choose only from these):')
        $systemParts.Add($techniqueBlock)

        # Preliminary caution: appended only when the loaded allowlist declares a
        # preliminary verificationStatus, so the copy tracks the data (CLAUDE.md decision
        # 1 and the JSON's own verificationNotes). -like is null-safe, so a missing
        # status simply skips this.
        if ($allowlist.verificationStatus -like 'preliminary*') {
            $systemParts.Add('')
            $systemParts.Add("CAUTION: this technique allowlist is preliminary (verificationStatus '$($allowlist.verificationStatus)'). The IDs are valid to choose from, but the names and tactics have not been cross-checked character-by-character against attack.mitre.org, so sanity-check the mapping in your Reasoning before relying on it.")
        }

        $systemPrompt = $systemParts -join [Environment]::NewLine
    }

    process {
        # EventId label with a generic fallback so an unexpected or absent ID never
        # throws and never prints a bare number. -as [int] tolerates a null/blank EventId.
        $eventId = $Event.EventId -as [int]
        if ($null -ne $eventId -and $eventLabels.ContainsKey($eventId)) {
            $label = $eventLabels[$eventId]
        }
        elseif ($null -ne $eventId) {
            $label = "Sysmon Event $eventId"
        }
        else {
            $label = 'Sysmon Event (unknown id)'
        }

        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add("Event: $label (Sysmon Event ID $eventId)")

        if ($Event.PSObject.Properties['Computer'] -and $Event.Computer) {
            $lines.Add("Host: $($Event.Computer)")
        }
        if ($Event.PSObject.Properties['TimeCreated'] -and $Event.TimeCreated) {
            # 'o' (round-trip) is unambiguous for the model and matches the timestamp
            # format Get-RecentSysmonEvents uses in its verbose output.
            $lines.Add("Time: $($Event.TimeCreated.ToString('o'))")
        }
        if ($Event.PSObject.Properties['EventTask'] -and $Event.EventTask) {
            $lines.Add("Task: $($Event.EventTask)")
        }

        # Render ONLY the curated, triage-relevant Data fields, in the fixed order, skipping
        # any that are absent or blank. This is deliberate: a real SwiftOnSecurity event
        # carries ~20 EventData fields (ProcessGuid, LogonGuid, IntegrityLevel, Company,
        # OriginalFileName, RuleName, UtcTime and so on) that are noise for classification,
        # so the whole hashtable is NOT dumped. $fieldOrder is the allowlist of fields worth
        # showing the model. Guard the Data property itself: a sparse event may carry an empty
        # hashtable or none at all, and that must not throw.
        $data = $null
        if ($Event.PSObject.Properties['Data']) { $data = $Event.Data }

        $dataLines = [System.Collections.Generic.List[string]]::new()
        if ($data -is [System.Collections.IDictionary] -and $data.Count -gt 0) {
            foreach ($key in $fieldOrder) {
                if ($data.Contains($key)) {
                    $value = $data[$key]
                    if ($null -ne $value -and "$value".Trim().Length -gt 0) {
                        # Do NOT truncate: a base64 -enc payload in CommandLine is the whole
                        # triage signal, so the full value goes to the model. Interpolation,
                        # not -f: inside a method call the comma in `-f $key, $value` is read
                        # as the method's argument separator, which would starve the format
                        # string of its second argument. Interpolation is also immune to
                        # literal braces in the value (GUIDs, registry CLSID paths) that -f
                        # would try to parse as {0}-style placeholders.
                        $dataLines.Add("  ${key}: $value")
                    }
                }
            }
        }

        if ($dataLines.Count -gt 0) {
            $lines.Add('')
            $lines.Add('Event data:')
            $lines.AddRange($dataLines)
        }

        $userPrompt = $lines -join [Environment]::NewLine

        # A fresh hashtable per event. System is identical across events in a batch,
        # which is exactly what a chat API expects (stable system, varying user turn).
        Write-Output @{
            System = $systemPrompt
            User   = $userPrompt
        }
    }
}