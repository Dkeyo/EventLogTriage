function Get-MitreAllowlist {
    <#
    .SYNOPSIS
        Loads, caches and returns the parsed MITRE ATT&CK technique allowlist that
        the LLM layer builds prompts from and validates model output against.

    .DESCRIPTION
        The single loader for the curated technique allowlist. Format-EventForLLM
        uses the returned object to build the constrained-choice prompt (CLAUDE.md
        decision 2); Invoke-EventClassification uses it to validate the model's
        MitreTechniques against the set of known-valid IDs (CLAUDE.md decision 1).
        Both call here so the load, cache and error handling live in ONE place and
        the prompt and the validator can never drift onto different copies of the list.

        The file at $script:MitreAllowlistPath is read and parsed once per resolved
        path and cached module-scoped in $script:MitreAllowlistCache. The cache is
        keyed by the path string, so a caller that repoints $script:MitreAllowlistPath
        at a different file gets its own entry instead of a stale hit. Everything is
        lazy: nothing touches the filesystem until the function is first called, which
        keeps it safe to dot-source in tests before $script:MitreAllowlistPath is set.

        A missing path constant, a missing file, or unparseable JSON throws with an
        actionable message. Those are module misconfigurations the caller must fix,
        not per-event conditions, so they surface loudly rather than returning $null.

    .EXAMPLE
        $allowlist = Get-MitreAllowlist
        $validIds  = $allowlist.techniques.PSObject.Properties.Name

        Returns the parsed allowlist and the set of valid technique IDs.

    .EXAMPLE
        $allowlist = Get-MitreAllowlist
        $allowlist.verificationStatus                    # e.g. 'preliminary-2026-06-17'

        Reads the verification status so a caller can surface the preliminary caution.

    .OUTPUTS
        System.Management.Automation.PSObject

    .NOTES
        Returns the PSCustomObject produced by ConvertFrom-Json: it carries the
        top-level verificationStatus and a techniques object keyed by technique ID
        (iterate techniques.PSObject.Properties, not hashtable keys). The parse is
        the shared cached instance, not a copy, so callers must treat it as read-only.
    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param()

    # Cache is a module-scoped hashtable keyed by the allowlist path. Guard the null
    # case first so the function is safe to call before EventLogTriage.psm1 has
    # initialised the constant (for example when dot-sourced directly in a test).
    $allowlistPath = $script:MitreAllowlistPath

    if ($null -eq $script:MitreAllowlistCache) {
        $script:MitreAllowlistCache = @{}
    }

    if (-not $allowlistPath) {
        throw "MITRE allowlist path is not configured. Expected `$script:MitreAllowlistPath to point at Data\valid-mitre-techniques.json (set in EventLogTriage.psm1)."
    }

    if (-not $script:MitreAllowlistCache.ContainsKey($allowlistPath)) {
        Write-Verbose "Loading MITRE allowlist from '$allowlistPath'."

        if (-not (Test-Path -LiteralPath $allowlistPath)) {
            throw "MITRE allowlist not found at '$allowlistPath'. Restore Data\valid-mitre-techniques.json or fix `$script:MitreAllowlistPath in EventLogTriage.psm1."
        }

        try {
            $raw = Get-Content -LiteralPath $allowlistPath -Raw -ErrorAction Stop
            $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "MITRE allowlist at '$allowlistPath' could not be parsed as JSON: $($_.Exception.Message)"
        }

        $script:MitreAllowlistCache[$allowlistPath] = $parsed
    }
    else {
        Write-Verbose "Using cached MITRE allowlist for '$allowlistPath'."
    }

    # Assign then return the single cached object, so a caller's
    # `$allowlist = Get-MitreAllowlist` never collapses into an array.
    $allowlist = $script:MitreAllowlistCache[$allowlistPath]
    return $allowlist
}