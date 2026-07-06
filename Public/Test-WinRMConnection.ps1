function Test-WinRMConnection {
    <#
    .SYNOPSIS
        Diagnoses WinRM (PowerShell remoting) connectivity to a target host and
        suggests the exact remediation command when something is wrong.

    .DESCRIPTION
        A non-throwing diagnostic for the remote-collection path of Get-RecentSysmonEvents.
        SOC-WKS01 (the analyst workstation) is a workgroup host and the target (WIN11-EP01)
        is domain-joined, so the usual failure causes are: WinRM not enabled, a firewall
        blocking the WinRM port, or the target not matched by this client's TrustedHosts.
        Each is checked in turn and reported as a structured result with a concrete
        Recommendation. The function never throws on a failed check.

        Status is tri-state:
          Healthy      - reachable AND the authenticated handshake (-Credential) succeeded.
          Inconclusive - the service answered an anonymous WSMan Identify, but no -Credential
                         was supplied, so authenticated remoting is NOT proven.
          Failed       - TCP or the WSMan handshake failed.

    .PARAMETER ComputerName
        Target host to diagnose, as you would connect to it (short name, FQDN, or IP).

    .PARAMETER Credential
        Credential for the authenticated WSMan handshake (e.g. renoma\Administrator).
        Strongly recommended: without it the result can only be Inconclusive.

    .PARAMETER Port
        WinRM TCP port to test. Default 5985 (HTTP).

    .EXAMPLE
        Test-WinRMConnection -ComputerName WIN11-EP01 -Credential (Get-Credential renoma\Administrator)

        Full diagnosis including the authenticated handshake.

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .NOTES
        Reading WSMan:\localhost\Client\TrustedHosts may require an elevated session; if it
        cannot be read it is reported as empty. TrustedHosts coverage is evaluated with
        wildcard matching against the connection name, mirroring WinRM's own behaviour.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter()]
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port = $script:WinRMDefaultPort
    )

    # Local host never uses WinRM; short-circuit with a benign, same-shaped result.
    if ($script:LocalComputerNames -contains $ComputerName) {
        Write-Verbose "'$ComputerName' is local; WinRM is not used for local collection."
        return [PSCustomObject]@{
            ComputerName             = $ComputerName
            IsLocal                  = $true
            Port                     = $Port
            TcpTestSucceeded         = $true
            WSManResponding          = $true
            WSManError               = $null
            CredentialTested         = $true
            TrustedHosts             = $null
            TrustedHostsCoversTarget = $true
            Status                   = 'Healthy'
            OverallSuccess           = $true
            Recommendation           = 'Local host - WinRM is not required for local collection.'
        }
    }

    # 1. TCP reachability on the WinRM port.
    Write-Verbose "Testing TCP connectivity to '$ComputerName' on port $Port."
    $tcpOk = $false
    try {
        $tcp   = Test-NetConnection -ComputerName $ComputerName -Port $Port -WarningAction SilentlyContinue -ErrorAction Stop
        $tcpOk = [bool]$tcp.TcpTestSucceeded
    }
    catch {
        Write-Verbose "TCP test threw: $($_.Exception.Message)"
    }

    # 2. WSMan handshake. With a credential we exercise the real Negotiate (NTLM) auth path;
    #    without one we only get an anonymous Identify, which proves far less (see Status below).
    Write-Verbose "Testing WSMan handshake on '$ComputerName'."
    $credentialTested = [bool]$Credential
    $wsmanOk    = $false
    $wsmanError = $null
    try {
        $wsmanParams = @{ ComputerName = $ComputerName; ErrorAction = 'Stop' }
        if ($credentialTested) {
            $wsmanParams['Credential']     = $Credential
            $wsmanParams['Authentication'] = 'Negotiate'
        }
        $null    = Test-WSMan @wsmanParams
        $wsmanOk = $true
    }
    catch {
        $wsmanError = $_.Exception.Message
        Write-Verbose "WSMan test failed: $wsmanError"
    }

    # 3. TrustedHosts state on THIS client (the usual workgroup -> domain blocker).
    $trustedHosts = ''
    try {
        $trustedHosts = (Get-Item -Path $script:TrustedHostsPath -ErrorAction Stop).Value
    }
    catch {
        Write-Verbose "Could not read TrustedHosts ($($script:TrustedHostsPath)): $($_.Exception.Message)"
    }
    # WinRM matches the exact connection string against each entry as a wildcard pattern
    # ('*', '*.renoma.pl', 'WIN11-*'), so we model coverage with -like against $ComputerName
    # (the string the analyst actually connects with) rather than -eq.
    #
    # Deliberate non-decision: we do NOT canonicalise short-name <-> FQDN. WinRM itself does not
    # expand 'WIN11-EP01' to cover 'win11-ep01.renoma.pl' (or vice versa) - it matches the literal
    # connection string against the patterns. Fuzzy-matching the two name forms here would claim
    # coverage WinRM would not actually grant: a false "covered" green, which is exactly the class
    # of bug this diagnostic exists to prevent. So if the forms diverge we correctly report "not
    # covered" and recommend adding the form being used.
    $trustedEntries     = @($trustedHosts -split '\s*,\s*' | Where-Object { $_ })
    $trustedHostsCovers = @($trustedEntries | Where-Object { $ComputerName -like $_ }).Count -gt 0

    $reachable       = $tcpOk -and $wsmanOk
    $recommendations = [System.Collections.Generic.List[string]]::new()
    if (-not $reachable) {
        if (-not $tcpOk) {
            $recommendations.Add("TCP $Port is unreachable. On the target run 'Enable-PSRemoting -Force', confirm the WinRM service is running, and that no firewall blocks port $Port.")
        }
        else {
            if (-not $trustedHostsCovers) {
                $recommendations.Add("'$ComputerName' is not matched by this client's TrustedHosts (the connection name must match an entry verbatim or via wildcard). Add it (elevated): Set-Item $($script:TrustedHostsPath) -Value '$ComputerName' -Concatenate -Force")
            }
            $recommendations.Add("Then retry with explicit credentials, e.g. -Credential renoma\Administrator.")
        }
    }
    elseif (-not $credentialTested) {
        $recommendations.Add("WinRM service responds, but this ran WITHOUT -Credential and only confirms an anonymous WSMan Identify - it does NOT prove authenticated remoting will succeed. Re-run with -Credential renoma\Administrator to validate the handshake Get-RecentSysmonEvents uses.")
    }

    # Tri-state: an authenticated 'Healthy' requires a credential to have actually been exercised.
    $status = if (-not $reachable) { 'Failed' } elseif (-not $credentialTested) { 'Inconclusive' } else { 'Healthy' }
    $overallSuccess = $status -eq 'Healthy'
    $recommendation = if ($recommendations.Count -gt 0) { $recommendations -join ' ' } else { 'WinRM connectivity looks healthy.' }

    if (-not $overallSuccess) {
        Write-Warning "WinRM diagnostics for '$ComputerName' [$status]. $recommendation"
    }

    [PSCustomObject]@{
        ComputerName             = $ComputerName
        IsLocal                  = $false
        Port                     = $Port
        TcpTestSucceeded         = $tcpOk
        WSManResponding          = $wsmanOk
        WSManError               = $wsmanError
        CredentialTested         = $credentialTested
        TrustedHosts             = $trustedHosts
        TrustedHostsCoversTarget = $trustedHostsCovers
        Status                   = $status
        OverallSuccess           = $overallSuccess
        Recommendation           = $recommendation
    }
}
