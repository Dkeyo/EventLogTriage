function Get-RecentSysmonEvents {
    <#
    .SYNOPSIS
        Collects recent Sysmon operational events from a local or remote Windows host
        and returns them as normalised objects.

    .DESCRIPTION
        Retrieves events from the Sysmon operational log within a recent time window.

        For the local machine the function calls Get-WinEvent directly. For a remote
        host it runs the same collection inside Invoke-Command over WinRM and REQUIRES
        an explicit -Credential: the analyst workstation (SOC-WKS01) is a workgroup host
        while the target (WIN11-EP01) is domain-joined, so there is no usable ambient
        authentication and we refuse to silently fall back to it.

        Each event is normalised to a PSCustomObject that carries source-event metadata
        (Computer, TimeCreated, EventId, RecordId, EventTask) plus a Data hashtable of
        the raw Sysmon EventData fields. The metadata lets downstream functions and the
        analyst pivot back to the exact event after classification.

    .PARAMETER ComputerName
        Target host. 'localhost' (the default), '.', '127.0.0.1', '::1' or this
        machine's name use the local Get-WinEvent path. Anything else is treated as
        remote and collected over WinRM.

    .PARAMETER Credential
        Credential used for remote WinRM collection, e.g. 'renoma\Administrator'.
        Mandatory in practice for any remote host (the function throws if omitted);
        ignored for local collection.

    .PARAMETER MaxEvents
        Maximum number of events to return (newest first). Default 100.

    .PARAMETER HoursBack
        Size of the look-back window in hours, ending now. Default 1.

    .PARAMETER EventIds
        Sysmon Event IDs to collect. Default 1,3,7,10,11,22 (ProcessCreate,
        NetworkConnect, ImageLoad, ProcessAccess, FileCreate, DnsQuery). Pass e.g.
        1,3,7,10,11,12,13,22 to also collect registry events.

    .EXAMPLE
        Get-RecentSysmonEvents -Verbose

        Collects the last hour of default Sysmon events from the local host.

    .EXAMPLE
        $cred = Get-Credential renoma\Administrator
        Get-RecentSysmonEvents -ComputerName WIN11-EP01 -Credential $cred -HoursBack 4 -MaxEvents 200

        Collects up to 200 events from the last 4 hours from the domain endpoint over WinRM.

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .NOTES
        On a remote target, if WinRM is unreachable the function throws an informative
        error pointing to Test-WinRMConnection for diagnostics.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Function deliberately returns a collection of events; the plural noun is the clearest domain term.')]
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = 'localhost',

        [Parameter()]
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateRange(1, 10000)]
        [int]$MaxEvents = $script:DefaultMaxEvents,

        [Parameter()]
        [ValidateRange(1, 168)]
        [int]$HoursBack = $script:DefaultHoursBack,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [int[]]$EventIds = $script:DefaultSysmonEventIds
    )

    $startTime = (Get-Date).AddHours(-$HoursBack)
    $isLocal   = $script:LocalComputerNames -contains $ComputerName

    Write-Verbose "Target='$ComputerName' (local=$isLocal); since=$($startTime.ToString('o')); EventIds=$($EventIds -join ','); MaxEvents=$MaxEvents"

    # One collection+normalisation routine, executed identically on the local box or on
    # the remote host. Defined once so the two paths can never drift apart. It is also
    # the unit that runs remotely, so it must be self-contained (no closure over locals).
    $collectScript = {
        param($LogName, $Ids, $Start, $Max)

        # When this block runs remotely, Invoke-Command serialises $Ids across the
        # session boundary and it comes back as a deserialised object array. Get-WinEvent's
        # FilterHashtable then silently matches nothing (a single scalar Id still works, an
        # array does not), so coerce back to a real [int[]] before building the filter.
        $filter = @{ LogName = $LogName; Id = [int[]]$Ids; StartTime = $Start }

        try {
            $records = Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction Stop
        }
        catch {
            # Get-WinEvent THROWS (it does not just warn) when nothing matches the filter.
            # An empty result is a valid outcome, not a failure, so swallow only this case.
            if ($_.Exception.Message -like '*No events were found*') { return }
            throw
        }

        foreach ($record in $records) {
            $xml  = [xml]$record.ToXml()
            $data = @{}
            foreach ($field in $xml.Event.EventData.Data) {
                if ($null -ne $field.Name) { $data[$field.Name] = [string]$field.'#text' }
            }

            [PSCustomObject]@{
                Computer    = $record.MachineName
                TimeCreated = $record.TimeCreated
                EventId     = [int]$record.Id
                RecordId    = [int64]$record.RecordId
                EventTask   = $record.TaskDisplayName
                Data        = $data
            }
        }
    }

    try {
        if ($isLocal) {
            Write-Verbose 'Collecting locally via Get-WinEvent.'
            $events = & $collectScript $script:SysmonLogName $EventIds $startTime $MaxEvents
        }
        else {
            if (-not $Credential) {
                throw "Remote collection from '$ComputerName' requires -Credential. SOC-WKS01 is a workgroup host, so pass explicit domain credentials, e.g. Get-Credential renoma\Administrator."
            }

            Write-Verbose "Collecting remotely from '$ComputerName' via Invoke-Command (WinRM)."
            $invokeParams = @{
                ComputerName = $ComputerName
                Credential   = $Credential
                ScriptBlock  = $collectScript
                ArgumentList = @($script:SysmonLogName, $EventIds, $startTime, $MaxEvents)
                ErrorAction  = 'Stop'
            }
            $events = Invoke-Command @invokeParams
        }
    }
    catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        throw "WinRM connection to '$ComputerName' failed: $($_.Exception.Message) Run 'Test-WinRMConnection -ComputerName $ComputerName' to diagnose TrustedHosts and credentials."
    }
    catch {
        throw "Failed to collect Sysmon events from '$ComputerName': $($_.Exception.Message)"
    }

    # @($null) would be a 1-element array containing $null, so guard the empty case explicitly.
    $result = if ($null -eq $events) { @() } else { @($events) }
    Write-Verbose "Returned $($result.Count) event(s) from '$ComputerName'."
    return $result
}
