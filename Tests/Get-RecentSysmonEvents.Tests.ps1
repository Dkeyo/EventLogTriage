#Requires -Modules Pester

BeforeAll {
    . "$PSScriptRoot/../Public/Get-RecentSysmonEvents.ps1"

    # Constants the function expects (normally provided by EventLogTriage.psm1).
    $script:SysmonLogName         = 'Microsoft-Windows-Sysmon/Operational'
    $script:DefaultMaxEvents      = 100
    $script:DefaultHoursBack      = 1
    $script:DefaultSysmonEventIds = @(1, 3, 7, 10, 11, 22)
    $script:LocalComputerNames    = @('localhost', '127.0.0.1', '::1', '.', $env:COMPUTERNAME)

    # Real EventLogRecord objects expose .ToXml(); this builds a stand-in that does too,
    # so we can exercise the normalisation path without a live event log.
    function New-MockSysmonRecord {
        param(
            [int]$Id = 1,
            [int64]$RecordId = 1001,
            [hashtable]$Data = @{ Image = 'C:\Windows\System32\cmd.exe'; CommandLine = 'cmd.exe /c whoami' }
        )
        $dataXml = ($Data.GetEnumerator() | ForEach-Object {
            "<Data Name='$($_.Key)'>$($_.Value)</Data>"
        }) -join ''
        $xml = "<Event><EventData>$dataXml</EventData></Event>"

        $record = [PSCustomObject]@{
            MachineName     = 'WIN11-EP01.renoma.pl'
            TimeCreated     = (Get-Date '2026-06-17T09:00:00')
            Id              = $Id
            RecordId        = $RecordId
            TaskDisplayName = 'Process Create (rule: ProcessCreate)'
        }
        $record | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $xml }.GetNewClosure()
        $record
    }

    function New-TestCredential {
        [pscredential]::new('renoma\Administrator', (ConvertTo-SecureString 'pw' -AsPlainText -Force))
    }
}

Describe 'Get-RecentSysmonEvents' {

    Context 'Local collection (localhost)' {

        BeforeEach {
            Mock Get-WinEvent  { @( New-MockSysmonRecord -Id 1 -RecordId 5001 ) }
            Mock Invoke-Command { }   # must never be called on the local path
        }

        It 'uses Get-WinEvent and never Invoke-Command for localhost' {
            $null = Get-RecentSysmonEvents -ComputerName 'localhost'
            Should -Invoke Get-WinEvent  -Times 1 -Exactly
            Should -Invoke Invoke-Command -Times 0 -Exactly
        }

        It 'normalises the source-event metadata fields' {
            $result = Get-RecentSysmonEvents -ComputerName 'localhost'
            $result           | Should -HaveCount 1
            $result.EventId   | Should -Be 1
            $result.RecordId  | Should -Be 5001
            $result.Computer  | Should -Be 'WIN11-EP01.renoma.pl'
            $result.EventTask | Should -Be 'Process Create (rule: ProcessCreate)'
        }

        It 'exposes the raw Sysmon EventData under .Data' {
            $result = Get-RecentSysmonEvents -ComputerName 'localhost'
            $result.Data['Image']       | Should -Be 'C:\Windows\System32\cmd.exe'
            $result.Data['CommandLine'] | Should -Be 'cmd.exe /c whoami'
        }

        It 'queries the Sysmon log with the requested EventIds' {
            Get-RecentSysmonEvents -ComputerName 'localhost' -HoursBack 2 -EventIds 1, 3 | Out-Null
            Should -Invoke Get-WinEvent -Times 1 -Exactly -ParameterFilter {
                $FilterHashtable.LogName -eq 'Microsoft-Windows-Sysmon/Operational' -and
                (($FilterHashtable.Id) -join ',') -eq '1,3'
            }
        }
    }

    Context 'No matching events' {
        It 'returns an empty array (not an error) when Get-WinEvent finds nothing' {
            Mock Get-WinEvent { throw 'No events were found that match the specified selection criteria.' }
            $result = Get-RecentSysmonEvents -ComputerName 'localhost'
            $result | Should -HaveCount 0
        }
    }

    Context 'Remote collection (WinRM)' {

        It 'throws and never touches the network when -Credential is missing' {
            Mock Invoke-Command { }
            { Get-RecentSysmonEvents -ComputerName 'WIN11-EP01' } |
                Should -Throw -ExpectedMessage '*requires -Credential*'
            Should -Invoke Invoke-Command -Times 0 -Exactly
        }

        It 'calls Invoke-Command with the supplied ComputerName and Credential' {
            # Remote path normalises on the far side, so the mock returns an already-normalised object.
            Mock Invoke-Command {
                [PSCustomObject]@{ Computer = 'WIN11-EP01'; EventId = 3; RecordId = 6001; Data = @{} }
            }
            $result = Get-RecentSysmonEvents -ComputerName 'WIN11-EP01' -Credential (New-TestCredential)
            $result.RecordId | Should -Be 6001
            Should -Invoke Invoke-Command -Times 1 -Exactly -ParameterFilter {
                $ComputerName -eq 'WIN11-EP01' -and $Credential.UserName -eq 'renoma\Administrator'
            }
        }

        It 'surfaces a WinRM transport failure with a Test-WinRMConnection hint' {
            Mock Invoke-Command {
                throw [System.Management.Automation.Remoting.PSRemotingTransportException]::new('Access is denied.')
            }
            { Get-RecentSysmonEvents -ComputerName 'WIN11-EP01' -Credential (New-TestCredential) } |
                Should -Throw -ExpectedMessage '*Test-WinRMConnection*'
        }
    }
}
