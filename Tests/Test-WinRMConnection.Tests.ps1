#Requires -Modules Pester

BeforeAll {
    . "$PSScriptRoot/../Public/Test-WinRMConnection.ps1"

    $script:WinRMDefaultPort   = 5985
    $script:TrustedHostsPath   = 'WSMan:\localhost\Client\TrustedHosts'
    $script:LocalComputerNames = @('localhost', '127.0.0.1', '::1', '.', $env:COMPUTERNAME)

    function New-TestCredential {
        [pscredential]::new('renoma\Administrator', (ConvertTo-SecureString 'pw' -AsPlainText -Force))
    }
}

Describe 'Test-WinRMConnection' {

    Context 'Local host short-circuit' {
        It 'reports Healthy without any network calls for localhost' {
            Mock Test-NetConnection { throw 'should not be called' }
            Mock Test-WSMan         { throw 'should not be called' }
            Mock Get-Item           { throw 'should not be called' }

            $r = Test-WinRMConnection -ComputerName 'localhost'
            $r.IsLocal        | Should -BeTrue
            $r.Status         | Should -Be 'Healthy'
            $r.OverallSuccess | Should -BeTrue
            Should -Invoke Test-NetConnection -Times 0 -Exactly
        }
    }

    Context 'Healthy remote host (credential supplied)' {
        BeforeEach {
            Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $true } }
            Mock Test-WSMan         { [PSCustomObject]@{ ProductVersion = 'OS: 10.0' } }
            Mock Get-Item           { [PSCustomObject]@{ Value = 'WIN11-EP01' } } -ParameterFilter { $Path -eq 'WSMan:\localhost\Client\TrustedHosts' }
        }

        It 'reports Status Healthy and exercises Negotiate auth' {
            $r = Test-WinRMConnection -ComputerName 'WIN11-EP01' -Credential (New-TestCredential)
            $r.CredentialTested | Should -BeTrue
            $r.Status           | Should -Be 'Healthy'
            $r.OverallSuccess   | Should -BeTrue
            $r.Recommendation   | Should -Be 'WinRM connectivity looks healthy.'
            Should -Invoke Test-WSMan -Times 1 -Exactly -ParameterFilter { $Authentication -eq 'Negotiate' }
        }
    }

    Context 'Service answers but no credential supplied' {
        BeforeEach {
            Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $true } }
            Mock Test-WSMan         { [PSCustomObject]@{ ProductVersion = 'OS: 10.0' } }
            Mock Get-Item           { [PSCustomObject]@{ Value = 'WIN11-EP01' } } -ParameterFilter { $Path -eq 'WSMan:\localhost\Client\TrustedHosts' }
        }

        It 'is Inconclusive, not Healthy, and steers toward -Credential' {
            $r = Test-WinRMConnection -ComputerName 'WIN11-EP01' -WarningAction SilentlyContinue
            $r.WSManResponding | Should -BeTrue
            $r.Status          | Should -Be 'Inconclusive'
            $r.OverallSuccess  | Should -BeFalse
            $r.Recommendation  | Should -BeLike '*WITHOUT -Credential*'
        }
    }

    Context 'WinRM port unreachable' {
        BeforeEach {
            Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $false } }
            Mock Test-WSMan         { throw 'The client cannot connect to the destination.' }
            Mock Get-Item           { [PSCustomObject]@{ Value = '*' } } -ParameterFilter { $Path -eq 'WSMan:\localhost\Client\TrustedHosts' }
        }

        It 'reports Failed and recommends Enable-PSRemoting / firewall checks' {
            $r = Test-WinRMConnection -ComputerName 'WIN11-EP01' -WarningAction SilentlyContinue
            $r.Status         | Should -Be 'Failed'
            $r.OverallSuccess | Should -BeFalse
            $r.Recommendation | Should -BeLike '*Enable-PSRemoting -Force*'
        }

        It 'treats a bare "*" in TrustedHosts as covering the target' {
            $r = Test-WinRMConnection -ComputerName 'WIN11-EP01' -WarningAction SilentlyContinue
            $r.TrustedHostsCoversTarget | Should -BeTrue
        }
    }

    Context 'TrustedHosts coverage via suffix wildcard' {
        It 'treats "*.renoma.pl" as covering an FQDN target' {
            Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $true } }
            Mock Test-WSMan         { [PSCustomObject]@{ ProductVersion = 'OS: 10.0' } }
            Mock Get-Item           { [PSCustomObject]@{ Value = '*.renoma.pl' } } -ParameterFilter { $Path -eq 'WSMan:\localhost\Client\TrustedHosts' }

            $r = Test-WinRMConnection -ComputerName 'WIN11-EP01.renoma.pl' -Credential (New-TestCredential)
            $r.TrustedHostsCoversTarget | Should -BeTrue
            $r.OverallSuccess           | Should -BeTrue
        }
    }

    Context 'Handshake fails, target not matched by TrustedHosts' {
        BeforeEach {
            Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $true } }
            Mock Test-WSMan         { throw 'The WinRM client cannot process the request.' }
            Mock Get-Item           { [PSCustomObject]@{ Value = '' } } -ParameterFilter { $Path -eq 'WSMan:\localhost\Client\TrustedHosts' }
        }

        It 'recommends the exact Set-Item TrustedHosts fix command' {
            $r = Test-WinRMConnection -ComputerName 'WIN11-EP01' -WarningAction SilentlyContinue
            $r.TrustedHostsCoversTarget | Should -BeFalse
            $r.Recommendation | Should -BeLike "*Set-Item WSMan:\localhost\Client\TrustedHosts -Value 'WIN11-EP01' -Concatenate -Force*"
            $r.Recommendation | Should -BeLike '*-Credential*'
        }
    }

    Context 'Handshake fails, target already matched by TrustedHosts' {
        BeforeEach {
            Mock Test-NetConnection { [PSCustomObject]@{ TcpTestSucceeded = $true } }
            Mock Test-WSMan         { throw 'Access is denied.' }
            Mock Get-Item           { [PSCustomObject]@{ Value = 'WIN11-EP01' } } -ParameterFilter { $Path -eq 'WSMan:\localhost\Client\TrustedHosts' }
        }

        It 'captures the WSMan error and does not re-suggest TrustedHosts' {
            $r = Test-WinRMConnection -ComputerName 'WIN11-EP01' -WarningAction SilentlyContinue
            $r.WSManError     | Should -Be 'Access is denied.'
            $r.Recommendation | Should -BeLike '*-Credential*'
            $r.Recommendation | Should -Not -BeLike '*Set-Item*'
        }

        It 'does not throw on a failed handshake' {
            { Test-WinRMConnection -ComputerName 'WIN11-EP01' -WarningAction SilentlyContinue } | Should -Not -Throw
        }
    }
}
