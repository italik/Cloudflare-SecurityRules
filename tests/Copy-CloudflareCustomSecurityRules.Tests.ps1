Describe 'Rule name normalization and matching' {
    It 'matches destination rule names case-insensitively' {
        . "$PSScriptRoot/../scripts/Copy-CloudflareCustomSecurityRules.ps1"

        $destRules = @(
            [pscustomobject]@{ id='r1'; description='Block Bad Bot' }
        )

        $index = New-RuleNameIndex -Rules $destRules
        $index['block bad bot'].id | Should -Be 'r1'
    }
}

Describe 'Cloudflare API wrapper' {
    It 'sends bearer token and returns result payload' {
        . "$PSScriptRoot/../scripts/Copy-CloudflareCustomSecurityRules.ps1"

        Mock Invoke-RestMethod { @{ success = $true; result = @{ id = '123' } } }

        $result = Invoke-CfApi -Method GET -Path '/zones' -ApiToken 'tok'

        Assert-MockCalled Invoke-RestMethod -Times 1 -ParameterFilter {
            $Headers.Authorization -eq 'Bearer tok' -and $Method -eq 'GET'
        }
        $result.id | Should -Be '123'
    }
}

Describe 'Zone and ruleset resolution' {
    It 'returns the firewall custom entrypoint ruleset id for a zone' {
        . "$PSScriptRoot/../scripts/Copy-CloudflareCustomSecurityRules.ps1"

        Mock Invoke-CfApi {
            if ($Path -like '/zones?name=*') { return @(@{ id = 'zone1' }) }
            if ($Path -like '/zones/zone1/rulesets/phases/http_request_firewall_custom/entrypoint') {
                return @{ id = 'rs1'; rules = @() }
            }
        }

        $context = Get-ZoneContext -Domain 'example.com' -ApiToken 'tok'
        $context.ZoneId | Should -Be 'zone1'
        $context.RulesetId | Should -Be 'rs1'
    }

    It 'handles entrypoint responses that omit the rules property' {
        . "$PSScriptRoot/../scripts/Copy-CloudflareCustomSecurityRules.ps1"

        Mock Invoke-CfApi {
            if ($Path -like '/zones?name=*') { return @(@{ id = 'zone1' }) }
            if ($Path -like '/zones/zone1/rulesets/phases/http_request_firewall_custom/entrypoint') {
                return @{ id = 'rs1' }
            }
        }

        $context = Get-ZoneContext -Domain 'example.com' -ApiToken 'tok'
        $context.RulesetId | Should -Be 'rs1'
        (@($context.Rules)).Count | Should -Be 0
    }
}

Describe 'Source validation' {
    It 'throws when source has duplicate normalized names' {
        . "$PSScriptRoot/../scripts/Copy-CloudflareCustomSecurityRules.ps1"

        $source = @(
            @{ description = 'Block Bad Bot' },
            @{ description = ' block bad bot ' }
        )

        { Test-SourceRules -SourceRules $source } | Should -Throw -ExpectedMessage '*Duplicate source rule name*'
    }
}

Describe 'Upsert operations' {
    It 'updates when destination contains same normalized name and creates when missing' {
        . "$PSScriptRoot/../scripts/Copy-CloudflareCustomSecurityRules.ps1"

        $src = @(
            @{ description = 'Block Bad Bot'; expression = '(cf.bot_management.score lt 30)'; action = 'block'; enabled = $true },
            @{ description = 'Geo Block'; expression = '(ip.geoip.country eq "RU")'; action = 'managed_challenge'; enabled = $true }
        )
        $dst = @(
            @{ id = 'r1'; description = 'block bad bot'; expression = 'old'; action = 'log'; enabled = $false }
        )

        Mock Invoke-CfApi { @{ id = 'ok' } }

        $result = Invoke-RuleUpsert -SourceRules $src -DestinationRules $dst -DestinationZoneId 'z2' -DestinationRulesetId 'rs2' -ApiToken 'tok'

        (@($result | Where-Object Operation -eq 'Updated')).Count | Should -Be 1
        (@($result | Where-Object Operation -eq 'Created')).Count | Should -Be 1
    }
}

Describe 'Result summary' {
    It 'counts operation totals including failures' {
        . "$PSScriptRoot/../scripts/Copy-CloudflareCustomSecurityRules.ps1"

        $results = @(
            [pscustomobject]@{ Operation = 'Updated' },
            [pscustomobject]@{ Operation = 'Failed' }
        )

        $summary = Get-ResultSummary -Results $results
        $summary.Failed | Should -Be 1
        $summary.Updated | Should -Be 1
    }
}
