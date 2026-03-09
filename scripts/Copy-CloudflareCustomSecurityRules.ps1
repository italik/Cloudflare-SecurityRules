param(
    [string]$SourceDomain,
    [string]$DestinationDomain,
    [string]$ApiToken = $env:CLOUDFLARE_API_TOKEN,
    [switch]$AllowSourceDuplicates,
    [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Normalize-RuleName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $null
    }

    return $Name.Trim().ToLowerInvariant()
}

function New-RuleNameIndex {
    param([array]$Rules)

    $index = @{}
    foreach ($rule in $Rules) {
        $key = Normalize-RuleName -Name $rule.description
        if ($null -ne $key) {
            $index[$key] = $rule
        }
    }

    return $index
}

function Invoke-CfApi {
    param(
        [ValidateSet('GET', 'POST', 'PATCH')]
        [string]$Method,
        [string]$Path,
        [string]$ApiToken,
        [object]$Body
    )

    $uri = "https://api.cloudflare.com/client/v4$Path"
    $headers = @{
        Authorization = "Bearer $ApiToken"
    }

    $params = @{
        Method      = $Method
        Uri         = $uri
        Headers     = $headers
        ErrorAction = 'Stop'
    }

    if ($PSBoundParameters.ContainsKey('Body')) {
        $params.ContentType = 'application/json'
        $params.Body = ($Body | ConvertTo-Json -Depth 20)
    }

    $response = Invoke-RestMethod @params
    if ($response -and $response.success) {
        return $response.result
    }

    $errorMessage = 'Unknown Cloudflare API error.'
    if ($response -and $response.PSObject.Properties.Name -contains 'errors' -and $response.errors) {
        $errorMessage = (@($response.errors | ForEach-Object { $_.message }) -join '; ')
    }

    throw "Cloudflare API call failed for path '$Path': $errorMessage"
}

function Get-ZoneContext {
    param(
        [string]$Domain,
        [string]$ApiToken,
        [switch]$CreateRulesetIfMissing
    )

    $zones = Invoke-CfApi -Method GET -Path "/zones?name=$Domain" -ApiToken $ApiToken
    if (-not $zones -or @($zones).Count -eq 0) {
        throw "Zone not found for domain '$Domain'."
    }

    $zoneId = @($zones)[0].id

    try {
        $ruleset = Invoke-CfApi -Method GET -Path "/zones/$zoneId/rulesets/phases/http_request_firewall_custom/entrypoint" -ApiToken $ApiToken
    }
    catch {
        if (-not $CreateRulesetIfMissing) {
            throw
        }

        $ruleset = Invoke-CfApi -Method POST -Path "/zones/$zoneId/rulesets" -ApiToken $ApiToken -Body @{
            name  = 'Default custom firewall ruleset'
            kind  = 'zone'
            phase = 'http_request_firewall_custom'
        }
    }

    return [pscustomobject]@{
        Domain    = $Domain
        ZoneId    = $zoneId
        RulesetId = $ruleset.id
        Rules     = @($ruleset.rules)
    }
}

function Test-SourceRules {
    param(
        [array]$SourceRules,
        [switch]$AllowSourceDuplicates
    )

    $seen = @{}
    foreach ($rule in $SourceRules) {
        $key = Normalize-RuleName -Name $rule.description
        if ($null -eq $key) {
            continue
        }

        if ($seen.ContainsKey($key) -and -not $AllowSourceDuplicates) {
            throw "Duplicate source rule name after normalization: $($rule.description)"
        }

        $seen[$key] = $true
    }
}

function New-RulePayload {
    param([object]$Rule)

    $payload = @{
        description = $Rule.description
        expression  = $Rule.expression
        action      = $Rule.action
        enabled     = [bool]$Rule.enabled
    }

    if ($Rule.PSObject.Properties.Name -contains 'action_parameters' -and $null -ne $Rule.action_parameters) {
        $payload.action_parameters = $Rule.action_parameters
    }

    if ($Rule.PSObject.Properties.Name -contains 'logging' -and $null -ne $Rule.logging) {
        $payload.logging = $Rule.logging
    }

    return $payload
}

function Invoke-RuleUpsert {
    param(
        [array]$SourceRules,
        [array]$DestinationRules,
        [string]$DestinationZoneId,
        [string]$DestinationRulesetId,
        [string]$ApiToken,
        [switch]$WhatIf
    )

    $destinationIndex = New-RuleNameIndex -Rules $DestinationRules
    $results = @()

    foreach ($sourceRule in $SourceRules) {
        $nameKey = Normalize-RuleName -Name $sourceRule.description
        if ($null -eq $nameKey) {
            $results += [pscustomobject]@{
                RuleName  = $sourceRule.description
                Operation = 'Skipped'
                Reason    = 'EmptyName'
            }
            continue
        }

        $payload = New-RulePayload -Rule $sourceRule

        try {
            if ($destinationIndex.ContainsKey($nameKey)) {
                $destinationRule = $destinationIndex[$nameKey]
                if (-not $WhatIf) {
                    Invoke-CfApi -Method PATCH -Path "/zones/$DestinationZoneId/rulesets/$DestinationRulesetId/rules/$($destinationRule.id)" -ApiToken $ApiToken -Body $payload | Out-Null
                }
                $results += [pscustomobject]@{
                    RuleName  = $sourceRule.description
                    Operation = 'Updated'
                    Reason    = ''
                }
            }
            else {
                if (-not $WhatIf) {
                    Invoke-CfApi -Method POST -Path "/zones/$DestinationZoneId/rulesets/$DestinationRulesetId/rules" -ApiToken $ApiToken -Body $payload | Out-Null
                }
                $results += [pscustomobject]@{
                    RuleName  = $sourceRule.description
                    Operation = 'Created'
                    Reason    = ''
                }
            }
        }
        catch {
            $results += [pscustomobject]@{
                RuleName  = $sourceRule.description
                Operation = 'Failed'
                Reason    = $_.Exception.Message
            }
        }
    }

    return $results
}

function Get-ResultSummary {
    param([array]$Results)

    return [pscustomobject]@{
        Updated = @($Results | Where-Object Operation -eq 'Updated').Count
        Created = @($Results | Where-Object Operation -eq 'Created').Count
        Skipped = @($Results | Where-Object Operation -eq 'Skipped').Count
        Failed  = @($Results | Where-Object Operation -eq 'Failed').Count
    }
}

function Invoke-CopyCloudflareCustomSecurityRules {
    param(
        [Parameter(Mandatory)]
        [string]$SourceDomain,
        [Parameter(Mandatory)]
        [string]$DestinationDomain,
        [Parameter(Mandatory)]
        [string]$ApiToken,
        [switch]$AllowSourceDuplicates,
        [switch]$WhatIf
    )

    if ($SourceDomain -eq $DestinationDomain) {
        throw 'SourceDomain and DestinationDomain must be different.'
    }

    $sourceContext = Get-ZoneContext -Domain $SourceDomain -ApiToken $ApiToken
    $destinationContext = Get-ZoneContext -Domain $DestinationDomain -ApiToken $ApiToken -CreateRulesetIfMissing

    Test-SourceRules -SourceRules $sourceContext.Rules -AllowSourceDuplicates:$AllowSourceDuplicates

    $results = Invoke-RuleUpsert `
        -SourceRules $sourceContext.Rules `
        -DestinationRules $destinationContext.Rules `
        -DestinationZoneId $destinationContext.ZoneId `
        -DestinationRulesetId $destinationContext.RulesetId `
        -ApiToken $ApiToken `
        -WhatIf:$WhatIf

    $summary = Get-ResultSummary -Results $results

    return [pscustomobject]@{
        SourceDomain      = $SourceDomain
        DestinationDomain = $DestinationDomain
        WhatIf            = [bool]$WhatIf
        Results           = $results
        Summary           = $summary
    }
}

function Write-RunSummary {
    param([object]$Run)

    if ($Run.Results.Count -gt 0) {
        $Run.Results | Select-Object RuleName, Operation, Reason | Format-Table -AutoSize
    }

    Write-Host "Summary: Updated=$($Run.Summary.Updated) Created=$($Run.Summary.Created) Skipped=$($Run.Summary.Skipped) Failed=$($Run.Summary.Failed)"
    if ($Run.WhatIf) {
        Write-Host 'Dry run mode (-WhatIf) was enabled. No changes were written.'
    }
}

$script:IsDotSourced = $MyInvocation.InvocationName -eq '.'
if (-not $script:IsDotSourced) {
    if ([string]::IsNullOrWhiteSpace($SourceDomain) -or [string]::IsNullOrWhiteSpace($DestinationDomain)) {
        throw 'Both -SourceDomain and -DestinationDomain are required.'
    }

    if ([string]::IsNullOrWhiteSpace($ApiToken)) {
        throw 'An API token is required via -ApiToken or CLOUDFLARE_API_TOKEN env var.'
    }

    $run = Invoke-CopyCloudflareCustomSecurityRules `
        -SourceDomain $SourceDomain `
        -DestinationDomain $DestinationDomain `
        -ApiToken $ApiToken `
        -AllowSourceDuplicates:$AllowSourceDuplicates `
        -WhatIf:$WhatIf

    Write-RunSummary -Run $run

    if ($run.Summary.Failed -gt 0) {
        exit 1
    }
}
