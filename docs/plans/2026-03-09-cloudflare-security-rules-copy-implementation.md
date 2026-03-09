# Cloudflare Security Rule Copy Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a PowerShell script that copies `http_request_firewall_custom` rules from a source zone to a destination zone by upserting on case-insensitive rule name (`description`) while preserving unrelated destination rules.

**Architecture:** A single script with small helper functions: Cloudflare API invocation, zone/ruleset resolution, rule normalization/indexing, and per-rule upsert operations. The script runs read-then-write with `-WhatIf` support and outputs per-rule plus summary results. TDD-first with Pester for matching, duplicate handling, and operation selection.

**Tech Stack:** PowerShell 7, Cloudflare Rulesets API v4, Pester 5

---

### Task 1: Project Skeleton and Failing Matching Tests

**Files:**
- Create: `scripts/Copy-CloudflareCustomSecurityRules.ps1`
- Create: `tests/Copy-CloudflareCustomSecurityRules.Tests.ps1`

**Step 1: Write the failing test**

```powershell
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
```

**Step 2: Run test to verify it fails**

Run: `pwsh -NoLogo -NoProfile -Command "Invoke-Pester tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 -Output Detailed"`
Expected: FAIL with missing function `New-RuleNameIndex`.

**Step 3: Write minimal implementation**

```powershell
function Normalize-RuleName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    return $Name.Trim().ToLowerInvariant()
}

function New-RuleNameIndex {
    param([array]$Rules)
    $index = @{}
    foreach ($rule in $Rules) {
        $key = Normalize-RuleName -Name $rule.description
        if ($key) { $index[$key] = $rule }
    }
    return $index
}
```

**Step 4: Run test to verify it passes**

Run: `pwsh -NoLogo -NoProfile -Command "Invoke-Pester tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 -Output Detailed"`
Expected: PASS for normalization/matching test.

**Step 5: Commit**

```bash
git add tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 scripts/Copy-CloudflareCustomSecurityRules.ps1
git commit -m "test: add rule-name matching foundation"
```

### Task 2: Add API Wrapper and Failing HTTP Contract Tests

**Files:**
- Modify: `scripts/Copy-CloudflareCustomSecurityRules.ps1`
- Modify: `tests/Copy-CloudflareCustomSecurityRules.Tests.ps1`

**Step 1: Write the failing test**

```powershell
It 'sends bearer token and returns result payload' {
    . "$PSScriptRoot/../scripts/Copy-CloudflareCustomSecurityRules.ps1"

    Mock Invoke-RestMethod { @{ success=$true; result=@{ id='123' } } }

    $result = Invoke-CfApi -Method GET -Path '/zones' -ApiToken 'tok'

    Assert-MockCalled Invoke-RestMethod -Times 1 -ParameterFilter {
        $Headers.Authorization -eq 'Bearer tok' -and $Method -eq 'GET'
    }
    $result.id | Should -Be '123'
}
```

**Step 2: Run test to verify it fails**

Run: `pwsh -NoLogo -NoProfile -Command "Invoke-Pester tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 -Output Detailed"`
Expected: FAIL with missing function `Invoke-CfApi`.

**Step 3: Write minimal implementation**

```powershell
function Invoke-CfApi {
    param(
        [ValidateSet('GET','POST','PATCH')][string]$Method,
        [string]$Path,
        [string]$ApiToken,
        [object]$Body
    )

    $uri = "https://api.cloudflare.com/client/v4$Path"
    $headers = @{ Authorization = "Bearer $ApiToken" }
    $params = @{ Method=$Method; Uri=$uri; Headers=$headers; ErrorAction='Stop' }

    if ($PSBoundParameters.ContainsKey('Body')) {
        $params.ContentType = 'application/json'
        $params.Body = ($Body | ConvertTo-Json -Depth 20)
    }

    $resp = Invoke-RestMethod @params
    if (-not $resp.success) {
        throw "Cloudflare API call failed: $Path"
    }
    return $resp.result
}
```

**Step 4: Run test to verify it passes**

Run: `pwsh -NoLogo -NoProfile -Command "Invoke-Pester tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 -Output Detailed"`
Expected: PASS for API wrapper tests.

**Step 5: Commit**

```bash
git add tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 scripts/Copy-CloudflareCustomSecurityRules.ps1
git commit -m "feat: add cloudflare api wrapper"
```

### Task 3: Zone and Ruleset Resolution

**Files:**
- Modify: `scripts/Copy-CloudflareCustomSecurityRules.ps1`
- Modify: `tests/Copy-CloudflareCustomSecurityRules.Tests.ps1`

**Step 1: Write the failing test**

```powershell
It 'returns the firewall custom entrypoint ruleset id for a zone' {
    . "$PSScriptRoot/../scripts/Copy-CloudflareCustomSecurityRules.ps1"

    Mock Invoke-CfApi {
        if ($Path -like '/zones?name=*') { return @(@{ id='zone1' }) }
        if ($Path -like '/zones/zone1/rulesets/phases/http_request_firewall_custom/entrypoint') {
            return @{ id='rs1'; rules=@() }
        }
    }

    $context = Get-ZoneContext -Domain 'example.com' -ApiToken 'tok'
    $context.ZoneId | Should -Be 'zone1'
    $context.RulesetId | Should -Be 'rs1'
}
```

**Step 2: Run test to verify it fails**

Run: `pwsh -NoLogo -NoProfile -Command "Invoke-Pester tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 -Output Detailed"`
Expected: FAIL with missing function `Get-ZoneContext`.

**Step 3: Write minimal implementation**

```powershell
function Get-ZoneContext {
    param([string]$Domain,[string]$ApiToken)

    $zones = Invoke-CfApi -Method GET -Path "/zones?name=$Domain" -ApiToken $ApiToken
    if (-not $zones -or $zones.Count -eq 0) { throw "Zone not found: $Domain" }

    $zoneId = $zones[0].id
    $ruleset = Invoke-CfApi -Method GET -Path "/zones/$zoneId/rulesets/phases/http_request_firewall_custom/entrypoint" -ApiToken $ApiToken

    return [pscustomobject]@{
        Domain    = $Domain
        ZoneId    = $zoneId
        RulesetId = $ruleset.id
        Rules     = @($ruleset.rules)
    }
}
```

**Step 4: Run test to verify it passes**

Run: `pwsh -NoLogo -NoProfile -Command "Invoke-Pester tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 -Output Detailed"`
Expected: PASS for zone/ruleset resolution.

**Step 5: Commit**

```bash
git add tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 scripts/Copy-CloudflareCustomSecurityRules.ps1
git commit -m "feat: resolve zone and custom firewall ruleset"
```

### Task 4: Duplicate and Empty-Name Source Validation

**Files:**
- Modify: `scripts/Copy-CloudflareCustomSecurityRules.ps1`
- Modify: `tests/Copy-CloudflareCustomSecurityRules.Tests.ps1`

**Step 1: Write the failing test**

```powershell
It 'throws when source has duplicate normalized names' {
    . "$PSScriptRoot/../scripts/Copy-CloudflareCustomSecurityRules.ps1"

    $source = @(
        @{ description='Block Bad Bot' },
        @{ description=' block bad bot ' }
    )

    { Test-SourceRules -SourceRules $source } | Should -Throw
}
```

**Step 2: Run test to verify it fails**

Run: `pwsh -NoLogo -NoProfile -Command "Invoke-Pester tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 -Output Detailed"`
Expected: FAIL with missing function `Test-SourceRules`.

**Step 3: Write minimal implementation**

```powershell
function Test-SourceRules {
    param([array]$SourceRules,[switch]$AllowSourceDuplicates)

    $seen = @{}
    foreach ($rule in $SourceRules) {
        $key = Normalize-RuleName -Name $rule.description
        if (-not $key) { continue }
        if ($seen.ContainsKey($key) -and -not $AllowSourceDuplicates) {
            throw "Duplicate source rule name after normalization: $($rule.description)"
        }
        $seen[$key] = $true
    }
}
```

**Step 4: Run test to verify it passes**

Run: `pwsh -NoLogo -NoProfile -Command "Invoke-Pester tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 -Output Detailed"`
Expected: PASS for duplicate handling.

**Step 5: Commit**

```bash
git add tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 scripts/Copy-CloudflareCustomSecurityRules.ps1
git commit -m "feat: validate source rule names"
```

### Task 5: Upsert Engine (Update vs Create)

**Files:**
- Modify: `scripts/Copy-CloudflareCustomSecurityRules.ps1`
- Modify: `tests/Copy-CloudflareCustomSecurityRules.Tests.ps1`

**Step 1: Write the failing test**

```powershell
It 'updates when destination contains same normalized name and creates when missing' {
    . "$PSScriptRoot/../scripts/Copy-CloudflareCustomSecurityRules.ps1"

    $src = @(
        @{ description='Block Bad Bot'; expression='(cf.bot_management.score lt 30)'; action='block'; enabled=$true },
        @{ description='Geo Block'; expression='(ip.geoip.country eq "RU")'; action='managed_challenge'; enabled=$true }
    )
    $dst = @(
        @{ id='r1'; description='block bad bot'; expression='old'; action='log'; enabled=$false }
    )

    Mock Invoke-CfApi { @{ id='ok' } }

    $result = Invoke-RuleUpsert -SourceRules $src -DestinationRules $dst -DestinationZoneId 'z2' -DestinationRulesetId 'rs2' -ApiToken 'tok'

    ($result | Where-Object Operation -eq 'Updated').Count | Should -Be 1
    ($result | Where-Object Operation -eq 'Created').Count | Should -Be 1
}
```

**Step 2: Run test to verify it fails**

Run: `pwsh -NoLogo -NoProfile -Command "Invoke-Pester tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 -Output Detailed"`
Expected: FAIL with missing function `Invoke-RuleUpsert`.

**Step 3: Write minimal implementation**

```powershell
function New-RulePayload {
    param([object]$Rule)
    $payload = @{
        description = $Rule.description
        expression  = $Rule.expression
        action      = $Rule.action
        enabled     = [bool]$Rule.enabled
    }
    if ($null -ne $Rule.action_parameters) { $payload.action_parameters = $Rule.action_parameters }
    if ($null -ne $Rule.logging) { $payload.logging = $Rule.logging }
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

    $destIndex = New-RuleNameIndex -Rules $DestinationRules
    $results = @()

    foreach ($src in $SourceRules) {
        $nameKey = Normalize-RuleName -Name $src.description
        if (-not $nameKey) {
            $results += [pscustomobject]@{ RuleName=$src.description; Operation='Skipped'; Reason='EmptyName' }
            continue
        }

        $payload = New-RulePayload -Rule $src
        if ($destIndex.ContainsKey($nameKey)) {
            $destRule = $destIndex[$nameKey]
            if (-not $WhatIf) {
                Invoke-CfApi -Method PATCH -Path "/zones/$DestinationZoneId/rulesets/$DestinationRulesetId/rules/$($destRule.id)" -ApiToken $ApiToken -Body $payload | Out-Null
            }
            $results += [pscustomobject]@{ RuleName=$src.description; Operation='Updated'; Reason='' }
        } else {
            if (-not $WhatIf) {
                Invoke-CfApi -Method POST -Path "/zones/$DestinationZoneId/rulesets/$DestinationRulesetId/rules" -ApiToken $ApiToken -Body $payload | Out-Null
            }
            $results += [pscustomobject]@{ RuleName=$src.description; Operation='Created'; Reason='' }
        }
    }

    return $results
}
```

**Step 4: Run test to verify it passes**

Run: `pwsh -NoLogo -NoProfile -Command "Invoke-Pester tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 -Output Detailed"`
Expected: PASS with one update and one create.

**Step 5: Commit**

```bash
git add tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 scripts/Copy-CloudflareCustomSecurityRules.ps1
git commit -m "feat: implement rule upsert logic"
```

### Task 6: CLI Entry Point and Summary Output

**Files:**
- Modify: `scripts/Copy-CloudflareCustomSecurityRules.ps1`
- Modify: `tests/Copy-CloudflareCustomSecurityRules.Tests.ps1`

**Step 1: Write the failing test**

```powershell
It 'prints totals and exits non-zero when failures occur' {
    . "$PSScriptRoot/../scripts/Copy-CloudflareCustomSecurityRules.ps1"

    $results = @(
        [pscustomobject]@{ Operation='Updated' },
        [pscustomobject]@{ Operation='Failed' }
    )

    $summary = Get-ResultSummary -Results $results
    $summary.Failed | Should -Be 1
}
```

**Step 2: Run test to verify it fails**

Run: `pwsh -NoLogo -NoProfile -Command "Invoke-Pester tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 -Output Detailed"`
Expected: FAIL with missing function `Get-ResultSummary`.

**Step 3: Write minimal implementation**

```powershell
function Get-ResultSummary {
    param([array]$Results)

    return [pscustomobject]@{
        Updated = @($Results | Where-Object Operation -eq 'Updated').Count
        Created = @($Results | Where-Object Operation -eq 'Created').Count
        Skipped = @($Results | Where-Object Operation -eq 'Skipped').Count
        Failed  = @($Results | Where-Object Operation -eq 'Failed').Count
    }
}

param(
    [Parameter(Mandatory)] [string]$SourceDomain,
    [Parameter(Mandatory)] [string]$DestinationDomain,
    [Parameter(Mandatory)] [string]$ApiToken,
    [switch]$AllowSourceDuplicates,
    [switch]$WhatIf
)

# Orchestration calls Get-ZoneContext, Test-SourceRules, Invoke-RuleUpsert, Get-ResultSummary.
# Exit 1 when summary.Failed > 0, else Exit 0.
```

**Step 4: Run test to verify it passes**

Run: `pwsh -NoLogo -NoProfile -Command "Invoke-Pester tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 -Output Detailed"`
Expected: PASS for summary/exit behavior.

**Step 5: Commit**

```bash
git add tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 scripts/Copy-CloudflareCustomSecurityRules.ps1
git commit -m "feat: add cli orchestration and summary"
```

### Task 7: Usage Docs and Manual Verification Script Runs

**Files:**
- Create: `README.md`

**Step 1: Write the failing test**

No automated test in this task; use manual verification commands.

**Step 2: Run validation command to verify docs/examples are executable**

Run:
- `pwsh -NoLogo -NoProfile -File scripts/Copy-CloudflareCustomSecurityRules.ps1 -SourceDomain source.example.com -DestinationDomain dest.example.com -ApiToken '$env:CLOUDFLARE_API_TOKEN' -WhatIf`
Expected: summary output with `Updated/Created/Skipped/Failed` counts and no write operations.

**Step 3: Write minimal documentation**

```markdown
# Cloudflare Custom Security Rule Copier

## Required Token Permissions
- Zone: Read
- Zone Rulesets: Read
- Zone Rulesets: Edit

## Dry Run
pwsh -File scripts/Copy-CloudflareCustomSecurityRules.ps1 -SourceDomain source.example.com -DestinationDomain dest.example.com -ApiToken $env:CLOUDFLARE_API_TOKEN -WhatIf

## Live Run
pwsh -File scripts/Copy-CloudflareCustomSecurityRules.ps1 -SourceDomain source.example.com -DestinationDomain dest.example.com -ApiToken $env:CLOUDFLARE_API_TOKEN
```

**Step 4: Run final test suite**

Run: `pwsh -NoLogo -NoProfile -Command "Invoke-Pester tests/Copy-CloudflareCustomSecurityRules.Tests.ps1 -Output Detailed"`
Expected: all tests PASS.

**Step 5: Commit**

```bash
git add README.md
git commit -m "docs: add usage for security rule copier"
```

## Skills to Use During Execution
- `@superpowers:test-driven-development` before each implementation change.
- `@superpowers:verification-before-completion` before claiming success.
- `@superpowers:requesting-code-review` before merge/hand-off.
