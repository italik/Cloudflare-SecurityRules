# Cloudflare Custom Security Rule Copier

This project provides a PowerShell script to copy Cloudflare custom security rules (`http_request_firewall_custom`) from one zone to another in the same account.

Behavior:
- If a destination rule has the same name (`description`) as a source rule, it is updated.
- If no same-name destination rule exists, a new rule is created.
- Destination rules that do not match by name are left unchanged.
- Name matching is case-insensitive exact match after trimming whitespace.

## Script

- `scripts/Copy-CloudflareCustomSecurityRules.ps1`

## Required API Token Permissions

Use a Cloudflare API token with:
- `Zone:Read`
- `Zone WAF:Edit`

Create an API token from here: https://dash.cloudflare.com/profile/api-tokens
Minimum permissions are:
<img width="905" height="281" alt="image" src="https://github.com/user-attachments/assets/36078edf-fd87-443a-b21d-15eaf6b30848" />

I would also recommend setting the specific zones that you want to include in the scope (prevents any accidents!):
<img width="921" height="181" alt="image" src="https://github.com/user-attachments/assets/d1595874-b35f-4642-ada7-8c83f7b09bbe" />


## Usage

Set token in environment variable (recommended):

```powershell
$env:CLOUDFLARE_API_TOKEN = 'your-token-here'
```

Dry run (no writes):

```powershell
pwsh -NoLogo -NoProfile -File scripts/Copy-CloudflareCustomSecurityRules.ps1 `
  -SourceDomain source.example.com `
  -DestinationDomain dest.example.com `
  -WhatIf
```

Live run:

```powershell
pwsh -NoLogo -NoProfile -File scripts/Copy-CloudflareCustomSecurityRules.ps1 `
  -SourceDomain source.example.com `
  -DestinationDomain dest.example.com
```

Explicit token parameter (optional alternative):

```powershell
pwsh -NoLogo -NoProfile -File scripts/Copy-CloudflareCustomSecurityRules.ps1 `
  -SourceDomain source.example.com `
  -DestinationDomain dest.example.com `
  -ApiToken 'your-token-here'
```

## Output

The script prints per-rule operations and a summary with counts for:
- `Updated`
- `Created`
- `Skipped`
- `Failed`

Exit code:
- `0` when no upsert failures occur.
- `1` when one or more upsert operations fail.
