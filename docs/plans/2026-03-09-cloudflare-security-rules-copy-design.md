# Cloudflare Security Rule Copy (Zone-to-Zone) Design

## Problem
Copy custom Cloudflare security rules from a source domain to a destination domain in the same account, with safe behavior:
- Update destination rules when a source rule has the same name.
- Create destination rules when no same-name rule exists.
- Leave other destination rules unchanged.

## Scope
- Cloudflare phase: `http_request_firewall_custom` (custom security rules).
- Matching key: rule name represented by `description`.
- Match mode: case-insensitive exact match after trim.

## Non-Goals
- Deleting destination rules not present in source.
- Reordering destination rules globally unless required by Cloudflare API behavior.
- Managing unrelated Cloudflare products/phases.

## Inputs
- Source domain (zone name).
- Destination domain (zone name).
- API token with ruleset read/write and zone read permissions.
- Optional switches:
  - `-WhatIf` dry run.
  - `-AllowSourceDuplicates` (default false).

## Architecture
1. Resolve source and destination zone IDs via zone lookup by domain.
2. Resolve each zone’s `http_request_firewall_custom` entry-point ruleset.
3. Read source and destination rule collections.
4. Build destination lookup map by normalized name.
5. Iterate source rules and perform upsert:
   - Match found: update matching destination rule.
   - No match: create new destination rule.
6. Emit operation summary and exit status.

## Data Flow
1. `GET /zones?name=<domain>` for source and destination zone IDs.
2. `GET /zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint` for both zones.
3. Build destination dictionary keyed on normalized `description`.
4. For each source rule:
   - Update existing rule via
     `PATCH /zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}`
   - Or create via
     `POST /zones/{zone_id}/rulesets/{ruleset_id}/rules`
5. Print final counts: updated, created, skipped, failed.

## Synced Fields
For update/create payloads:
- `description`
- `expression`
- `action`
- `enabled`
- `action_parameters` (when present)
- `logging` (when present)

## Matching Rules
- Normalize with `Trim().ToLowerInvariant()`.
- Case-insensitive exact match only.
- If source contains duplicate normalized names:
  - Default: fail fast with clear diagnostic.
  - Optional: allow with `-AllowSourceDuplicates` and process in source order.

## Error Handling and Safeguards
- Validate required inputs and token before API writes.
- Handle zone/ruleset resolution failures with actionable messages.
- Skip and report source rules with empty `description`.
- Isolate per-rule failures (continue processing remaining rules).
- Non-zero process exit if any operation failed.
- Full dry-run support via `-WhatIf`.

## Observability
- Per-rule result record:
  - `RuleName`, `Operation` (`Updated|Created|Skipped|Failed`), `Reason`.
- End-of-run totals and concise summary.
- Optional verbose logging for request IDs/status codes.

## Verification Strategy
1. Dry run in test environment.
2. Confirm three core scenarios:
   - Same-name destination rule updates even with case differences.
   - Missing destination rule is created.
   - Unmatched destination rule remains untouched.
3. Re-query destination rules and print post-run comparison by normalized name.
4. Treat any failed operation as failed run.

## Security and Token Requirements
- Use API token, not global API key.
- Required permissions (minimum):
  - Zone: Read
  - Account Zone Rulesets: Read
  - Account Zone Rulesets: Edit

## Open Decisions Resolved
- Name match mode: case-insensitive exact match.
- Destination preservation behavior: keep all non-matching destination rules unchanged.

