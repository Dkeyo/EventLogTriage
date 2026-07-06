# FUTURE_WORK

Tracked, deliberately-deferred polish. These are known low-priority improvements,
not bugs. Each entry notes the date it was raised.

## Get-RecentSysmonEvents
- **`TaskDisplayName` null-coalescing (2026-06-17).** `EventTask` passes
  `$record.TaskDisplayName` straight through. On some custom Sysmon configurations
  this field can be null. Current behaviour is correct (null flows through), but
  production-grade output should default it. Target PowerShell is 5.1, so use an
  `if`-based fallback rather than `??`:
  `EventTask = if ($record.TaskDisplayName) { $record.TaskDisplayName } else { 'Unknown' }`
  (the `??` null-coalescing operator is PowerShell 7+ only). Low priority.

## Test-WinRMConnection
- **IPv6 bracket literals in TrustedHosts (2026-06-17).** TrustedHosts coverage is
  evaluated with `-like`, so a bracketed IPv6 literal entry (e.g. `[2001:db8::1]`)
  would be misinterpreted as a `-like` character class and fail to match. Extremely
  rare in practice, and `::1` is already handled by the local short-circuit, so left
  as-is. A fully-correct fix would escape `[`/`]` before the wildcard comparison.
- **FQDN vs short-name reporting nuance (2026-06-17).** Coverage is matched against
  the literal connection string (mirroring WinRM, which does NOT canonicalise
  short-name <-> FQDN; see the comment in `Test-WinRMConnection.ps1`). This is
  deliberate and correct, but when the forms diverge the tool reports "not covered"
  and recommends adding the connection-string form. A future enhancement could
  additionally detect "a *different* name form of this host is already trusted" and
  surface that as an informational note, to save the analyst a redundant entry.
  Informational only; not a correctness issue.

## MITRE allowlist
- **Live verification pass (Week 6).** `Data/valid-mitre-techniques.json` carries
  `verificationStatus: "preliminary-2026-06-17"`. Names/tactics were verified from
  expert knowledge; a character-by-character cross-check against attack.mitre.org
  was deferred (tooling outage). Re-confirm all 37 entries before treating the
  allowlist as production-validated, then update `verificationStatus`.
