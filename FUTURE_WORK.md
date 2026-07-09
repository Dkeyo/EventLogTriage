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
- **Authorization vs authentication residual (2026-07-09).** A `Healthy` result proves
  WS-Man transport plus a Negotiate-authenticated handshake, not that the account is
  authorized for the PowerShell remoting session configuration (Remote Management Users
  membership or the endpoint SDDL). An account that authenticates but lacks remoting
  rights would report `Healthy` yet fail `Invoke-Command` with Access Denied. The
  `Healthy` definition in the help is accurate about what it tests; a future enhancement
  could add a lightweight authorization probe and note the boundary in the recommendation.

## Invoke-EventClassification
- **Semantic misapplication check via `sysmonEvents` (2026-07-09).** The allowlist
  validation catches *fabricated* IDs (existence check), but a *real* ID applied to the
  wrong behaviour (the Bielik failure mode) passes clean; today that is caught only by the
  analyst reading `Reasoning`. Each allowlist entry already carries a `sysmonEvents` array,
  which the validator ignores. Cross-referencing the source event's `EventId` against the
  returned technique's declared `sysmonEvents` would be a cheap, deterministic partial check
  (e.g. LSASS credential dumping `T1003.001` mapped onto a DNS-query event is a mismatch).
  Would strengthen the guard beyond fabrication without needing the model.

## MITRE allowlist
- **Ongoing verification caution.** `Data/valid-mitre-techniques.json` carries
  `verificationStatus: "preliminary-*"`. IDs, names, and tactics were verified from expert
  ATT&CK knowledge; a character-by-character cross-check against attack.mitre.org is not yet
  done. The runtime surfaces this as `MitreNote` on every result by design. Completing the
  37-entry cross-check and flipping `verificationStatus` to a verified value would remove the
  caution and substantiate the allowlist as production-validated.
