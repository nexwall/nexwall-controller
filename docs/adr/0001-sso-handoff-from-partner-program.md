# ADR 0001: Accept a signed SSO handoff token from the Nexwall Partner Program

**Status**: Proposed — this is a requirement, not yet implemented. Written
from the `nexwall-partner-multitenant` side of this design
(`docs/adr/0006-single-fqdn-email-login-tenant-handoff.md` there); this ADR
records what it requires of *this* repo specifically.

## Context

`partner.nexwall.com.br` (a separate service, separate repo/cluster —
`nexwall-partner-multitenant`) is becoming the single login surface for
both MSP partners and their customers' own end-users, Sophos-Central-style.
When a customer's own admin logs in there, they should land directly inside
*their* `nexwall-controller` instance, already authenticated — not see a
second, local login screen.

Today, `api/methods/auth.go` only knows local username/password + TOTP
(`gin-jwt`, `storage`-backed local users) — it has no concept of an
external identity provider at all.

## Decision

Add a new endpoint, e.g. `POST /sso/handoff`, that:

1. Accepts a short-lived, signed token minted by `nexwall-partner-
   multitenant` (JWT: customer identity, role/permissions, `aud` = this
   specific tenant, `jti`, short `exp` — 30–60s).
2. Validates it against a **per-tenant** signing secret — generated at
   provisioning time by the Management Plane (`nexwall-multi-tenant`) and
   injected into this instance's environment/config the same way its other
   secrets already arrive (via `values.yaml`'s `secrets:` block, per that
   repo's Helm chart). Not a secret shared across every tenant — a leak
   here should only ever affect this one customer.
3. Checks `jti` against a short-lived seen-token cache to reject replay —
   the token travels as a URL query parameter and can leak via browser
   history/Referer/logs, so single-use matters. `activeTokens sync.Map` in
   this same file is a reasonable existing pattern to extend for this.
4. On success, mints a normal session via the **existing** `gin-jwt`
   mechanism — same output as today's username/password login path, just a
   different, additional input. No change to how sessions work once
   established.

## What this deliberately does NOT do

- Does not replace local username/password + TOTP login — that remains for
  direct access (an admin who doesn't come through the Partner Program,
  or emergency access if the handoff path is unavailable).
- Does not make this instance a general OIDC relying party trusting
  arbitrary tokens — only tokens signed with *this tenant's own* secret,
  scoped to `aud` = this tenant, are accepted.

## Consequences

- New env var / secret: something like `SSO_HANDOFF_SECRET`, sourced from
  Management Plane at provisioning time — coordinate the exact field name
  and delivery mechanism with `nexwall-multi-tenant`'s
  `management-plane-openapi.yaml` and `values.schema.json` before
  implementing either side in isolation.
- `nexwall-ui` needs a route to receive `/sso/handoff?token=...`, call this
  new endpoint, and on success behave exactly as if the user had just
  logged in normally (store the returned session token, redirect to the
  dashboard) — a frontend task, not covered by this ADR's backend scope.
- Until this ships, `nexwall-partner-multitenant`'s redirect (ADR 0006
  there) still works as a plain deep link to this instance's normal login
  page — degrades gracefully, doesn't block that repo's own Phase 1.
