# @logi-auth/browser

Browser SDK for **logi (1pass)** — OAuth 2.0 + OIDC PKCE for SPAs. Zero dependencies, ~3 KB minified.

```bash
npm install @logi-auth/browser
```

## Quickstart

```ts
import { LogiAuth } from "@logi-auth/browser";

const auth = new LogiAuth({
  clientId: "logi_xxx",
  redirectUri: window.location.origin + "/auth/callback",
  // scopes: ["openid", "profile:basic", "email"],   // default
  // issuer: "https://api.1pass.dev",                 // default
});
```

### Sign in (page A — wherever the login button lives)

```ts
loginButton.addEventListener("click", () => {
  auth.signIn({ returnTo: location.pathname });
  // → redirects to https://api.1pass.dev/oauth/authorize
});
```

### Handle callback (page B — `/auth/callback`)

```ts
if (auth.hasPendingCallback()) {
  try {
    const session = await auth.handleCallback();
    // session.sub          — VERIFIED subject (RS256 sig + iss/aud/exp/nonce checked)
    // session.email        — email claim, if granted
    // session.accessToken  — Bearer token for your API
    // session.refreshToken — store securely (see "Public vs confidential" below)
    // session.idToken      — raw id_token (already verified)
    // session.returnTo     — what you passed to signIn({ returnTo })
    // session.expiresAt    — ms epoch
    location.replace(session.returnTo ?? "/");
  } catch (err) {
    if (err instanceof LogiAuthError) {
      console.error(err.code, err.message, err.details);
    }
  }
}
```

### Refresh

```ts
const fresh = await auth.refresh(savedRefreshToken);
// fresh.refreshToken is the rotated token — persist the new value.
```

### Read the ID token (UI hints only)

```ts
const claims = auth.parseIdToken<{ sub: string; email?: string }>(tokens.idToken!);
// ⚠️ No signature verification. Don't make authorization decisions client-side.
```

## Why this SDK

Browser PKCE flow is small but easy to get wrong:
- Generating the `code_verifier` + SHA-256 `code_challenge`
- Persisting `verifier` + `state` across the IdP redirect
- Validating returned `state` to defeat CSRF
- Distinguishing `error=` callbacks from missing-`code` cases
- Cleaning up `sessionStorage` on every exit path (success or failure)

This SDK does all of that in ~250 LOC, zero deps, ESM-only.

## Design

- **Zero dependencies.** Uses `crypto.subtle` and `fetch` directly.
- **Public client.** Never sends `client_secret`. Token endpoint must accept `none` auth (logi PKCE clients do).
- **Verifies the id_token.** `handleCallback()` fetches `/.well-known/jwks.json` and verifies the id_token (RS256 signature + `iss`/`aud`/`exp`/`iat`/`nonce`) before returning a `LogiSession`, so `session.sub` is trustworthy client-side. See **Public vs confidential** for when that's the right boundary.
- **sessionStorage by default.** Pending handoff is wiped on tab close. Override via `storage:` option.
- **TTL on pending handoff.** Stale handoffs (default 10 min) are rejected with `expired_handoff`.

## Requirements

- **Secure context.** `crypto.subtle` is undefined on plain `http://` (except `http://localhost`). Serve your SPA over HTTPS.
- **Modern browsers.** Chromium 92+, Safari 15.4+, Firefox 90+ (anything with `crypto.subtle.digest("SHA-256")` and `fetch`).
- **Node ≥ 18** if you import this from a server-side test harness or SSR layer.

## Errors

`LogiAuthError` with one of:

- `storage_unavailable` — `signIn()` couldn't persist the PKCE handoff (Safari ITP, iOS private browsing, corp policy). Thrown **before** redirecting to the IdP so the user doesn't waste a round-trip.
- `no_pending_handoff` — `handleCallback()` called without a prior `signIn()` in this tab
- `state_mismatch` — returned `state` ≠ persisted (CSRF attempt or stale callback)
- `missing_code` — callback URL had no `code` parameter
- `authorization_server_error` — IdP returned `?error=...`
- `token_exchange_failed` — `/oauth/token` POST failed (HTTP status + truncated body in `details`)
- `network_error` — `fetch` rejected (offline, DNS, CORS, TLS)
- `expired_handoff` — pending older than `pendingTtlMs`

> **`details.body` may include server payloads.** We truncate to 2 KB but logging it to Sentry/Datadog without scrubbing could leak tokens that the IdP echoed in a 4xx response.

## Limitations (v0.1.0)

- **Multi-tab race.** Concurrent `signIn()` calls in multiple tabs share `sessionStorage` per origin, so only the most-recent handoff completes; the older tab's `handleCallback()` will fail with `state_mismatch`. State-keyed storage is on the v0.2.0 roadmap.
- **No automatic refresh.** Call `auth.refresh(savedRefreshToken)` yourself before `expiresAt`. A token-manager wrapper (`@logi-auth/react`) is planned.

## Public client vs confidential (who verifies the id_token?)

This SDK is for **public clients** — SPAs / apps with **no backend** in the auth path. There the browser is the final relying party, so `handleCallback()` verifies the id_token itself and hands you a trustworthy `session.sub`.

If your app **has a backend** (confidential client / BFF), the standard, safer split is:
- the browser sends the authorization `code` to **your** backend,
- your backend exchanges it and verifies the id_token server-side (a generic OIDC library on the discovery document below),
- the browser never becomes the trust root.

In that case you don't need this SDK's verification — use it only for the PKCE/redirect plumbing, or skip it and let the backend own the flow.

## Server side

This SDK only handles the browser. Your backend should:
1. Validate `accessToken` against `/.well-known/jwks.json` on every protected request
2. Store `refreshToken` server-side (HttpOnly cookie) — don't keep it in `localStorage`

For Node.js servers, use a generic OIDC library pointed at `https://api.1pass.dev/.well-known/openid-configuration`. logi advertises a full discovery document so `oauth4webapi`, `openid-client`, `next-auth`, `auth.js` all auto-configure.

## License

MIT © Seunghan Kim
