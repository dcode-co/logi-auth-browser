// @logi-auth/browser — OAuth 2.0 + OIDC PKCE client for SPAs.
//
// Usage:
//   const auth = new LogiAuth({
//     clientId: 'logi_xxx',
//     redirectUri: window.location.origin + '/auth/callback',
//   });
//
//   // Page A — kick off
//   await auth.signIn();
//
//   // Page B (callback) — finish
//   const tokens = await auth.handleCallback();
//
//   // Server validates id_token via /.well-known/jwks.json — this SDK does
//   // NOT verify signatures (browsers can't keep the public-key cache safe
//   // and the RP backend should be the trust root anyway).

import { generateCodeVerifier, deriveCodeChallenge, generateState, generateNonce } from "./pkce.js";
import {
  type StorageBackend,
  sessionStorageBackend,
  savePending,
  loadPending,
  clearPending,
} from "./storage.js";
import { verifyIdToken, IdTokenError, type Jwks } from "./verify.js";

export interface LogiAuthOptions {
  /** OAuth client_id from logi developer portal. Public PKCE client. */
  clientId: string;
  /** Where the IdP returns the user. Must be one of the registered redirect_uris. */
  redirectUri: string;
  /** Default scopes; override per-call via signIn({ scopes }). */
  scopes?: string[];
  /** Issuer URL (authorize/token/JWKS base). Defaults to https://api.1pass.dev. */
  issuer?: string;
  /** Expected `iss` claim inside the id_token (server OIDC_ISSUER). Defaults to "logi". */
  tokenIssuer?: string;
  /** Override storage backend (default: sessionStorage). */
  storage?: StorageBackend;
  /** Maximum age of a pending handoff in ms (default: 10 minutes). */
  pendingTtlMs?: number;
}

export interface SignInRequest {
  /** Override default scopes. */
  scopes?: string[];
  /** Caller-supplied passthrough — restored in handleCallback().returnTo. */
  returnTo?: string;
  /** OIDC `prompt` parameter (e.g. "login" or "consent"). */
  prompt?: "none" | "login" | "consent" | "select_account";
}

export interface TokenResponse {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  tokenType: string;
  expiresAt?: number;
  scope?: string;
}

export interface LogiSession {
  /** Verified subject from the id_token — pairwise per client. */
  sub: string;
  /** `email` claim, if present and the scope was granted. */
  email?: string;
  /** Raw id_token (already verified by this SDK). */
  idToken: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
  scope?: string;
  /** The `returnTo` value passed to signIn(), if any. */
  returnTo?: string;
}

export type LogiAuthErrorCode =
  | "no_pending_handoff"
  | "state_mismatch"
  | "missing_code"
  | "authorization_server_error"
  | "token_exchange_failed"
  | "expired_handoff"
  | "storage_unavailable"
  | "network_error"
  | "missing_id_token"
  | "id_token_invalid"
  | "jwks_fetch_failed";

export class LogiAuthError extends Error {
  constructor(
    public readonly code: LogiAuthErrorCode,
    message: string,
    public readonly details?: unknown
  ) {
    super(message);
    this.name = "LogiAuthError";
  }
}

export class LogiAuth {
  readonly issuer: string;
  readonly tokenIssuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly defaultScopes: string[];
  private readonly storage: StorageBackend;
  private readonly pendingTtlMs: number;

  constructor(opts: LogiAuthOptions) {
    if (!opts.clientId) throw new Error("LogiAuth: clientId is required");
    if (!opts.redirectUri) throw new Error("LogiAuth: redirectUri is required");
    this.clientId = opts.clientId;
    this.redirectUri = opts.redirectUri;
    this.issuer = (opts.issuer ?? "https://api.1pass.dev").replace(/\/+$/, "");
    this.tokenIssuer = opts.tokenIssuer ?? "logi";
    this.defaultScopes = opts.scopes ?? ["openid", "profile:basic", "email"];
    this.storage = opts.storage ?? sessionStorageBackend;
    this.pendingTtlMs = opts.pendingTtlMs ?? 10 * 60 * 1000;
  }

  /**
   * Build the authorize URL and navigate the browser to it. Persists the PKCE
   * verifier + state to sessionStorage so handleCallback() can complete the
   * exchange after the IdP redirects back.
   */
  async signIn(req: SignInRequest = {}): Promise<void> {
    const verifier = generateCodeVerifier();
    const challenge = await deriveCodeChallenge(verifier);
    const state = generateState();
    const nonce = generateNonce();
    const scopes = (req.scopes ?? this.defaultScopes).join(" ");

    // Persist BEFORE navigating. If sessionStorage is disabled (Safari ITP,
    // iOS private browsing, corp policy), throw a typed error instead of
    // redirecting the user into a flow that can't complete (codex P2
    // 2026-05-15).
    try {
      savePending(
        {
          state,
          verifier,
          nonce,
          redirectUri: this.redirectUri,
          returnTo: req.returnTo,
          startedAt: Date.now(),
        },
        this.storage
      );
    } catch (cause) {
      throw new LogiAuthError(
        "storage_unavailable",
        "Could not persist PKCE handoff to sessionStorage (private browsing, ITP, or corp policy).",
        cause
      );
    }

    const url = new URL(`${this.issuer}/oauth/authorize`);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.clientId);
    url.searchParams.set("redirect_uri", this.redirectUri);
    url.searchParams.set("scope", scopes);
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
    if (req.prompt) url.searchParams.set("prompt", req.prompt);

    window.location.assign(url.toString());
  }

  /**
   * Read the current page URL for ?code & ?state, validate against the
   * persisted handoff, and exchange the code for tokens. Call this from your
   * `/auth/callback` route.
   *
   * Pass an explicit URL if you've already routed past the callback (rare).
   */
  async handleCallback(callbackUrl?: string | URL): Promise<LogiSession> {
    const url = new URL(
      callbackUrl ?? (typeof window !== "undefined" ? window.location.href : "http://localhost/")
    );
    const params = url.searchParams;

    const pending = loadPending(this.storage);
    if (!pending) {
      throw new LogiAuthError(
        "no_pending_handoff",
        "No pending sign-in handoff in sessionStorage. Did you call signIn() in this tab?"
      );
    }

    if (Date.now() - pending.startedAt > this.pendingTtlMs) {
      clearPending(this.storage);
      throw new LogiAuthError(
        "expired_handoff",
        `Pending handoff older than ${this.pendingTtlMs}ms — the user took too long. Restart sign-in.`
      );
    }

    const errParam = params.get("error");
    if (errParam) {
      clearPending(this.storage);
      throw new LogiAuthError(
        "authorization_server_error",
        `Authorization server returned error: ${errParam}`,
        { error: errParam, errorDescription: params.get("error_description") }
      );
    }

    const returnedState = params.get("state");
    if (returnedState !== pending.state) {
      clearPending(this.storage);
      throw new LogiAuthError(
        "state_mismatch",
        "state parameter mismatch — possible CSRF attempt or stale callback."
      );
    }

    const code = params.get("code");
    if (!code) {
      clearPending(this.storage);
      throw new LogiAuthError(
        "missing_code",
        "Callback URL had no `code` parameter."
      );
    }

    // PKCE token exchange. Public client → no client_secret.
    let tokenResp: Response;
    try {
      tokenResp = await fetch(`${this.issuer}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: pending.redirectUri,
          client_id: this.clientId,
          code_verifier: pending.verifier,
        }).toString(),
      });
    } catch (cause) {
      clearPending(this.storage);
      throw new LogiAuthError(
        "network_error",
        "Network error during token exchange (offline, DNS, CORS, or TLS failure).",
        cause
      );
    }

    clearPending(this.storage);

    if (!tokenResp.ok) {
      // Truncate body to 2 KB — IdPs occasionally echo request params on
      // 4xx, and consumers shouldn't blindly log multi-MB payloads to Sentry.
      const rawBody = await tokenResp.text();
      const body = rawBody.length > 2048 ? rawBody.slice(0, 2048) + "…[truncated]" : rawBody;
      throw new LogiAuthError(
        "token_exchange_failed",
        `Token exchange failed: HTTP ${tokenResp.status}`,
        { status: tokenResp.status, body }
      );
    }

    const tokens = await tokenResp.json();
    const idToken = tokens.id_token;
    if (typeof idToken !== "string" || !idToken) {
      throw new LogiAuthError(
        "missing_id_token",
        "Token response had no id_token — was `openid` in the requested scopes?"
      );
    }

    // Verify the id_token (public-client trust boundary). Confidential RPs with
    // a backend should verify server-side instead of relying on this SDK.
    const jwks = await this.fetchJwks();
    let verified;
    try {
      verified = await verifyIdToken(idToken, {
        jwks,
        expected: {
          issuer: this.tokenIssuer,
          clientId: this.clientId,
          nonce: pending.nonce,
        },
      });
    } catch (cause) {
      const code = cause instanceof IdTokenError ? cause.code : "unknown";
      throw new LogiAuthError(
        "id_token_invalid",
        `id_token verification failed (${code}).`,
        cause
      );
    }

    const email = verified.claims["email"];
    return {
      sub: verified.sub,
      email: typeof email === "string" ? email : undefined,
      idToken,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: tokens.expires_in
        ? Date.now() + Number(tokens.expires_in) * 1000
        : undefined,
      scope: tokens.scope,
      returnTo: pending.returnTo,
    };
  }

  /** Fetch the IdP's JWKS for id_token signature verification. */
  private async fetchJwks(): Promise<Jwks> {
    let resp: Response;
    try {
      resp = await fetch(`${this.issuer}/.well-known/jwks.json`);
    } catch (cause) {
      throw new LogiAuthError(
        "network_error",
        "Network error fetching JWKS for id_token verification.",
        cause
      );
    }
    if (!resp.ok) {
      throw new LogiAuthError("jwks_fetch_failed", `JWKS fetch failed: HTTP ${resp.status}`);
    }
    return (await resp.json()) as Jwks;
  }

  /**
   * Exchange a refresh_token for a fresh access_token. Public clients should
   * persist the rotated refresh_token returned in `refreshToken`.
   */
  async refresh(refreshToken: string): Promise<TokenResponse> {
    let resp: Response;
    try {
      resp = await fetch(`${this.issuer}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: this.clientId,
        }).toString(),
      });
    } catch (cause) {
      throw new LogiAuthError(
        "network_error",
        "Network error during refresh (offline, DNS, CORS, or TLS failure).",
        cause
      );
    }

    if (!resp.ok) {
      const rawBody = await resp.text();
      const body = rawBody.length > 2048 ? rawBody.slice(0, 2048) + "…[truncated]" : rawBody;
      throw new LogiAuthError(
        "token_exchange_failed",
        `Refresh failed: HTTP ${resp.status}`,
        { status: resp.status, body }
      );
    }

    const tokens = await resp.json();
    return {
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
      refreshToken: tokens.refresh_token,
      tokenType: tokens.token_type ?? "Bearer",
      expiresAt: tokens.expires_in
        ? Date.now() + Number(tokens.expires_in) * 1000
        : undefined,
      scope: tokens.scope,
    };
  }

  /**
   * Decode an ID token's payload (no signature verification). Use only for
   * UI hints (e.g. show user's email). Real authorization decisions must be
   * made server-side after re-verifying via JWKS.
   */
  parseIdToken<T = Record<string, unknown>>(idToken: string): T {
    const [, payload] = idToken.split(".");
    if (!payload) throw new Error("Invalid id_token: missing payload");
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
    // Decode as UTF-8, not Latin-1 — Korean / Japanese / emoji claim values
    // round-trip correctly. atob() returns a binary string interpreted as
    // UTF-16 by JSON.parse, which mojibakes any non-ASCII (codex P2 fix).
    const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    const json = new TextDecoder("utf-8").decode(bytes);
    return JSON.parse(json) as T;
  }

  /**
   * True when sessionStorage has a pending sign-in (i.e. user just returned
   * from the IdP). Use to gate calling handleCallback() in shared components.
   */
  hasPendingCallback(): boolean {
    return loadPending(this.storage) !== null;
  }
}

export type { StorageBackend, PendingHandoff } from "./storage.js";
