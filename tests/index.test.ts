// Vitest unit tests for @logi-auth/browser. We stub crypto.subtle, sessionStorage,
// and fetch so the SDK's PKCE round-trip can be exercised without a browser.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LogiAuth, LogiAuthError } from "../src/index.js";
import type { StorageBackend } from "../src/storage.js";
import { generateCodeVerifier, deriveCodeChallenge, generateState } from "../src/pkce.js";

class MemoryStorage implements StorageBackend {
  private map = new Map<string, string>();
  get(key: string) { return this.map.get(key) ?? null; }
  set(key: string, value: string) { this.map.set(key, value); }
  remove(key: string) { this.map.delete(key); }
  has(key: string) { return this.map.has(key); }
}

// jsdom-free crypto.subtle shim for the digest path.
beforeEach(() => {
  if (typeof globalThis.crypto === "undefined" || !globalThis.crypto.subtle) {
    Object.defineProperty(globalThis, "crypto", {
      value: {
        getRandomValues: <T extends ArrayBufferView>(arr: T): T => {
          const view = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
          for (let i = 0; i < view.length; i++) view[i] = (i * 7 + 13) & 0xff; // deterministic
          return arr;
        },
        subtle: {
          digest: async (_alg: string, data: ArrayBuffer) => {
            // Fake hash: identity-truncated to 32 bytes (good enough for round-trip math).
            const out = new Uint8Array(32);
            const src = new Uint8Array(data);
            for (let i = 0; i < 32; i++) out[i] = src[i % src.length] ?? 0;
            return out.buffer;
          },
        },
      },
      configurable: true,
    });
  }
});

describe("PKCE helpers", () => {
  it("generates a base64url verifier of the requested byte length", () => {
    const v = generateCodeVerifier(48);
    expect(v).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(v.length).toBeGreaterThanOrEqual(43);
    expect(v.length).toBeLessThanOrEqual(128);
  });

  it("derives a 43-char unpadded base64url challenge", async () => {
    const ch = await deriveCodeChallenge("test-verifier-12345");
    expect(ch).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("state is opaque and base64url-safe", () => {
    const s = generateState();
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(s.length).toBeGreaterThanOrEqual(20);
  });
});

describe("LogiAuth construction", () => {
  it("rejects missing clientId", () => {
    expect(() => new LogiAuth({ clientId: "", redirectUri: "https://x" })).toThrow(/clientId/);
  });
  it("rejects missing redirectUri", () => {
    expect(() => new LogiAuth({ clientId: "x", redirectUri: "" })).toThrow(/redirectUri/);
  });
  it("uses defaults for issuer + scopes", () => {
    const a = new LogiAuth({ clientId: "x", redirectUri: "https://r" });
    expect(a.issuer).toBe("https://api.1pass.dev");
    expect(a.defaultScopes).toEqual(["openid", "profile:basic", "email"]);
  });
  it("strips trailing slash from issuer override", () => {
    const a = new LogiAuth({ clientId: "x", redirectUri: "https://r", issuer: "https://idp.example/" });
    expect(a.issuer).toBe("https://idp.example");
  });
});

describe("handleCallback", () => {
  let storage: MemoryStorage;
  let auth: LogiAuth;

  beforeEach(() => {
    storage = new MemoryStorage();
    auth = new LogiAuth({
      clientId: "logi_test",
      redirectUri: "https://rp.example/cb",
      storage,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("throws no_pending_handoff when sessionStorage is empty", async () => {
    await expect(
      auth.handleCallback("https://rp.example/cb?code=abc&state=xyz")
    ).rejects.toThrow(LogiAuthError);
  });

  it("throws state_mismatch when returned state ≠ persisted state", async () => {
    storage.set("logi-auth.pending", JSON.stringify({
      state: "expected", verifier: "v", redirectUri: "https://rp.example/cb", startedAt: Date.now(),
    }));
    await expect(
      auth.handleCallback("https://rp.example/cb?code=abc&state=wrong")
    ).rejects.toMatchObject({ code: "state_mismatch" });
  });

  it("throws missing_code when callback has state but no code", async () => {
    storage.set("logi-auth.pending", JSON.stringify({
      state: "s", verifier: "v", redirectUri: "https://rp.example/cb", startedAt: Date.now(),
    }));
    await expect(
      auth.handleCallback("https://rp.example/cb?state=s")
    ).rejects.toMatchObject({ code: "missing_code" });
  });

  it("throws expired_handoff when pending older than ttl", async () => {
    storage.set("logi-auth.pending", JSON.stringify({
      state: "s", verifier: "v", redirectUri: "https://rp.example/cb",
      startedAt: Date.now() - 60 * 60 * 1000, // 1h ago
    }));
    await expect(
      auth.handleCallback("https://rp.example/cb?code=abc&state=s")
    ).rejects.toMatchObject({ code: "expired_handoff" });
  });

  it("throws authorization_server_error when callback contains ?error=", async () => {
    storage.set("logi-auth.pending", JSON.stringify({
      state: "s", verifier: "v", redirectUri: "https://rp.example/cb", startedAt: Date.now(),
    }));
    await expect(
      auth.handleCallback("https://rp.example/cb?error=access_denied&state=s")
    ).rejects.toMatchObject({ code: "authorization_server_error" });
  });

  it("exchanges code for tokens on a happy path and clears pending", async () => {
    storage.set("logi-auth.pending", JSON.stringify({
      state: "s", verifier: "v", redirectUri: "https://rp.example/cb", returnTo: "/dashboard",
      startedAt: Date.now(),
    }));
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({
        access_token: "at_xxx", id_token: "header.eyJzdWIiOiJ1XzEifQ.sig",
        refresh_token: "rt_xxx", token_type: "Bearer", expires_in: 3600, scope: "openid",
      }), { status: 200, headers: { "Content-Type": "application/json" } })
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await auth.handleCallback("https://rp.example/cb?code=abc&state=s");

    expect(result.accessToken).toBe("at_xxx");
    expect(result.refreshToken).toBe("rt_xxx");
    expect(result.returnTo).toBe("/dashboard");
    expect(result.expiresAt).toBeGreaterThan(Date.now());
    expect(storage.has("logi-auth.pending")).toBe(false);

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("https://api.1pass.dev/oauth/token");
    const body = (init as RequestInit).body as string;
    expect(body).toContain("grant_type=authorization_code");
    expect(body).toContain("code=abc");
    expect(body).toContain("client_id=logi_test");
    expect(body).toContain("code_verifier=v");
    expect(body).not.toContain("client_secret"); // public client, never sends it
  });

  it("token_exchange_failed surfaces HTTP body for diagnostics", async () => {
    storage.set("logi-auth.pending", JSON.stringify({
      state: "s", verifier: "v", redirectUri: "https://rp.example/cb", startedAt: Date.now(),
    }));
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      new Response("invalid_grant", { status: 400 })
    ));
    await expect(
      auth.handleCallback("https://rp.example/cb?code=abc&state=s")
    ).rejects.toMatchObject({
      code: "token_exchange_failed",
      details: { status: 400, body: "invalid_grant" },
    });
  });
});

describe("refresh", () => {
  it("posts refresh_token grant and returns new tokens", async () => {
    const auth = new LogiAuth({ clientId: "logi_test", redirectUri: "https://rp.example/cb" });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      new Response(JSON.stringify({
        access_token: "at2", refresh_token: "rt2", expires_in: 1800,
      }), { status: 200 })
    ));
    const tokens = await auth.refresh("rt_old");
    expect(tokens.accessToken).toBe("at2");
    expect(tokens.refreshToken).toBe("rt2"); // rotated
  });
});

describe("parseIdToken", () => {
  it("decodes base64url payload without verification", () => {
    const auth = new LogiAuth({ clientId: "x", redirectUri: "https://r" });
    // payload = {"sub":"u_1","email":"a@b.c"} → base64url
    const claims = auth.parseIdToken<{ sub: string; email: string }>("h.eyJzdWIiOiJ1XzEiLCJlbWFpbCI6ImFAYi5jIn0.s");
    expect(claims).toEqual({ sub: "u_1", email: "a@b.c" });
  });

  it("decodes UTF-8 claim values without mojibake (Korean, emoji)", () => {
    const auth = new LogiAuth({ clientId: "x", redirectUri: "https://r" });
    // Build a JWT-style payload with UTF-8 multi-byte characters
    const utf8 = new TextEncoder().encode('{"name":"김승한","emoji":"🚀"}');
    let bin = "";
    for (const b of utf8) bin += String.fromCharCode(b);
    const payload = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const claims = auth.parseIdToken<{ name: string; emoji: string }>(`h.${payload}.s`);
    // Codex P2 fix: atob → UTF-16 reinterpretation was mojibaking these.
    expect(claims).toEqual({ name: "김승한", emoji: "🚀" });
  });
});

describe("storage_unavailable", () => {
  it("signIn throws typed error when storage.set rejects (private browsing)", async () => {
    const failingStorage: StorageBackend = {
      get: () => null,
      set: () => { throw new DOMException("QuotaExceeded", "QuotaExceededError"); },
      remove: () => {},
    };
    const auth = new LogiAuth({
      clientId: "x", redirectUri: "https://r", storage: failingStorage,
    });
    // Without throwing here the user would be redirected to the IdP and
    // fail at handleCallback() with no_pending_handoff (codex P2 fix).
    await expect(auth.signIn()).rejects.toMatchObject({ code: "storage_unavailable" });
  });
});

describe("network_error", () => {
  it("handleCallback throws network_error when fetch rejects", async () => {
    const storage = new MemoryStorage();
    storage.set("logi-auth.pending", JSON.stringify({
      state: "s", verifier: "v", redirectUri: "https://rp.example/cb", startedAt: Date.now(),
    }));
    const auth = new LogiAuth({
      clientId: "logi_test", redirectUri: "https://rp.example/cb", storage,
    });
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(
      auth.handleCallback("https://rp.example/cb?code=abc&state=s")
    ).rejects.toMatchObject({ code: "network_error" });
  });

  it("refresh throws network_error when fetch rejects", async () => {
    const auth = new LogiAuth({ clientId: "x", redirectUri: "https://r" });
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(auth.refresh("rt_old")).rejects.toMatchObject({ code: "network_error" });
  });
});

describe("token_exchange_failed", () => {
  it("truncates response body to 2 KB to avoid log bloat / param echo leaks", async () => {
    const storage = new MemoryStorage();
    storage.set("logi-auth.pending", JSON.stringify({
      state: "s", verifier: "v", redirectUri: "https://rp.example/cb", startedAt: Date.now(),
    }));
    const auth = new LogiAuth({
      clientId: "logi_test", redirectUri: "https://rp.example/cb", storage,
    });
    const huge = "x".repeat(10_000);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(huge, { status: 400 })));
    try {
      await auth.handleCallback("https://rp.example/cb?code=abc&state=s");
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(LogiAuthError);
      const details = (err as LogiAuthError).details as { body: string };
      expect(details.body).toMatch(/…\[truncated\]$/);
      expect(details.body.length).toBeLessThan(huge.length);
    }
  });
});
