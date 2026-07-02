import { describe, it, expect } from "vitest";
import {
  createHash,
  createSign,
  createPublicKey,
  generateKeyPairSync,
} from "node:crypto";
import { verifyIdToken } from "../src/verify.js";

// P2 hardening: at_hash binding + JWKS kty filter. These are self-contained —
// they sign their own RS256 tokens so they do not touch the shared golden
// fixture (that byte-sync happens in the integration step, not in parallel).

const b64url = (x: string) => Buffer.from(x).toString("base64url");

// --- RS256 signing key (= the JWKS "sig" key) ---
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PEM = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const RSA_JWK = createPublicKey(PEM).export({ format: "jwk" }) as {
  n: string;
  e: string;
};
const KID = "hardening-kid-1";
const rsaKey = { kty: "RSA", n: RSA_JWK.n, e: RSA_JWK.e, kid: KID, alg: "RS256", use: "sig" };

// --- EC key sharing the SAME kid (the "future EC key mixed in" case) ---
const { privateKey: ecPriv } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const EC_JWK = createPublicKey(ecPriv).export({ format: "jwk" }) as {
  crv: string;
  x: string;
  y: string;
};
const ecKey = { kty: "EC", crv: EC_JWK.crv, x: EC_JWK.x, y: EC_JWK.y, kid: KID };

function sign(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = createSign("RSA-SHA256").update(input).sign(PEM);
  return `${input}.${sig.toString("base64url")}`;
}

// Independent (node-crypto) reference implementation of the cross-SDK at_hash
// contract: base64url_nopad(SHA256(access_token)[0:16]). Verifying the SDK's
// WebCrypto path against this doubles as a byte-equivalence check.
function atHashFor(accessToken: string): string {
  return createHash("sha256")
    .update(Buffer.from(accessToken, "utf8"))
    .digest()
    .subarray(0, 16)
    .toString("base64url");
}

const NOW = 1_700_000_000;
const ISSUER = "https://api.1pass.dev";
const CLIENT_ID = "logi_test_client_abc";
const NONCE = "nonce-abc123";
const ACCESS_TOKEN = "sample.access.token.value";
const HEADER = { alg: "RS256", kid: KID, typ: "JWT" };
const BASE_PAYLOAD = {
  iss: ISSUER,
  aud: CLIENT_ID,
  sub: "pairwise-sub-0001",
  exp: NOW + 3600,
  iat: NOW - 30,
  nonce: NONCE,
  jti: "jti-h1",
};

const baseOpts = {
  expected: { issuer: ISSUER, clientId: CLIENT_ID, nonce: NONCE },
  now: NOW,
  clockSkewSec: 60,
} as const;

// Cast helper — EC entries legitimately lack n/e, and the SDK never touches
// those fields for a non-selected key.
const jwksOf = (...keys: unknown[]) => ({ jwks: { keys } as never });

describe("at_hash binding (OIDC §3.1.3.6)", () => {
  it("accepts a matching at_hash when access_token is supplied", async () => {
    const token = sign(HEADER, { ...BASE_PAYLOAD, at_hash: atHashFor(ACCESS_TOKEN) });
    const result = await verifyIdToken(token, {
      ...baseOpts,
      ...jwksOf(rsaKey),
      accessToken: ACCESS_TOKEN,
    });
    expect(result.sub).toBe(BASE_PAYLOAD.sub);
  });

  it("rejects a mismatched at_hash (swapped access_token)", async () => {
    const token = sign(HEADER, { ...BASE_PAYLOAD, at_hash: atHashFor(ACCESS_TOKEN) });
    await expect(
      verifyIdToken(token, {
        ...baseOpts,
        ...jwksOf(rsaKey),
        accessToken: "a-DIFFERENT-access-token",
      })
    ).rejects.toMatchObject({ code: "at_hash_mismatch" });
  });

  it("skips the check when access_token is not supplied (non-breaking)", async () => {
    const token = sign(HEADER, { ...BASE_PAYLOAD, at_hash: atHashFor(ACCESS_TOKEN) });
    const result = await verifyIdToken(token, { ...baseOpts, ...jwksOf(rsaKey) });
    expect(result.sub).toBe(BASE_PAYLOAD.sub);
  });

  it("skips the check when the id_token carries no at_hash", async () => {
    const token = sign(HEADER, { ...BASE_PAYLOAD });
    const result = await verifyIdToken(token, {
      ...baseOpts,
      ...jwksOf(rsaKey),
      accessToken: ACCESS_TOKEN,
    });
    expect(result.sub).toBe(BASE_PAYLOAD.sub);
  });
});

describe("JWKS kty filter", () => {
  it("selects the RSA key when an EC key shares the kid", async () => {
    const token = sign(HEADER, { ...BASE_PAYLOAD });
    // EC listed first — without the kty filter, a kid-only find would pick it
    // and RSA importKey would throw.
    const result = await verifyIdToken(token, { ...baseOpts, ...jwksOf(ecKey, rsaKey) });
    expect(result.sub).toBe(BASE_PAYLOAD.sub);
  });

  it("returns unknown_kid when only a non-RSA key matches the kid", async () => {
    const token = sign(HEADER, { ...BASE_PAYLOAD });
    await expect(
      verifyIdToken(token, { ...baseOpts, ...jwksOf(ecKey) })
    ).rejects.toMatchObject({ code: "unknown_kid" });
  });
});
