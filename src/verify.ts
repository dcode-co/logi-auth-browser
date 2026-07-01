// RS256 id_token 검증 — WebCrypto(crypto.subtle), zero runtime deps.
// 서버 검증 규칙 mirror: logi server/app/lib/oauth/jwt_verifier.rb
//   kid 필수 → JWKS 조회 → RS256 서명검증 → iss · aud · exp · iat · nonce · sub.
// 4플랫폼 공통 골든 벡터(../../test-vectors/id-token-vectors.json)를 동일 통과해야 함.
//
// 주의: 이 SDK 는 public client(backend 없는 SPA)용 자체 검증 경로다. backend 있는
// confidential RP 는 backend 가 검증하는 게 표준이며 이 함수를 쓸 필요가 없다.

export type VerifyErrorCode =
  | "malformed"
  | "missing_kid"
  | "unknown_kid"
  | "bad_signature"
  | "iss_mismatch"
  | "aud_mismatch"
  | "expired"
  | "nonce_mismatch"
  | "missing_claim";

export class IdTokenError extends Error {
  constructor(
    public readonly code: VerifyErrorCode,
    message: string
  ) {
    super(message);
    this.name = "IdTokenError";
  }
}

export interface JwkKey {
  kty: string;
  n: string;
  e: string;
  kid: string;
  alg?: string;
  use?: string;
}
export interface Jwks {
  keys: JwkKey[];
}

export interface VerifyExpected {
  /** id_token.iss must equal this (logi issuer). */
  issuer: string;
  /** id_token.aud must contain this (the RP's client_id). */
  clientId: string;
  /** If set, id_token.nonce must equal this (the value sent in authorize). */
  nonce?: string;
}

export interface VerifyOptions {
  jwks: Jwks;
  expected: VerifyExpected;
  /** Unix seconds; defaults to now. Injectable for deterministic tests. */
  now?: number;
  /** Allowed clock skew in seconds (default 60). */
  clockSkewSec?: number;
}

export interface VerifiedIdToken {
  sub: string;
  claims: Record<string, unknown>;
}

function b64urlToBytes(seg: string): Uint8Array {
  const b64 = seg.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function decodeSegment(seg: string): Record<string, unknown> {
  const json = new TextDecoder("utf-8").decode(b64urlToBytes(seg));
  return JSON.parse(json) as Record<string, unknown>;
}

/**
 * Verify a logi-issued id_token and return its verified subject.
 * Throws IdTokenError (with a `code`) on any failure. Never returns an
 * unverified subject.
 */
export async function verifyIdToken(
  idToken: string,
  opts: VerifyOptions
): Promise<VerifiedIdToken> {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const skew = opts.clockSkewSec ?? 60;

  const parts = idToken.split(".");
  const h = parts[0];
  const p = parts[1];
  const s = parts[2];
  if (parts.length !== 3 || !h || !p || !s) {
    throw new IdTokenError("malformed", "id_token must have three non-empty segments");
  }

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = decodeSegment(h);
  } catch {
    throw new IdTokenError("malformed", "id_token header is not valid base64url JSON");
  }
  try {
    payload = decodeSegment(p);
  } catch {
    throw new IdTokenError("malformed", "id_token payload is not valid base64url JSON");
  }

  // Only RS256 is accepted — never verify a token whose header declares another
  // (or no) algorithm, even if the RSA signature happens to match.
  if (header["alg"] !== "RS256") {
    throw new IdTokenError("bad_signature", "unexpected alg; only RS256 is accepted");
  }

  const kid = header["kid"];
  if (typeof kid !== "string" || !kid) {
    throw new IdTokenError("missing_kid", "id_token header is missing kid");
  }
  const jwk = opts.jwks.keys.find((k) => k.kid === kid);
  if (!jwk) {
    throw new IdTokenError("unknown_kid", `no JWKS key matches kid=${kid}`);
  }

  // RS256 signature verification via WebCrypto (no dependency).
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true } as JsonWebKey,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const signingInput = new TextEncoder().encode(`${h}.${p}`);
  const signature = b64urlToBytes(s);
  const sigOk = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    signature as unknown as BufferSource,
    signingInput as unknown as BufferSource
  );
  if (!sigOk) {
    throw new IdTokenError("bad_signature", "RS256 signature verification failed");
  }

  // Claim checks (order: iss → aud → exp → iat → nonce → sub).
  if (payload["iss"] !== opts.expected.issuer) {
    throw new IdTokenError("iss_mismatch", `iss ${String(payload["iss"])} != ${opts.expected.issuer}`);
  }

  const aud = payload["aud"];
  const audOk = Array.isArray(aud)
    ? aud.includes(opts.expected.clientId)
    : aud === opts.expected.clientId;
  if (!audOk) {
    throw new IdTokenError("aud_mismatch", `aud does not contain ${opts.expected.clientId}`);
  }

  // OIDC §3.1.3.7 azp: with multiple audiences an azp MUST be present; whenever
  // azp is present it MUST equal our client_id.
  const azp = payload["azp"];
  if (Array.isArray(aud) && aud.length > 1) {
    if (azp !== opts.expected.clientId) {
      throw new IdTokenError("aud_mismatch", "azp must equal client_id for a multi-audience id_token");
    }
  } else if (azp !== undefined && azp !== null) {
    if (azp !== opts.expected.clientId) {
      throw new IdTokenError("aud_mismatch", "azp does not match client_id");
    }
  }

  const exp = payload["exp"];
  if (typeof exp !== "number" || exp <= now - skew) {
    throw new IdTokenError("expired", "id_token is expired");
  }

  const iat = payload["iat"];
  if (typeof iat !== "number" || iat > now + skew) {
    throw new IdTokenError("malformed", "id_token iat is missing or in the future");
  }

  if (opts.expected.nonce !== undefined && payload["nonce"] !== opts.expected.nonce) {
    throw new IdTokenError("nonce_mismatch", "id_token nonce does not match the value sent in authorize");
  }

  const sub = payload["sub"];
  if (typeof sub !== "string" || !sub) {
    throw new IdTokenError("missing_claim", "id_token is missing sub");
  }

  return { sub, claims: payload };
}
