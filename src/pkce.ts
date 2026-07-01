// PKCE helpers (RFC 7636) — browser-only, uses crypto.subtle.
//
// `code_verifier`: 43–128 char URL-safe random string.
// `code_challenge`: BASE64URL(SHA256(verifier)), 43 chars unpadded.

function base64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function generateCodeVerifier(byteLength = 48): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

export async function deriveCodeChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64url(new Uint8Array(digest));
}

export function generateState(): string {
  // Random opaque value to defeat CSRF on the callback. 16 bytes → 22 chars.
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

export function generateNonce(): string {
  // OIDC nonce — echoed into the id_token by the IdP and verified on callback.
  // Binds the id_token to this specific authorize request (replay defense).
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}
