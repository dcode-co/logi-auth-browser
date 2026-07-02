import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { verifyIdToken } from "../src/verify.js";

// 4플랫폼 공통 골든 벡터 (SoT: ../../test-vectors/generate.mjs).
// Web SDK 의 검증기가 이 벡터를 정확히 통과하는지 = 안전성 코어 정합성.
interface GoldenCase {
  name: string;
  token: string;
  // Present-only at_hash binding: threaded into verifyIdToken when set (cases
  // without it skip at_hash, staying backward compatible).
  accessToken?: string;
  expect: { valid: true; sub: string } | { valid: false; error: string };
}
interface GoldenVectors {
  now: number;
  expected: { issuer: string; clientId: string; nonce?: string };
  jwks: { keys: Array<{ kty: string; n: string; e: string; kid: string; alg?: string; use?: string }> };
  cases: GoldenCase[];
}

// 골든 벡터는 4플랫폼 공유(SoT: dcode-co-migration/test-vectors/generate.mjs).
// 각 레포 자립을 위해 fixture 로 복사해 둔다 — 벡터 갱신 시 재복사.
const vectors = JSON.parse(
  readFileSync(new URL("./fixtures/id-token-vectors.json", import.meta.url), "utf8")
) as GoldenVectors;

describe("id_token golden vectors (Web)", () => {
  const opts = {
    jwks: vectors.jwks,
    expected: vectors.expected,
    now: vectors.now,
    clockSkewSec: 60,
  };

  for (const c of vectors.cases) {
    it(c.name, async () => {
      const caseOpts = { ...opts, accessToken: c.accessToken };
      if (c.expect.valid) {
        const result = await verifyIdToken(c.token, caseOpts);
        expect(result.sub).toBe(c.expect.sub);
      } else {
        await expect(verifyIdToken(c.token, caseOpts)).rejects.toMatchObject({
          code: c.expect.error,
        });
      }
    });
  }
});
