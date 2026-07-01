// Per-handoff storage for the PKCE verifier + CSRF state. Kept in
// sessionStorage so it survives the IdP redirect round-trip but is wiped on
// tab close.

const KEY = "logi-auth.pending";

export interface PendingHandoff {
  state: string;
  verifier: string;
  redirectUri: string;
  /** Optional caller-supplied passthrough (e.g. UI route to restore). */
  returnTo?: string;
  /** OIDC nonce — echoed in the id_token, verified in handleCallback. */
  nonce: string;
  /** ms epoch — used to expire stale handoffs. */
  startedAt: number;
}

export interface StorageBackend {
  get(key: string): string | null;
  set(key: string, value: string): void;
  remove(key: string): void;
}

export const sessionStorageBackend: StorageBackend = {
  get(key) {
    try {
      return sessionStorage.getItem(key);
    } catch {
      return null;
    }
  },
  set(key, value) {
    // Re-throw on quota / disabled storage so signIn() can refuse to
    // navigate to the IdP. Silent failure (codex P2 2026-05-15) lets the
    // user complete the IdP round-trip and only fail at handleCallback()
    // with a misleading no_pending_handoff. Real-world hits: Safari ITP,
    // iOS private browsing, corporate policies disabling sessionStorage.
    sessionStorage.setItem(key, value);
  },
  remove(key) {
    try {
      sessionStorage.removeItem(key);
    } catch {
      // ignore
    }
  },
};

export function savePending(p: PendingHandoff, backend: StorageBackend): void {
  backend.set(KEY, JSON.stringify(p));
}

export function loadPending(backend: StorageBackend): PendingHandoff | null {
  const raw = backend.get(KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as PendingHandoff;
  } catch {
    return null;
  }
}

export function clearPending(backend: StorageBackend): void {
  backend.remove(KEY);
}
