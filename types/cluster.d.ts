// ---------------------------------------------------------------------------
// THE RESULT SHAPES OF `cluster/` (#50, 2026-09-16).
//
// Each function says in its own header what it resolves; these are those
// sentences as types, referenced by the functions' JSDoc so a checked caller
// may read `reason`, `why` or `highest` after testing `ok`. One interface per
// function with optional members, rather than a union per outcome, because
// the callers read the members before narrowing as often as after.
// ---------------------------------------------------------------------------

// `cluster/cluster_claims.js` claim().
export interface ClaimResult {
  ok: boolean;
  handle?: any;
  reason?: 'used' | 'store' | string;
  why?: string;
  existing?: any;
  errorCode?: string;
}

// `cluster/cluster_counters.js` advance().
export interface AdvanceResult {
  ok: boolean;
  advanced?: boolean;
  highest?: number;
  reason?: 'behind' | 'store' | string;
  why?: string;
}

// `cluster/cluster_counters.js` countInWindow() and peekWindow().
export interface WindowResult {
  ok: boolean;
  count?: number;
  remainingMs?: number;
  reason?: 'store' | 'unshared' | string;
  why?: string;
}
