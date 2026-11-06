// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ---------------------------------------------------------------------------
// THE VALIDATION DOOR'S SHAPES (#1360): `common/certificate_trust.ts` answers
// a `TrustVerdict`, and `common/signer_truststore.ts` holds `SignerAnchor`s.
// ---------------------------------------------------------------------------

export type CheckStatus = 'passed' | 'failed' | 'not-asked' | 'exempt-by-spec';

export type CheckId = 'path' | 'validity' | 'revocation' |
  'basic-constraints' | 'key-usage' | 'extended-key-usage' |
  'name-constraints' | 'signature-strength' | 'key-strength' |
  'critical-extensions' | 'self-signed-allowed' | 'name-match';

export type AnchorSource = 'realm' | 'signer-truststore' |
  'client-truststore' | 'caller' | 'registered-root' | 'pinned';

export interface PathStep {
  der: Buffer;
  subject: string;
  fingerprint256: string;
}

export interface TrustVerdict {
  ok: boolean;
  purpose: string;
  inForce: boolean;
  anchor: AnchorSource | 'none';
  path: PathStep[];
  revocation: any;
  checks: Record<CheckId, CheckStatus>;
  code: string;
  why: string;
}

export interface LeafRule {
  keyUsage: string[];
  eku: { oids: string[]; required: boolean } | null;
  mayBeCa: boolean;
}

export interface PurposeVariant {
  leaf?: Partial<LeafRule>;
  selfSigned?: 'refuse' | 'allow-by-spec';
  validity?: 'now' | 'not-before-by-spec';
  revocation?: 'required' | 'exempt-by-spec';
}

export interface Purpose {
  id: string;
  setting: string;
  title: string;
  covers: string;
  adds: string;
  sites: string[];
  anchors: AnchorSource[];
  leaf: LeafRule;
  selfSigned: 'refuse' | 'allow-by-spec';
  validity: 'now' | 'not-before-by-spec';
  revocation: 'required' | 'exempt-by-spec';
  exemptions: Array<{ check: CheckId; spec: string }>;
  variants?: Record<string, PurposeVariant>;
  baseline: 'none' | 'peer-chain' | 'signer-chain' | 'caller-path' |
    'direct' | 'realm-leaf';
  code: string;
  phase: number;
}

export interface SignerAnchor {
  fingerprint256: string;
  pem: string;
  kind: 'anchor' | 'intermediate';
  purposes: string[];
  source: 'file' | 'runtime' | 'import';
  addedBy: string;
  addedAt: string;
  subject: string;
  issuer: string;
  notBefore: number;
  notAfter: number;
  unadmittable?: string;
}

export type PinStatus = 'valid' | 'expiring' | 'expired' | 'not-yet-valid' |
  'revoked' | 'chain-missing' | 'self-signed' | 'thumbprint-only' |
  'unreadable';

export interface PinnedSource {
  source: string;
  where: string;
  purpose: string;
  pem?: string;
  chain?: string[];
  thumbprint?: string;
  href?: string;
}

export interface PinnedCertificate extends PinnedSource {
  pem?: string;
  subject: string;
  notBefore: number;
  notAfter: number;
  selfSigned: boolean;
  chainedTo: string;
  revocation: string;
  status: PinStatus;
  code: string;
  fingerprint256: string;
}
