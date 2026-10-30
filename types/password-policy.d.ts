// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ---------------------------------------------------------------------------
// A PASSWORD POLICY PROFILE, as `common/password_policy.ts` read() answers it
// (#50, 2026-09-16): the description of the entry, and then one member per row
// of that file's FIELDS table — the table is the source, and a field added
// there is added here.
// ---------------------------------------------------------------------------
export interface PasswordProfile {
  name: string;
  stored: boolean;
  dn: string;
  description: string;
  sources: Record<string, string>;
  problems: string[];
  enforced: boolean;
  // A named policy's precedence (#1236); absent on `default`.
  precedence?: number;
  // The FIELDS rows.
  minLength: number;
  history: number;
  minSymbols: number;
  requireUppercase: boolean;
  requireDigit: boolean;
  generatedLength: number;
  // How a new password is stored (#847).
  hashAlgorithm: string;
  argon2Memory: number;
  argon2Iterations: number;
  argon2Parallelism: number;
  scryptLogN: number;
  scryptBlockSize: number;
  scryptParallelism: number;
  [field: string]: any;
}
