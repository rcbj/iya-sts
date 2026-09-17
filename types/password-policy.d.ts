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
  // The FIELDS rows.
  minLength: number;
  history: number;
  minSymbols: number;
  requireUppercase: boolean;
  requireDigit: boolean;
  generatedLength: number;
  [field: string]: any;
}
