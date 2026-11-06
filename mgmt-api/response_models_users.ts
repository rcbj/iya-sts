// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: response_models_users.ts
//
// ---------------------------------------------------------------------------
// RESPONSE MODELS (#1353): Users, Groups, Multi-factor authentication, Admin roles, Roles, Sign-out, Sessions, Ownership, TOTP MFA, Recovery codes, WebAuthn.
//
// `operations` is keyed by operationId, each value naming the statuses that
// have a model of their own; `components` replaces a named schema of
// `admin_api_spec.ts`. `common/response_model_kit.ts` says how a model is
// written and `mgmt-api/response_models.ts` how these are applied.
// ---------------------------------------------------------------------------

export = {
  components: {} as Record<string, unknown>,
  operations: {} as Record<string, Record<string, unknown>>
};
