// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: response_models_directory.ts
//
// ---------------------------------------------------------------------------
// RESPONSE MODELS (#1353): Kerberos, LDAP, Directory, TLS, WS-Trust, WS-Federation, SCIM, SAML 2.0, SAML 1.1, SAML assertions, Custom SAML attributes, Custom claims, UserInfo claims.
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
