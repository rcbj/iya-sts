// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The entry point of the abstract model (#1390). `tests/model_typespec.js`
// compiles this file with the TypeSpec compiler and reads the result through
// `lib/model_lib.mjs`.

import "./directory/application.tsp";
import "./directory/role.tsp";
import "./directory/device.tsp";
import "./directory/service_account.tsp";
import "./directory/spiffe.tsp";
import "./directory/xacml_policy.tsp";
import "./directory/xacml_pep.tsp";
import "./directory/federation_relationship.tsp";
import "./directory/policy_password.tsp";
import "./directory/policy_authn.tsp";
import "./directory/policy_passkey.tsp";
import "./directory/policy_locale.tsp";
import "./directory/policy_attributes.tsp";
import "./directory/policy_post_login.tsp";
import "./directory/policy_service_account.tsp";
import "./directory/operational.tsp";
import "./directory/person.tsp";
import "./directory/group.tsp";
import "./directory/attribute_source.tsp";
import "./directory/oidfed.tsp";
import "./directory/claim_provider.tsp";
import "./directory/kerberos_trust.tsp";
import "./directory/trust_anchor.tsp";
import "./directory/signer_trust_anchor.tsp";
import "./directory/names.tsp";
import "./domain/identity.tsp";
import "./domain/application.tsp";
import "./domain/authorization.tsp";
import "./domain/federation.tsp";
import "./domain/pki.tsp";
import "./persistence/persistence.tsp";
import "./persistence/persistence_mariadb.tsp";
import "./api/report.tsp";
import "./api/authn.tsp";
import "./api/account.tsp";
import "./api/management.tsp";
import "./api/console.tsp";
