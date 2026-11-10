// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/policy_service_account.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table:
// `models/tools/generate.mjs` compiles it during the image build and `common/service_account_policy.ts`
// reads the result. The comments are the ones that sat on these rows there.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

@entry(#{
  id: "policy.serviceAccount",
  source: "policy_kinds:serviceAccount",
  container: "ou=serviceAccountPolicies",
  ownContainer: true,
  authored: true,
  // THE PASSWORD DOORS a service account may be allowed, in the order the
  // page draws them. `id` is what a door passes to `credentials.verify()` as
  // `door` (`browser` and `kerberos` are answered by the sign-in funnel and the
  // KDC); `key` is the policy setting, stsSvcAcct<Key>, built from the row by
  // common/service_account_policy.ts, on by default.
  doors: #[
    #{id: "ldap", key: "allowLdapBind", label: "LDAP simple bind"},
    #{id: "wstrust", key: "allowWsTrust", label: "WS-Trust UsernameToken"},
    #{id: "scim", key: "allowScim", label: "SCIM HTTP Basic"},
    #{id: "ssf", key: "allowSsf", label: "Shared Signals HTTP Basic"},
    #{id: "est", key: "allowEst", label: "EST HTTP Basic"},
    #{id: "kerberos", key: "allowKerberos", label: "Kerberos AS exchange"},
    #{id: "ropc", key: "allowPasswordGrant", label: "OAuth 2.0 password grant"}
  ],
  objectClasses: #[
    #{
      name: "stsServiceAccountPolicy",
      what: "This service's class for a service-account policy: what a service account in this realm may do and how its password rotates. The entry is named by the PROFILE: `cn=default`, or a named profile a service account names in its stsServiceAccountPolicy."
    }
  ]
})
model PolicyServiceAccount {
  @attr(#{
    what: "OFF BY DEFAULT. On, the authentication policy's second-factor requirements do not apply to a service account in this realm, and nor does the refusal of a password alone at the password doors (#101). The account's amr still says pwd only, so a relying party asking for more is refused it. WEAKER: an account on a password alone is an account anyone with the password is.",
    field: #{key: "exemptFromSecondFactor", type: "bool", dflt: false, label: "Service accounts are exempt from the second factor"}
  })
  stsSvcAcctExemptFromSecondFactor?: boolean;
  @attr(#{
    what: "OFF BY DEFAULT. Off, the sign-in screen, the user portal and the admin console refuse a service account, whichever first factor it presents, and turning a person into a service account ends their browser sessions. A service account is used by a program, and a program has no business at a sign-in screen.",
    field: #{key: "allowBrowserSignIn", type: "bool", dflt: false, label: "Service accounts may sign in at a browser"}
  })
  stsSvcAcctAllowBrowserSignIn?: boolean;
  @attr(#{
    what: "A bind on 389 or 636 (RFC 4513). Off, a service account's right password is refused there as a wrong one is."
  })
  stsSvcAcctAllowLdapBind?: DirectoryBoolean;
  @attr(#{
    what: "A WS-Security UsernameToken sent to the security token service. Off, a service account's right password is refused there as a wrong one is."
  })
  stsSvcAcctAllowWsTrust?: DirectoryBoolean;
  @attr(#{
    what: "HTTP Basic at /scim/v2 (RFC 7617). Off, a service account's right password is refused there as a wrong one is."
  })
  stsSvcAcctAllowScim?: DirectoryBoolean;
  @attr(#{
    what: "HTTP Basic at the /ssf endpoints (RFC 7617). Off, a service account's right password is refused there as a wrong one is."
  })
  stsSvcAcctAllowSsf?: DirectoryBoolean;
  @attr(#{
    what: "HTTP Basic at /.well-known/est (RFC 7030 section 3.2.3). Off, a service account's right password is refused there as a wrong one is."
  })
  stsSvcAcctAllowEst?: DirectoryBoolean;
  @attr(#{
    what: "An AS-REQ whose pre-authentication proves the password's key (RFC 4120), and MS-KKDCP. Off, a service account's right password is refused there as a wrong one is."
  })
  stsSvcAcctAllowKerberos?: DirectoryBoolean;
  @attr(#{
    what: "grant_type=password at the token endpoint (RFC 6749 section 4.3), where the realm allows the grant at all. Off, a service account's right password is refused there as a wrong one is."
  })
  stsSvcAcctAllowPasswordGrant?: DirectoryBoolean;
  @attr(#{
    what: "OFF BY DEFAULT. On, the service-accounts.rotate job gives every service account that names a push destination a new generated password each interval: pushed to the destination FIRST, its hash committed only after the push succeeds, the previous password kept for the overlap below. A failed push changes nothing. Cannot be turned on while this realm has no push destination.",
    field: #{key: "rotationEnabled", type: "bool", dflt: false, label: "Rotate service-account passwords automatically"}
  })
  stsSvcAcctRotationEnabled?: boolean;
  @attr(#{
    what: "How long a service account's password is kept before the job replaces it, counted from the last rotation (or the account's last password change).",
    field: #{key: "rotationIntervalDays", type: "int", dflt: 30, min: 1, max: 3650, unit: "days", label: "Rotation interval"}
  })
  stsSvcAcctRotationIntervalDays?: int32;
  @attr(#{
    what: "After a rotation the previous password is accepted for this long, so a consumer slow to read the new one is not refused — nor counted by risk scoring as guessing (#226). The previous Kerberos keys are kept as long. 0: the old password stops at once.",
    field: #{key: "rotationOverlapMinutes", type: "int", dflt: 60, min: 0, max: 10080, unit: "minutes", label: "How long the previous password still works"}
  })
  stsSvcAcctRotationOverlapMinutes?: int32;
  @attr(#{
    what: "Drawn by the password policy's generator, so it meets that policy, and never shorter than its minimum length.",
    field: #{key: "generatedLength", type: "int", dflt: 32, min: 16, max: 128, unit: "characters", label: "Length of a rotated password"}
  })
  stsSvcAcctGeneratedLength?: int32;
  @attr(#{
    what: "ON BY DEFAULT. The owner — a person or a group in this realm — is who answers for the account; a service account cannot be saved without one while this is on.",
    field: #{key: "requireOwner", type: "bool", dflt: true, label: "A service account must name an owner"}
  })
  stsSvcAcctRequireOwner?: boolean;
  @attr(#{
    what: "A failed rotation is retried at the job's next run. After this many in a row the account is reported on Monitoring → Service accounts and logged as an alarm (STS-SVCACCT-0042).",
    field: #{key: "rotationAlarmFailures", type: "int", dflt: 3, min: 1, max: 100, unit: "failures", label: "Failed rotations in a row before the alarm"}
  })
  stsSvcAcctRotationAlarmFailures?: int32;
  @attr(#{
    what: "Which named service-account policy wins where several are named: the lowest, from 1 to 1000. A service account names one policy, so today it decides nothing.",
    selector: #{key: "precedence"}
  })
  stsServiceAccountPrecedence?: DirectoryInteger;
  @attr(#{
    what: "What the profile is for, for the next person."
  })
  description?: (string)[];
}
