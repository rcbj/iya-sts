// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/policy_post_login.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table:
// `models/tools/generate.mjs` compiles it during the image build and `common/post_login_policy.ts`
// reads the result. The comments are the ones that sat on these rows there.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

// RETIRED BY #1135, KEPT IN THE SCHEMA: no field reads it, and an entry
// written before still holds it, which a schema without it would refuse.
@entry(#{
  id: "policy.postLogin",
  source: "policy_kinds:postLogin",
  container: "ou=postLoginPolicies",
  ownContainer: true,
  authored: true,
  objectClasses: #[
    #{
      name: "stsPostLoginPolicy",
      what: "This service's class for a post-login activity profile: what a person is asked to do after signing in. Named by the PROFILE (`cn=default`, or a named profile an application or a group names)."
    }
  ]
})
model PolicyPostLogin {
  @attr(#{
    what: "OFF BY DEFAULT. On, every person this profile reaches who is due the activity below is asked to do it after signing in, before they are sent back to the application. A named profile with this off EXCLUDES whoever it is selected for: the members of the groups naming it, and a sign-in to an application naming it.",
    field: #{key: "enabled", type: "bool", dflt: false, label: "Ask after sign-in"}
  })
  stsPostLoginEnabled?: boolean;
  @attr(#{
    what: "What is asked. pqc-passkey-migration: a person holding a passkey made with a classical algorithm is asked to register a post-quantum (ML-DSA) passkey. Whether the classical passkey is replaced in place or kept beside it is the method's to say (below). Nobody is asked where the realm offers no ML-DSA algorithm at registration (the default webauthn.algorithms does).",
    field: #{key: "activity", type: "enum", dflt: "pqc-passkey-migration", label: "Activity"}
  })
  stsPostLoginActivity?: string;
  @attr(#{
    what: "How long Skip puts the activity off for that person.",
    field: #{key: "snoozeDays", type: "int", dflt: 7, min: 1, max: 90, unit: "days", label: "Skip puts it off for"}
  })
  stsPostLoginSnoozeDays?: int32;
  @attr(#{
    what: "Counted from the person's FIRST invitation. When it has passed, Skip is gone and the sign-in is held — no session is started — until the activity is done. 0 is no deadline: it can always be skipped.",
    field: #{key: "graceDays", type: "int", dflt: 0, min: 0, max: 3650, unit: "days", label: "Allotted time"}
  })
  stsPostLoginGraceDays?: int32;
  @attr(#{
    what: "leave: not asked. invite: asked to register a post-quantum passkey, and may always skip it. require: asked, and may skip it only until the allotted time has passed.",
    field: #{key: "noPasskey", type: "enum", dflt: "leave", values: #["leave", "invite", "require"], label: "A person with no passkey"}
  })
  stsPostLoginNoPasskey?: string;
  @attr(#{
    what: "upgrade: the person uses their classical passkey once, then an ML-DSA passkey replaces it in place on the same authenticator — one passkey, nothing left behind. alongside: an ML-DSA passkey is added beside it, in the post-quantum lane where the realm offers two lanes, or on another authenticator where it offers one. automatic: alongside where the person's passkey policy offers two lanes, upgrade where it offers one.",
    field: #{key: "method", type: "enum", dflt: "automatic", values: #["automatic", "upgrade", "alongside"], label: "How a classical passkey is migrated"}
  })
  stsPostLoginMethod?: string;
  @attr(#{
    what: "any: its key algorithm is ML-DSA. post-quantum: its key algorithm is ML-DSA AND its recorded attestation was signed with post-quantum algorithms throughout; a passkey with a classical attestation, or none recorded, does not count, and its holder is asked for one that does.",
    field: #{key: "attestation", type: "enum", dflt: "any", values: #["any", "post-quantum"], label: "A passkey counts as post-quantum when"}
  })
  stsPostLoginAttestation?: string;
  @attr(#{
    what: "none: ML-DSA only. classical: after an ML-DSA registration fails on the device, a retry with the classical algorithms is offered (where the passkey policy allows one) — a classical passkey is better than a password, and its holder is asked for the migration later like anyone else's.",
    field: #{key: "noPasskeyFallback", type: "enum", dflt: "none", values: #["none", "classical"], label: "A person with no passkey whose device cannot make ML-DSA"}
  })
  stsPostLoginNoPasskeyFallback?: string;
  @attr(#{
    what: "Which named post-login profile wins where several are named for one sign-in — by the application and by the person's groups: the lowest, from 1 to 1000.",
    selector: #{key: "precedence"}
  })
  stsPostLoginPrecedence?: DirectoryInteger;
  @attr(#{
    what: "What the profile is for, for the next person."
  })
  description?: (string)[];
  @attr(#{
    what: "Retired (#1135): the role a person with no passkey registered one in. A passkey has no role; nothing reads it."
  })
  stsPostLoginNoPasskeyRole?: string;
}
