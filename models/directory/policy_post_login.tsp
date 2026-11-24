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
    kind: "single",
    what: "OFF BY DEFAULT. On, every person this profile reaches who is due the activity below is asked to do it after signing in, before they are sent back to the application. A named profile with this off EXCLUDES whoever it is selected for: the members of the groups naming it, and a sign-in to an application naming it.",
    field: #{key: "enabled", type: "bool", dflt: false, label: "Ask after sign-in"}
  })
  stsPostLoginEnabled?: boolean;
  @attr(#{
    kind: "single",
    what: "What is asked. pqc-passkey-migration: a person holding a passkey made with a classical algorithm is asked to register a post-quantum (ML-DSA) passkey. Whether the classical passkey is replaced in place or kept beside it is the method's to say (below). Nobody is asked where the realm offers no ML-DSA algorithm at registration (the default webauthn.algorithms does).",
    field: #{key: "activity", type: "enum", dflt: "pqc-passkey-migration", label: "Activity"}
  })
  stsPostLoginActivity?: string;
  @attr(#{
    kind: "single",
    what: "How long Skip puts the activity off for that person.",
    field: #{key: "snoozeDays", type: "int", dflt: 7, min: 1, max: 90, unit: "days", label: "Skip puts it off for"}
  })
  stsPostLoginSnoozeDays?: int32;
  @attr(#{
    kind: "single",
    what: "Counted from the person's FIRST invitation. When it has passed, Skip is gone and the sign-in is held — no session is started — until the activity is done. 0 is no deadline: it can always be skipped.",
    field: #{key: "graceDays", type: "int", dflt: 0, min: 0, max: 3650, unit: "days", label: "Allotted time"}
  })
  stsPostLoginGraceDays?: int32;
  @attr(#{
    kind: "single",
    what: "leave: not asked. invite: asked to register a post-quantum passkey, and may always skip it. require: asked, and may skip it only until the allotted time has passed.",
    field: #{key: "noPasskey", type: "enum", dflt: "leave", values: #["leave", "invite", "require"], label: "A person with no passkey"}
  })
  stsPostLoginNoPasskey?: string;
  @attr(#{
    kind: "single",
    what: "upgrade: the person uses their classical passkey once, then an ML-DSA passkey replaces it in place on the same authenticator — one passkey, nothing left behind. alongside: an ML-DSA passkey is added beside it, in the post-quantum lane where the realm offers two lanes, or on another authenticator where it offers one. automatic: alongside where the person's passkey policy offers two lanes, upgrade where it offers one.",
    field: #{key: "method", type: "enum", dflt: "automatic", values: #["automatic", "upgrade", "alongside"], label: "How a classical passkey is migrated"}
  })
  stsPostLoginMethod?: string;
  @attr(#{
    kind: "single",
    what: "any: its key algorithm is ML-DSA. post-quantum: its key algorithm is ML-DSA AND its recorded attestation was signed with post-quantum algorithms throughout; a passkey with a classical attestation, or none recorded, does not count, and its holder is asked for one that does.",
    field: #{key: "attestation", type: "enum", dflt: "any", values: #["any", "post-quantum"], label: "A passkey counts as post-quantum when"}
  })
  stsPostLoginAttestation?: string;
  @attr(#{
    kind: "single",
    what: "none: ML-DSA only. classical: after an ML-DSA registration fails on the device, a retry with the classical algorithms is offered (where the passkey policy allows one) — a classical passkey is better than a password, and its holder is asked for the migration later like anyone else's.",
    field: #{key: "noPasskeyFallback", type: "enum", dflt: "none", values: #["none", "classical"], label: "A person with no passkey whose device cannot make ML-DSA"}
  })
  stsPostLoginNoPasskeyFallback?: string;
  // THE MAIL-ENCRYPTION ACTIVITY'S BLOCK (#2009 P2, design X2 and X4): rows
  // of its own, with its own switch, so a profile saved before it existed
  // reads it as off. `optional`: a save that leaves the block out keeps
  // what the profile stored.
  @attr(#{
    kind: "single",
    what: "OFF BY DEFAULT. On, every person this profile reaches whose mail is encrypted to a classical key — an OpenPGP key whose encryption key is not ML-KEM, or an S/MIME certificate whose key is not ML-KEM — is asked after signing in to register a post-quantum one (pqc-mail-encryption): mail encrypted to a classical key today can be read once that key falls. A named profile with this off excludes whoever it is selected for from this activity.",
    field: #{key: "mailEnabled", type: "bool", dflt: false, optional: true, label: "Ask for post-quantum mail encryption"}
  })
  stsPostLoginMailEnabled?: boolean;
  @attr(#{
    kind: "single",
    what: "How long Skip puts the mail-encryption activity off for that person.",
    field: #{key: "mailSnoozeDays", type: "int", dflt: 7, min: 1, max: 90, unit: "days", optional: true, label: "Mail encryption: Skip puts it off for"}
  })
  stsPostLoginMailSnoozeDays?: int32;
  @attr(#{
    kind: "single",
    what: "Counted from the person's FIRST invitation to the mail-encryption activity. When it has passed, Skip is gone and the sign-in is held until a post-quantum key is registered. 0 is no deadline.",
    field: #{key: "mailGraceDays", type: "int", dflt: 0, min: 0, max: 3650, unit: "days", optional: true, label: "Mail encryption: allotted time"}
  })
  stsPostLoginMailGraceDays?: int32;
  @attr(#{
    kind: "single",
    what: "A person whose mail is not encrypted at all (stsMailEncryption none or absent). leave: not asked. invite: asked to register a post-quantum key, and may always skip it. require: asked, and may skip it only until the allotted time has passed.",
    field: #{key: "mailNoKey", type: "enum", dflt: "leave", values: #["leave", "invite", "require"], optional: true, label: "Mail encryption: a person whose mail is not encrypted"}
  })
  stsPostLoginMailNoKey?: string;
  @attr(#{
    kind: "single",
    what: "What the step offers. either: an OpenPGP key and an S/MIME certificate, the kind the person uses now first. openpgp: an RFC 9980 OpenPGP key only. smime: an ML-KEM S/MIME certificate only, uploaded (this realm does not issue one). A kind the realm cannot take is never offered, and nobody is asked where neither can be.",
    field: #{key: "mailPrefer", type: "enum", dflt: "either", values: #["either", "openpgp", "smime"], optional: true, label: "Mail encryption: what is offered"}
  })
  stsPostLoginMailPrefer?: string;
  @attr(#{
    kind: "single",
    what: "How many days a person's classical OpenPGP key stays on their entry and in the Web Key Directory beside the post-quantum key that replaced it, so a correspondent that cannot use the new key still finds the old one. New mail from this service goes to the post-quantum key at once. Afterwards a scheduler job removes the classical key from the entry and the Web Key Directory. 0 removes it at once.",
    field: #{key: "mailKeepClassical", type: "int", dflt: 90, min: 0, max: 3650, unit: "days", optional: true, label: "Mail encryption: keep the classical OpenPGP key for"}
  })
  stsPostLoginMailKeepClassical?: int32;
  // THE PIV RE-ISSUE'S BLOCK (#2009 P3, design X2 and X5): rows of its own,
  // with its own switch, `optional` as the mail block's are.
  @attr(#{
    kind: "single",
    what: "OFF BY DEFAULT. On, every person this profile reaches who holds a PIV slot certificate this realm issued, in a slot pivSlots names, is asked after signing in to enrol a new one (piv-reissue) when pivTrigger says it is due: its issuer signed it with a classical algorithm while this realm's EST Issuing CA is post-quantum, or it expires within pivRenewDays. The old certificate is revoked (superseded) when the new one is first used at a sign-in. A named profile with this off excludes whoever it is selected for from this activity.",
    field: #{key: "pivEnabled", type: "bool", dflt: false, optional: true, label: "Ask for PIV certificate re-issue"}
  })
  stsPostLoginPivEnabled?: boolean;
  @attr(#{
    kind: "single",
    what: "How long Skip puts the PIV re-issue off for that person.",
    field: #{key: "pivSnoozeDays", type: "int", dflt: 7, min: 1, max: 90, unit: "days", optional: true, label: "PIV re-issue: Skip puts it off for"}
  })
  stsPostLoginPivSnoozeDays?: int32;
  @attr(#{
    kind: "single",
    what: "Counted from the person's FIRST invitation to the PIV re-issue. When it has passed, Skip is gone and the sign-in is held until every due slot has a new certificate. 0 is no deadline.",
    field: #{key: "pivGraceDays", type: "int", dflt: 0, min: 0, max: 3650, unit: "days", optional: true, label: "PIV re-issue: allotted time"}
  })
  stsPostLoginPivGraceDays?: int32;
  @attr(#{
    kind: "single",
    what: "The PIV slots whose certificates the activity looks at, comma-separated: 9a (PIV authentication), 9c (digital signature), 9d (key management), 9e (card authentication). A slot whose profile est.allowedProfiles leaves out is never asked for.",
    field: #{key: "pivSlots", type: "list", dflt: "9a,9c,9d,9e", values: #["9a", "9c", "9d", "9e"], optional: true, label: "PIV re-issue: slots"}
  })
  stsPostLoginPivSlots?: string;
  @attr(#{
    kind: "single",
    what: "What makes a slot's certificate due. classical-issuer: its issuer signed it with a classical algorithm and this realm's EST Issuing CA is post-quantum (a certificate re-issued under a classical CA would be no better). expiring: it expires within pivRenewDays. both: either.",
    field: #{key: "pivTrigger", type: "enum", dflt: "both", values: #["classical-issuer", "expiring", "both"], optional: true, label: "PIV re-issue: what makes a certificate due"}
  })
  stsPostLoginPivTrigger?: string;
  @attr(#{
    kind: "single",
    what: "How many days before a PIV slot certificate expires it is due for renewal, where pivTrigger is expiring or both.",
    field: #{key: "pivRenewDays", type: "int", dflt: 30, min: 1, max: 365, unit: "days", optional: true, label: "PIV re-issue: renew this long before expiry"}
  })
  stsPostLoginPivRenewDays?: int32;
  @attr(#{
    kind: "single",
    what: "What the new certificate is over. reissue: a new certificate over a key the card makes again in the same slot, signed by the realm's EST Issuing CA. rekey: a post-quantum key on the card, which no PIV card can make today, so a profile set to rekey asks nobody.",
    field: #{key: "pivTarget", type: "enum", dflt: "reissue", values: #["reissue", "rekey"], optional: true, label: "PIV re-issue: what is issued"}
  })
  stsPostLoginPivTarget?: string;
  @attr(#{
    kind: "single",
    what: "Which named post-login profile wins where several are named for one sign-in — by the application and by the person's groups: the lowest, from 1 to 1000.",
    selector: #{key: "precedence"}
  })
  stsPostLoginPrecedence?: DirectoryInteger;
  @attr(#{
    what: "What the profile is for, for the next person."
  })
  description?: (string)[];
  @attr(#{
    kind: "single",
    what: "Retired (#1135): the role a person with no passkey registered one in. A passkey has no role; nothing reads it."
  })
  stsPostLoginNoPasskeyRole?: string;
}
