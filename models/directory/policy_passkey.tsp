// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/policy_passkey.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table:
// `models/tools/generate.mjs` compiles it during the image build and `common/passkey_policy.ts`
// reads the result. The comments are the ones that sat on these rows there.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

// #724: what a recovery leaves on a PERSON's entry.
@entry(#{
  id: "policy.passkey",
  source: "policy_kinds:passkey",
  container: "ou=passkeyPolicies",
  ownContainer: true,
  authored: true,
  objectClasses: #[
    #{
      name: "stsPasskeyPolicy",
      what: "This service's class for a passkey policy: how passkeys behave in this realm. The entry is named by the PROFILE (`cn=default`)."
    }
  ]
})
model PolicyPasskey {
  @attr(#{
    kind: "single",
    what: "ON BY DEFAULT. On, the sign-in screen offers *Sign in with a passkey* and the username field's autofill, which ask the browser for any discoverable credential of this realm (WebAuthn Level 3 section 5.4, `allowCredentials` empty) and sign in the account its user handle names, with user verification required and checked. Off, neither is offered and a sign-in always names the person first. Replaces the setting webauthn.usernameless.",
    field: #{key: "allowUsernameless", type: "bool", dflt: true, label: "Allow a passkey sign-in with no username"}
  })
  stsPasskeyAllowUsernameless?: boolean;
  @attr(#{
    kind: "single",
    what: "OFF BY DEFAULT. On, an application whose authentication mechanism is a passkey and nothing else (the authentication policy it names, appAuthnPolicy, lists `webauthn` alone) gets a sign-in screen with no username field: *Sign in with a passkey* is the way in, and a sign-in that names a person is refused. It needs the row above. The realm's `default` profile does not apply it to the admin console, the debugger or the user portal; a named profile selecting that application does.",
    field: #{key: "requireUsernameless", type: "bool", dflt: false, label: "Require a passkey sign-in with no username"}
  })
  stsPasskeyRequireUsernameless?: boolean;
  @attr(#{
    kind: "single",
    what: "The `residentKey` an enrolment through *Use a security key* (or one that names no kind) sends WHILE usernameless sign-in is ON. While it is off the button always asks `required`, so it makes a discoverable credential as *Create a passkey* does (which asks `required` always). `discouraged` or `preferred` spare a security key's few resident slots, at the cost of a key that needs the username to sign in. Replaces the setting webauthn.residentKey.",
    field: #{key: "securityKeyResidentKey", type: "enum", dflt: "required", label: "What \"Use a security key\" asks for while usernameless sign-in is on"}
  })
  stsPasskeySecurityKeyResidentKey?: string;
  @attr(#{
    kind: "single",
    what: "`allow` (the default) accepts any passkey. `disallow` accepts only DEVICE-BOUND ones: a passkey whose authenticator says it may be backed up or synced (the BE flag, WebAuthn Level 3 section 6.1) is refused when it is registered and when it signs somebody in, so a synced passkey enrolled before the realm said no stops working too. BE never changes for a credential.",
    field: #{key: "backupEligibility", type: "enum", dflt: "allow", label: "Synced passkeys (backup eligible)"}
  })
  stsPasskeyBackupEligibility?: string;
  @attr(#{
    kind: "single",
    what: "OFF BY DEFAULT. On, registration asks the authenticator for its minimum PIN length (CTAP 2.1 section 12.4, the minPinLength extension), records it on the key, and refuses a key whose minimum is below the next row, at registration and at every sign-in. A key answers only for relying parties it was configured to tell (CTAP 2.1 setMinPINLength with this RP ID); every other key, and every platform or synced passkey, does not report, and is refused unless the row after next is on.",
    field: #{key: "enforcePinLength", type: "bool", dflt: false, label: "Require a minimum security-key PIN length"}
  })
  stsPasskeyEnforcePinLength?: boolean;
  @attr(#{
    kind: "single",
    what: "The shortest PIN a security key may be set to accept, as the key itself reports it, while the row above is on. Between 4 (CTAP 2.1's own floor) and 63.",
    field: #{key: "minPinLength", type: "int", unit: "characters", label: "Minimum security-key PIN length"}
  })
  stsPasskeyMinPinLength?: int32;
  @attr(#{
    kind: "single",
    what: "OFF BY DEFAULT, which is the strict reading: while the PIN length is enforced, a key that does not report it is refused. On, such a key is accepted and only a reported minimum is held to the rule — so the rule then binds only keys configured to report to this relying party.",
    field: #{key: "pinLengthOnlyIfSupported", type: "bool", dflt: false, label: "Accept a key that does not report its PIN length"}
  })
  stsPasskeyPinLengthOnlyIfSupported?: boolean;
  @attr(#{
    kind: "single",
    what: "OFF BY DEFAULT. The attestation rules (the webauthn.attestation* settings: the policy, the AAGUID list, the certification level and FIPS) are checked when a passkey is registered. On, they are checked again at every sign-in against what was recorded then and the FIDO Metadata Service as it is now, so a key registered before a rule was tightened, or whose model was since reported compromised, stops signing anybody in. A key with no trusted attestation fails every rule that demands one.",
    field: #{key: "enforceAttestationAtSignIn", type: "bool", dflt: false, label: "Hold every sign-in to the attestation rules in force"}
  })
  stsPasskeyEnforceAttestationAtSignIn?: boolean;
  @attr(#{
    kind: "single",
    what: "`off` (the default) accepts a passkey whatever its signature algorithm. `sign-in` accepts only a POST-QUANTUM passkey, one whose algorithm is ML-DSA-44, ML-DSA-65 or ML-DSA-87 (RFC 9964), when it signs somebody in, as the first credential or as the second factor; a classical one may still be registered. `registration-and-sign-in` refuses a classical one at registration too, and enrolment then offers only ML-DSA. The algorithm decides, not the lane a key was created in. Refused while the realm offers no ML-DSA (webauthn.algorithms names none, and neither webauthn.pqcOnly nor webauthn.pqcAlongsideClassical is on).",
    field: #{key: "postQuantumRequired", type: "enum", dflt: "off", label: "Require a post-quantum passkey"}
  })
  stsPasskeyPostQuantumRequired?: string;
  @attr(#{
    kind: "single",
    what: "`realm` (the default) follows the realm's webauthn.postQuantumAllowCredentials. Read only while postQuantumRequired requires a post-quantum passkey at sign-in. `narrow` names only the person's post-quantum (ML-DSA) passkeys in the passkey step's request, so a classical one is never offered, and a person whose device holds only their classical one sees the platform's own \"no passkey found\" message. `list-and-refuse` names every passkey they hold and refuses a classical one after the ceremony, with a page saying that this application requires a post-quantum passkey and where to add one; the person may then pick a passkey that will be refused. A person holding no post-quantum passkey is told before any ceremony either way. Left out of a save, `realm` is kept.",
    field: #{key: "postQuantumAllowCredentials", type: "enum", dflt: "realm", optional: true, label: "Passkeys a sign-in names where a post-quantum one is required"}
  })
  stsPasskeyPostQuantumAllowCredentials?: string;
  @attr(#{
    kind: "single",
    what: "`realm` (the default) offers the realm's webauthn.algorithms. Otherwise the signature algorithms a passkey registration offers to this profile's people, in order of preference (an authenticator makes the first it supports), from the algorithms webauthn.algorithms may name. The next row may narrow or reorder it, and a passkey whose algorithm is not one this profile offers is refused when it is registered. Left out of a save, `realm` is kept.",
    field: #{key: "registrationAlgorithms", type: "list", optional: true, label: "Algorithms a passkey registration offers"}
  })
  stsPasskeyRegistrationAlgorithms?: string;
  @attr(#{
    kind: "single",
    what: "`realm` (the default) follows webauthn.pqcOnly and webauthn.pqcAlongsideClassical. `pq-only` offers only ML-DSA, and refuses a retry with the classical algorithms. `pq-first` offers ML-DSA first and the classical algorithms after it, even where the realm requests ML-DSA only. `classical-only` offers no ML-DSA and no post-quantum passkey beside a classical one, for people whose devices fail an ML-DSA registration. Refused with postQuantumRequired other than off or with attestationAlgorithms set (classical-only), and where the algorithms offered name no ML-DSA (pq-only, pq-first). Left out of a save, `realm` is kept.",
    field: #{key: "registrationMode", type: "enum", dflt: "realm", optional: true, label: "Post-quantum algorithms at registration"}
  })
  stsPasskeyRegistrationMode?: string;
  // TWO LANES PER POPULATION (#1104): a classical and a post-quantum passkey
  // side by side (#643) for THIS profile's people, or not, whatever the
  // realm's `webauthn.pqcAlongsideClassical` says. `webauthn.pqcOnly` and a
  // `classical-only` mode still leave one lane.
  @attr(#{
    kind: "single",
    what: "`realm` (the default) follows webauthn.pqcAlongsideClassical. `both` gives this profile's people a classical and a post-quantum passkey side by side, each under its own user handle, wherever the realm's setting is off; `one` gives them one lane wherever it is on. webauthn.pqcOnly still means one lane. Refused as `both` with registrationMode classical-only. Left out of a save, `realm` is kept.",
    field: #{key: "lanes", type: "enum", dflt: "realm", optional: true, label: "A classical and a post-quantum passkey side by side"}
  })
  stsPasskeyLanes?: string;
  // THE CLIENTS NOT OFFERED ML-DSA (#1112): a registration from a browser
  // and system a rule names offers the list less ML-DSA, so a platform that
  // fails the whole ceremony when offered an algorithm it cannot do is not
  // offered it. Matched against the ceremony row's own client name
  // (`clientRuleFor()`); never applied where a classical passkey is not
  // allowed (`common/passkey_clients.ts`).
  @attr(#{
    kind: "single",
    what: "EMPTY BY DEFAULT: every client is offered the list as it stands. Otherwise up to 20 rules separated by `;`, each `<browser> on <system>`, where either side is a family as the passkey ceremony rows name it (`Chrome`, `Firefox`, `macOS`, `Android`) or `*` for any, optionally followed by a major-version range (`141`, `130-140`, `130-`, `-140`): `Firefox 140- on Linux; * on Android 13`. A passkey registration from a matching client offers the list less ML-DSA (ES256 and RS256 where that leaves none). Not applied where a classical passkey is not allowed — registrationMode pq-only, webauthn.pqcOnly, postQuantumRequired registration-and-sign-in, or at the sign-in step under postQuantumRequired sign-in — nor to the post-quantum lane, and the ceremony row says it was not. Left out of a save, empty is kept.",
    field: #{key: "clientRules", type: "clientRules", dflt: "", optional: true, label: "Clients a registration offers no ML-DSA"}
  })
  stsPasskeyClientRules?: string;
  @attr(#{
    kind: "single",
    what: "The WebAuthn hints (Level 3 section 5.4.8) the portal's *Create a passkey* sends, in order, from security-key, client-device and hybrid, or none. They tell the browser which way of making the passkey to lead with. A hint may not contradict webauthn.authenticatorAttachment: client-device implies platform, security-key and hybrid cross-platform.",
    field: #{key: "passkeyHints", type: "list", dflt: "client-device,hybrid", label: "Hints \"Create a passkey\" sends"}
  })
  stsPasskeyHintsPasskey?: string;
  @attr(#{
    kind: "single",
    what: "The hints *Use a security key* sends, in order, or none. The button asks for a cross-platform authenticator, so client-device contradicts it and is refused.",
    field: #{key: "securityKeyHints", type: "list", dflt: "security-key", label: "Hints \"Use a security key\" sends"}
  })
  stsPasskeyHintsSecurityKey?: string;
  @attr(#{
    kind: "single",
    what: "The hints a sign-in ceremony sends — the passkey step, the sign-in with no username and its autofill — in order, or none (the default: the browser offers every way it knows).",
    field: #{key: "signInHints", type: "list", label: "Hints a passkey sign-in sends"}
  })
  stsPasskeyHintsSignIn?: string;
  @attr(#{
    kind: "single",
    what: "EMPTY BY DEFAULT: no serial is checked. Set to an attribute of a person's entry (for example `serialNumber`, which may hold several values), a security key registers only with a TRUSTED enterprise attestation whose certificate names a device serial that is one of that person's values. Needs webauthn.attestation set to enterprise, and the vendor or platform configured to release enterprise attestation to this RP ID; without that the browser sends ordinary attestation and every registration is refused.",
    field: #{key: "enterpriseSerialAttribute", type: "attribute", dflt: "", label: "Directory attribute holding a person's security-key serials"}
  })
  stsPasskeyEnterpriseSerialAttribute?: string;
  @attr(#{
    kind: "single",
    what: "EMPTY BY DEFAULT: the name the sign-in knows, else the username. Otherwise up to six directory attributes in order, separated by commas; a group of attributes separated by spaces (givenName sn) joins their values. The first whose every attribute has a value becomes user.displayName (WebAuthn Level 3 section 5.4.3), with control and direction-changing characters removed and at most 64 characters. The username is always user.name.",
    field: #{key: "userDisplayName", type: "attributes", dflt: "", label: "The name a passkey prompt shows for the person"}
  })
  stsPasskeyUserDisplayName?: string;
  @attr(#{
    kind: "single",
    what: "`none` (the default) shows webauthn.rpName alone. `realm`, `organisation` or `realm-and-organisation` append the realm's name and/or saml.organizationName, so a person with accounts in several realms can tell the prompts apart.",
    field: #{key: "rpNameExtras", type: "enum", dflt: "none", label: "What a passkey prompt adds to the service's name"}
  })
  stsPasskeyRpNameExtras?: string;
  @attr(#{
    kind: "single",
    what: "EMPTY BY DEFAULT: the provider's name, else \"Passkey\" or \"Security key\". Otherwise this text, with {provider} and {kind} filled in, at most 60 characters. The person may rename it afterwards, as always.",
    field: #{key: "credentialLabel", type: "text", dflt: "", label: "The name a new passkey is given"}
  })
  stsPasskeyCredentialLabel?: string;
  @attr(#{
    kind: "single",
    what: "ON BY DEFAULT: one \"Use passkey\" step whose request lists every one of the person's passkeys, and the browser offers whichever is present. Off, a person with more than one is shown a choice per passkey, by its name, and the request names only that one.",
    field: #{key: "aggregateDevices", type: "bool", dflt: true, label: "Offer a person's passkeys as one sign-in choice"}
  })
  stsPasskeyAggregateDevices?: boolean;
  @attr(#{
    kind: "single",
    what: "`any` BY DEFAULT IN DEVELOPMENT, `not-weaker` IN PRODUCT. Whether a way back into the account that asks for no passkey — a password reset link, an activation link, a recovery code, an emailed code or link — restores access for a person who holds one. `any`: at once. `not-weaker`: the first sign-in after it that is not a passkey sign-in reaches no application; the person registers a passkey that satisfies this policy and signs in with it. `operator-only`: as not-weaker, and the self-service doors (the forgot-password form, a recovery code or an emailed code or link at sign-in) are refused; only an administrator's reset link, generated password or activation link remains. Left out of a save, the built-in default is kept.",
    field: #{key: "recoveryAssurance", type: "enum", dflt: "any", optional: true, label: "Account recovery for a person who holds a passkey"}
  })
  stsPasskeyRecoveryAssurance?: string;
  @attr(#{
    kind: "single",
    what: "`none` BY DEFAULT: an attestation is accepted whatever it is signed with. Otherwise a list from post-quantum, ml-dsa-44, ml-dsa-65, ml-dsa-87, slh-dsa and composite-ml-dsa: a passkey registers only with a TRUSTED attestation that carries a certificate, whose statement signature and the signature on every certificate of its chain, from the leaf to the trust anchor, are each one the list allows (`post-quantum` allows any ML-DSA, SLH-DSA or composite ML-DSA signature). Self and none attestation are refused, having no certificate. With enforceAttestationAtSignIn on, every sign-in holds the passkey to it by what its registration recorded, so a passkey registered before the rule stops working. This is the attestation's algorithm, not the passkey's own (postQuantumRequired). Left out of a save, the built-in default is kept.",
    field: #{key: "attestationAlgorithms", type: "list", optional: true, label: "Algorithms a passkey's attestation must be signed with"}
  })
  stsPasskeyAttestationAlgorithms?: string;
  @attr(#{
    kind: "single",
    what: "`off` BY DEFAULT. `on` lets an administrator holding the Admin Write console role enrol a passkey for a person this profile applies to, from the person's page on the console or /admin-api: the registration ceremony runs in the administrator's own browser, against an authenticator they hold (a security key to be handed over, say), under the person's user handle, and is verified exactly as the person's own registration is — attestation, algorithms and this policy's registration rules. Nothing made elsewhere can be imported. The key records which administrator enrolled it and when, and the person is told. Left out of a save, the built-in default is kept.",
    field: #{key: "adminEnrolment", type: "enum", dflt: "off", optional: true, label: "Let an administrator enrol a passkey for a person"}
  })
  stsPasskeyAdminEnrolment?: string;
  // #740. Optional, so a save written before the row existed keeps the
  // stored value (or the built-in off) instead of failing as a missing
  // field. Refused while device-bound sessions are off: see save().
  @attr(#{
    kind: "single",
    what: "OFF BY DEFAULT. On, an issuance to an application this profile covers waits until the sign-on session is bound to the browser's key, and is refused when the browser skipped that registration or the wait elapsed without a binding. A session that was never offered registration is not refused by this row. Refused while authn.deviceBoundSessions is off.",
    field: #{key: "deviceBoundRequired", type: "bool", dflt: false, optional: true, label: "Require a device-bound session"}
  })
  stsPasskeyDeviceBoundRequired?: boolean;
  @attr(#{
    kind: "single",
    what: "Which named passkey policy wins where several match: the lowest, from 1 to 1000.",
    selector: #{key: "precedence"}
  })
  stsPasskeyPrecedence?: DirectoryInteger;
  @attr(#{
    what: "What the profile is for, for the next person."
  })
  description?: (string)[];
}

@entry(#{
  id: "policy.passkey",
  source: "policy_kinds:passkey",
  onPerson: true
})
model PolicyPasskeyOnPerson {
  @attr(#{kind: "single", what: "A recovery restored access to this person, who holds a passkey, and no passkey has signed them in since: the door and when, as `<door> <ISO 8601 instant>`. While the passkey policy's recoveryAssurance is not-weaker or operator-only, a sign-in that is not a passkey reaches no application. Maintained by this service."})
  stsRecoveryPending?: string;
  @attr(#{kind: "single", what: "Who issued the password reset link on this entry: `self` (the forgot-password form) or `operator` (an administrator). Written and cleared with the link. Maintained by this service."})
  stsPasswordResetSource?: string;
}
