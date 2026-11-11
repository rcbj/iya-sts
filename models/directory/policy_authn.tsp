// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/directory/policy_authn.tsp
//
// Written by hand (#1390). THIS IS THE SOURCE of this object's table:
// `models/tools/generate.mjs` compiles it during the image build and `common/authn_policy.ts`
// reads the result. The comments are the ones that sat on these rows there.

import "../lib/model_lib.tsp";

using IyaSts.ModelLib;

namespace IyaSts.Directory;

// A NAMED AUTHENTICATION POLICY'S TWO LISTS (#1148).
// ITS PRECEDENCE (#1237): the policy an application names and the
// policies a person's groups name compete, and the lowest wins.
@entry(#{
  id: "policy.authn",
  source: "policy_kinds:authn",
  container: "ou=authnPolicies",
  ownContainer: true,
  authored: true,
  objectClasses: #[
    #{
      name: "stsAuthnPolicy",
      what: "This service's class for an authentication policy: which mechanisms are accepted as a first and as a second factor, and when a second factor is required. The entry is named by the PROFILE (`cn=default`)."
    }
  ]
})
model PolicyAuthn {
  @attr(#{
    what: "`if-held`: a person is asked for a second factor when they hold one (or their entry says stsMfaRequired). `always`: everybody in this realm is, and somebody who holds none is sent to enrol one at their next sign-in. This replaced authn.mfaRequired. There is no \"never\": a held factor is always asked for.",
    field: #{key: "requireSecondFactor", type: "enum", values: #["if-held", "always"], dflt: "if-held", label: "Second factor required"}
  })
  stsAuthnRequireSecondFactor?: string;
  // #246 (rcbj, 2026-09-26): whether the people who can change everything
  // must use a second factor "will vary by organization", so it is this
  // policy's to say, in the default realm and inherited. `offer` is the
  // default FOR NOW, at rcbj's word: an administrator with no second factor
  // is shown the set-up step with an Ignore button, every sign-in.
  @attr(#{
    what: "For anybody holding a console role (Admin Read or Admin Write) who holds no second factor. `offer`: they are shown the step that sets one up, with an Ignore button, at every sign-in. `always`: they must set one up before they are signed in — except the default realm's built-in administrator (admin.bootstrapUsername), who is only ever offered one, so a service is never left with nobody who can sign in. `if-held`: as everybody else, by the field above. WEAKER THAN `always`: an administrator on a password alone is an administrator anyone with the password is.",
    field: #{key: "requireSecondFactorForAdministrators", type: "enum", values: #["if-held", "offer", "always"], dflt: "offer", label: "Second factor for administrators"}
  })
  stsAuthnRequireSecondFactorForAdministrators?: string;
  @attr(#{
    what: "A password on the sign-in screen. As a SECOND factor it is the password asked for after a wallet or other passwordless first factor."
  })
  stsAuthnPasswordPrimary?: DirectoryBoolean;
  @attr(#{
    what: "A password on the sign-in screen. As a SECOND factor it is the password asked for after a wallet or other passwordless first factor."
  })
  stsAuthnPasswordSecondFactor?: DirectoryBoolean;
  @attr(#{
    what: "Any passkey (WebAuthn credential) the person holds, signing them in with no password. A passkey has no role: this row says, at each sign-in, whether any of them may be a first factor in this realm, unless the first factors of the authentication policy an application names (appAuthnPolicy) say otherwise."
  })
  stsAuthnPasskeyPrimary?: DirectoryBoolean;
  @attr(#{
    what: "Any passkey (WebAuthn credential) the person holds, asked for after a first factor. A passkey has no role: this row says, at each sign-in, whether any of them may be a second factor in this realm, unless the second factors of the authentication policy an application names (appAuthnPolicy) say otherwise."
  })
  stsAuthnSecurityKeySecondFactor?: DirectoryBoolean;
  @attr(#{
    what: "An RFC 6238 one-time code. Never a first factor: this service holds the same shared secret the app does. Off here, nobody may ENROL one; a person who already holds one is still asked for it, because an off switch that downgraded every enrolled account to a password alone would do something other than it says (this row replaced totp.enabled, and keeps its contract)."
  })
  stsAuthnTotpSecondFactor?: DirectoryBoolean;
  @attr(#{
    what: "A single-use code from a set the person generated. Off here, no new set may be generated; a set already held still works (this row replaced backupCodes.enabled, and keeps its contract)."
  })
  stsAuthnRecoveryCodeSecondFactor?: DirectoryBoolean;
  @attr(#{
    what: "A six-digit code mailed to the person's VERIFIED address. NIST SP 800-63B-4 section 3.1.3.1: \"Email SHALL NOT be used for out-of-band authentication\", because a mailbox may be reached with a password alone, and mail may be read in transit or rerouted. Off by default for that reason; turn it on only where that is an accepted risk."
  })
  stsAuthnEmailCodePrimary?: DirectoryBoolean;
  @attr(#{
    what: "A six-digit code mailed to the person's VERIFIED address. NIST SP 800-63B-4 section 3.1.3.1: \"Email SHALL NOT be used for out-of-band authentication\", because a mailbox may be reached with a password alone, and mail may be read in transit or rerouted. Off by default for that reason; turn it on only where that is an accepted risk."
  })
  stsAuthnEmailCodeSecondFactor?: DirectoryBoolean;
  @attr(#{
    what: "A single-use link mailed to the person's VERIFIED address, which completes the sign-in only in the browser that started it. NIST SP 800-63B-4 section 3.1.3.1: \"Email SHALL NOT be used for out-of-band authentication\", because a mailbox may be reached with a password alone, and mail may be read in transit or rerouted. Off by default for that reason; turn it on only where that is an accepted risk."
  })
  stsAuthnEmailLinkPrimary?: DirectoryBoolean;
  @attr(#{
    what: "A single-use link mailed to the person's VERIFIED address, which completes the sign-in only in the browser that started it. NIST SP 800-63B-4 section 3.1.3.1: \"Email SHALL NOT be used for out-of-band authentication\", because a mailbox may be reached with a password alone, and mail may be read in transit or rerouted. Off by default for that reason; turn it on only where that is an accepted risk."
  })
  stsAuthnEmailLinkSecondFactor?: DirectoryBoolean;
  @attr(#{
    what: "A verified TLS client certificate: GET /tls/sign-in, or Continue with your certificate on the sign-in screen."
  })
  stsAuthnCertificatePrimary?: DirectoryBoolean;
  @attr(#{
    what: "GET /authn/spnego with a Kerberos ticket."
  })
  stsAuthnKerberosPrimary?: DirectoryBoolean;
  @attr(#{
    what: "/authn/wallet with a credential this realm issued, or a SIOPv2 self-issued ID Token from an enrolled key. As a SECOND factor, the wallet presented after a password."
  })
  stsAuthnWalletPrimary?: DirectoryBoolean;
  @attr(#{
    what: "/authn/wallet with a credential this realm issued, or a SIOPv2 self-issued ID Token from an enrolled key. As a SECOND factor, the wallet presented after a password."
  })
  stsAuthnWalletSecondFactor?: DirectoryBoolean;
  @attr(#{
    what: "A sign-in asserted by a configured federation partner."
  })
  stsAuthnFederationPrimary?: DirectoryBoolean;
  @attr(#{
    what: "From the moment it is sent. At most ten minutes, NIST SP 800-63B-4 section 3.1.3.2's bound for an out-of-band secret.",
    field: #{key: "emailCodeTtlS", type: "int", dflt: 300, min: 60, max: 600, unit: "seconds", email: true, label: "How long an emailed code or link is valid"}
  })
  stsAuthnEmailCodeTtlS?: int32;
  @attr(#{
    what: "How many wrong codes one sign-in step accepts before it is ended and the person starts again. The per-person and per-network rate limits apply as well.",
    field: #{key: "emailCodeAttempts", type: "int", dflt: 5, min: 1, max: 10, unit: "attempts", email: true, label: "Wrong codes before the sign-in step ends"}
  })
  stsAuthnEmailCodeAttempts?: int32;
  @attr(#{
    what: "A new code or link replaces the last one, which stops working. At most three are sent for one sign-in step.",
    field: #{key: "emailResendS", type: "int", dflt: 60, min: 15, max: 600, unit: "seconds", email: true, label: "Shortest wait before another code or link is sent"}
  })
  stsAuthnEmailResendS?: int32;
  @attr(#{
    what: "NIST SP 800-63B-4 section 3.2.2 asks for no more than 100. The person, and their administrators, are told, and the person turns it on again from the portal.",
    field: #{key: "emailFailureLimit", type: "int", dflt: 100, min: 5, max: 100, unit: "failures", email: true, label: "Consecutive failures before a person's email factor is turned off"}
  })
  stsAuthnEmailFailureLimit?: int32;
  // A REMEMBERED BROWSER MAY STAND IN FOR THE SECOND FACTOR (#265, rcbj):
  // off by default, for a period an administrator sets per realm (30 days by
  // default), and never at the admin console or the user portal. It is a
  // policy of the REALM because it is a statement about which evidence the
  // realm accepts — the rest of this table's question.
  @attr(#{
    what: "OFF BY DEFAULT. On, a person signing in on a browser they chose to remember is not asked for their second factor again within the period below of last giving it on that browser. NEVER at the admin console, the user portal or the protocol debugger; never for an administrator; never while the sign-in's risk is medium or higher; and the sign-in is then ONE factor to every relying party — amr [\"pwd\"] and acr \"1\", as a password alone — so an application asking for \"mfa\" is refused it. The browser is recognised by a bearer cookie: whoever copies the cookie skips the second factor too, until the copy is caught.",
    field: #{key: "rememberedBrowserSkipsSecondFactor", type: "bool", dflt: false, label: "A remembered browser may skip the second factor"}
  })
  stsAuthnRememberedBrowserSkipsSecondFactor?: boolean;
  @attr(#{
    what: "Counted from the last time the person gave their second factor on that browser. After it they are asked again, and giving it starts the period again.",
    field: #{key: "rememberedBrowserDays", type: "int", dflt: 30, min: 1, max: 400, unit: "days", label: "How long a remembered browser skips the second factor"}
  })
  stsAuthnRememberedBrowserDays?: int32;
  @attr(#{
    what: "What the profile is for, for the next person."
  })
  description?: (string)[];
  @attr(#{
    what: "On a NAMED authentication policy (#1148, #1237): a first-factor mechanism a sign-in it applies to allows — where the application (appAuthnPolicy) or one of the person's groups (stsAuthnPolicy) names it and its precedence is the lowest named — password, password-mfa, webauthn, spnego, wallet or federation, one value each. None allows every one the realm allows."
  })
  stsAuthnPolicyMechanism?: (string)[];
  @attr(#{
    what: "On a NAMED authentication policy (#1148, #1237): a second factor a sign-in it applies to allows — where the application (appAuthnPolicy) or one of the person's groups (stsAuthnPolicy) names it and its precedence is the lowest named — password, securityKey, totp, recoveryCode, emailCode, emailLink or wallet, one value each. None leaves the realm's authentication policy as it is."
  })
  stsAuthnPolicySecondFactor?: (string)[];
  @attr(#{
    what: "On a NAMED authentication policy (#1237): which one applies where several are named for one sign-in — by the application (appAuthnPolicy) and by the person's groups (stsAuthnPolicy) — the lowest, from 1 to 1000, ties by name. 100 when absent."
  })
  stsAuthnPolicyPrecedence?: DirectoryInteger;
}

@entry(#{
  id: "policy.authn",
  source: "policy_kinds:authn",
  onPerson: true
})
model PolicyAuthnOnPerson {
  @attr(#{what: "Which emailed second factor this person opted in to: `code` or `link`. Absent: none. Set on /portal/mfa, cleared on /admin/mfa and after too many consecutive failures."})
  stsMailFactor?: string;
  @attr(#{what: "Consecutive failed emailed codes or links, reset by a success. Maintained by this service."})
  stsMailFactorFailures?: DirectoryInteger;
}
