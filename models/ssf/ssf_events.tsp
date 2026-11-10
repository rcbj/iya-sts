// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/ssf/ssf_events.tsp
//
// Written by hand (#1579), from the tables `ssf/ssf_events.js` held until
// then. THE SOURCE OF EVERY EVENT TYPE THIS SERVICE SENDS AND KNOWS: SSF
// 1.0's own two, CAEP 1.0's eight, RISC 1.0's fourteen and this service's
// own, each with its payload members, the JSON shape of each, whether a SET
// of it names somebody, and the prose the console and `GET /ssf` draw.
// `ssf/ssf_events.js` builds its catalogue rows from the generated
// `models/generated/ssf.json` and keeps only what each row DOES: the
// function that fills a payload from what a caller supplied.
//
// A member's TypeSpec type is its shape: `string`, `numeric` (a number of
// seconds, never a quoted one), `boolean`, `string[]`, `Record<string>` (a
// map keyed by a BCP 47 language tag — CAEP's reasons), `Record<unknown>` (a
// JSON object), a union of string literals (a CLOSED list: a value outside
// it is refused) or such a union with `string` beside it (an OPEN list the
// specification lets two parties extend: a value outside it is carried with
// a warning). A member that is not optional is required.
//
// THE ORDER IS THE CATALOGUE'S: SSF's first, then CAEP's, RISC's and this
// service's own, and within a row the order the console draws. CAEP's four
// common members end every CAEP row (`...CaepCommon`); RISC's three end the
// one row that has them. A change here is a change to what a receiver is
// sent and to what the console says, and owes
// `tests/ssf_model_wire.snapshot.json`.

import "../lib/ssf_lib.tsp";
import "./ssf.tsp";

using IyaSts.SsfLib;

namespace IyaSts.Ssf;

// ---------------------------------------------------------------------------
// THE MEMBERS SEVERAL EVENT TYPES SHARE, WRITTEN ONCE.
// ---------------------------------------------------------------------------

@common(#{ id: "caep", cite: "CAEP 1.0 section 2" })
model CaepCommon {
  @eventMember(#{ what: "When the thing described actually happened, in seconds since the epoch. OPTIONAL in CAEP 1.0 section 2 — which surprises people, because a receiver deciding whether to end a session wants it more than it wants anything else in the payload. caep.omitEventTimestamp leaves it out on purpose, so a receiver that assumes one can be shown falling over." })
  event_timestamp?: numeric;

  @eventMember(#{ what: "Who invoked it. It is the member that lets a receiver tell \"an administrator revoked this\" from \"a risk engine did\" — two facts that call for two different responses, and which are indistinguishable without it." })
  initiating_entity?: "admin" | "user" | "policy" | "system";

  @eventMember(#{ what: "Why, for a log and for an auditor. **It is an OBJECT KEYED BY A LANGUAGE TAG** — {\"en\": \"Policy 4.2 was violated\"} — and not a string, which is the commonest way this member is got wrong. A string here is refused rather than carried, because a receiver indexing it by language reads nothing from one." })
  reason_admin?: Record<string>;

  @eventMember(#{ what: "The same, in words meant for the person it happened to. Two members rather than one because what an auditor needs to read and what may be shown on a screen are rarely the same sentence." })
  reason_user?: Record<string>;
}

@common(#{ id: "risc", cite: "RISC 1.0 section 2.7" })
model RiscCommon {
  @eventMember(#{ what: "When the transmitter DISCOVERED the compromise, in seconds since the epoch. RISC section 2.7 words it as discovery rather than as occurrence, which is not pedantry: a credential found in a breach corpus was compromised long before anybody noticed, and a receiver that read this as \"when it happened\" would date the incident from the wrong end." })
  event_timestamp?: numeric;

  @eventMember(#{ what: "Why, for an administrator. THIS SERVICE SENDS THE LANGUAGE-MAP SHAPE CAEP DEFINES — {\"en\": \"...\"} — and RISC 1.0 does not actually repeat that requirement, which makes a bare string arguably conforming to RISC and certainly unreadable to a receiver built against CAEP. Sending the map is the reading that is right under both." })
  reason_admin?: Record<string>;

  @eventMember(#{ what: "The same, in words meant for the person it happened to." })
  reason_user?: Record<string>;
}

// ---------------------------------------------------------------------------
// SSF 1.0'S OWN TWO, ABOUT THE STREAM.
// ---------------------------------------------------------------------------

@event(#{
  uri: "https://schemas.openid.net/secevent/ssf/event-type/verification",
  family: "ssf",
  name: "Verification",
  subject: "none",
  what: "THE ONLY END-TO-END TEST A STREAM HAS. Everything else a receiver can do — create the stream, read it back, add a subject — exercises the management API and proves nothing about whether an event can actually be delivered. This travels the ordinary delivery path, so a 202 from the receiver's push endpoint (or a poll that returns it) is the first evidence the pipe works.",
  cite: "SSF 1.0 section 8.1.4.1"
})
model VerificationEvent {
  @eventMember(#{ what: "Whatever the receiver put in its verification request, echoed back UNCHANGED. It is the only thing that ties this event to the request that asked for it — without it a receiver watching two streams cannot tell which one just answered." })
  state?: string;
}

@event(#{
  uri: "https://schemas.openid.net/secevent/ssf/event-type/stream-updated",
  family: "ssf",
  name: "Stream Updated",
  subject: "none",
  what: "The stream's status changed and the receiver is being told IN BAND. It is the one event a receiver gets without asking for it, and the one whose absence is hardest to notice: a stream quietly paused at the transmitter looks exactly like a service where nothing has happened lately.",
  cite: "SSF 1.0 section 8.1.5"
})
model StreamUpdatedEvent {
  @eventMember(#{ what: "The stream's new status." })
  status: StreamStatus;

  @eventMember(#{ what: "Why, in words, for a person reading a log. Nothing parses it." })
  reason?: string;
}

// ---------------------------------------------------------------------------
// CAEP 1.0, ABOUT A SESSION.
// ---------------------------------------------------------------------------

@event(#{
  uri: "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
  family: "caep",
  name: "Session Revoked",
  subject: "required",
  what: "THE EVENT THE WHOLE PROFILE EXISTS FOR. The session named by the subject is no longer good, whatever its token says its lifetime is. It carries NO event-specific member at all — everything it has to say is in the subject and in the four common claims — and that is not an oversight: there is nothing to qualify. Where the subject is a COMPLEX one, the revocation applies to any session matching every part of it at once.",
  cite: "CAEP 1.0 section 3.1"
})
model SessionRevokedEvent {
  ...CaepCommon;
}

@event(#{
  uri: "https://schemas.openid.net/secevent/caep/event-type/session-established",
  family: "caep",
  name: "Session Established",
  subject: "required",
  what: "A session was created. It is what CLOSES THE LOOP — without it a receiver only ever hears about sessions ending, so it cannot hold an inventory of what is open and cannot notice a sign-in it did not expect. This service emits one on every sign-in unless caep.autoEmit is off.",
  cite: "CAEP 1.0 section 3.6"
})
model SessionEstablishedEvent {
  @eventMember(#{ what: "A fingerprint of the user agent, computed by the transmitter. Its value is comparing two of them, so what it is made of is the transmitter's business and no receiver should parse one." })
  fp_ua?: string;

  @eventMember(#{ what: "The authentication context class, with OpenID Connect's own meaning." })
  acr?: string;

  @eventMember(#{ what: "The authentication methods, as an ARRAY of strings — OpenID Connect's `amr`. A bare string here is refused: a session authenticated by a password AND a security key has two values, and a receiver that read a string would see one." })
  amr?: string[];

  @eventMember(#{ what: "The transmitter's own identifier for this session, for a receiver correlating with something it already holds." })
  ext_id?: string;

  ...CaepCommon;
}

@event(#{
  uri: "https://schemas.openid.net/secevent/caep/event-type/session-presented",
  family: "caep",
  name: "Session Presented",
  subject: "required",
  what: "The session was USED — presented at the transmitter and honoured. It is the one CAEP event about something entirely ordinary, and it is there so that a receiver can see a live session it is not itself being asked about, and can spot the same session in two places at once. This service emits one when an authorization request is answered from a session that already existed, which is exactly single sign-on.",
  cite: "CAEP 1.0 section 3.7"
})
model SessionPresentedEvent {
  @eventMember(#{ what: "The user agent fingerprint observed THIS time. Comparing it with the one on the session-established event is the whole point of the member: the same session presented from a different agent is the abnormality this event exists to make visible." })
  fp_ua?: string;

  @eventMember(#{ what: "The transmitter's own identifier for the session." })
  ext_id?: string;

  ...CaepCommon;
}

@event(#{
  uri: "https://schemas.openid.net/secevent/caep/event-type/token-claims-change",
  family: "caep",
  name: "Token Claims Change",
  subject: "required",
  what: "A claim behind the token changed while the token is still valid — a role, a group, a tenant. It is the event that makes the access-token lifetime argument go away: the receiver does not have to wait for a refresh to find out that somebody left the group that authorises them.",
  cite: "CAEP 1.0 section 3.2"
})
model TokenClaimsChangeEvent {
  @eventMember(#{ what: "The claims that changed, with their NEW values — an object, and only the ones that moved. It is not a whole token and it is not a diff: a receiver applies what is here over what it holds. A group membership taken away is therefore the new LIST rather than the group that went, which catches people." })
  claims: Record<unknown>;

  ...CaepCommon;
}

@event(#{
  uri: "https://schemas.openid.net/secevent/caep/event-type/credential-change",
  family: "caep",
  name: "Credential Change",
  subject: "required",
  what: "A credential was enrolled, renewed, revoked or deleted. It is the event a receiver acts on WITHOUT ending anything: a second factor being deleted does not invalidate the session it was used to establish, and it does change what that session should be allowed to do next.",
  cite: "CAEP 1.0 section 3.3"
})
model CredentialChangeEvent {
  @eventMember(#{ what: "Which kind of credential. The list is CAEP's own and it is OPEN — the specification allows types two parties agree between themselves — so a value not on it is carried with a warning rather than refused. Refusing would make this service unable to carry a vendor's own type, which is precisely what testing needs." })
  credential_type: CredentialType;

  @eventMember(#{ what: "What happened to it. CLOSED, unlike the type above: these four are the whole lifecycle and a fifth would be a receiver guessing." })
  change_type: "create" | "revoke" | "update" | "delete";

  @eventMember(#{ what: "What the person calls it — \"my work phone\". For a screen, not for a decision." })
  friendly_name?: string;

  @eventMember(#{ what: "The certificate's issuer (RFC 5280), where the credential is an X.509 one." })
  x509_issuer?: string;

  @eventMember(#{ what: "The certificate's serial number (RFC 5280). Serial numbers are unique per ISSUER and not globally, which is why this member is useless without the one above it." })
  x509_serial?: string;

  @eventMember(#{ what: "The authenticator's AAGUID, where the credential is a FIDO2 one. It names a MODEL of authenticator rather than the individual one, which is what makes it publishable." })
  fido2_aaguid?: string;

  ...CaepCommon;
}

@event(#{
  uri: "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change",
  family: "caep",
  name: "Assurance Level Change",
  subject: "required",
  what: "The strength of the authentication behind this session moved. A DECREASE is the interesting one and it is easy to forget it can happen at all: a second factor that has expired, or a session carried forward past the window its step-up was good for, both lower assurance without anybody signing in again.",
  cite: "CAEP 1.0 section 3.4"
})
model AssuranceLevelChangeEvent {
  @eventMember(#{ what: "WHICH SCALE THE TWO LEVELS BELOW ARE ON, and it is required for the reason the whole event would otherwise be useless: \"AAL2\" means nothing until you know it is NIST's. The list is open — two parties may agree an alias — so an unlisted namespace is carried with a warning." })
  `namespace`: "RFC8176" | "RFC6711" | "ISO-IEC-29115" | "NIST-IAL" | "NIST-AAL" | "NIST-FAL" | string;

  @eventMember(#{ what: "The level the session is at NOW, spelt the way the namespace above spells it. It is a free string precisely because the namespace decides its shape." })
  current_level: string;

  @eventMember(#{ what: "Where it was before. Optional, and worth sending: without it a receiver can see that assurance changed and not whether it went UP." })
  previous_level?: string;

  @eventMember(#{ what: "Which way, said outright rather than inferred. It exists because a receiver cannot order two levels it does not understand the namespace of — which is the ordinary case across two organisations." })
  change_direction?: "increase" | "decrease";

  ...CaepCommon;
}

@event(#{
  uri: "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change",
  family: "caep",
  name: "Device Compliance Change",
  subject: "required",
  what: "The device the session runs on fell out of, or back into, compliance with whatever the estate's policy is. The subject is normally a COMPLEX one naming the device as well as the person, because the same person on a second device is unaffected and a receiver cannot tell that from a subject naming only them.",
  cite: "CAEP 1.0 section 3.5"
})
model DeviceComplianceChangeEvent {
  @eventMember(#{ what: "What the device was. REQUIRED, and that is the member that makes this event safe to act on out of order: a receiver holding \"compliant\" that gets an event whose previous status is \"not-compliant\" knows it has missed one." })
  previous_status: "compliant" | "not-compliant";

  @eventMember(#{ what: "What it is now. The hyphen in \"not-compliant\" is the specification's and is worth checking against: \"noncompliant\" is silently ignored by a conforming receiver." })
  current_status: "compliant" | "not-compliant";

  ...CaepCommon;
}

@event(#{
  uri: "https://schemas.openid.net/secevent/caep/event-type/risk-level-change",
  family: "caep",
  name: "Risk Level Change",
  subject: "required",
  what: "A risk engine changed its mind about somebody. It is the only CAEP event that is a JUDGEMENT rather than a fact — the other seven report something that happened — which is why it carries a reason and why a receiver is expected to weigh it rather than act on it.",
  cite: "CAEP 1.0 section 3.8"
})
model RiskLevelChangeEvent {
  @eventMember(#{ what: "WHAT the risk level is about, and it is required because the subject alone cannot say: a complex subject names a person AND a device AND a session, and \"risk went to HIGH\" about the device is a different fact from the same sentence about the person. The values are UPPER CASE here and lower case in a complex subject's member names, which catches everybody once." })
  principal: "USER" | "DEVICE" | "SESSION" | "TENANT" | "ORG_UNIT" | "GROUP" | string;

  @eventMember(#{ what: "The level now. Three values, upper case, closed." })
  current_level: "LOW" | "MEDIUM" | "HIGH";

  @eventMember(#{ what: "The level before." })
  previous_level?: "LOW" | "MEDIUM" | "HIGH";

  @eventMember(#{ what: "What contributed. RECOMMENDED rather than required, and it is the member that decides whether a receiver can do anything but step up: \"impossible travel\" and \"credential seen in a breach corpus\" call for different answers." })
  risk_reason?: string;

  ...CaepCommon;
}

// ---------------------------------------------------------------------------
// RISC 1.0, ABOUT AN ACCOUNT.
// ---------------------------------------------------------------------------

@event(#{
  uri: "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required",
  family: "risc",
  name: "Account Credential Change Required",
  subject: "required",
  what: "The account named by the subject was REQUIRED to change a credential — a forced password reset, most often. It is not a report that a credential changed: nothing here says one did, and the person may never comply. What a receiver learns is that this provider no longer trusts what it currently holds.",
  cite: "RISC 1.0 section 2.1"
})
model AccountCredentialChangeRequiredEvent {
}

@event(#{
  uri: "https://schemas.openid.net/secevent/risc/event-type/account-purged",
  family: "risc",
  name: "Account Purged",
  subject: "required",
  what: "The account was PERMANENTLY DELETED. It is the one terminal event in the vocabulary and the register treats it as one: nothing can be said about a purged account afterwards except by contradiction. The distinction from account-disabled is the whole of its meaning — a disabled account may come back, and this one may not.",
  cite: "RISC 1.0 section 2.2"
})
model AccountPurgedEvent {
}

@event(#{
  uri: "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
  family: "risc",
  name: "Account Disabled",
  subject: "required",
  what: "The account was disabled and MAY BE ENABLED AGAIN. It is the ordinary account-takeover signal, and the pair it forms with account-enabled is what makes it different from a purge.",
  cite: "RISC 1.0 section 2.3"
})
model AccountDisabledEvent {
  @eventMember(#{ what: "Why, as one of two words RISC names — and it is worth knowing what those two are FOR. \"hijacking\" says this one account was taken over, which is a signal about a person. \"bulk-account\" says it was one of a population created by a script, which is a signal about the PROVIDER and asks a receiver to look at everything else that arrived at the same time. The specification says \"possible values\" rather than closing the list, so a third word is carried with a warning." })
  reason?: "hijacking" | "bulk-account" | string;
}

@event(#{
  uri: "https://schemas.openid.net/secevent/risc/event-type/account-enabled",
  family: "risc",
  name: "Account Enabled",
  subject: "required",
  what: "The account was enabled. It is RISC's only GOOD NEWS and it is the one everybody forgets to implement: a receiver that acts on account-disabled and ignores this one has locked somebody out permanently on the strength of an incident that was resolved.",
  cite: "RISC 1.0 section 2.4"
})
model AccountEnabledEvent {
}

@event(#{
  uri: "https://schemas.openid.net/secevent/risc/event-type/identifier-changed",
  family: "risc",
  name: "Identifier Changed",
  subject: "required",
  subjectFormats: #["email", "phone_number"],
  what: "The identifier IN THE SUBJECT changed, and the subject carries the OLD value — which is the reverse of every other event here and the thing that catches everybody. RISC says only the provider AUTHORITATIVE over the identifier should send this: an email provider may say john.doe@ became john.roe@, and a site where that address is merely a username may not — it sends recovery-information-changed instead.",
  cite: "RISC 1.0 section 2.5"
})
model IdentifierChangedEvent {
  @eventMember(#{ what: "What the identifier became. **THE ONLY HYPHENATED MEMBER NAME IN ANY OF THE THREE VOCABULARIES** — everything else in SSF, CAEP and RISC is snake_case — so `new_value` typed from habit produces an event that delivers and says nothing. It is OPTIONAL, and a transmitter that leaves it out is telling a receiver that an address it holds is stale without telling it what to hold instead, which is legal and nearly useless." })
  `new-value`?: string;
}

@event(#{
  uri: "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled",
  family: "risc",
  name: "Identifier Recycled",
  subject: "required",
  subjectFormats: #["email", "phone_number"],
  what: "The identifier in the subject was RECYCLED and now belongs to somebody else. It is the event whose absence causes the quietest account takeover there is: a mail provider reissues a lapsed address, a relying party keyed on the address by itself lets the new owner into the old owner's account, and nothing anywhere was compromised. It is the whole argument for keying on iss_sub rather than on an email address.",
  cite: "RISC 1.0 section 2.6"
})
model IdentifierRecycledEvent {
}

@event(#{
  uri: "https://schemas.openid.net/secevent/risc/event-type/credential-compromise",
  family: "risc",
  name: "Credential Compromise",
  subject: "required",
  what: "A credential belonging to this account was FOUND compromised — seen in a breach corpus, or reported. THE ONLY ONE OF THE FOURTEEN WITH A REQUIRED MEMBER, and the only one carrying any of the claims CAEP gives all eight of its own. A receiver acts on it differently by type: a compromised password is a reset, and a compromised hardware key is a revocation.",
  cite: "RISC 1.0 section 2.7"
})
model CredentialCompromiseEvent {
  @eventMember(#{ what: "Which kind of credential was found compromised. **RISC SECTION 2.7 DEFINES THIS BY REFERENCE TO CAEP's credential-change**, so the two lists are the same list rather than two alike ones — which is why there is one CREDENTIAL_TYPES here and not a copy per vocabulary." })
  credential_type: CredentialType;

  ...RiscCommon;
}

@event(#{
  uri: "https://schemas.openid.net/secevent/risc/event-type/opt-in",
  family: "risc",
  name: "Opt In",
  subject: "required",
  what: "The account is participating in RISC exchange again. It is one of the four events that ARE a state transition rather than a report of one — RISC section 2.8 defines each of them as \"the account is in the X state\" — and it is the only event that may be sent about an account which has opted OUT, because without it a receiver would never learn that one came back.",
  cite: "RISC 1.0 section 2.8.1"
})
model OptInEvent {
}

@event(#{
  uri: "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated",
  family: "risc",
  name: "Opt Out Initiated",
  subject: "required",
  what: "The person asked to stop RISC exchange, AND IT CARRIES ON FOR A WHILE ANYWAY. That delay is the point of the state existing at all: RISC section 2.8 says it is there to stop a hijacker from opting out the moment they take an account over and silencing the very events that would report them.",
  cite: "RISC 1.0 section 2.8.2"
})
model OptOutInitiatedEvent {
}

@event(#{
  uri: "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled",
  family: "risc",
  name: "Opt Out Cancelled",
  subject: "required",
  what: "The opt-out was called off and the account is back in the opt-in state. **THE SPELLING IS BRITISH AND IT IS THE SPECIFICATION'S** — \"cancelled\" with two Ls — where a transmitter writing \"opt-out-canceled\" produces a URI a conforming receiver silently ignores, because there is no unknown-event-type error in this protocol.",
  cite: "RISC 1.0 section 2.8.3"
})
model OptOutCancelledEvent {
}

@event(#{
  uri: "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective",
  family: "risc",
  name: "Opt Out Effective",
  subject: "required",
  what: "The opt-out has taken effect and no further RISC events will be sent about this account. IT IS THE LAST ONE — an event announcing that there will be no more events — which is what makes it the one the opt-out gate in risc.js must never suppress. Suppressing it would leave a receiver waiting for signals that stopped without notice.",
  cite: "RISC 1.0 section 2.8.4"
})
model OptOutEffectiveEvent {
}

@event(#{
  uri: "https://schemas.openid.net/secevent/risc/event-type/recovery-activated",
  family: "risc",
  name: "Recovery Activated",
  subject: "required",
  what: "The account went through a recovery flow. It is a signal about RISK rather than about a change: a recovery is how a legitimate owner gets back in and it is also how an attacker who controls the recovery channel takes over, and the transmitter cannot tell which. A receiver is expected to weigh it, not act on it.",
  cite: "RISC 1.0 section 2.9"
})
model RecoveryActivatedEvent {
}

@event(#{
  uri: "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed",
  family: "risc",
  name: "Recovery Information Changed",
  subject: "required",
  what: "A recovery address or number was added, changed or removed. It is what a provider sends about an identifier IT IS NOT AUTHORITATIVE OVER — RISC says so where identifier-changed says the opposite — so the pair of them is the same act reported by two different kinds of provider. It carries no member saying WHICH information moved, deliberately: that would be publishing somebody's recovery address to every receiver on the stream.",
  cite: "RISC 1.0 section 2.10"
})
model RecoveryInformationChangedEvent {
}

@event(#{
  uri: "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked",
  family: "risc",
  name: "Sessions Revoked",
  subject: "required",
  deprecated: "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
  what: "EVERY session the account has, everywhere, is gone — which is a far larger instruction than CAEP's session-revoked, whose subject names ONE of them. **DEPRECATED by RISC 1.0 section 2.11**, which says new implementations MUST use CAEP's singular event instead. The two names differ by one letter and mean different things, so this is the pair to check when a receiver ends more sessions than anybody intended.",
  cite: "RISC 1.0 section 2.11"
})
model SessionsRevokedEvent {
}

// ---------------------------------------------------------------------------
// THIS SERVICE'S OWN, ABOUT ITS KEYS AND ITS PEOPLE.
// ---------------------------------------------------------------------------

@event(#{
  uri: "urn:iya:sts:secevent:event-type:signing-key-rotated",
  family: "sts",
  name: "Signing Key Rotated",
  subject: "none",
  what: "NON-SPEC, this service's own. A realm's signing keys rotated: the next key of each unit named is current now, and the key it replaced is retired (or, for an emergency, gone). A receiver that caches this issuer's keys fetches them again.",
  cite: "this service's own (#42)"
})
model SigningKeyRotatedEvent {
  @eventMember(#{ what: "The trust realm whose keys rotated." })
  realm: string;

  @eventMember(#{ what: "The units rotated, each as \"<unit> <previous kid> -> <kid>\"." })
  rotated: string;

  @eventMember(#{ what: "Why: the schedule, an administrator, or a key presumed compromised — in which case the previous key no longer verifies anything." })
  reason: "scheduled" | "requested" | "emergency";

  @eventMember(#{ what: "Where the realm's current keys are." })
  jwks_uri?: string;

  @eventMember(#{ what: "The realm's crypto metadata document, which lists every generation of every key." })
  crypto_metadata_uri?: string;

  @eventMember(#{ what: "When the rotation happened, in seconds since the epoch." })
  event_timestamp?: numeric;
}

@event(#{
  uri: "urn:iya:sts:secevent:event-type:kerberos-tickets-invalidated",
  family: "sts",
  name: "Kerberos Tickets Invalidated",
  subject: "none",
  what: "NON-SPEC, this service's own. A realm's krbtgt key was replaced and no previous version kept, so every Kerberos ticket-granting ticket issued before this event is refused (KRB_AP_ERR_BADKEYVER) at its next use, and every person signs in to Kerberos again. A receiver that trusts sessions built on those tickets re-checks them.",
  cite: "this service's own (#169)"
})
model KerberosTicketsInvalidatedEvent {
  @eventMember(#{ what: "The trust realm whose krbtgt key was replaced." })
  realm: string;

  @eventMember(#{ what: "The Kerberos realm its KDC answers for." })
  kerberos_realm: string;

  @eventMember(#{ what: "The krbtgt key version now current; no earlier one is kept." })
  kvno: numeric;

  @eventMember(#{ what: "Why: an administrator asked for \"rotate and invalidate\" (invalidated), or an ordinary rotation kept no previous version because krb5.retainedKeyVersions is 0 (nothing-retained, #245) — the same outcome, unasked." })
  reason: "invalidated" | "nothing-retained";

  @eventMember(#{ what: "When the key was replaced, in seconds since the epoch." })
  event_timestamp?: numeric;
}

@event(#{
  uri: "urn:iya:sts:secevent:event-type:federation-key-rotated",
  family: "sts",
  name: "Federation Entity Key Rotated",
  subject: "none",
  what: "NON-SPEC, this service's own. A realm's OpenID Federation entity key rotated (or, in an emergency, the current and next keys were revoked as compromised), or a retired key was revoked. A receiver that resolves Trust Chains through this realm fetches its Entity Configuration again; after an emergency nothing the revoked keys signed verifies.",
  cite: "this service's own (#245)"
})
model FederationKeyRotatedEvent {
  @eventMember(#{ what: "The trust realm the key belongs to." })
  realm: string;

  @eventMember(#{ what: "The keys moved, each as \"federation-entity-key <previous kid> -> <kid>\", or \"federation-entity-key <kid> -> revoked\" for a key that left the published set." })
  rotated: string;

  @eventMember(#{ what: "Why: the schedule, an administrator, or a key presumed compromised — in which case what it signed no longer verifies." })
  reason: "scheduled" | "requested" | "emergency";

  @eventMember(#{ what: "The realm's Entity Configuration, whose jwks now carries the keys; the Historical Keys endpoint lists every one it retired." })
  entity_configuration_uri?: string;

  @eventMember(#{ what: "When it happened, in seconds since the epoch." })
  event_timestamp?: numeric;
}

@event(#{
  uri: "urn:iya:sts:secevent:event-type:spiffe-authority-rotated",
  family: "sts",
  name: "SPIFFE Authority Rotated",
  subject: "none",
  what: "NON-SPEC, this service's own. A realm's SPIFFE X.509 or JWT authority was rotated or re-issued — on the schedule, by an administrator, or because the certificate hierarchy under it was rebuilt. A receiver that caches the trust domain's bundle fetches it again.",
  cite: "this service's own (#245)"
})
model SpiffeAuthorityRotatedEvent {
  @eventMember(#{ what: "The trust realm the key belongs to." })
  realm: string;

  @eventMember(#{ what: "The authorities moved, each as \"x509-authority <previous> -> <new>\" or \"jwt-authority <previous kid> -> <kid>\"." })
  rotated: string;

  @eventMember(#{ what: "Why: the schedule, an administrator, or a key presumed compromised — in which case what it signed no longer verifies." })
  reason: "scheduled" | "requested" | "emergency";

  @eventMember(#{ what: "The realm's SPIFFE bundle endpoint (the trust domain's bundle), which carries the authorities a workload verifies against." })
  bundle_uri?: string;

  @eventMember(#{ what: "The realm's SPIFFE trust domain." })
  trust_domain?: string;

  @eventMember(#{ what: "Whether the published bundle changed. False for an X.509 authority re-issued under this service's Root: the bundle publishes the Root, so SVIDs go on verifying and only the Issuing CA in an SVID's chain is new." })
  bundle_changed?: boolean;

  @eventMember(#{ what: "When it happened, in seconds since the epoch." })
  event_timestamp?: numeric;
}

@event(#{
  uri: "urn:iya:sts:secevent:event-type:tls-certificate-changed",
  family: "sts",
  name: "TLS Certificate Changed",
  subject: "none",
  what: "NON-SPEC, this service's own. The certificate this service's main port (and LDAPS, and every realm's SPIRE Server API) presents was re-issued — the certificate hierarchy it chains to was rebuilt, or the service started again with a listener key made at that start. A receiver that pins the certificate or its anchor fetches them again. Sent to every realm's streams, because the listener is the whole service's.",
  cite: "this service's own (#245, #264)"
})
model TlsCertificateChangedEvent {
  @eventMember(#{ what: "The trust realm the key belongs to." })
  realm: string;

  @eventMember(#{ what: "The listener certificates replaced, each as \"<algorithm> <previous SHA-256 fingerprint> -> <fingerprint>\"." })
  rotated: string;

  @eventMember(#{ what: "Why: the schedule, an administrator, or a key presumed compromised — in which case what it signed no longer verifies. For this type, \"restarted\": the service (or one node of it) started and presents a certificate other than the one it last announced." })
  reason: "scheduled" | "requested" | "emergency" | "restarted";

  @eventMember(#{ what: "GET /tls/server-certificate, which publishes the certificate the main port presents and the anchor it chains to." })
  certificate_uri?: string;

  @eventMember(#{ what: "When it happened, in seconds since the epoch." })
  event_timestamp?: numeric;
}

@event(#{
  uri: "urn:iya:sts:secevent:event-type:announcement",
  family: "sts",
  name: "Announcement",
  subject: "none",
  what: "NON-SPEC, this service's own. An administrator's announcement for everybody signed in to this service's admin console, user portal or reports application; each draws it as a banner in the tabs open when it arrives.",
  cite: "this service's own (#1086)"
})
model AnnouncementEvent {
  @eventMember(#{ what: "The trust realm the announcement is for." })
  realm: string;

  @eventMember(#{ what: "The text to show, plain and at most ssf.announcementMaxChars characters." })
  message: string;

  @eventMember(#{ what: "Which of this service's applications show it: \"admin-console\", \"user-portal\", \"report\"." })
  surfaces: string[];

  @eventMember(#{ what: "When it was sent, in seconds since the epoch." })
  event_timestamp?: numeric;
}

