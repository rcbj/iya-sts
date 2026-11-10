// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The Session, Authentication, Token and Audit areas of the catalogue
// (#1390). None of these is in the directory: each is a record this service's
// own code keeps, so `tests/model_domain.js` holds each field to a real one.

import "../lib/domain_lib.tsp";

using IyaSts.DomainLib;

namespace IyaSts.Domain;

@domain(#{
  area: "Authentication",
  record: "authn/authn.ts authenticationEvent()",
  what: "One act of proving who somebody is, recorded on the session it happened in."
})
model AuthenticationEvent {
  @fromRecord(#{key: "at"})
  at: integer;

  @fromRecord(#{key: "amr"})
  methods?: string[];

  @fromRecord(#{key: "acr"})
  assuranceLevel?: string;

  @fromRecord(#{key: "via"})
  protocol: string;

  @fromRecord(#{key: "authenticated"})
  authenticated: boolean;

  @fromRecord(#{key: "authority.kind"})
  authorityKind?: string;
}

@domain(#{
  area: "Session",
  record: "authn/authn.ts startSession()",
  what: "An authenticated identity: the internal record every issued artifact is a projection of."
})
@invariant(#{
  id: "session.no-protocol-token",
  statement: "A session is no protocol's token: every artifact is a projection of it and every credential is evidence on an event."
})
@invariant(#{
  id: "session.subject-frozen",
  statement: "subjectId is fixed when the session is made, so a later rename does not move it."
})
model Session {
  @fromRecord(#{key: "id"})
  id: string;

  @fromRecord(#{key: "user.username"})
  username: string;

  @fromRecord(#{key: "subjectId"})
  subjectId: string;

  @fromRecord(#{key: "authenticated"})
  authenticated: boolean;

  @fromRecord(#{key: "authTime"})
  authTime: integer;

  @fromRecord(#{key: "amr"})
  methods?: string[];

  @fromRecord(#{key: "acr"})
  assuranceLevel?: string;

  @fromRecord(#{key: "via"})
  startedThrough: string;

  @fromRecord(#{key: "startedAt"})
  startedAt: integer;

  @fromRecord(#{key: "expires"})
  expires: integer;

  @fromRecord(#{key: "lastSeenAt"})
  lastSeenAt: integer;

  @fromRecord(#{key: "events"})
  events: AuthenticationEvent[];

  /** Events the session dropped, oldest first: `events` is capped. */
  @fromRecord(#{key: "eventsDropped"})
  eventsDropped?: integer;

  /** The person's `sub` (`urn:uuid:<entryUUID>`), or none. */
  @fromRecord(#{key: "user.sub"})
  sub?: string;

  /** The sign-on session a relying-party session was derived from. */
  @fromRecord(#{key: "derivedFrom"})
  derivedFrom?: string;

  /** The application of this service's own that holds it, if any. */
  @fromRecord(#{key: "rpSurface"})
  relyingPartySurface?: string;

  /** That application's name as a page draws it. */
  @fromRecord(#{key: "rpLabel"})
  relyingPartyLabel?: string;

  /** That application's client. */
  @fromRecord(#{key: "rpClientId"})
  relyingPartyClientId?: string;

  /** How often that application has renewed its tokens. */
  @fromRecord(#{key: "rpRenewals"})
  relyingPartyRenewals?: integer;

  /** When it last did, in milliseconds. */
  @fromRecord(#{key: "rpRenewedAt"})
  relyingPartyRenewedAt?: integer;

  /** How many requests an API session's credential was accepted for. */
  @fromRecord(#{key: "calls"})
  apiCalls?: integer;

  /** The browser's account set, where the session is in one (#561). */
  @fromRecord(#{key: "accountSetId"})
  accountSetId?: string;
}

@domain(#{
  area: "Token",
  record: "common/admin_stats.js recordJwt()",
  what: "A token this service issued, as its register remembers it. The signed value is not kept."
})
model IssuedToken {
  @fromRecord(#{key: "jti"})
  id: string;

  @fromRecord(#{key: "kind"})
  kind: string;

  @fromRecord(#{key: "sub"})
  subject: string;

  @fromRecord(#{key: "iss"})
  issuer: string;

  @fromRecord(#{key: "client_id"})
  clientId?: string;

  @fromRecord(#{key: "audience"})
  audience?: string;

  @fromRecord(#{key: "scope"})
  scope?: string;

  @fromRecord(#{key: "exp"})
  expires: integer;

  @fromRecord(#{key: "sessionId"})
  sessionId?: string;

  @fromRecord(#{key: "grantId"})
  grantId?: string;

  @fromRecord(#{key: "revoked"})
  revoked: boolean;

  /** The person or client it was issued for, as the register files it. */
  @fromRecord(#{key: "username"})
  username?: string;

  /** When it was issued, in milliseconds. */
  @fromRecord(#{key: "issuedAt"})
  issuedAt: integer;

  /** Whether it has a jti and is of a kind that can be revoked. */
  @fromRecord(#{key: "revocable"})
  revocable: boolean;

  /** The RFC 9449 thumbprint of the key it is bound to, or none. */
  @fromRecord(#{key: "jkt"})
  dpopThumbprint?: string;

  /** `valid`, `expired`, `revoked` or `no expiry stated`: `tokenList()`'s. */
  @fromRecord(#{key: "state"})
  state?: string;
}

@domain(#{
  area: "Audit",
  record: "common/audit.js audit()",
  what: "One thing that happened, as the realm's audit log records it."
})
@invariant(#{
  id: "audit.code-is-recorded-never-sent",
  statement: "An error code is on this record and in no client's response."
})
model AuditEvent {
  @fromRecord(#{key: "seq"})
  sequence: integer;

  @fromRecord(#{key: "at"})
  at: integer;

  @fromRecord(#{key: "category"})
  category: string;

  @fromRecord(#{key: "action"})
  action: string;

  @fromRecord(#{key: "outcome"})
  outcome: string;

  @fromRecord(#{key: "errorCode"})
  errorCode?: string;

  @fromRecord(#{key: "actor"})
  actor?: string;

  @fromRecord(#{key: "target"})
  target?: string;

  @fromRecord(#{key: "summary"})
  summary: string;

  /** Which process recorded it, or none with no shared store (#465). */
  @fromRecord(#{key: "origin"})
  origin?: string;

  /** The identity exactly as presented, where that differs from `actor`. */
  @fromRecord(#{key: "actorForm"})
  actorForm?: string;

  /** Which family, where one applies. */
  @fromRecord(#{key: "protocol"})
  protocol?: string;

  /** How it came in: `http`, `ldap`, `kerberos` and the others. */
  @fromRecord(#{key: "channel"})
  channel?: string;

  /** The client's IP address, or none for something nobody sent. */
  @fromRecord(#{key: "address"})
  address?: string;

  /** What else the recording site said. Its members are the site's own. */
  @fromRecord(#{key: "detail"})
  detail?: Record<unknown>;
}
