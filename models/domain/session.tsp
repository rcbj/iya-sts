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
}
