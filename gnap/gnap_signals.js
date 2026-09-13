'use strict';
//
// File: gnap_signals.js
//
// ---------------------------------------------------------------------------
// GNAP AND THE SHARED SIGNALS FRAMEWORK: CAEP FOR GRANTS, AND A STREAM THAT
// HEARS ONLY ABOUT ITS OWN USERS.
//
// The user asked (2026-09-12) for three things and explicitly not a fourth:
//
//   1. **GNAP sessions emit CAEP.** A resource owner signs in through the one
//      authentication service, so `session-established` and `session-revoked`
//      already follow; `gnap_interact.js` makes the `notePresented()` call when
//      an interaction honours an existing session. Nothing in this file.
//   2. **GNAP web applications are receivers whose streams are SCOPED.** A
//      stream owned by a GNAP client application carries events only about
//      people who approved a grant to that application. `ssf/ssf_streams.js`
//      offers one hook, `setSubjectScope()`, consulted by
//      `streamCoversSubject()` — the single function every CAEP, RISC and
//      by-hand delivery already asks — and this file fills it.
//   3. **Grant and token revocation emit CAEP.** This REVERSES a documented
//      rule — docs/caep-events.md said revoking a token emits nothing — for
//      GNAP only, and the reason it is not a contradiction is the shape of a
//      GNAP grant: it is a DELEGATED SESSION between a client instance and a
//      resource owner (RFC 9767 section 2.1.13 calls it the grant's current
//      state), with a lifetime, a continuation and a revocation of its own. So
//      a grant revoked is a `session-revoked` whose session is the GRANT, a
//      token revoked is a `session-revoked` whose session is that token, and a
//      grant modified onto different rights is a `token-claims-change` carrying
//      the new `access`.
//   4. NOT: signals revoking grants. Nothing here listens to CAEP or RISC.
//
// **THE SUBJECT IS A COMPLEX ONE, `user` + `session`**, with the session id
// prefixed `gnap-grant:` or `gnap-token:` — the same shape `caep.subjectFor()`
// builds for a sign-on session, so a receiver that already matches
// `session-revoked` by user needs nothing new, and the prefix means a GNAP
// grant id can never be mistaken for a sign-on session id of the same bytes.
//
// **SSF IS REQUIRED LAZILY**, inside the functions that deliver. `ssf/ssf.js`
// registers every `/ssf` route (rule 1), and this file is required by the grant
// engine, which an in-process test loads with no router at all. Here, at call
// time in a running service, the require is a cache hit.
// ---------------------------------------------------------------------------

const { log, userFor } = require('../common/helpers');
const errorCodes = require('../common/error_codes');
const realms = require('../common/realms');
const config = require('../common/config');

// WHO APPROVED WHICH APPLICATION, for the scope. The durable record is the
// consent register (gnap_grants.js's header); this is its index for the one
// case the register cannot answer — `gnap.rememberApprovals` off, where no
// consent is written and a person who approved a grant must still be a person
// the application's stream may hear about. Persisted like every GNAP store.
const approvers = realms.map({ persist: 'gnap.approvers' });

function noteApprover(identifier, username) {
  try {
    const key = String(identifier);
    const list = approvers.has(key) ? approvers.get(key).slice() : [];
    const name = String(username || '').toLowerCase();
    if (name && list.indexOf(name) < 0) {
      list.push(name);
      approvers.set(key, list.slice(-5000));
    }
  } catch (e) {
    // Bookkeeping on the path of an approval; never allowed to fail one.
    log.error(errorCodes.tag('STS-GNAP-0700') + 'gnap: an approver could not be recorded: ' + e.message);
  }
}

function approvedBy(identifier, username) {
  const name = String(username || '').toLowerCase();
  if (!name) {
    return false;
  }
  const list = approvers.get(String(identifier)) || [];
  if (list.indexOf(name) >= 0) {
    return true;
  }
  try {
    return require('../common/consent').consentsOf(name).some(function (row) {
      return row.client === String(identifier) && String(row.scope).indexOf('gnap:') === 0;
    });
  } catch (e) {
    // No consent register reachable; the index above is the whole answer.
    log.debug("approvedBy(): the consent register could not be read: " + e.message);
    return false;
  }
}

function subjectFor(req, username, sessionId) {
  const transport = require('../ssf/ssf_http');
  return {
    user: { format: 'issuer_subject_id', iss: transport.transmitterIssuer(req),
            sub: userFor(username).sub },
    session: { format: 'opaque', id: sessionId }
  };
}

// Deliver one CAEP event to every stream that takes it. Never rejects.
function emit(req, type, username, sessionId, values, reason) {
  log.debug("Entering emit(). type=" + type);
  if (!username || config.value('gnap.caepEvents') === false) {
    log.debug("Leaving emit(). No resource owner, or GNAP CAEP events are off.");
    return Promise.resolve({ sent: 0 });
  }
  let ssf;
  try {
    ssf = require('../ssf/ssf');
  } catch (e) {
    // No SSF family in this process (an in-process test): nothing to deliver to.
    log.debug("Leaving emit(). SSF is not loaded: " + e.message);
    return Promise.resolve({ sent: 0 });
  }
  if (typeof ssf.emitProtocolEvent !== 'function') {
    log.debug("Leaving emit(). This SSF build has no protocol emission.");
    return Promise.resolve({ sent: 0 });
  }
  log.debug("Leaving emit(). Delivering.");
  return Promise.resolve(ssf.emitProtocolEvent({
    req: req, protocol: 'GNAP', type: type, subject: subjectFor(req, username, sessionId),
    values: values || {}, initiatingEntity: 'system',
    reasonAdmin: reason, reasonUser: reason
  })).catch(function (e) {
    log.error(errorCodes.tag('STS-GNAP-0701') + 'gnap: a CAEP ' + type + ' could not be delivered: ' +
              e.message);
    return { sent: 0, why: e.message };
  });
}

function grantRevoked(req, grant, reason) {
  return emit(req, 'session-revoked', grant.ro && grant.ro.username, 'gnap-grant:' + grant.id, {},
              reason || 'A GNAP grant was revoked.');
}

function tokenRevoked(req, record, grant) {
  const username = record.username || (grant && grant.ro && grant.ro.username);
  return emit(req, 'session-revoked', username, 'gnap-token:' + record.jti, {},
              'A GNAP access token was revoked by its client instance.');
}

function grantModified(req, grant, access) {
  return emit(req, 'token-claims-change', grant.ro && grant.ro.username, 'gnap-grant:' + grant.id,
              { claims: { access: access } }, 'A GNAP grant was modified onto different access.');
}

// ---------------------------------------------------------------------------
// THE SCOPE. `(record, subject) -> true | false | undefined`: undefined means
// "not a GNAP-owned stream; this file has no opinion", which is every stream
// that existed before this feature.
// ---------------------------------------------------------------------------
function usernameOf(subjectValue) {
  if (!subjectValue || typeof subjectValue !== 'object') {
    return null;
  }
  const one = subjectValue.format ? subjectValue : subjectValue.user;
  if (!one) {
    return null;
  }
  const sub = String(one.sub || one.uri || '');
  if (sub.indexOf('urn:sts:user:') === 0) {
    return sub.slice('urn:sts:user:'.length);
  }
  if (one.email) {
    return String(one.email).split('@')[0];
  }
  if (one.format === 'account' && one.uri) {
    const match = String(one.uri).match(/^acct:([^@]+)@/);
    return match ? match[1] : null;
  }
  return null;
}

function scope(record, subjectValue) {
  if (config.value('gnap.scopedSignals') === false || !record || !record.createdBy || !subjectValue) {
    return undefined;
  }
  let app = null;
  try {
    app = require('../common/applications').get(String(record.createdBy));
  } catch (e) {
    // No registry: no opinion.
    return undefined;
  }
  if (!app || (app.kinds || []).indexOf('gnap-client') < 0) {
    return undefined;
  }
  const fields = app.fields || {};
  if (String(fields.gnapScopedSignals || '').toUpperCase() === 'FALSE') {
    return undefined;
  }
  // A WEB APPLICATION is the population the user named: a client that finishes
  // an interaction in a browser or by push has a finish URI on its entry.
  if (!fields.gnapFinishUri || (Array.isArray(fields.gnapFinishUri) && !fields.gnapFinishUri.length)) {
    return undefined;
  }
  const username = usernameOf(subjectValue);
  return username ? approvedBy(app.identifier, username) : false;
}

function install() {
  try {
    const streams = require('../ssf/ssf_streams');
    if (typeof streams.setSubjectScope === 'function') {
      streams.setSubjectScope('gnap', scope);
      return true;
    }
  } catch (e) {
    // SSF absent in this process; the scope is simply not installed.
    log.debug("install(): ssf_streams is not loadable: " + e.message);
  }
  return false;
}

module.exports = {
  noteApprover: noteApprover,
  approvedBy: approvedBy,
  grantRevoked: grantRevoked,
  tokenRevoked: tokenRevoked,
  grantModified: grantModified,
  scope: scope,
  usernameOf: usernameOf,
  install: install
};
