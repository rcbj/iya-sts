// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/tools/exchange_oracle.js
//
// NOT A TEST: the oracle `tests/exchange_policy.js` and
// `tests/exchange_policy_exhaustive.js` hold the exchange policy (#186) to.
// It lives in tools/ so `run.js` does not run it as a test file.

// ===========================================================================
// M. EVERY COMBINATION, AGAINST AN ORACLE (rcbj, 2026-10-03: "execute every
// logical combination ... and test against positive and negative outcomes").
//
// The oracle below is the rules on #186 written a second time, here, from the
// design rather than from the policy document: the semantics by precedence,
// then the first refusal that applies in the policy's order, then the allow
// and its audience. The policy is asked every combination of the dimensions
// below and must agree with the oracle on the verdict, the refusal, whether a
// refusal is enforced, the semantics and the audience. Each dimension is cut
// to the classes the rules can tell apart — a subject either holds a role S
// requires or does not; an actor is S, is R, is accepted by R, is the subject
// itself, or is none of them — so a combination is a logical case rather than
// a value.
// ===========================================================================
const log = require('bunyan').createLogger({ name: 'exchange_oracle',
  level: process.env.LOG_LEVEL || 'info' });

const POSITIONS = ['subject', 'source', 'target', 'accepted', 'unrelated'];

// The facts of one combination. `c`: mode, subjectKind, protect ('', 'flag',
// 'group'), actor ('application', 'user-role', 'user', 'unknown'), position,
// relation ('to', 'accepts', ''), requested, actorDefault, subjectDefault,
// settingDefault, actorAllowed, subjectAllowed, reach (actor delegates to R),
// groups ('', 'member', 'outsider'), mayAct ('', 'names', 'other'),
// sourceAuthority, targetAuthority, targets (0, 1, 'unregistered', 2).
//
// ACROSS A KERBEROS TRUST (#430 Phase 3), when `c.across` names a mechanism
// ('S4U2Self', 'S4U2Proxy-classic', 'S4U2Proxy-rbcd', 'forwarded'): the
// trust's `trustEnabled`, `direction` and `tgtBits` ('', 'enable',
// 'enable-no', 'enable-quarantined', 'within-forest'), whether the actor
// lists the user's realm (`selfListed`), the realm's classic setting
// (`classicSetting`), the target's `foreignTgt` ('', 'inherit', 'deny'), and
// which parties are of the other realm (`foreignSubject`, `foreignActor`,
// `foreignTarget`). With no `across` none of these facts is sent, which is
// every combination the rules of #186 were tested on.
//
// A HOT PATH: no Entering/Leaving pair here, in oracle() or in walk() below —
// each runs once for every one of up to 2,488,320 combinations, and the pair
// would drown the log.
function combination(c) {
  // `out` rather than a bare return, so the trust facts can be added.
  const actorId = c.position === 'subject' ? 'sub'
    : c.position === 'source' ? 'S'
      : c.position === 'target' ? 'R' : 'X';
  const user = c.actor === 'user-role' || c.actor === 'user';
  const count = c.targets === 2 ? 2 : (c.targets === 0 ? 0 : 1);
  const targetId = count === 0 ? '' : (c.targets === 'unregistered'
    ? 'https://unregistered.example' : 'R');
  const out = {
    subject: { id: 'sub', kind: c.subjectKind,
               roles: ['EVERYBODY'].concat(c.sourceAuthority ? ['src'] : [])
                 .concat(c.targetAuthority ? ['tgt'] : []),
               notDelegated: c.protect === 'flag',
               groups: (c.protect === 'group' ? ['protected'] : [])
                 .concat(c.groups === 'member' ? ['g'] : []),
               semantics: c.subjectAllowed,
               defaultSemantics: c.subjectDefault },
    actor: { id: actorId, kind: user ? 'user' : 'application',
             registered: c.actor !== 'unknown',
             roles: ['EVERYBODY'].concat(c.actor === 'user-role'
               ? ['DELEGATION_ACTOR'] : []),
             semantics: c.actorAllowed, defaultSemantics: c.actorDefault,
             delegatesTo: c.reach ? ['R'] : [],
             subjectGroups: c.groups ? ['g'] : [] },
    source: { id: 'S', requiredRoles: ['src'],
              delegatesTo: c.relation === 'to' ? ['R'] : [] },
    target: { id: targetId, count: count,
              registered: targetId === 'R',
              requiredRoles: ['tgt'],
              accepts: (c.relation === 'accepts' ? ['S'] : [])
                .concat(c.position === 'accepted' ? ['X'] : []) },
    requestedSemantics: c.requested,
    mayActPresent: c.mayAct !== '',
    mayActNamesActor: c.mayAct === 'names',
    protectedGroups: ['protected']
  };
  if (!c.across) {
    return out;
  }
  const bits = { '': [], 'enable': ['enable-tgt-delegation'],
                 'enable-no': ['enable-tgt-delegation', 'no-tgt-delegation'],
                 'enable-quarantined': ['enable-tgt-delegation',
                                        'quarantined'],
                 'within-forest': ['within-forest'] }[c.tgtBits || ''];
  out.trust = { partner: 'P.TEST', type: 'trust-realm',
                direction: c.direction || 'bidirectional',
                attributes: bits, path: ['P.TEST'], hops: 1,
                enabled: c.trustEnabled !== false };
  out.localRealm = 'L.TEST';
  out.mechanism = c.across;
  out.subject.realm = c.foreignSubject ? 'P.TEST' : 'L.TEST';
  // A subject of another realm holds no built-in role (rcbj, 2026-10-19):
  // only what was granted to it, which `src` and `tgt` stand for here.
  if (c.foreignSubject) {
    out.subject.roles = out.subject.roles.filter(function (one) {
      return one !== 'EVERYBODY';
    });
  }
  out.actor.realm = c.foreignActor ? 'P.TEST' : 'L.TEST';
  out.actor.selfRealms = c.selfListed ? ['P.TEST'] : [];
  out.target.realm = c.foreignTarget ? 'P.TEST' : 'L.TEST';
  out.target.foreignTgtDelegation = c.foreignTgt || '';
  return out;
}

// The settings a combination is asked with: the classic setting only for a
// question across a trust, as `delegation_policy.ts` sends it. A HOT PATH,
// asked once per combination: no Entering/Leaving pair (see combination()).
function settingsFor(c) {
  const out = { defaultSemantics: c.settingDefault,
                actorRole: 'DELEGATION_ACTOR' };
  if (c.across) {
    out.crossRealmClassicDelegation = !!c.classicSetting;
  }
  return out;
}

// THE ORACLE: the rules of #186, in the policy's order, from the facts. A HOT
// PATH, with its helpers: no Entering/Leaving pair would drown the log (see
// combination()).
function oracle(c, f) {
  const has = function (list, value) {
    return list.indexOf(value) >= 0;
  };
  const chosen = f.requestedSemantics || f.actor.defaultSemantics ||
    f.subject.defaultSemantics || c.settingDefault;
  const self = f.actor.id === f.subject.id ||
    (f.actor.id === f.source.id && (f.target.id === f.source.id ||
                                    f.target.count === 0));
  const actorAllows = function (s) {
    return has(f.actor.semantics, s) ||
      (s === 'delegation' && f.actor.semantics.length === 0);
  };
  const subjectAllows = function (s) {
    return f.subject.semantics.length === 0 || has(f.subject.semantics, s);
  };
  const authority = function (required) {
    return required.length === 0 || required.some(function (role) {
      return has(f.subject.roles, role);
    });
  };
  const refuse = function (kind, always) {
    return { verdict: 'refuse', refusal: kind,
             enforced: always || c.mode === 'product', chosen: chosen };
  };
  // #430: across a Kerberos trust.
  const across = !!f.trust;
  const foreign = function (realm) {
    return !!realm && !!f.localRealm && realm !== f.localRealm;
  };
  const mech = across ? f.mechanism : '';
  const forwardedAcross = across && mech === 'forwarded';
  const classicVouched = across && mech === 'S4U2Proxy-classic' &&
    foreign(f.actor.realm) && !!c.classicSetting;
  const rbcdDeferred = across && mech === 'S4U2Proxy-rbcd' &&
    foreign(f.target.realm);
  const foreignActorAccepted = across && foreign(f.actor.realm) &&
    has(f.target.accepts, f.actor.id);
  const trustBits = across ? f.trust.attributes : [];
  const tgtEnabled = (has(trustBits, 'within-forest') ||
                      has(trustBits, 'enable-tgt-delegation')) &&
    !(has(trustBits, 'no-tgt-delegation') || has(trustBits, 'quarantined'));
  if (f.mayActPresent && !f.mayActNamesActor) {
    return refuse('may-act', true);
  }
  if (f.target.count > 1) {
    return refuse('targets');
  }
  if (f.target.count === 1 && !f.target.registered &&
      !foreign(f.target.realm) && !forwardedAcross) {
    return refuse('unregistered-target');
  }
  if (f.target.count === 0 && !self) {
    return refuse('no-target');
  }
  if (!self && (f.subject.notDelegated ||
                f.subject.groups.some(function (g) {
                  return has(f.protectedGroups, g);
                }))) {
    return refuse('subject');
  }
  if (across) {
    if (!f.trust.enabled) {
      return refuse('trust-disabled');
    }
    if (mech === 'S4U2Self' && foreign(f.subject.realm) &&
        ['inbound', 'bidirectional'].indexOf(f.trust.direction) < 0) {
      return refuse('trust-direction');
    }
    if (mech === 'S4U2Self' && foreign(f.subject.realm) &&
        !has(f.actor.selfRealms, f.subject.realm)) {
      return refuse('self-realm');
    }
    if (mech === 'S4U2Proxy-classic' && !c.classicSetting) {
      return refuse('classic-across-realms');
    }
    if (mech === 'forwarded' &&
        (!tgtEnabled || f.target.foreignTgtDelegation === 'deny')) {
      return refuse('tgt-delegation');
    }
  }
  if (!self && !f.actor.registered && !foreignActorAccepted &&
      !classicVouched && !forwardedAcross) {
    return refuse('intermediary');
  }
  if (!self && !forwardedAcross && f.actor.kind === 'user' &&
      !has(f.actor.roles, 'DELEGATION_ACTOR')) {
    return refuse('intermediary');
  }
  if (!self && !forwardedAcross &&
      !(actorAllows(chosen) && subjectAllows(chosen))) {
    return refuse('semantics');
  }
  if (!self && !forwardedAcross && f.actor.subjectGroups.length &&
      !f.mayActNamesActor &&
      !f.subject.groups.some(function (g) {
        return has(f.actor.subjectGroups, g);
      })) {
    return refuse('subject');
  }
  if ((!self && chosen === 'delegation' &&
       !authority(f.source.requiredRoles)) ||
      ((self || chosen === 'impersonation') && f.target.count === 1 &&
       !authority(f.target.requiredRoles))) {
    return refuse('authority');
  }
  const delegates = has(f.source.delegatesTo, f.target.id) ||
    has(f.target.accepts, f.source.id);
  if (!self && chosen === 'delegation' && !forwardedAcross &&
      !rbcdDeferred && !classicVouched &&
      !((f.actor.id === f.source.id || f.actor.id === f.target.id ||
         has(f.target.accepts, f.actor.id)) && delegates)) {
    return refuse('target');
  }
  if (!self && !forwardedAcross && chosen === 'impersonation' &&
      !(f.actor.id === f.target.id || has(f.actor.delegatesTo, f.target.id) ||
        has(f.target.accepts, f.actor.id))) {
    return refuse('target');
  }
  return { verdict: 'allow', semantics: self ? 'self' : chosen,
           audience: self && f.target.count === 0 ? f.source.id : f.target.id,
           chosen: chosen };
}

// Every combination of the named dimensions, the rest at `fixed`.
function product(dimensions, fixed, visit) {
  log.debug("Entering product().");
  const names = Object.keys(dimensions);
  // A HOT PATH: no Entering/Leaving pair (see combination()).
  const walk = function (i, current) {
    if (i === names.length) {
      visit(Object.assign({}, fixed, current));
      return;
    }
    dimensions[names[i]].forEach(function (value) {
      const next = Object.assign({}, current);
      next[names[i]] = value;
      walk(i + 1, next);
    });
  };
  walk(0, {});
  log.debug("Leaving product().");
}

module.exports = {
  POSITIONS: POSITIONS,
  combination: combination,
  settingsFor: settingsFor,
  oracle: oracle,
  product: product
};
