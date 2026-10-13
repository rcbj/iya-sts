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
// A HOT PATH: no Entering/Leaving pair here, in oracle() or in walk() below —
// each runs once for every one of up to 2,488,320 combinations, and the pair
// would drown the log.
function combination(c) {
  const actorId = c.position === 'subject' ? 'sub'
    : c.position === 'source' ? 'S'
      : c.position === 'target' ? 'R' : 'X';
  const user = c.actor === 'user-role' || c.actor === 'user';
  const count = c.targets === 2 ? 2 : (c.targets === 0 ? 0 : 1);
  const targetId = count === 0 ? '' : (c.targets === 'unregistered'
    ? 'https://unregistered.example' : 'R');
  return {
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
  if (f.mayActPresent && !f.mayActNamesActor) {
    return refuse('may-act', true);
  }
  if (f.target.count > 1) {
    return refuse('targets');
  }
  if (f.target.count === 1 && !f.target.registered) {
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
  if (!self && !f.actor.registered) {
    return refuse('intermediary');
  }
  if (!self && f.actor.kind === 'user' &&
      !has(f.actor.roles, 'DELEGATION_ACTOR')) {
    return refuse('intermediary');
  }
  if (!self && !(actorAllows(chosen) && subjectAllows(chosen))) {
    return refuse('semantics');
  }
  if (!self && f.actor.subjectGroups.length && !f.mayActNamesActor &&
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
  if (!self && chosen === 'delegation' &&
      !((f.actor.id === f.source.id || f.actor.id === f.target.id ||
         has(f.target.accepts, f.actor.id)) && delegates)) {
    return refuse('target');
  }
  if (!self && chosen === 'impersonation' &&
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
  oracle: oracle,
  product: product
};
