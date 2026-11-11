// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// File: common/protocol_repeats.ts
// ---------------------------------------------------------------------------
// SAML and WS-Federation read one value of each parameter. Given twice, or in
// both the query and the body, which one counts is an accident of the parsing,
// and two parts of a request can be made to disagree (ASVS 5.0.0 15.3.7). None
// of these bindings defines a repeated parameter, so product refuses one.
// ---------------------------------------------------------------------------

import errorCodes = require('./error_codes');
import helpers = require('./helpers');
import mode = require('./mode');

const PATHS = /^\/(?:saml2|saml11|wsfed)(?:\/|$)/;

class ProtocolRepeats {
  /**
   * Names a parameter that is repeated, or given in both places.
   *
   * @param query - the parsed query
   * @param body - the parsed body
   * @returns its name, or ''
   */
  static repeatedIn(query: any, body: any): string {
    helpers.log.debug("Entering ProtocolRepeats.repeatedIn().");
    const q = query || {};
    const b = body || {};
    const found = Object.keys(q).filter(function (name) {
      return Array.isArray(q[name]) || b[name] !== undefined;
    }).concat(Object.keys(b).filter(function (name) {
      return Array.isArray(b[name]);
    }))[0];
    helpers.log.debug("Leaving ProtocolRepeats.repeatedIn().");
    return found || '';
  }

  // Hot path: every request. No Entering/Leaving pair, which would drown the
  // log; it stops at the path test for everything but these three families.
  static middleware() {
    return function protocolRepeats(req: any, res: any, next: () => void): void {
      if (!PATHS.test(String(req.path || '')) ||
          !mode.refusesRepeatedTokenParameters()) {
        next();
        return;
      }
      const name = ProtocolRepeats.repeatedIn(req.query,
        req.method === 'POST' ? helpers.parseBody(req) : null);
      if (!name) {
        next();
        return;
      }
      errorCodes.mark(res, 'STS-CORE-0173');
      res.status(400).type('text/plain')
        .send('A parameter may be given only once.\n');
    };
  }
}

export = ProtocolRepeats;
