// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// File: common/request_budget.ts
// ---------------------------------------------------------------------------
// A ceiling on the requests one address may make in a minute, for everything
// the credential rate limits do not cover (ASVS 5.0.0 2.4.1).
//
// Counted per process, in the front process only: a worker's request has been
// counted already. One map per minute rather than a sweep, so nothing has to
// run in the background, and the map is capped because an attacker chooses how
// many addresses there are. Past the cap new addresses are not counted: the
// ceiling is a brake, and it must not become a way to spend this process's
// memory.
// ---------------------------------------------------------------------------

import config = require('./config');
import errorCodes = require('./error_codes');
import clientAddress = require('./client_address');

const WINDOW_MS = 60000;
const MAX_ADDRESSES = 200000;
const EXEMPT = /^\/healthcheck(?:$|\?)/;

class RequestBudget {
  private static windowStart = 0;
  private static counts = new Map<string, number>();

  // Hot path: every request. No Entering/Leaving pair, which would drown the
  // log.
  static allowed(address: string, limit: number, now: number): boolean {
    if (now - RequestBudget.windowStart >= WINDOW_MS) {
      RequestBudget.windowStart = now;
      RequestBudget.counts = new Map();
    }
    const counts = RequestBudget.counts;
    const seen = counts.get(address);
    if (seen === undefined) {
      if (counts.size < MAX_ADDRESSES) {
        counts.set(address, 1);
      }
      return true;
    }
    counts.set(address, seen + 1);
    return seen < limit;
  }

  // Hot path, as above.
  static middleware() {
    return function requestBudget(req: any, res: any, next: () => void): void {
      const limit = Number(config.value('security.requestsPerAddressPerMinute'));
      if (limit <= 0 || clientAddress.fromFrontProcess(req) ||
          EXEMPT.test(String(req.url || '')) ||
          RequestBudget.allowed(String(clientAddress.clientAddressOf(req)),
                                limit, Date.now())) {
        next();
        return;
      }
      errorCodes.mark(res, 'STS-CORE-0172');
      res.status(429).type('text/plain').set('Retry-After', '60')
        .send('Too many requests from this address.\n');
    };
  }
}

export = RequestBudget;
