'use strict';
//
// File: risk/risk_model.ts
//
// ===========================================================================
// THE RISK SCORE OF ONE SIGN-IN: FREEMAN ET AL. (2016), PORTED (#62 P2,
// 2026-09-23).
//
// PORTED FROM `das-group/rba-algorithm`'s notebook (`freeman_rba_score()`
// and the functions it calls), which implements Freeman, Jain, Dürmuth,
// Biggio and Giacinto, "Who Are You? A Statistical Approach to Measuring User
// Authenticity", NDSS 2016 (doi:10.14722/ndss.2016.23240) — Equation 7,
// without per-member attack data. The notebook is under the MIT licence
// below, and because this file follows its code, edge cases and weightings
// rather than only the paper, the notice travels with it (the licence
// review on #62):
//
//   MIT License
//
//   Copyright (c) 2022 Stephan Wiefling / Data and Application Security
//   Group
//
//   Permission is hereby granted, free of charge, to any person obtaining a
//   copy of this software and associated documentation files (the
//   "Software"), to deal in the Software without restriction, including
//   without limitation the rights to use, copy, modify, merge, publish,
//   distribute, sublicense, and/or sell copies of the Software, and to
//   permit persons to whom the Software is furnished to do so, subject to
//   the following conditions:
//
//   The above copyright notice and this permission notice shall be included
//   in all copies or substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
//   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
//   NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
//   DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
//   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
//   THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// ---------------------------------------------------------------------------
// WHAT THE SCORE IS.
//
//   risk = Π over features f of  p_global(f) / p_user(f)
//          × (1 / number of users) / (user's sign-ins / all sign-ins)
//
// A feature is a HIERARCHY: the address, then the network it is in (ASN),
// then the country; the browser's User-Agent, then its browser and version,
// its operating system and version, its device type. Each level is weighted
// (the notebook's weightings, fitted to its own dataset) and a value seen
// before at a coarser level still counts for something. A familiar sign-in
// scores far below 1; a sign-in from somewhere and something the person has
// never used, which the population does not use much either, scores above.
//
// WHAT THE NOTEBOOK'S CODE DOES THAT THE PAPER DOES NOT SAY, kept as it is:
//
//   * THE USER'S SIDE IS NOT SMOOTHED; the population's is, at the first
//     level of each hierarchy only (the "unseen" count is the number of
//     distinct values below it, plus one).
//   * A VALUE THE USER HAS NEVER USED AT ANY LEVEL gets a quarter of its
//     population likelihood, rather than a smoothed near-zero — otherwise a
//     sign-in that is new to the user AND to the population would score LOW.
//   * A FIRST SIGN-IN IS NOT SCORED: with no history the user's likelihood
//     of signing in is zero and the score is undefined. `score()` answers
//     null, and the caller says why.
//
// The notebook reads pandas frames; this reads COUNTS (`History`), which is
// what `sts_risk_feature_counts` holds — the same numbers, asked for one
// value at a time. `tests/risk_model.js` holds the port to the notebook's
// own functions, run on a synthetic history.
// ===========================================================================

import bunyan = require('bunyan');
import config = require('../common/config');

const log = bunyan.createLogger({ name: 'sts-risk-model' });
config.registerLogger(log);

type Json = any;

// ---------------------------------------------------------------------------
// THE FEATURES AND THEIR WEIGHTINGS — the notebook's `feature_weightings`,
// renamed from its dataset's column names to this service's. The first name
// of each is the feature itself; the rest are its levels, coarsest last.
// `risk_score_weightings` is 1 for both in the notebook, so its power is not
// carried.
// ---------------------------------------------------------------------------
const FEATURES: Array<{ name: string; levels: Array<[string, number]> }> = [
  { name: 'ip', levels: [['ip', 0.6], ['asn', 0.3], ['country', 0.1]] },
  { name: 'ua', levels: [['ua', 0.5386653840551359],
                         ['browser', 0.2680451498625666],
                         ['os', 0.18818295100109536],
                         ['device', 0.0051065150812021525]] }
];

// ---------------------------------------------------------------------------
// A HISTORY, AS COUNTS. One for the person, one for the whole realm.
//
//   n                        — how many sign-ins it holds
//   count(level, value)      — how many had that value at that level
//   distinct(level)          — how many different values that level has
//   distinctWithin(first, value, level)
//                            — among the sign-ins whose FIRST level had
//                              `value`, how many different values `level`
//                              has (the notebook's unseen count for the
//                              population's first level)
//   users                    — how many people have signed in (population
//                              only)
// ---------------------------------------------------------------------------
interface History {
  n: number;
  users?: number;
  count(level: string, value: string): number;
  distinct(level: string): number;
  distinctWithin(first: string, value: string, level: string): number;
}

class RiskModel {
  static readonly FEATURES = FEATURES;

  // The notebook's get_unseen_values(): the distinct values of every level
  // BELOW `level` in its hierarchy, plus one. `within` narrows the history to
  // the sign-ins whose first level had a value (a subset of rows).
  static unseen(history: History, feature: Json, level: string,
                within?: { first: string; value: string }): number {
    log.debug("Entering RiskModel.unseen(). " + level);
    const names = feature.levels.map(function (l: Json): string {
      return l[0];
    });
    let total = 1;
    for (let i = names.indexOf(level) + 1; i > 0 && i < names.length; i++) {
      total += within
        ? history.distinctWithin(within.first, within.value, names[i])
        : history.distinct(names[i]);
    }
    log.debug("Leaving RiskModel.unseen(). " + total);
    return total;
  }

  // The notebook's get_likelihood() for one level of a history.
  static likelihood(appearance: number, n: number, unseen: number,
                    smoothing: boolean): number {
    log.debug("Entering RiskModel.likelihood().");
    const u = smoothing || appearance === 0 ? unseen : 0;
    let answer = 0;
    if (appearance > 0) {
      answer = (appearance / n) * (1 - u / (n + u));
    } else if (smoothing) {
      answer = 1 / (n + u);
    }
    log.debug("Leaving RiskModel.likelihood().");
    return answer;
  }

  // -------------------------------------------------------------------------
  // The notebook's get_sub_likelihood() for one level: the likelihood of the
  // value WITHIN the sign-ins that share it (1 when it was seen and the side
  // is not smoothed; the smoothed share otherwise) times its likelihood in
  // the whole history.
  // -------------------------------------------------------------------------
  static subLikelihood(history: History, feature: Json, level: string,
                       value: string, smoothing: boolean): number {
    log.debug("Entering RiskModel.subLikelihood(). " + level);
    const appearance = history.count(level, value);
    // Within the rows with this value, every row has it: appearance is the
    // subset's size, and its unseen count is over the subset only. An unseen
    // count changes the answer only on a SMOOTHED side: unsmoothed, a value
    // seen takes none (`likelihood()`'s rule) and a value unseen is 0
    // whatever it is. So it is only asked for then — which means a person's
    // history, never smoothed, is never asked for a distinct count — and for
    // an absent value the subset is empty, whose unseen count is 1 by
    // definition, with nothing to ask.
    const wanted = smoothing;
    const innerUnseen = !wanted ? 0 : (appearance === 0 ? 1
      : RiskModel.unseen(history, feature, level,
                         { first: level, value: value }));
    const inner = RiskModel.likelihood(appearance, appearance, innerUnseen,
                                       smoothing);
    const outer = RiskModel.likelihood(
      appearance, history.n,
      wanted ? RiskModel.unseen(history, feature, level) : 0, smoothing);
    log.debug("Leaving RiskModel.subLikelihood().");
    return inner * outer;
  }

  // One feature's weighted likelihood in one history: the notebook's loop
  // over `feature_weightings[feature]`, smoothing the first level only where
  // `smoothFirst` (the population) and none where not (the person).
  static featureLikelihood(history: History, feature: Json, attempt: Json,
                           smoothFirst: boolean): number {
    log.debug("Entering RiskModel.featureLikelihood(). " + feature.name);
    let total = 0;
    feature.levels.forEach(function (pair: Json, i: number): void {
      const level = pair[0];
      total += pair[1] * RiskModel.subLikelihood(
        history, feature, level, String(attempt[level] === undefined
                                        ? '' : attempt[level]),
        smoothFirst && i === 0);
    });
    log.debug("Leaving RiskModel.featureLikelihood().");
    return total;
  }

  // -------------------------------------------------------------------------
  // score(attempt, user, population) — the notebook's freeman_rba_score().
  // `attempt` maps each level name to this sign-in's value. Answers
  // { score, factors } — each feature's population/person ratio, for the
  // assessment's record — or { score: null, why } for a sign-in that cannot
  // be scored.
  // -------------------------------------------------------------------------
  static score(attempt: Json, user: History, population: History): Json {
    log.debug("Entering RiskModel.score().");
    if (!user.n) {
      log.debug("Leaving RiskModel.score(). First sign-in.");
      return { score: null, why: 'the first sign-in: there is no history ' +
               'to compare it with' };
    }
    if (!population.n || !population.users) {
      log.debug("Leaving RiskModel.score(). No population.");
      return { score: null, why: 'no population history yet' };
    }
    let risk = 1;
    const factors: Json = {};
    FEATURES.forEach(function (feature): void {
      let local = RiskModel.featureLikelihood(user, feature, attempt, false);
      const global = RiskModel.featureLikelihood(population, feature,
                                                 attempt, true);
      // THE NOTEBOOK'S EDGE CASE: never seen by this person at any level.
      if (local === 0) {
        local = global / 4;
      }
      const ratio = local > 0 ? global / local : 0;
      factors[feature.name] = ratio;
      risk *= ratio;
    });
    const userLoginLikelihood = user.n / population.n;
    const attackLikelihood = 1 / population.users;
    risk = risk * (attackLikelihood / userLoginLikelihood);
    log.debug("Leaving RiskModel.score(). " + risk);
    return { score: risk, factors: factors };
  }

  // -------------------------------------------------------------------------
  // A HISTORY FROM ROWS, for the tests and for a process with no store: each
  // row maps level names to values. The same questions `History` asks of
  // `sts_risk_feature_counts`, answered by counting.
  // -------------------------------------------------------------------------
  static historyOf(rows: Json[], userOf?: (row: Json) => string): History {
    log.debug("Entering RiskModel.historyOf(). " + rows.length + " row(s).");
    const users = new Set<string>();
    if (userOf) {
      rows.forEach(function (row: Json): void {
        users.add(userOf(row));
      });
    }
    log.debug("Leaving RiskModel.historyOf().");
    return {
      n: rows.length,
      users: users.size,
      count: function (level: string, value: string): number {
        return rows.filter(function (row: Json): boolean {
          return String(row[level]) === String(value);
        }).length;
      },
      distinct: function (level: string): number {
        return new Set(rows.map(function (row: Json): string {
          return String(row[level]);
        })).size;
      },
      distinctWithin: function (first: string, value: string,
                                level: string): number {
        return new Set(rows.filter(function (row: Json): boolean {
          return String(row[first]) === String(value);
        }).map(function (row: Json): string {
          return String(row[level]);
        })).size;
      }
    };
  }
}

export = {
  RiskModel: RiskModel,
  FEATURES: RiskModel.FEATURES,
  score: RiskModel.score,
  historyOf: RiskModel.historyOf,
  unseen: RiskModel.unseen,
  likelihood: RiskModel.likelihood
};
