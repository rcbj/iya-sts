// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The combining algorithms: twelve identifiers per level, nine behaviours.
//!
//! **A combiner CONTROLS evaluation; it is not handed results.** The
//! specification's pseudocode returns from inside the loop, so a
//! `deny-overrides` set whose fourth child denies never evaluates the fifth
//! — and if the fifth carries an obligation, a PDP that evaluated everything
//! up front puts that obligation in the Response with the right decision
//! attached (IID307). So a combiner is handed a function that evaluates one
//! child on demand and returns the results it ACTUALLY produced; obligations
//! are collected from those, and "never run, contributes nothing" is true by
//! construction.
//!
//! The ordered variants are the unordered ones: children are evaluated in
//! document order always, which the specification permits, and which is what
//! makes "the first Deny" well defined.
//!
//! Each body is transcribed from Appendix C's pseudocode rather than reasoned
//! out; the order of the final tests in `deny-overrides` alone separates four
//! wrong implementations that pass the simple cases.
//!
//! `only-one-applicable` is not here: it must know which children are
//! applicable BEFORE evaluating any, so it lives in the PDP.

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::model::{policy_alg, rule_alg, Decision, XacmlResult};
use crate::pdp::NodeResult;

/// What a combination produced: the decision, and the child results in the
/// order they were evaluated (only those that were).
pub struct Combination {
    pub decision: Decision,
    pub results: Vec<NodeResult>,
}

/// Evaluates child `i` on demand. An `Err` is a failure that escapes the
/// tree (an obligation on a policy that could not be resolved), and it
/// stops the combination where it happens, as a throw does in the Node
/// engine.
pub type EvaluateChild<'a> = dyn FnMut(usize) -> XacmlResult<NodeResult> + 'a;

/// A combining algorithm.
pub trait Combiner: Send + Sync {
    fn combine(
        &self,
        count: usize,
        evaluate: &mut EvaluateChild<'_>,
    ) -> XacmlResult<Combination>;
}

/// The extended Indeterminate flags the two 3.0 overrides algorithms track.
#[derive(Default)]
struct Seen {
    error_d: bool,
    error_p: bool,
    error_dp: bool,
}

impl Seen {
    fn note(&mut self, decision: Decision) {
        match decision {
            Decision::IndeterminateD => self.error_d = true,
            Decision::IndeterminateP => self.error_p = true,
            Decision::IndeterminateDP | Decision::Indeterminate => {
                self.error_dp = true
            }
            _ => {}
        }
    }
}

/// deny-overrides, XACML 3.0 (C.2).
struct DenyOverrides;

impl Combiner for DenyOverrides {
    fn combine(
        &self,
        count: usize,
        evaluate: &mut EvaluateChild<'_>,
    ) -> XacmlResult<Combination> {
        let mut results = Vec::new();
        let mut seen = Seen::default();
        let mut permit = false;
        for i in 0..count {
            let result = evaluate(i)?;
            let decision = result.decision;
            results.push(result);
            if decision == Decision::Deny {
                return Ok(Combination { decision, results });
            }
            if decision == Decision::Permit {
                permit = true;
            } else {
                seen.note(decision);
            }
        }
        // The order of these tests IS the algorithm.
        let decision =
            if seen.error_dp || (seen.error_d && (seen.error_p || permit)) {
                Decision::IndeterminateDP
            } else if seen.error_d {
                Decision::IndeterminateD
            } else if permit {
                Decision::Permit
            } else if seen.error_p {
                Decision::IndeterminateP
            } else {
                Decision::NotApplicable
            };
        Ok(Combination { decision, results })
    }
}

/// permit-overrides, XACML 3.0 (C.3): the exact mirror.
struct PermitOverrides;

impl Combiner for PermitOverrides {
    fn combine(
        &self,
        count: usize,
        evaluate: &mut EvaluateChild<'_>,
    ) -> XacmlResult<Combination> {
        let mut results = Vec::new();
        let mut seen = Seen::default();
        let mut deny = false;
        for i in 0..count {
            let result = evaluate(i)?;
            let decision = result.decision;
            results.push(result);
            if decision == Decision::Permit {
                return Ok(Combination { decision, results });
            }
            if decision == Decision::Deny {
                deny = true;
            } else {
                seen.note(decision);
            }
        }
        let decision =
            if seen.error_dp || (seen.error_p && (seen.error_d || deny)) {
                Decision::IndeterminateDP
            } else if seen.error_p {
                Decision::IndeterminateP
            } else if deny {
                Decision::Deny
            } else if seen.error_d {
                Decision::IndeterminateD
            } else {
                Decision::NotApplicable
            };
        Ok(Combination { decision, results })
    }
}

/// deny-unless-permit and permit-unless-deny (C.6, C.7): the two that
/// CANNOT return NotApplicable or Indeterminate, which is their purpose.
struct UnlessOther {
    /// The decision that stops the walk and wins.
    wins: Decision,
    /// The decision otherwise.
    otherwise: Decision,
}

impl Combiner for UnlessOther {
    fn combine(
        &self,
        count: usize,
        evaluate: &mut EvaluateChild<'_>,
    ) -> XacmlResult<Combination> {
        let mut results = Vec::new();
        for i in 0..count {
            let result = evaluate(i)?;
            let decision = result.decision;
            results.push(result);
            if decision == self.wins {
                return Ok(Combination { decision, results });
            }
        }
        Ok(Combination {
            decision: self.otherwise,
            results,
        })
    }
}

/// first-applicable (C.8). A 1.0 algorithm, so it produces a PLAIN
/// Indeterminate: it stops at the first child that decided anything, so no
/// later child's direction could matter.
struct FirstApplicable;

impl Combiner for FirstApplicable {
    fn combine(
        &self,
        count: usize,
        evaluate: &mut EvaluateChild<'_>,
    ) -> XacmlResult<Combination> {
        let mut results = Vec::new();
        for i in 0..count {
            let result = evaluate(i)?;
            let decision = result.decision;
            results.push(result);
            if decision == Decision::NotApplicable {
                continue;
            }
            let decision = if decision.is_indeterminate() {
                Decision::Indeterminate
            } else {
                decision
            };
            return Ok(Combination { decision, results });
        }
        Ok(Combination {
            decision: Decision::NotApplicable,
            results,
        })
    }
}

/// The legacy 1.0 RULE overrides algorithms. Genuinely different from the
/// 3.0 ones: a possible win for the overriding side is a plain Indeterminate.
/// The extended value already records which way a rule could have gone,
/// which is what the 2.0 pseudocode reads `effect(rule)` for.
struct LegacyRuleOverrides {
    overriding: Decision,
}

impl Combiner for LegacyRuleOverrides {
    fn combine(
        &self,
        count: usize,
        evaluate: &mut EvaluateChild<'_>,
    ) -> XacmlResult<Combination> {
        let (other, could_override) = if self.overriding == Decision::Deny {
            (Decision::Permit, Decision::IndeterminateD)
        } else {
            (Decision::Deny, Decision::IndeterminateP)
        };
        let mut results = Vec::new();
        let mut error = false;
        let mut potential = false;
        let mut saw_other = false;
        for i in 0..count {
            let result = evaluate(i)?;
            let decision = result.decision;
            results.push(result);
            if decision == self.overriding {
                return Ok(Combination { decision, results });
            }
            if decision == other {
                saw_other = true;
            } else if decision.is_indeterminate() {
                error = true;
                if decision == could_override
                    || decision == Decision::IndeterminateDP
                {
                    potential = true;
                }
            }
        }
        let decision = if potential {
            Decision::Indeterminate
        } else if saw_other {
            other
        } else if error {
            Decision::Indeterminate
        } else {
            Decision::NotApplicable
        };
        Ok(Combination { decision, results })
    }
}

/// The legacy 1.0 POLICY overrides algorithms, which differ from the rule
/// versions: an error anywhere makes the overriding decision win outright.
struct LegacyPolicyOverrides {
    overriding: Decision,
}

impl Combiner for LegacyPolicyOverrides {
    fn combine(
        &self,
        count: usize,
        evaluate: &mut EvaluateChild<'_>,
    ) -> XacmlResult<Combination> {
        let other = if self.overriding == Decision::Deny {
            Decision::Permit
        } else {
            Decision::Deny
        };
        let mut results = Vec::new();
        let mut error = false;
        let mut saw_other = false;
        for i in 0..count {
            let result = evaluate(i)?;
            let decision = result.decision;
            results.push(result);
            if decision == self.overriding {
                return Ok(Combination { decision, results });
            }
            if decision == other {
                saw_other = true;
            } else if decision.is_indeterminate() {
                error = true;
            }
        }
        let decision = if error {
            self.overriding
        } else if saw_other {
            other
        } else {
            Decision::NotApplicable
        };
        Ok(Combination { decision, results })
    }
}

/// Every combining algorithm but only-one-applicable, by identifier.
pub struct CombiningAlgorithms {
    by_uri: HashMap<&'static str, Box<dyn Combiner>>,
}

static STANDARD: LazyLock<CombiningAlgorithms> =
    LazyLock::new(CombiningAlgorithms::build);

impl CombiningAlgorithms {
    fn build() -> CombiningAlgorithms {
        let mut by_uri: HashMap<&'static str, Box<dyn Combiner>> =
            HashMap::new();
        let mut add =
            |uris: &[&'static str], make: &dyn Fn() -> Box<dyn Combiner>| {
                for uri in uris {
                    by_uri.insert(uri, make());
                }
            };
        add(
            &[
                rule_alg::DENY_OVERRIDES,
                rule_alg::ORDERED_DENY_OVERRIDES,
                policy_alg::DENY_OVERRIDES,
                policy_alg::ORDERED_DENY_OVERRIDES,
            ],
            &|| Box::new(DenyOverrides),
        );
        add(
            &[
                rule_alg::PERMIT_OVERRIDES,
                rule_alg::ORDERED_PERMIT_OVERRIDES,
                policy_alg::PERMIT_OVERRIDES,
                policy_alg::ORDERED_PERMIT_OVERRIDES,
            ],
            &|| Box::new(PermitOverrides),
        );
        add(
            &[rule_alg::DENY_UNLESS_PERMIT, policy_alg::DENY_UNLESS_PERMIT],
            &|| {
                Box::new(UnlessOther {
                    wins: Decision::Permit,
                    otherwise: Decision::Deny,
                })
            },
        );
        add(
            &[rule_alg::PERMIT_UNLESS_DENY, policy_alg::PERMIT_UNLESS_DENY],
            &|| {
                Box::new(UnlessOther {
                    wins: Decision::Deny,
                    otherwise: Decision::Permit,
                })
            },
        );
        add(
            &[rule_alg::FIRST_APPLICABLE, policy_alg::FIRST_APPLICABLE],
            &|| Box::new(FirstApplicable),
        );
        add(
            &[
                rule_alg::LEGACY_DENY_OVERRIDES,
                rule_alg::LEGACY_ORDERED_DENY_OVERRIDES,
            ],
            &|| {
                Box::new(LegacyRuleOverrides {
                    overriding: Decision::Deny,
                })
            },
        );
        add(
            &[
                rule_alg::LEGACY_PERMIT_OVERRIDES,
                rule_alg::LEGACY_ORDERED_PERMIT_OVERRIDES,
            ],
            &|| {
                Box::new(LegacyRuleOverrides {
                    overriding: Decision::Permit,
                })
            },
        );
        add(
            &[
                policy_alg::LEGACY_DENY_OVERRIDES,
                policy_alg::LEGACY_ORDERED_DENY_OVERRIDES,
            ],
            &|| {
                Box::new(LegacyPolicyOverrides {
                    overriding: Decision::Deny,
                })
            },
        );
        add(
            &[
                policy_alg::LEGACY_PERMIT_OVERRIDES,
                policy_alg::LEGACY_ORDERED_PERMIT_OVERRIDES,
            ],
            &|| {
                Box::new(LegacyPolicyOverrides {
                    overriding: Decision::Permit,
                })
            },
        );
        CombiningAlgorithms { by_uri }
    }

    pub fn standard() -> &'static CombiningAlgorithms {
        &STANDARD
    }

    pub fn get(&self, uri: &str) -> Option<&dyn Combiner> {
        self.by_uri.get(uri).map(|c| c.as_ref())
    }

    /// Whether an identifier names a known algorithm, only-one-applicable
    /// included.
    pub fn is_known(&self, uri: &str) -> bool {
        uri == policy_alg::ONLY_ONE_APPLICABLE || self.by_uri.contains_key(uri)
    }
}
