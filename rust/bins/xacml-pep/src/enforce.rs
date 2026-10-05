// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What this PEP does with a decision: the service's rule, RESTATED rather
//! than imported, so this PEP can be configured with a different bias from
//! the embedded one and the two then disagree about exactly the answers the
//! biases disagree about.
//!
//! 1. **The bias** decides what a non-Permit means.
//! 2. **An obligation that cannot be discharged turns a Permit into a
//!    refusal** (section 7.2). This PEP can discharge exactly one obligation
//!    and refuses on any other: allowing the access and dropping the
//!    obligation would enforce half a policy and report success.
//!
//! `xacml-pep/enforcement_cases.json` is the table both this and the
//! embedded PEP (`xacml.js`'s `enforce()`) are held to.

use sts_core::errors::codes;
use sts_core::log::tag;
use sts_xacml::model::Decision;
use sts_xacml::request::ResolvedObligation;

use crate::options::Bias;

/// The obligations this PEP can discharge.
pub const DISCHARGEABLE: [&str; 1] = ["urn:sts:xacml:obligation:log"];

/// The enforcement of one decision.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub allowed: bool,
    pub bias: Bias,
    pub why: String,
    pub discharged: Vec<String>,
    pub undischargeable: Vec<String>,
}

/// The enforcement rule, configured with a bias.
#[derive(Debug, Clone, Copy)]
pub struct Enforcer {
    bias: Bias,
}

impl Enforcer {
    pub fn new(bias: Bias) -> Enforcer {
        Enforcer { bias }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn enforce(
        &self,
        decision: Decision,
        obligations: &[ResolvedObligation],
    ) -> Outcome {
        let mut discharged = Vec::new();
        let mut undischargeable = Vec::new();
        for obligation in obligations {
            if DISCHARGEABLE.contains(&obligation.id.as_str()) {
                tracing::info!(
                    "xacml-pep: discharging obligation {} with {} \
                     assignment(s).",
                    obligation.id,
                    obligation.assignments.len()
                );
                discharged.push(obligation.id.clone());
            } else {
                undischargeable.push(obligation.id.clone());
            }
        }
        let permitted = decision == Decision::Permit;
        let denied = decision == Decision::Deny;
        let (mut allowed, mut why) = match self.bias {
            Bias::DenyBiased => (
                permitted,
                if permitted {
                    "The PDP policy said Permit.".to_string()
                } else {
                    format!(
                        "The policy said {}, and this PEP is deny-biased, so \
                         anything that is not Permit is a refusal.",
                        decision
                    )
                },
            ),
            Bias::PermitBiased => (
                !denied,
                if denied {
                    "The policy said Deny.".to_string()
                } else {
                    format!(
                        "The policy said {}, and this PEP is permit-biased, \
                         so anything that is not Deny is allowed.",
                        decision
                    )
                },
            ),
        };
        if allowed && !undischargeable.is_empty() {
            allowed = false;
            let list = undischargeable.join(", ");
            tracing::warn!(
                "{}xacml-pep: refusing a {} that carries obligation(s) this \
                 PEP cannot discharge: {}.",
                tag(codes::STS_XPEP_0004),
                decision,
                list
            );
            why = format!(
                "The policy said {}, but the decision carries {} this PEP \
                 cannot discharge ({}). Section 7.2: a PEP that cannot fulfil \
                 an obligation MUST NOT grant the access. Allowing it and \
                 dropping the obligation would enforce half a policy and \
                 report success.",
                decision,
                if undischargeable.len() == 1 {
                    "an obligation"
                } else {
                    "obligations"
                },
                list
            );
        }
        Outcome {
            allowed,
            bias: self.bias,
            why,
            discharged,
            undischargeable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared table: the same file `tests/xacml_pep.js` holds the
    /// embedded PEP to, so the two implementations of section 7.2 are
    /// checked against one expectation.
    #[test]
    fn agrees_with_the_shared_enforcement_table() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../xacml-pep/enforcement_cases.json"
        );
        let table: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap())
                .unwrap();
        for (bias, key) in [
            (Bias::DenyBiased, "deny-biased"),
            (Bias::PermitBiased, "permit-biased"),
        ] {
            let enforcer = Enforcer::new(bias);
            for case in table["cases"].as_array().unwrap() {
                let decision =
                    Decision::from_external(case["decision"].as_str().unwrap())
                        .unwrap();
                let obligations: Vec<ResolvedObligation> = case["obligations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| ResolvedObligation {
                        id: id.as_str().unwrap().to_string(),
                        assignments: Vec::new(),
                    })
                    .collect();
                let outcome = enforcer.enforce(decision, &obligations);
                assert_eq!(
                    outcome.allowed,
                    case[key].as_bool().unwrap(),
                    "{} {:?}",
                    key,
                    case
                );
            }
        }
    }
}
