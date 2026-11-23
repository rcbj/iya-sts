// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/authzen/authzen_members.tsp (#1205) by
// models/lib/pep_lib.mjs: the Obligations Profile's registered types,
// the member sets marked `obligation: true`, in the model's order. Do
// not edit: change the model and run tests/tools/regenerate-pep-model.sh.
// tests/model_pep.js fails when this differs.

/// One registered type: the properties it may not be handed without,
/// and those that collect every assignment of their name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObligationRule {
    pub name: &'static str,
    pub required: &'static [&'static str],
    pub arrays: &'static [&'static str],
}

/// Every registered type, in the model's order.
pub const OBLIGATION_RULES: &[ObligationRule] = &[
    ObligationRule {
        name: "step-up",
        required: &["acr_value"],
        arrays: &["amr_values"],
    },
    ObligationRule {
        name: "notification",
        required: &["to", "body"],
        arrays: &["to"],
    },
    ObligationRule {
        name: "session_termination",
        required: &["subject"],
        arrays: &[],
    },
];

/// What the metadata advertises while the profile is on: every registered
/// type, then `custom`, which is every other obligation.
pub const SUPPORTED_OBLIGATION_TYPES: &[&str] = &["step-up", "notification", "session_termination", "custom"];
