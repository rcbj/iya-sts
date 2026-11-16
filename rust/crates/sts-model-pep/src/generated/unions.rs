// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/pep/ (#1830) by models/lib/pep_lib.mjs, through
// models/lib/rust_lib.mjs (#444, D15). Do not edit: change the model and
// run tests/tools/regenerate-pep-model.sh. tests/model_pep.js fails when
// this differs.

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum BoolOrIntegerOrString {
    Bool(bool),
    Integer(i64),
    String(String),
}
