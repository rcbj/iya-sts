// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444). Do not edit: change the
// model and run tests/tools/regenerate-model-docs.sh.
// tests/model_domain.js fails when this differs.

// The unions of scalars the five documents use (`number | string`
// and the like), each an untagged enum named by its kinds. Included by
// sts-model-base's lib.rs.

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum BoolOrInteger {
    Bool(bool),
    Integer(i64),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum BoolOrNumber {
    Bool(bool),
    Number(f64),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum BoolOrNumberOrString {
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum BoolOrNumberOrStringOrList {
    Bool(bool),
    Number(f64),
    String(String),
    List(Vec<serde_json::Value>),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum BoolOrString {
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum BoolOrStringOrObject {
    Bool(bool),
    String(String),
    Object(serde_json::Map<String, serde_json::Value>),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum IntegerOrString {
    Integer(i64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum NumberOrString {
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum StringOrList {
    String(String),
    List(Vec<serde_json::Value>),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum StringOrObject {
    String(String),
    Object(serde_json::Map<String, serde_json::Value>),
}
