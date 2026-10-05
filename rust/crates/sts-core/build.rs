// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Turns the table exports `tests/tools/export-rust-tables.js` writes into
//! code:
//!
//! * `tables/error_codes.json` (`common/error_codes.js`) into a constant per
//!   code and the table `sts_core::errors` describes them with. A code that
//!   is not in the table is a name that does not exist, so it does not
//!   compile; a RETIRED code is a deprecated constant, so a new use of one is
//!   a warning the workspace's CI treats as an error.
//! * `tables/settings.json` (`common/config.js`'s SETTINGS) into the rows
//!   `sts_core::settings` reads and a constant per KEY, so a setting read by
//!   a name the table does not have does not compile either — where Node
//!   throws `no such setting` at the first read.

use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

fn text<'a>(value: &'a serde_json::Value, key: &str) -> &'a str {
    value.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

/// `oauth2.rfc9700` → `OAUTH2_RFC9700`, `global.publicBaseUrl` →
/// `GLOBAL_PUBLIC_BASE_URL`.
fn constant_name(key: &str) -> String {
    let mut out = String::new();
    let mut previous_lower = false;
    for c in key.chars() {
        if c.is_ascii_uppercase() && previous_lower {
            out.push('_');
        }
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push('_');
        }
        previous_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
    }
    out
}

fn option_text(value: Option<&serde_json::Value>) -> String {
    match value.and_then(|v| v.as_str()) {
        Some(text) => format!("Some({:?})", text),
        None => "None".to_string(),
    }
}

fn option_int(
    key: &str,
    field: &str,
    value: Option<&serde_json::Value>,
) -> Result<String, Box<dyn Error>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok("None".to_string()),
        Some(v) => match v.as_i64() {
            Some(n) => Ok(format!("Some({})", n)),
            None => Err(format!("{}: {} is not an integer", key, field).into()),
        },
    }
}

fn flag(row: &serde_json::Value, key: &str) -> bool {
    row.get(key).and_then(|v| v.as_bool()) == Some(true)
}

fn strings(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|one| one.as_str().map(|s| format!("{:?}", s)))
                .collect()
        })
        .unwrap_or_default()
}

fn settings(out: &mut String) -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-changed=tables/settings.json");
    let source = fs::read_to_string("tables/settings.json")?;
    let table: serde_json::Value = serde_json::from_str(&source)?;
    let empty = Vec::new();
    let rows = table
        .get("settings")
        .and_then(|c| c.as_array())
        .unwrap_or(&empty);
    if rows.is_empty() {
        return Err("tables/settings.json holds no settings".into());
    }
    let mut names = std::collections::BTreeMap::new();
    writeln!(out, "pub mod keys {{")?;
    writeln!(out, "    use super::Key;")?;
    for row in rows {
        let key = text(row, "key");
        let name = constant_name(key);
        if let Some(other) = names.insert(name.clone(), key.to_string()) {
            return Err(format!(
                "{} and {} make the same constant {}",
                other, key, name
            )
            .into());
        }
        writeln!(out, "    pub const {}: Key = Key({:?});", name, key)?;
    }
    writeln!(out, "}}")?;
    writeln!(out, "pub(crate) static ROWS: &[SettingRow] = &[")?;
    for row in rows {
        let key = text(row, "key");
        let kind = match text(row, "type") {
            "string" => "SettingType::String",
            "int" => "SettingType::Int",
            "port" => "SettingType::Port",
            "bool" => "SettingType::Bool",
            "csv" => "SettingType::Csv",
            "enum" => "SettingType::Enum",
            other => {
                return Err(format!("{}: unknown type {}", key, other).into())
            }
        };
        let dflt = if flag(row, "derivedDefault") {
            "DefaultValue::Derived".to_string()
        } else {
            match row.get("dflt") {
                Some(serde_json::Value::Bool(b)) => {
                    format!("DefaultValue::Bool({})", b)
                }
                Some(serde_json::Value::Number(n)) => match n.as_i64() {
                    Some(n) => format!("DefaultValue::Int({})", n),
                    None => {
                        return Err(
                            format!("{}: a fractional default", key).into()
                        )
                    }
                },
                Some(serde_json::Value::String(s)) => {
                    format!("DefaultValue::Text({:?})", s)
                }
                Some(serde_json::Value::Array(list)) => format!(
                    "DefaultValue::List(&[{}])",
                    list.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| format!("{:?}", s))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                _ => {
                    return Err(format!("{}: no default", key).into());
                }
            }
        };
        let notes = row
            .get("csvValueNotes")
            .and_then(|v| v.as_object())
            .map(|map| {
                map.iter()
                    .map(|(k, v)| {
                        format!("({:?}, {:?})", k, v.as_str().unwrap_or(""))
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let csv_values = if row.get("csvValues").is_some() {
            format!("Some(&[{}])", strings(row.get("csvValues")).join(", "))
        } else {
            "None".to_string()
        };
        let only_while_values = if row.get("onlyWhileValues").is_some() {
            format!(
                "Some(&[{}])",
                strings(row.get("onlyWhileValues")).join(", ")
            )
        } else {
            "None".to_string()
        };
        writeln!(
            out,
            "    SettingRow {{ key: {:?}, group: {:?}, label: {:?}, \
             env: {}, legacy_env: {}, kind: {}, default: {}, \
             runtime: {}, restart_reason: {:?}, description: {:?}, \
             min: {}, max: {}, step: {}, realm_runtime: {}, \
             realm_only: {}, enum_values: &[{}], csv_values: {}, \
             csv_value_notes: &[{}], ordered: {}, derived: {}, \
             per_process: {}, path: {}, secret: {}, only_while: {}, \
             only_while_values: {} }},",
            key,
            text(row, "group"),
            text(row, "label"),
            option_text(row.get("env")),
            option_text(row.get("legacyEnv")),
            kind,
            dflt,
            flag(row, "runtime"),
            text(row, "restartReason"),
            text(row, "description"),
            option_int(key, "min", row.get("min"))?,
            option_int(key, "max", row.get("max"))?,
            option_int(key, "step", row.get("step"))?,
            flag(row, "realmRuntime"),
            flag(row, "realmOnly"),
            strings(row.get("enumValues")).join(", "),
            csv_values,
            notes,
            flag(row, "ordered"),
            flag(row, "derived"),
            flag(row, "perProcess"),
            option_text(row.get("path")),
            flag(row, "secret"),
            option_text(row.get("onlyWhile")),
            only_while_values
        )?;
    }
    writeln!(out, "];")?;
    let replaced = table
        .get("replaced")
        .and_then(|c| c.as_array())
        .unwrap_or(&empty);
    writeln!(out, "pub(crate) static REPLACED: &[Replaced] = &[")?;
    for one in replaced {
        writeln!(
            out,
            "    Replaced {{ key: {:?}, env: {}, now: &[{}], why: {} }},",
            text(one, "key"),
            option_text(one.get("env")),
            strings(one.get("now")).join(", "),
            option_text(one.get("why"))
        )?;
    }
    writeln!(out, "];")?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-changed=tables/error_codes.json");
    let source = fs::read_to_string("tables/error_codes.json")?;
    let table: serde_json::Value = serde_json::from_str(&source)?;
    let empty = Vec::new();
    let codes = table
        .get("codes")
        .and_then(|c| c.as_array())
        .unwrap_or(&empty);
    let subsystems = table
        .get("subsystems")
        .and_then(|c| c.as_array())
        .unwrap_or(&empty);
    if codes.is_empty() || subsystems.is_empty() {
        return Err("tables/error_codes.json holds no codes".into());
    }

    let mut out = String::new();
    writeln!(
        out,
        "// Generated by build.rs from tables/error_codes.json."
    )?;
    for row in codes {
        let code = text(row, "code");
        let name = code.replace('-', "_");
        if row.get("retired").and_then(|r| r.as_bool()) == Some(true) {
            writeln!(
                out,
                "#[deprecated(note = \"retired: the condition no longer \
                 exists\")]"
            )?;
        }
        writeln!(
            out,
            "pub const {}: ErrorCode = ErrorCode({:?});",
            name, code
        )?;
    }
    writeln!(out, "pub(crate) static ROWS: &[Row] = &[")?;
    for row in codes {
        writeln!(
            out,
            "    Row {{ code: {:?}, summary: {:?}, spec: {:?}, \
             retired: {} }},",
            text(row, "code"),
            text(row, "summary"),
            text(row, "spec"),
            row.get("retired").and_then(|r| r.as_bool()) == Some(true)
        )?;
    }
    writeln!(out, "];")?;
    writeln!(out, "pub(crate) static SUBSYSTEMS: &[Subsystem] = &[")?;
    for one in subsystems {
        writeln!(
            out,
            "    Subsystem {{ id: {:?}, label: {:?}, location: {:?}, \
             what: {:?} }},",
            text(one, "id"),
            text(one, "label"),
            text(one, "where"),
            text(one, "what")
        )?;
    }
    writeln!(out, "];")?;

    let dir = std::env::var("OUT_DIR")?;
    fs::write(Path::new(&dir).join("error_codes.rs"), out)?;
    let mut table = String::new();
    writeln!(table, "// Generated by build.rs from tables/settings.json.")?;
    settings(&mut table)?;
    fs::write(Path::new(&dir).join("settings.rs"), table)?;
    Ok(())
}
