// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What a process checks before it serves, as `common/config.js` checks it
//! when it is first required and `server.js` checks the rest: a refusal
//! here is a sentence for stderr and an exit, never a stack trace.
//!
//! In config.js's order:
//!
//! 1. **`requireComplete()`** (STS-CORE-0002) has nothing to catch here:
//!    the defaults layer is the compiled table, which IS `env/defaults.js`'s
//!    content (that file is generated from it), so no row can be without a
//!    value. It is not ported, and says so.
//! 2. **[`refuse_replaced_settings`]** (STS-CORE-0105, #171, #523): a
//!    removed key in the operator's file, or its variable in the
//!    environment, stops the start, naming what replaced it.
//! 3. **[`refuse_malformed_settings`]** (STS-CORE-0108, #86): every value
//!    the environment, the operator's file and the defaults hold is held to
//!    the write's own check — a shadowed one included — with an absolute-
//!    URI row WARNED about rather than refused (STS-CORE-0176).
//! 4. **[`audit_appconfig`]**: the operator's file against the table —
//!    settings it no longer lists and keys it carries that the table does
//!    not know, said only for a file that is this service's.
//!
//! and then `server.js`'s: **[`deliver_secrets`]** (#254, STS-CORE-0150,
//! 0151, 0152) and **[`cleartext_refusal`]** (STS-CORE-0167, #1457).

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value as Json;

use crate::errors::codes;
use crate::log::tag;
use crate::mode::Mode;
use crate::settings::{dig, replaced, replaced_by, row, rows, Settings};

/// The settings `common/delivered_secrets.ts` may read from a file: a
/// list, not "every secret row" — see that module.
pub const DELIVERED_KEYS: &[&str] = &[
    "adminApi.clientSecret",
    "krb5.krbtgtPassword",
    "krb5.servicePassword",
    "global.edgeSecret",
    "admin.bootstrapPassword",
    "scim.digestPassword",
];

/// The names a refusal uses for the two appconfig files: `CONFIG_FILE` as
/// resolved, and `env/defaults.js` under the package root.
#[derive(Debug, Clone)]
pub struct Files {
    pub config_file: Option<String>,
    pub defaults_file: String,
}

impl Files {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(config_file: Option<String>, root: &Path) -> Files {
        Files {
            config_file,
            defaults_file: root
                .join("env")
                .join("defaults.js")
                .to_string_lossy()
                .into_owned(),
        }
    }

    fn named(&self) -> &str {
        self.config_file.as_deref().unwrap_or("the appconfig file")
    }
}

/// `refuseReplacedSettings()`: `Err` is the STS-CORE-0105 text.
#[tracing::instrument(level = "debug", skip_all)]
pub fn refuse_replaced_settings(
    settings: &Settings,
    files: &Files,
) -> Result<(), String> {
    let mut named = Vec::new();
    for one in replaced() {
        if dig(settings.operator(), one.key).is_some() {
            named.push(format!(
                "  {} (in {}) is now {}.{}",
                one.key,
                files.named(),
                one.now.join(", "),
                replaced_by(one.key)
            ));
        }
        for name in [one.env, one.legacy_env].into_iter().flatten() {
            if settings.env_var(name).is_some() {
                let now: Vec<&str> = one
                    .now
                    .iter()
                    .map(|key| match row(key) {
                        Some(r) => r.env.unwrap_or(""),
                        None => key,
                    })
                    .collect();
                named.push(format!(
                    "  {} (in the environment) is now {}.{}",
                    name,
                    now.join(", "),
                    replaced_by(one.key)
                ));
            }
        }
    }
    if named.is_empty() {
        return Ok(());
    }
    Err(format!(
        "\n{}config: FATAL — {} setting(s) that were removed are still \
         named:\n\n{}\n\nThere is no mapping from an old name to a new one: \
         what the old value meant is for the operator to say. Remove the old \
         name and set the ones intended.\n\n",
        tag(codes::STS_CORE_0105),
        named.len(),
        named.join("\n")
    ))
}

/// What [`refuse_malformed_settings`] found that is not a refusal: one
/// STS-CORE-0176 sentence per value that is not an absolute URI, already
/// logged.
pub type Warnings = Vec<String>;

/// `refuseMalformedSettings()`: `Err` is the STS-CORE-0108 text.
#[tracing::instrument(level = "debug", skip_all)]
pub fn refuse_malformed_settings(
    settings: &Settings,
    files: &Files,
) -> Result<Warnings, String> {
    let mut named = Vec::new();
    let mut warnings = Vec::new();
    for setting in rows() {
        let dotted = setting.dotted();
        let mut layers: Vec<(Json, String)> = Vec::new();
        for name in [setting.env, setting.legacy_env].into_iter().flatten() {
            if let Some(raw) = settings.env_var(name) {
                layers.push((
                    Json::from(raw),
                    format!("{} (in the environment)", name),
                ));
            }
        }
        if let Some(raw) = dig(settings.operator(), dotted) {
            layers.push((
                raw.clone(),
                format!("{} (in {})", dotted, files.named()),
            ));
        }
        if let Some(raw) = setting.defaults_file_value() {
            layers.push((
                raw,
                format!("{} (in {})", dotted, files.defaults_file),
            ));
        }
        for (raw, wher) in layers {
            let problem = setting.check_at_startup(&raw);
            if let Some(problem) = &problem {
                named.push(format!(
                    "  {}: \"{}\" {}",
                    wher, setting.key, problem
                ));
            }
            if problem.is_none()
                && setting.absolute_uri
                && setting.check(&raw).is_some()
            {
                let line = format!(
                    "{}config: {}: \"{}\" is not an absolute URI. It is used \
                     as configured; /admin/config and the management API \
                     refuse it on the next save.",
                    tag(codes::STS_CORE_0176),
                    wher,
                    setting.key
                );
                tracing::warn!("{}", line);
                warnings.push(line);
            }
        }
    }
    if named.is_empty() {
        return Ok(warnings);
    }
    Err(format!(
        "\n{}config: FATAL — {} configured value(s) would be refused by \
         /admin/config and the management API, and are refused here for the \
         same reason:\n\n{}\n\nFix or remove each one. A setting holds one of \
         the values GET /admin-api/config lists for it (`enumValues`, or \
         `csvValues` for each entry of a list) and within its bounds.\n\n",
        tag(codes::STS_CORE_0108),
        named.len(),
        named.join("\n")
    ))
}

/// `auditAppconfig()`'s answer: settings the operator's file does not
/// carry, and dot paths it carries that the table does not know.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Audit {
    pub missing: Vec<String>,
    pub unknown: Vec<String>,
}

/// `auditAppconfig()`, read against the operator's file and not the union
/// (which can never be missing a key).
#[tracing::instrument(level = "debug", skip_all)]
pub fn audit_appconfig(operator: &Json) -> Audit {
    let missing = rows()
        .iter()
        .filter(|s| !s.derived && dig(operator, s.dotted()).is_none())
        .map(|s| s.key.to_string())
        .collect();
    let mut present = Vec::new();
    if let Some(top) = operator.as_object() {
        for (key, node) in top {
            match node.as_object() {
                Some(leaves) => {
                    for leaf in leaves.keys() {
                        present.push(format!("{}.{}", key, leaf));
                    }
                }
                None => present.push(key.clone()),
            }
        }
    }
    let known: std::collections::HashSet<&str> =
        rows().iter().map(|s| s.dotted()).collect();
    let unknown = present
        .into_iter()
        .filter(|p| !known.contains(p.as_str()))
        .collect();
    Audit { missing, unknown }
}

/// `nameList()`: twelve names and a count.
fn name_list(keys: &[String]) -> String {
    let shown = keys.iter().take(12).cloned().collect::<Vec<_>>().join(", ");
    if keys.len() > 12 {
        format!("{}, and {} more", shown, keys.len() - 12)
    } else {
        shown
    }
}

/// The two drift warnings config.js logs after the audit, or neither for a
/// file that carries none of this service's distinctive keys (somebody
/// else's file, which the union exists for). Each is logged and returned.
#[tracing::instrument(level = "debug", skip_all)]
pub fn audit_warnings(operator: &Json, files: &Files) -> Vec<String> {
    let audit = audit_appconfig(operator);
    let distinctive: Vec<&str> = rows()
        .iter()
        .filter(|s| !s.derived && s.dotted() != "logLevel")
        .map(|s| s.key)
        .collect();
    let distinctive_missing = distinctive
        .iter()
        .filter(|k| audit.missing.iter().any(|m| m == *k))
        .count();
    let theirs = distinctive_missing == distinctive.len();
    let mut out = Vec::new();
    if theirs {
        tracing::debug!(
            "config: {} carries none of this service's settings, so every \
             value comes from {} or from the environment.",
            files.named(),
            files.defaults_file
        );
    } else if !audit.missing.is_empty() {
        out.push(format!(
            "config: {} setting(s) are not in {} and are coming from {} \
             instead: {}. That is not an error — the union is what that file \
             is for, and the value is the same either way — but a file that \
             is meant to list the whole surface no longer does.",
            audit.missing.len(),
            files.named(),
            files.defaults_file,
            name_list(&audit.missing)
        ));
    }
    if !audit.unknown.is_empty() && !theirs {
        out.push(format!(
            "config: {} carries {} key(s) this service does not know and is \
             not reading: {}. A misspelt key looks exactly like this.",
            files.named(),
            audit.unknown.len(),
            name_list(&audit.unknown)
        ));
    }
    for line in &out {
        tracing::warn!("{}", line);
    }
    out
}

/// A filesystem for [`deliver_secrets`]: the real one, or a test's.
pub trait SecretFiles {
    fn read(&self, path: &str) -> Result<String, String>;
    fn remove(&self, path: &str) -> Result<(), String>;
}

/// The process's own files.
pub struct RealFiles;

impl SecretFiles for RealFiles {
    fn read(&self, path: &str) -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|e| node_error(&e, "open", path))
    }

    fn remove(&self, path: &str) -> Result<(), String> {
        std::fs::remove_file(path).map_err(|e| node_error(&e, "unlink", path))
    }
}

/// An I/O error in node's words (`ENOENT: no such file or directory, open
/// '/x'`), which the refusal quotes.
fn node_error(e: &std::io::Error, syscall: &str, path: &str) -> String {
    let (code, text) = match e.kind() {
        std::io::ErrorKind::NotFound => ("ENOENT", "no such file or directory"),
        std::io::ErrorKind::PermissionDenied => ("EACCES", "permission denied"),
        std::io::ErrorKind::IsADirectory => {
            ("EISDIR", "illegal operation on a directory")
        }
        _ => return format!("{}, {} '{}'", e, syscall, path),
    };
    format!("{}: {}, {} '{}'", code, text, syscall, path)
}

/// `DeliveredSecrets.load()` (#254): every `<ENV>_FILE` naming a file for
/// one of [`DELIVERED_KEYS`] is read (trimmed), the file DELETED, the value
/// held at the environment layer (`Settings::set_delivered`) and the
/// variable taken out of `env`. `Err` is the STS-CORE-0150 (unreadable) or
/// 0151 (empty) refusal: the service was told where its secret is, and
/// starting without it would mint a different one. A file that cannot be
/// deleted is warned about (0152) and the service starts. The keys
/// delivered.
#[tracing::instrument(level = "debug", skip_all)]
pub fn deliver_secrets(
    settings: &Settings,
    env: &mut HashMap<String, String>,
    files: &dyn SecretFiles,
) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for key in DELIVERED_KEYS {
        let Some(variable) = row(key).and_then(|r| r.env) else {
            continue;
        };
        let file_variable = format!("{}_FILE", variable);
        let wher = env
            .get(&file_variable)
            .map(|w| crate::settings::js_trim(w).to_string())
            .unwrap_or_default();
        if wher.is_empty() {
            continue;
        }
        let value = match files.read(&wher) {
            Ok(text) => crate::settings::js_trim(&text).to_string(),
            Err(why) => {
                return Err(format!(
                    "{}{} names {}, which could not be read ({}). The service \
                     does not start without the secret it was told is there.",
                    tag(codes::STS_CORE_0150),
                    file_variable,
                    wher,
                    why
                ));
            }
        };
        if value.is_empty() {
            return Err(format!(
                "{}{} names {}, which is empty.",
                tag(codes::STS_CORE_0151),
                file_variable,
                wher
            ));
        }
        if let Err(why) = files.remove(&wher) {
            tracing::warn!(
                "{}{} named {}, which was read and could not be deleted ({}); \
                 it is still readable there.",
                tag(codes::STS_CORE_0152),
                file_variable,
                wher,
                why
            );
        }
        env.remove(&file_variable);
        settings.set_delivered(key, &value)?;
        out.push(key.to_string());
    }
    if !out.is_empty() {
        tracing::info!(
            "delivered_secrets: read {} from the file{} named by its \
             <ENV>_FILE, and deleted {}.",
            out.join(", "),
            if out.len() == 1 { "" } else { "s" },
            if out.len() == 1 { "it" } else { "them" }
        );
    }
    Ok(out)
}

/// `server.js`'s refusal of a product process that would serve its main
/// port in cleartext (#1457, ASVS 5.0.0 12.2.1): `Some` is the fatal line.
#[tracing::instrument(level = "debug", skip_all)]
pub fn cleartext_refusal(mode: &Mode, use_https: bool) -> Option<String> {
    let problem = mode.cleartext_startup_problem(use_https);
    if problem.is_empty() {
        return None;
    }
    Some(format!(
        "{}sts: NOT STARTING. {}",
        tag(codes::STS_CORE_0167),
        problem
    ))
}

/// Every check config.js makes as it loads, in its order: the refusals as
/// one `Err` (the first that fires; config.js exits on it), the drift
/// warnings logged. What `main` calls once the settings are built.
#[tracing::instrument(level = "debug", skip_all)]
pub fn check_settings(
    settings: &Settings,
    files: &Files,
) -> Result<(), String> {
    tracing::info!(
        "config: {} settings from {} over {}, {} of them changeable while \
         running. /admin/config shows them all.",
        rows().len(),
        files.config_file.as_deref().unwrap_or("(no CONFIG_FILE)"),
        files.defaults_file,
        rows().iter().filter(|r| r.runtime).count()
    );
    refuse_replaced_settings(settings, files)?;
    refuse_malformed_settings(settings, files)?;
    audit_warnings(settings.operator(), files);
    Ok(())
}
