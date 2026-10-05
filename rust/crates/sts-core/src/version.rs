// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The version, M.N.O, fixed when an artifact is BUILT. A port of
//! `common/version.js`, with the same two files and the same rule.
//!
//! `VERSION` holds M.N. The build number is the UTC build instant
//! (`BUILD_NUMBER` overrides it), stamped into `version.json` when an image
//! is built (`--stamp <dir>`), so a restarted container reports the same
//! build. Without a stamp the version is COMPUTED at start and says so
//! (`stamped: false`). **A version may never be the thing that stops a
//! process starting**: an unreadable `VERSION` is 0.0, a corrupt stamp is a
//! computed record.

use crate::errors::codes;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use serde::{Deserialize, Serialize};

const VERSION_FILE: &str = "VERSION";
const STAMP_FILE: &str = "version.json";

/// What `version.json` holds, in its field order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionInfo {
    pub version: String,
    pub major: String,
    pub minor: String,
    pub build: String,
    pub commit: String,
    pub built_at: String,
    pub stamped: bool,
}

/// `VERSION` in `dir` or its parent, as `version.js`'s `findRoot()` looks.
fn find_root(dir: &Path) -> PathBuf {
    for candidate in [dir.to_path_buf(), dir.join("..")] {
        if candidate.join(VERSION_FILE).is_file() {
            return candidate;
        }
    }
    dir.to_path_buf()
}

fn read_major_minor(root: &Path) -> (String, String) {
    let file = root.join(VERSION_FILE);
    match std::fs::read_to_string(&file) {
        Ok(raw) => {
            let raw = raw.trim();
            if let Some((major, minor)) = raw.split_once('.') {
                let digits = |s: &str| {
                    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
                };
                if digits(major) && digits(minor) {
                    return (major.to_string(), minor.to_string());
                }
            }
            if !raw.is_empty() {
                tracing::error!(
                    "{}[version] ignoring malformed {}: \"{}\" (want M.N)",
                    crate::log::tag(codes::STS_CORE_0039),
                    file.display(),
                    raw
                );
            }
        }
        Err(error) => {
            tracing::debug!("no {}: {}", file.display(), error);
        }
    }
    tracing::error!(
        "{}[version] no readable {}; falling back to 0.0",
        crate::log::tag(codes::STS_CORE_0040),
        VERSION_FILE
    );
    ("0".into(), "0".into())
}

fn git_commit(root: &Path) -> String {
    if let Ok(commit) = std::env::var("GIT_COMMIT") {
        return commit.trim().chars().take(12).collect();
    }
    Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_default()
}

/// The version computed now, from `VERSION`, `BUILD_NUMBER` and the clock.
pub fn resolve(dir: &Path) -> VersionInfo {
    let root = find_root(dir);
    let (major, minor) = read_major_minor(&root);
    let now = Utc::now();
    let build = std::env::var("BUILD_NUMBER")
        .ok()
        .map(|b| b.trim().to_string())
        .filter(|b| !b.is_empty())
        .unwrap_or_else(|| now.format("%Y%m%d%H%M%S").to_string());
    VersionInfo {
        version: format!("{}.{}.{}", major, minor, build),
        major,
        minor,
        build,
        commit: git_commit(&root),
        built_at: crate::time::iso_seconds(now),
        stamped: false,
    }
}

/// Writes `version.json` into `dir` — the image build's step.
pub fn stamp(dir: &Path) -> VersionInfo {
    let mut info = resolve(dir);
    info.stamped = true;
    let written = std::fs::create_dir_all(dir).and_then(|()| {
        let text = serde_json::to_string_pretty(&info)
            .map_err(std::io::Error::other)?;
        std::fs::write(dir.join(STAMP_FILE), text + "\n")
    });
    if let Err(error) = written {
        tracing::error!(
            "{}[version] could not write {}: {}",
            crate::log::tag(codes::STS_CORE_0041),
            dir.join(STAMP_FILE).display(),
            error
        );
    }
    info
}

/// The stamped version in `dir`, or one computed now.
pub fn load(dir: &Path) -> VersionInfo {
    let stamped = std::fs::read_to_string(dir.join(STAMP_FILE))
        .ok()
        .and_then(|text| serde_json::from_str::<VersionInfo>(&text).ok())
        .filter(|info| !info.version.is_empty());
    match stamped {
        Some(mut info) => {
            info.stamped = true;
            info
        }
        None => resolve(dir),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_then_load_round_trips() {
        let dir = std::env::temp_dir()
            .join(format!("sts-version-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(VERSION_FILE), "2.7\n").unwrap();
        let written = stamp(&dir);
        assert!(written.version.starts_with("2.7."));
        let read = load(&dir);
        assert_eq!(read, written);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
