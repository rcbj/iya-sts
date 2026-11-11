// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The version, M.N.O.<build> (#1298, #1317). A port of `common/version.js`,
//! with the same two files and the same rules, so a PEP built from the same
//! tree with the same build arguments reports what the service does.
//!
//! `VERSION` holds the release, the whole M.N.O; the build number follows it
//! as a fourth component. **By default the build number is the UTC build
//! instant, `YYYYMMDDHHMMSS`.** A RELEASE build is flagged with
//! `STS_RELEASE=true` and names its number in `BUILD_NUMBER` (a non-negative
//! integer, no leading zero): `1.0.0.0`. A release flag without a valid
//! number is REFUSED at `--stamp` (`STS-CORE-0164`), so the image does not
//! build; without the flag `BUILD_NUMBER` is IGNORED, so a stray CI variable
//! cannot pass an ordinary build off as a release.
//!
//! The number, the commit and the build instant are stamped into
//! `version.json` when an image is built (`--stamp <dir>`), so a restarted
//! container reports the same build. Without a stamp the record is COMPUTED
//! at start, its number is the start instant, it is never a release, and it
//! says so (`stamped: false`). **A version may never be the thing that stops
//! a process starting**: an unreadable `VERSION` is 0.0.0, a corrupt stamp
//! is a computed record, and a stamp written by a #1298 build (no `build`)
//! still loads, reporting the bare M.N.O it was written with.
//!
//! **A build of main carries the patch its workflow worked out (2026-11-11)**:
//! `STS_VERSION_RELEASE`, when set, is the release a stamp records in place
//! of `VERSION`'s, and it must be M.N.O exactly or the stamp is REFUSED
//! (`STS-CORE-0175`) and writes nothing. Unset or empty, nothing changes.

use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{DateTime, Utc};
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
    /// Absent from a stamp written before #1298, whose third component was
    /// a build number; such a stamp still loads.
    #[serde(default)]
    pub patch: String,
    /// The build number (#1317): the UTC build instant as YYYYMMDDHHMMSS, or
    /// a release build's own. Empty in a stamp written by a #1298 build.
    #[serde(default)]
    pub build: String,
    /// Whether the build was flagged as a release and named its number.
    #[serde(default)]
    pub release: bool,
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

/// One component of a semantic version: digits, and no leading zero
/// (Semantic Versioning 2.0.0, section 2).
fn is_component(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'))
}

/// A release, M.N.O exactly, broken out; `None` for anything else.
fn parse_release(raw: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() == 3 && parts.iter().all(|p| is_component(p)) {
        Some((
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
        ))
    } else {
        None
    }
}

/// The release a STAMPED build carries, from `STS_VERSION_RELEASE`, as
/// `common/version.js`'s `releaseFrom()` decides it: `Ok(None)` when it is
/// unset or empty (`VERSION`'s, as before it existed), `Ok(Some(..))` when it
/// is M.N.O exactly, and a refusal for anything else.
pub fn release_from(
    version_release: Option<&str>,
) -> Result<Option<(String, String, String)>, String> {
    let given = version_release.unwrap_or("").trim();
    if given.is_empty() {
        return Ok(None);
    }
    match parse_release(given) {
        Some(parts) => Ok(Some(parts)),
        None => Err(format!(
            "STS_VERSION_RELEASE is \"{}\"; it must be a release, M.N.O \
             exactly (three non-negative integers with no leading zero, \
             e.g. 1.0.1), or unset for VERSION's",
            given
        )),
    }
}

/// `VERSION`'s M.N.O, or 0.0.0 — never a failure.
fn read_release(root: &Path) -> (String, String, String) {
    let file = root.join(VERSION_FILE);
    match std::fs::read_to_string(&file) {
        Ok(raw) => {
            let raw = raw.trim();
            if let Some(parts) = parse_release(raw) {
                return parts;
            }
            if !raw.is_empty() {
                tracing::error!(
                    "{}[version] ignoring malformed {}: \"{}\" (want M.N.O)",
                    crate::log::tag("STS-CORE-0039"),
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
        "{}[version] no readable {}; falling back to 0.0.0",
        crate::log::tag("STS-CORE-0040"),
        VERSION_FILE
    );
    ("0".into(), "0".into(), "0".into())
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

/// The UTC instant as YYYYMMDDHHMMSS — the default build number.
fn utc_stamp(at: DateTime<Utc>) -> String {
    at.format("%Y%m%d%H%M%S").to_string()
}

/// A stamped build's number and whether it is a release, from the two
/// variables `common/version.js`'s `buildNumberFrom()` reads, decided the
/// same way: `STS_RELEASE` is `true`, `false` or empty (anything else is
/// refused rather than guessed at); a release needs a valid `BUILD_NUMBER`;
/// without the flag `BUILD_NUMBER` is ignored and the instant is the number.
/// `Ok` carries the number, the flag, and the BUILD_NUMBER that was ignored.
pub fn build_number_from(
    release_flag: Option<&str>,
    build_number: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(String, bool, String), String> {
    let flag = release_flag.unwrap_or("").trim().to_ascii_lowercase();
    let given = build_number.unwrap_or("").trim().to_string();
    match flag.as_str() {
        "true" => {
            if is_component(&given) {
                Ok((given, true, String::new()))
            } else {
                Err(format!(
                    "STS_RELEASE=true marks a release build, and a release \
                     names its build number: BUILD_NUMBER must be a \
                     non-negative integer with no leading zero (e.g. \
                     BUILD_NUMBER=0), and it is {}",
                    if given.is_empty() {
                        "not set".to_string()
                    } else {
                        format!("\"{}\"", given)
                    }
                ))
            }
        }
        "false" | "" => Ok((utc_stamp(now), false, given)),
        other => Err(format!(
            "STS_RELEASE is \"{}\"; it must be true (a release build, which \
             names its BUILD_NUMBER) or false (the default: the build number \
             is the UTC build instant)",
            other
        )),
    }
}

fn record(
    dir: &Path,
    now: DateTime<Utc>,
    build: String,
    release: bool,
    named: Option<(String, String, String)>,
) -> VersionInfo {
    let root = find_root(dir);
    let (major, minor, patch) = named.unwrap_or_else(|| read_release(&root));
    VersionInfo {
        version: format!("{}.{}.{}.{}", major, minor, patch, build),
        major,
        minor,
        patch,
        build,
        release,
        commit: git_commit(&root),
        built_at: crate::time::iso_seconds(now),
        stamped: false,
    }
}

/// The version computed now: `VERSION`'s M.N.O with the start instant as
/// its build number, the commit and the clock. Never a release.
pub fn resolve(dir: &Path) -> VersionInfo {
    let now = Utc::now();
    record(dir, now, utc_stamp(now), false, None)
}

/// Writes `version.json` into `dir` — the image build's step — with the
/// build number `STS_RELEASE` and `BUILD_NUMBER` decide, and the release
/// `STS_VERSION_RELEASE` names (`VERSION`'s when it is unset). A refusal
/// writes nothing and is returned, for `--stamp` to exit non-zero with.
pub fn stamp(dir: &Path) -> Result<VersionInfo, String> {
    let now = Utc::now();
    let flag = std::env::var("STS_RELEASE").ok();
    let given = std::env::var("BUILD_NUMBER").ok();
    let named = std::env::var("STS_VERSION_RELEASE").ok();
    stamp_with_release(
        dir,
        named.as_deref(),
        flag.as_deref(),
        given.as_deref(),
        now,
    )
}

/// [`stamp`] with its inputs given rather than read from the environment,
/// and the release `VERSION`'s.
pub fn stamp_with(
    dir: &Path,
    release_flag: Option<&str>,
    build_number: Option<&str>,
    now: DateTime<Utc>,
) -> Result<VersionInfo, String> {
    stamp_with_release(dir, None, release_flag, build_number, now)
}

/// [`stamp_with`] with `STS_VERSION_RELEASE`'s value given as well.
pub fn stamp_with_release(
    dir: &Path,
    version_release: Option<&str>,
    release_flag: Option<&str>,
    build_number: Option<&str>,
    now: DateTime<Utc>,
) -> Result<VersionInfo, String> {
    let (build, release, ignored) =
        match build_number_from(release_flag, build_number, now) {
            Ok(decided) => decided,
            Err(problem) => {
                return Err(format!(
                    "{}[version] refusing to stamp a build: {}",
                    crate::log::tag("STS-CORE-0164"),
                    problem
                ));
            }
        };
    let named = match release_from(version_release) {
        Ok(named) => named,
        Err(problem) => {
            return Err(format!(
                "{}[version] refusing to stamp a build: {}",
                crate::log::tag("STS-CORE-0175"),
                problem
            ));
        }
    };
    if let Some((major, minor, patch)) = &named {
        tracing::info!(
            "[version] the release is {}.{}.{}, from STS_VERSION_RELEASE, \
             in place of VERSION's",
            major,
            minor,
            patch
        );
    }
    if !ignored.is_empty() {
        tracing::info!(
            "[version] BUILD_NUMBER={} is ignored: this is not a release \
             build (STS_RELEASE is not true), so the build number is the \
             UTC build instant",
            ignored
        );
    }
    let mut info = record(dir, now, build, release, named);
    info.stamped = true;
    let written = std::fs::create_dir_all(dir).and_then(|()| {
        let text = serde_json::to_string_pretty(&info)
            .map_err(std::io::Error::other)?;
        std::fs::write(dir.join(STAMP_FILE), text + "\n")
    });
    if let Err(error) = written {
        tracing::error!(
            "{}[version] could not write {}: {}",
            crate::log::tag("STS-CORE-0041"),
            dir.join(STAMP_FILE).display(),
            error
        );
    }
    Ok(info)
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
    use chrono::TimeZone;

    fn at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 4, 15, 12, 0).unwrap()
    }

    #[test]
    fn stamp_then_load_round_trips() {
        let dir = std::env::temp_dir()
            .join(format!("sts-version-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(VERSION_FILE), "2.7.1\n").unwrap();
        let written = stamp_with(&dir, None, Some("7"), at()).unwrap();
        // BUILD_NUMBER without the release flag is ignored: the instant.
        assert_eq!(written.version, "2.7.1.20261104151200");
        assert_eq!(written.build, "20261104151200");
        assert_eq!(written.patch, "1");
        assert!(!written.release);
        assert!(written.stamped);
        let read = load(&dir);
        assert_eq!(read, written);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_release_names_its_build_number() {
        let dir = std::env::temp_dir()
            .join(format!("sts-version-rel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(VERSION_FILE), "1.0.0\n").unwrap();
        let written =
            stamp_with(&dir, Some("true"), Some("0"), at()).unwrap();
        assert_eq!(written.version, "1.0.0.0");
        assert_eq!(written.build, "0");
        assert!(written.release);
        assert_eq!(load(&dir), written);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_release_without_a_number_is_refused_and_writes_nothing() {
        let dir = std::env::temp_dir()
            .join(format!("sts-version-norel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(VERSION_FILE), "1.0.0\n").unwrap();
        for (flag, number) in [
            (Some("true"), None),
            (Some("true"), Some("")),
            (Some("true"), Some("01")),
            (Some("true"), Some("-1")),
            (Some("true"), Some("x")),
            (Some("yes"), Some("0")),
        ] {
            let refused = stamp_with(&dir, flag, number, at()).unwrap_err();
            assert!(refused.contains("STS-CORE-0164"), "{}", refused);
            assert!(refused.contains("STS_RELEASE"), "{}", refused);
        }
        assert!(!dir.join(STAMP_FILE).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_named_release_is_stamped_in_place_of_version() {
        let dir = std::env::temp_dir()
            .join(format!("sts-version-named-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(VERSION_FILE), "1.0.0\n").unwrap();
        let written =
            stamp_with_release(&dir, Some(" 1.0.7 "), None, None, at())
                .unwrap();
        assert_eq!(written.version, "1.0.7.20261104151200");
        assert_eq!(
            (
                written.major.as_str(),
                written.minor.as_str(),
                written.patch.as_str()
            ),
            ("1", "0", "7")
        );
        assert!(!written.release);
        assert_eq!(load(&dir), written);
        // With a release build's number as well: 1.0.7.0.
        let both = stamp_with_release(
            &dir,
            Some("1.0.7"),
            Some("true"),
            Some("0"),
            at(),
        )
        .unwrap();
        assert_eq!(both.version, "1.0.7.0");
        assert!(both.release);
        // Unset or empty is VERSION's, exactly as stamp_with().
        for absent in [None, Some(""), Some("  ")] {
            let plain =
                stamp_with_release(&dir, absent, None, None, at()).unwrap();
            assert_eq!(plain.version, "1.0.0.20261104151200");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_malformed_named_release_is_refused_and_writes_nothing() {
        let dir = std::env::temp_dir()
            .join(format!("sts-version-badnamed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(VERSION_FILE), "1.0.0\n").unwrap();
        for bad in [
            "v1.0.1",
            "1.0",
            "1.0.1.0",
            "01.0.1",
            "1.0.01",
            "1.0.1-rc.1",
            "x",
        ] {
            let refused = stamp_with_release(&dir, Some(bad), None, None, at())
                .unwrap_err();
            assert!(refused.contains("STS-CORE-0175"), "{}", refused);
            assert!(refused.contains("STS_VERSION_RELEASE"), "{}", refused);
        }
        assert!(!dir.join(STAMP_FILE).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_stamp_from_1298_still_loads() {
        let dir = std::env::temp_dir()
            .join(format!("sts-version-old-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(STAMP_FILE),
            r#"{"version":"1.0.0","major":"1","minor":"0","patch":"0",
               "commit":"abc","builtAt":"2026-11-03T00:00:00Z",
               "stamped":true}"#,
        )
        .unwrap();
        let read = load(&dir);
        assert_eq!(read.version, "1.0.0");
        assert_eq!(read.build, "");
        assert!(!read.release);
        assert!(read.stamped);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_malformed_version_is_zero_never_a_failure() {
        let dir = std::env::temp_dir()
            .join(format!("sts-version-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for bad in ["0.1", "v1.0.0", "1.0.0-rc1", "01.0.0", "1.0.0.0"] {
            std::fs::write(dir.join(VERSION_FILE), bad).unwrap();
            assert!(resolve(&dir).version.starts_with("0.0.0."), "{}", bad);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
