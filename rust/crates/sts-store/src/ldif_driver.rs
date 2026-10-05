// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `persistence.mode=ldif`: local development's store, a directory of
//! files (`persistence_ldif.js`).
//!
//! ```text
//! <dataDir>/realm-<id>.ldif   one per realm, the default realm included
//! <dataDir>/realms.json       the realm registry
//! <dataDir>/appconfig.json    the runtime appconfig overrides
//! ```
//!
//! **Every write is atomic**: to `<name>.tmp`, then renamed over the
//! target, so a reader — the next start included — sees the whole old file
//! or the whole new one, never a directory truncated mid-record.
//!
//! **It writes whole files, and the diff is read only for `touched`**, the
//! realms something happened in, so a change in `acme` does not rewrite the
//! default realm's file. Every file is mode 0600.
//!
//! **No minted state**: it writes whole files per flush, which is right for
//! a directory that changes when somebody types and wrong for a session
//! table that changes on every request.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value as Json};

use crate::driver::{Directory, Driver, StoreError, StoreFuture, StoreResult};
use crate::ldif;
use crate::model::DirectoryChange;

const HEADER: &[&str] = &[
    "",
    "RFC 2849 LDIF. It is read back at startup when persistence.mode=ldif, and it is ordinary LDIF otherwise: \
     ldapadd -f will load it into any directory.",
    "A \"# sts-origin:\" comment above a record is this service's own marker for how the entry came to exist. \
     Every other reader ignores it.",
    "Editing this file by hand is fine while the service is STOPPED. While it is running, the service rewrites \
     the whole file on the next change and your edit is gone.",
];

/// The header lines of one realm's file.
pub fn header_for(realm_id: &str) -> Vec<String> {
    let mut out = vec![format!(
        "The \"{}\" realm's directory, written by iya-sts.",
        realm_id
    )];
    out.extend(HEADER[1..].iter().map(|s| s.to_string()));
    out
}

/// A realm id this driver will build a filename from: the realm pattern,
/// checked here too because the path is built from data.
fn safe_id(id: &str) -> StoreResult<&str> {
    let b = id.as_bytes();
    let ok = !b.is_empty()
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-'
        });
    if ok {
        Ok(id)
    } else {
        Err(StoreError::new(format!(
            "persistence: \"{}\" is not a realm id this driver will build a filename from.",
            id
        )))
    }
}

pub struct LdifDriver {
    dir: PathBuf,
}

impl LdifDriver {
    pub fn new(dir: impl Into<PathBuf>) -> LdifDriver {
        LdifDriver { dir: dir.into() }
    }

    fn realm_file(&self, id: &str) -> StoreResult<PathBuf> {
        Ok(self.dir.join(format!("realm-{}.ldif", safe_id(id)?)))
    }

    fn write_atomic(file: &Path, text: &str) -> StoreResult<()> {
        let tmp = file.with_extension(format!(
            "{}.tmp",
            file.extension().and_then(|e| e.to_str()).unwrap_or("")
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, file)?;
        Ok(())
    }

    fn read_if_present(file: &Path) -> StoreResult<Option<String>> {
        match fs::read_to_string(file) {
            Ok(t) => Ok(Some(t)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// `JSON.stringify(value, null, 2) + '\n'`.
    fn pretty(value: &Json) -> StoreResult<String> {
        Ok(format!("{}\n", serde_json::to_string_pretty(value)?))
    }
}

impl Driver for LdifDriver {
    fn name(&self) -> &'static str {
        "ldif"
    }

    fn open(&self) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            fs::create_dir_all(&self.dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &self.dir,
                    fs::Permissions::from_mode(0o700),
                )?;
            }
            // Written and removed rather than assumed: a read-only volume is a
            // real mistake, and found here rather than at the first flush.
            let probe = self.dir.join(".writable");
            fs::write(&probe, "sts")?;
            fs::remove_file(&probe)?;
            tracing::info!(
                "persistence: the ldif store is {}.",
                self.dir.display()
            );
            Ok(())
        })
    }

    fn close(&self) -> StoreFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn load_directory(&self) -> StoreFuture<'_, Option<Directory>> {
        Box::pin(async move {
            let names = match fs::read_dir(&self.dir) {
                Ok(r) => r,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(None)
                }
                Err(e) => return Err(e.into()),
            };
            let mut out = Directory::new();
            for item in names {
                let name = item?.file_name().to_string_lossy().into_owned();
                let Some(id) = name
                    .strip_prefix("realm-")
                    .and_then(|n| n.strip_suffix(".ldif"))
                else {
                    continue;
                };
                if safe_id(id).is_err() {
                    continue;
                }
                if let Some(text) =
                    LdifDriver::read_if_present(&self.dir.join(&name))?
                {
                    let entries = ldif::from_ldif(&text);
                    tracing::info!(
                        "persistence: read {} entry/ies for the realm \"{}\" from {}.",
                        entries.len(),
                        id,
                        name
                    );
                    out.insert(id.to_string(), entries);
                }
            }
            Ok((!out.is_empty()).then_some(out))
        })
    }

    fn load_realms(&self) -> StoreFuture<'_, Option<Vec<Json>>> {
        Box::pin(async move {
            let Some(text) =
                LdifDriver::read_if_present(&self.dir.join("realms.json"))?
            else {
                return Ok(None);
            };
            let parsed: Json = serde_json::from_str(&text)?;
            Ok(Some(
                parsed
                    .get("realms")
                    .and_then(Json::as_array)
                    .cloned()
                    .unwrap_or_default(),
            ))
        })
    }

    fn load_overrides(&self) -> StoreFuture<'_, Option<Map<String, Json>>> {
        Box::pin(async move {
            let Some(text) =
                LdifDriver::read_if_present(&self.dir.join("appconfig.json"))?
            else {
                return Ok(None);
            };
            let parsed: Json = serde_json::from_str(&text)?;
            Ok(Some(
                parsed
                    .get("overrides")
                    .and_then(Json::as_object)
                    .cloned()
                    .unwrap_or_default(),
            ))
        })
    }

    fn save_directory<'a>(
        &'a self,
        change: &'a DirectoryChange,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            for id in &change.removed_realms {
                match fs::remove_file(self.realm_file(id)?) {
                    Ok(()) => tracing::info!(
                        "persistence: the realm \"{}\" is gone; its LDIF file was removed with it.",
                        id
                    ),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            for id in &change.touched {
                let Some(rows) = change.all.get(id) else {
                    continue;
                };
                let header = header_for(id);
                let header: Vec<&str> =
                    header.iter().map(String::as_str).collect();
                LdifDriver::write_atomic(
                    &self.realm_file(id)?,
                    &ldif::to_ldif(rows, &header),
                )?;
                tracing::info!(
                    "persistence: wrote {} entry/ies for the realm \"{}\".",
                    rows.len(),
                    id
                );
            }
            Ok(())
        })
    }

    fn save_realms<'a>(&'a self, rows: &'a [Json]) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let doc = json!({
                "version": 1,
                "note": "The trust realms iya-sts had defined when this was written. The DEFAULT realm is not here \
                         and never will be: it is a constant in common/realms.js, not a row.",
                "realms": rows,
            });
            LdifDriver::write_atomic(
                &self.dir.join("realms.json"),
                &LdifDriver::pretty(&doc)?,
            )
        })
    }

    fn save_overrides<'a>(
        &'a self,
        overrides: &'a Map<String, Json>,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let doc = json!({
                "version": 1,
                "note": "Runtime appconfig overrides — the TOP of config.js's five layers, which is what a console \
                         Save and POST /admin-api/config/set write. They are re-applied at startup through the same \
                         setOverride() a caller uses, so this file adds no layer. Only a runtime-changeable setting \
                         can be here; a restart-only one is refused at the writing end.",
                "overrides": overrides,
            });
            LdifDriver::write_atomic(
                &self.dir.join("appconfig.json"),
                &LdifDriver::pretty(&doc)?,
            )
        })
    }
}
