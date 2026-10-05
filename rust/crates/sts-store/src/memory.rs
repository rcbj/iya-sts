// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `persistence.mode=memory`, the default: nothing is written and nothing
//! is read. Every load answers "nothing has ever been written".

use serde_json::{Map, Value as Json};

use crate::driver::{Directory, Driver, StoreFuture};
use crate::model::DirectoryChange;

#[derive(Debug, Default)]
pub struct MemoryDriver;

impl Driver for MemoryDriver {
    fn name(&self) -> &'static str {
        "memory"
    }
    fn open(&self) -> StoreFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn close(&self) -> StoreFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn load_directory(&self) -> StoreFuture<'_, Option<Directory>> {
        Box::pin(async { Ok(None) })
    }
    fn load_realms(&self) -> StoreFuture<'_, Option<Vec<Json>>> {
        Box::pin(async { Ok(None) })
    }
    fn load_overrides(&self) -> StoreFuture<'_, Option<Map<String, Json>>> {
        Box::pin(async { Ok(None) })
    }
    fn save_directory<'a>(
        &'a self,
        _change: &'a DirectoryChange,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn save_realms<'a>(&'a self, _rows: &'a [Json]) -> StoreFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn save_overrides<'a>(
        &'a self,
        _overrides: &'a Map<String, Json>,
    ) -> StoreFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}
