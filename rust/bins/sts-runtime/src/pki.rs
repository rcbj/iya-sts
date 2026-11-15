// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The certificate authority in the runtime (#444 phase 6): `common/pki.js`
//! started over the store, `pki/pki_service.ts`'s routes on the main port
//! and on the plain-HTTP revocation listener (`pki.httpPort`).
//!
//! **WHERE THE ROWS LIVE.** Where key material persists (product, a
//! store, a key-encryption key) the `pki:<scope>` rows are the keystore's,
//! read at the store's start and SEALED back by [`StoreRows`] in the order
//! they were attached — merged under the row's lock where the driver merges
//! (`sts-pki`'s `pki_merge.js` port) — so a hierarchy a 1.x Node install
//! stored is the one this runtime issues under, and Node reads what it
//! writes. Anywhere else the hierarchy is this process's memory and is
//! built at every start, as Node's is in development.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Body;
use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::get;
use serde_json::Value as Json;
use sts_core::mode::Mode;
use sts_core::settings::Settings;
use sts_pki::authority::merge;
use sts_pki::authority::surface::{self, Answer};
use sts_pki::authority::{Authority, MemoryRows, PkiConfig, RowStore};
use sts_store::key_sets::KeySets;

/// The rows held here, written to the keystore behind.
pub struct StoreRows {
    sets: Arc<KeySets>,
    held: Mutex<BTreeMap<String, Json>>,
    /// Attachments in order, one writer: a later attach of a scope never
    /// lands before an earlier one.
    queue: tokio::sync::mpsc::UnboundedSender<(String, Option<Json>, u64)>,
    generation: Mutex<BTreeMap<String, u64>>,
}

impl StoreRows {
    /// Holds what the keystore read and starts the writer.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(sets: Arc<KeySets>) -> Arc<StoreRows> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(
            String,
            Option<Json>,
            u64,
        )>();
        let mut held = BTreeMap::new();
        for scope in sets.pki_scopes() {
            if let Some(row) = sets
                .pki_row_exact(&scope)
                .filter(|r| r.as_object().is_some_and(|o| !o.is_empty()))
            {
                held.insert(scope, row);
            }
        }
        let rows = Arc::new(StoreRows {
            sets: sets.clone(),
            held: Mutex::new(held),
            queue: tx,
            generation: Mutex::new(BTreeMap::new()),
        });
        let weak = Arc::downgrade(&rows);
        tokio::spawn(async move {
            while let Some((scope, row, generation)) = rx.recv().await {
                let mut mine = row.clone();
                if let Some(m) = mine.as_mut() {
                    // A row may not publish a certificate its own CRL
                    // calls revoked (`dropRevocationsOfLiveTiers()`).
                    let dropped = merge::live_again(m);
                    if !dropped.is_empty() {
                        tracing::warn!(
                            "{}keystore: the \"{}\" certificate authority listed {} certificate(s) it \
                             still PUBLISHES as revoked; the revocation(s) were dropped rather than \
                             written.",
                            sts_core::log::tag(
                                sts_core::errors::codes::STS_KEYS_0069
                            ),
                            scope,
                            dropped.len()
                        );
                    }
                }
                let now = sts_core::time::now_ms_f64() as i64;
                let decided = sets
                    .write_pki(
                        &scope,
                        mine,
                        Box::new(move |base, mine, theirs| {
                            merge::merge(
                                base.as_ref(),
                                &mine,
                                theirs.as_ref(),
                                now,
                            )
                            .row
                        }),
                    )
                    .await;
                let Some(rows) = weak.upgrade() else {
                    break;
                };
                match decided {
                    Ok(stored) => {
                        // THE STORE'S ROW IS THE ONE HELD, unless this
                        // process attached something newer meanwhile.
                        let newest = rows
                            .generation
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .get(&scope)
                            .copied()
                            == Some(generation);
                        if newest {
                            let mut held = rows
                                .held
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner);
                            match stored {
                                Some(r) => {
                                    held.insert(scope, r);
                                }
                                None => {
                                    held.remove(&scope);
                                }
                            }
                        }
                    }
                    Err(e) => tracing::error!("{}", e),
                }
            }
        });
        rows
    }
}

impl RowStore for StoreRows {
    fn get(&self, scope: &str) -> Option<Json> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(scope)
            .cloned()
    }

    fn attach(&self, scope: &str, row: Option<&Json>) {
        {
            let mut held =
                self.held.lock().unwrap_or_else(PoisonError::into_inner);
            match row {
                Some(r) => {
                    held.insert(scope.to_string(), r.clone());
                }
                None => {
                    held.remove(scope);
                }
            }
        }
        let generation = {
            let mut g = self
                .generation
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let n = g.get(scope).copied().unwrap_or(0) + 1;
            g.insert(scope.to_string(), n);
            n
        };
        if self
            .queue
            .send((scope.to_string(), row.cloned(), generation))
            .is_err()
        {
            tracing::error!(
                "{}keystore: the \"{}\" realm's certificate authority CANNOT BE WRITTEN — the writer \
                 has stopped.",
                sts_core::log::tag(sts_core::errors::codes::STS_KEYS_0041),
                scope
            );
        }
    }

    fn scopes(&self) -> Vec<String> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }

    fn persists(&self) -> bool {
        self.sets.durable()
    }
}

/// The authority over the stack's keystore, or over memory.
#[tracing::instrument(level = "debug", skip_all)]
pub fn authority(
    settings: &Settings,
    mode: &Mode,
    sets: Option<Arc<KeySets>>,
    realm_domains: Vec<(String, String)>,
) -> Arc<Authority> {
    let mut config = PkiConfig::from_settings(settings, mode);
    for (id, domain) in realm_domains {
        config
            .distribution
            .realm_base_dns
            .insert(id, sts_pki::authority::config::base_dn_of_domain(&domain));
    }
    let rows: Arc<dyn RowStore> = match sets.filter(|s| s.durable()) {
        Some(sets) => StoreRows::new(sets),
        None => Arc::new(MemoryRows::new()),
    };
    Authority::new(rows, config)
}

/// An answer as axum sends it, its code marked for the log.
fn respond(answer: Answer) -> Response {
    let mut response = Response::new(Body::from(answer.body));
    *response.status_mut() =
        StatusCode::from_u16(answer.status).unwrap_or(StatusCode::OK);
    for (name, value) in answer.headers {
        if let Ok(v) = HeaderValue::from_str(&value) {
            response.headers_mut().insert(name, v);
        }
    }
    match answer.code {
        Some(code) => sts_http::mark(response, code),
        None => response,
    }
}

/// `registerRoutes()`: the five public paths, no gate.
#[tracing::instrument(level = "debug", skip_all)]
pub fn routes(
    authority: Arc<Authority>,
    publish_to_directory: bool,
) -> axum::Router {
    let a = authority;
    let (crl, cer, bare, post, tail, index) =
        (a.clone(), a.clone(), a.clone(), a.clone(), a.clone(), a);
    axum::Router::new()
        .route(
            "/pki/crl/{scope}/{ca}",
            get(move |Path((scope, ca)): Path<(String, String)>| {
                let a = crl.clone();
                async move {
                    respond(
                        tokio::task::spawn_blocking(move || {
                            surface::crl_for(&a, &scope, &ca)
                        })
                        .await
                        .unwrap_or_else(|e| internal(&e.to_string())),
                    )
                }
            }),
        )
        .route(
            "/pki/ca/{scope}/{ca}",
            get(move |Path((scope, ca)): Path<(String, String)>| {
                let a = cer.clone();
                async move { respond(surface::ca_certificate_for(&a, &scope, &ca)) }
            }),
        )
        .route(
            "/pki/ocsp/{scope}/{ca}",
            get(move |Path((scope, ca)): Path<(String, String)>| {
                let a = bare.clone();
                async move { respond(surface::ocsp_bare_get(&a, &scope, &ca)) }
            })
            .post(
                move |Path((scope, ca)): Path<(String, String)>,
                      body: axum::body::Bytes| {
                    let a = post.clone();
                    async move {
                        respond(
                            tokio::task::spawn_blocking(move || {
                                surface::ocsp_post(&a, &scope, &ca, &body)
                            })
                            .await
                            .unwrap_or_else(|e| internal(&e.to_string())),
                        )
                    }
                },
            ),
        )
        .route(
            "/pki/ocsp/{scope}/{ca}/{*request}",
            get(
                move |Path((scope, ca, request)): Path<(
                    String,
                    String,
                    String,
                )>| {
                    let a = tail.clone();
                    async move {
                        respond(
                            tokio::task::spawn_blocking(move || {
                                surface::ocsp_get(&a, &scope, &ca, &request)
                            })
                            .await
                            .unwrap_or_else(|e| internal(&e.to_string())),
                        )
                    }
                },
            ),
        )
        .route(
            "/pki/revocation",
            get(move || {
                let a = index.clone();
                async move {
                    respond(surface::revocation_index(&a, publish_to_directory))
                }
            }),
        )
}

fn internal(why: &str) -> Answer {
    Answer {
        status: 500,
        headers: vec![(
            "Content-Type",
            "text/plain; charset=utf-8".to_string(),
        )],
        body: format!("{}\n", why).into_bytes(),
        code: Some(sts_core::errors::codes::STS_PKI_0069),
    }
}

/// The plain-HTTP revocation listener (`listen()`): the `/pki/` paths,
/// SCEP and `/healthcheck` of the router given, anything else refused.
#[tracing::instrument(level = "debug", skip_all)]
pub fn revocation_listener(router: axum::Router) -> axum::Router {
    router.layer(axum::middleware::from_fn(
        |request: axum::extract::Request, next: axum::middleware::Next| async move {
            if surface::revocation_listener_serves(request.uri().path()) {
                next.run(request).await
            } else {
                respond(surface::revocation_only_refusal())
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use std::collections::HashMap;

    use axum::http::Request;
    use serde_json::json;
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn the_public_surface_answers_from_the_hierarchy() {
        let settings = Arc::new(Settings::new(json!({}), HashMap::new()));
        let mode = Mode::new(settings.clone());
        let a = authority(&settings, &mode, None, Vec::new());
        let started = a.start(&[]);
        assert!(started.built, "{:?}", started);
        let router = revocation_listener(routes(a, false));
        let call = |path: &str| Request::get(path).body(Body::empty()).unwrap();
        let r = router
            .clone()
            .oneshot(call("/pki/crl/service/root.crl"))
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["content-type"], "application/pkix-crl");
        let r = router
            .clone()
            .oneshot(call("/pki/ca/default/acme.cer"))
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let r = router
            .clone()
            .oneshot(call("/pki/ocsp/default/acme"))
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
        let r = router
            .clone()
            .oneshot(call("/pki/crl/default/nope.crl"))
            .await
            .unwrap();
        assert_eq!(r.status(), 404);
        let r = router
            .clone()
            .oneshot(call("/pki/revocation"))
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let r = router.oneshot(call("/oauth2/token")).await.unwrap();
        assert_eq!(r.status(), 404);
        assert_eq!(
            sts_http::code_of(&r),
            Some(sts_core::errors::codes::STS_PKI_0134)
        );
    }
}
