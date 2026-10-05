// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The standard function library: its signatures, and the one place a
//! function is invoked. A port of `xacml/xacml_functions.js`; the
//! definitions themselves are in `standard.rs`.
//!
//! **Every value is a bag.** A parameter is declared `Primitive` (the bag
//! MUST hold exactly one value, which the function is handed) or `Bag` (the
//! function is handed the whole bag). [`FunctionLibrary::invoke`] enforces
//! that in ONE place, so a definition never sees an unchecked argument and
//! cannot quietly use the first of two values.
//!
//! **Ten functions are lazy.** `and`, `or` and `n-of` short-circuit — so
//! `and(false, <missing attribute>)` is False, not Indeterminate — and the
//! six higher-order functions and `map` take a FUNCTION as their first
//! argument. A lazy definition receives the unevaluated argument expressions
//! and a way to evaluate them ([`LazyCall`]).

mod standard;
mod xsd_regex;

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::model::{Bag, XacmlError, XacmlResult};
use crate::policy::Expression;
use crate::value::Value;

pub use xsd_regex::xml_schema_regex;

/// What a parameter (or a return) is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    /// Exactly one value.
    Primitive,
    /// A whole bag.
    Bag,
    /// A `<Function>` reference (higher-order functions only).
    Function,
    /// Either, where the SPECIFICATION allows both (`any-of` takes its bag
    /// either way round). Never used to avoid stating an inconvenient type.
    Any,
}

/// A parameter or return declaration. A `None` type means "of some type
/// that cannot be named here" — `map`'s result — which is a different answer
/// from "any type is fine".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub kind: ParamKind,
    pub type_uri: Option<String>,
}

impl Param {
    pub fn primitive(type_uri: &str) -> Param {
        Param {
            kind: ParamKind::Primitive,
            type_uri: Some(type_uri.into()),
        }
    }

    pub fn bag(type_uri: &str) -> Param {
        Param {
            kind: ParamKind::Bag,
            type_uri: Some(type_uri.into()),
        }
    }

    pub fn untyped(kind: ParamKind) -> Param {
        Param {
            kind,
            type_uri: None,
        }
    }
}

/// A function's declared shape, read by the PDP to unwrap arguments and by
/// the validator to typecheck a policy before any request arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub args: Vec<Param>,
    pub variadic: Option<Param>,
    pub returns: Param,
}

/// A resolved argument of a strict function.
#[derive(Debug, Clone, Copy)]
pub enum Arg<'a> {
    Value(&'a Value),
    Bag(&'a Bag),
}

impl<'a> Arg<'a> {
    /// The one value of a primitive parameter. A definition only ever asks
    /// this of a parameter it declared primitive, so a `None` here is a
    /// declaration out of step with its body and is reported as such.
    pub fn value(&self) -> XacmlResult<&'a Value> {
        match self {
            Arg::Value(v) => Ok(v),
            Arg::Bag(_) => Err(XacmlError::processing(
                "a function read a bag parameter as a single value",
            )),
        }
    }

    pub fn bag(&self) -> XacmlResult<&'a Bag> {
        match self {
            Arg::Bag(b) => Ok(b),
            Arg::Value(_) => Err(XacmlError::processing(
                "a function read a single-value parameter as a bag",
            )),
        }
    }
}

/// What a lazy function is handed instead of resolved bags.
pub struct LazyCall<'a> {
    /// The unevaluated argument expressions.
    pub args: &'a [Expression],
    /// Evaluates one of them in the caller's context.
    pub evaluate: &'a dyn Fn(&Expression) -> XacmlResult<Bag>,
    /// The library, for the higher-order functions to apply another
    /// function through.
    pub library: &'a FunctionLibrary,
}

type StrictBody = Box<dyn Fn(&[Arg<'_>]) -> XacmlResult<Bag> + Send + Sync>;
type LazyBody = Box<dyn Fn(&LazyCall<'_>) -> XacmlResult<Bag> + Send + Sync>;
type StaticCheck = Box<dyn Fn(&[Expression], &mut Vec<String>) + Send + Sync>;

/// How a function runs.
pub enum Body {
    Strict(StrictBody),
    Lazy(LazyBody),
}

/// One function: its identifier, its signature, its body and — for the
/// constraints that are about a literal's VALUE rather than its type (a
/// substring index written into the policy) — a load-time check.
pub struct FunctionDef {
    pub uri: String,
    pub signature: Signature,
    pub body: Body,
    pub static_check: Option<StaticCheck>,
}

impl FunctionDef {
    pub fn is_lazy(&self) -> bool {
        matches!(self.body, Body::Lazy(_))
    }
}

/// The library: every standard function, by identifier.
pub struct FunctionLibrary {
    by_uri: HashMap<String, FunctionDef>,
}

static STANDARD: LazyLock<FunctionLibrary> = LazyLock::new(|| {
    let mut library = FunctionLibrary {
        by_uri: HashMap::new(),
    };
    standard::register_all(&mut library);
    library
});

impl FunctionLibrary {
    /// The standard library, built once.
    pub fn standard() -> &'static FunctionLibrary {
        &STANDARD
    }

    fn define(&mut self, definition: FunctionDef) {
        self.by_uri.insert(definition.uri.clone(), definition);
    }

    pub fn get(&self, uri: &str) -> Option<&FunctionDef> {
        self.by_uri.get(uri)
    }

    /// Every identifier, sorted.
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> =
            self.by_uri.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Invokes a strict function with already-evaluated argument bags. This
    /// is where the primitive/bag distinction is enforced: a primitive
    /// parameter given a bag of nought or of two is Indeterminate.
    pub fn invoke(
        &self,
        definition: &FunctionDef,
        bags: &[Bag],
    ) -> XacmlResult<Bag> {
        let body = match &definition.body {
            Body::Strict(body) => body,
            Body::Lazy(_) => {
                return Err(XacmlError::processing(format!(
                    "{} cannot be applied to evaluated arguments here.",
                    definition.uri
                )));
            }
        };
        let declared = &definition.signature.args;
        let variadic = definition.signature.variadic.as_ref();
        if variadic.is_none() && bags.len() != declared.len() {
            return Err(XacmlError::processing(format!(
                "{} takes {} argument(s) and was given {}.",
                definition.uri,
                declared.len(),
                bags.len()
            )));
        }
        if variadic.is_some() && bags.len() < declared.len() {
            return Err(XacmlError::processing(format!(
                "{} takes at least {} argument(s) and was given {}.",
                definition.uri,
                declared.len(),
                bags.len()
            )));
        }
        let mut resolved = Vec::with_capacity(bags.len());
        for (index, bag) in bags.iter().enumerate() {
            let declaration = declared.get(index).or(variadic);
            let kind = declaration.map_or(ParamKind::Primitive, |d| d.kind);
            if kind == ParamKind::Bag {
                resolved.push(Arg::Bag(bag));
                continue;
            }
            if bag.values.len() != 1 {
                return Err(XacmlError::processing(format!(
                    "{} expects exactly one value for argument {} and was \
                     given a bag of {}.",
                    definition.uri,
                    index + 1,
                    bag.values.len()
                )));
            }
            resolved.push(Arg::Value(&bag.values[0]));
        }
        body(&resolved)
    }
}
