// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Every standard function, GENERATED over the datatype table where the
//! specification parameterises by type, and written out where it does not.
//!
//! XACML 3.0 defines a little over two hundred function identifiers and they
//! are not two hundred functions: `string-is-in`, `integer-is-in` and twelve
//! more are one function and a table row each. Defining a family once and
//! registering it for every type that has the operation is what stops
//! `string`'s comparison being pasted into `anyURI`'s row.
//!
//! The version segment of an identifier is the SPECIFICATION's and is not
//! uniform — the duration families are entirely `3.0`, the `-from-string`
//! conversions are `3.0`, three of the six higher-order functions are `1.0`
//! — and each place that picks one says why.

use num_bigint::BigInt;
use num_traits::{FromPrimitive, ToPrimitive, Zero};

use super::{
    xml_schema_regex, Arg, Body, FunctionDef, FunctionLibrary, LazyCall, Param,
    ParamKind, Signature,
};
use crate::datatypes::{
    civil_from_days, days_from_civil, x500_equal, DataType, DataTypes,
};
use crate::model::{canonical_type, types, Bag, XacmlError, XacmlResult};
use crate::policy::Expression;
use crate::value::{Temporal, TemporalShape, Value};

const F1: &str = "urn:oasis:names:tc:xacml:1.0:function:";

type OrderTest = fn(std::cmp::Ordering) -> bool;
type IntOp = fn(&BigInt, &BigInt) -> BigInt;
type DoubleOp = fn(f64, f64) -> f64;
type TextTest = fn(&str, &str) -> bool;
const F2: &str = "urn:oasis:names:tc:xacml:2.0:function:";
const F3: &str = "urn:oasis:names:tc:xacml:3.0:function:";

/// Registers the whole standard library.
pub(super) fn register_all(library: &mut FunctionLibrary) {
    register_type_families(library);
    register_logical(library);
    register_arithmetic(library);
    register_strings(library);
    register_conversions(library);
    register_temporal_arithmetic(library);
    register_regex(library);
    register_name_matches(library);
    register_higher_order(library);
    register_xpath(library);
}

// ---------------------------------------------------------------------------
// Builders.
// ---------------------------------------------------------------------------
fn strict<F>(
    uri: String,
    args: Vec<Param>,
    variadic: Option<Param>,
    returns: Param,
    body: F,
) -> FunctionDef
where
    F: Fn(&[Arg<'_>]) -> XacmlResult<Bag> + Send + Sync + 'static,
{
    FunctionDef {
        uri,
        signature: Signature {
            args,
            variadic,
            returns,
        },
        body: Body::Strict(Box::new(body)),
        static_check: None,
    }
}

fn lazy<F>(
    uri: String,
    args: Vec<Param>,
    variadic: Option<Param>,
    returns: Param,
    body: F,
) -> FunctionDef
where
    F: Fn(&LazyCall<'_>) -> XacmlResult<Bag> + Send + Sync + 'static,
{
    FunctionDef {
        uri,
        signature: Signature {
            args,
            variadic,
            returns,
        },
        body: Body::Lazy(Box::new(body)),
        static_check: None,
    }
}

fn mismatch(expected: &str) -> XacmlError {
    XacmlError::processing(format!("expected a {} value", expected))
}

fn text<'a>(arg: &Arg<'a>) -> XacmlResult<&'a str> {
    arg.value()?.as_text().ok_or_else(|| mismatch("string"))
}

fn integer<'a>(arg: &Arg<'a>) -> XacmlResult<&'a BigInt> {
    arg.value()?.as_integer().ok_or_else(|| mismatch("integer"))
}

fn double(arg: &Arg<'_>) -> XacmlResult<f64> {
    arg.value()?.as_double().ok_or_else(|| mismatch("double"))
}

fn int_bag(value: BigInt) -> Bag {
    Bag::singleton(types::INTEGER, Value::Integer(value))
}

fn double_bag(value: f64) -> Bag {
    Bag::singleton(types::DOUBLE, Value::Double(value))
}

fn string_bag(value: String) -> Bag {
    Bag::singleton(types::STRING, Value::String(value))
}

/// One argument of `and`, `or` or `n-of`: exactly one boolean.
fn as_boolean(bag: &Bag, place: &str) -> XacmlResult<bool> {
    if bag.values.len() != 1 {
        return Err(XacmlError::processing(format!(
            "{} requires each argument to be exactly one boolean; it was \
             given a bag of {}.",
            place,
            bag.values.len()
        )));
    }
    if canonical_type(&bag.type_uri) != types::BOOLEAN {
        return Err(XacmlError::processing(format!(
            "{} requires boolean arguments; it was given {}.",
            place, bag.type_uri
        )));
    }
    bag.values[0].as_bool().ok_or_else(|| mismatch("boolean"))
}

/// Whether `values` already holds one EQUAL to `candidate` at the type —
/// "the same value", which is what union, intersection, subset and
/// set-equals are defined over.
fn bag_has(
    row: &dyn DataType,
    values: &[Value],
    candidate: &Value,
) -> XacmlResult<bool> {
    for value in values {
        if row.equal(value, candidate)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The function-name prefix for a type's family: the two duration types are
/// entirely `3.0`, because they were re-issued when they moved out of the
/// XQuery namespace; everything else is `1.0`.
fn family_prefix(uri: &str) -> &'static str {
    if uri == types::DAYTIME_DURATION || uri == types::YEARMONTH_DURATION {
        F3
    } else {
        F1
    }
}

/// Every type but xpathExpression, which has no equality and takes part in
/// no family (A.3.15).
fn family_types() -> Vec<&'static dyn DataType> {
    DataTypes::standard()
        .all()
        .filter(|row| row.uri() != types::XPATH_EXPRESSION)
        .collect()
}

// ---------------------------------------------------------------------------
// The type-parameterised families.
// ---------------------------------------------------------------------------
fn register_type_families(library: &mut FunctionLibrary) {
    for row in family_types() {
        let uri = row.uri();
        let name = |suffix: &str| {
            format!("{}{}-{}", family_prefix(uri), row.name(), suffix)
        };
        let both_primitive =
            || vec![Param::primitive(uri), Param::primitive(uri)];
        let both_bags = || vec![Param::bag(uri), Param::bag(uri)];

        library.define(strict(
            name("equal"),
            both_primitive(),
            None,
            Param::primitive(types::BOOLEAN),
            move |a| Ok(Bag::boolean(row.equal(a[0].value()?, a[1].value()?)?)),
        ));

        if row.is_ordered() {
            let comparisons: [(&str, OrderTest); 4] = [
                ("greater-than", |o| o.is_gt()),
                ("greater-than-or-equal", |o| o.is_ge()),
                ("less-than", |o| o.is_lt()),
                ("less-than-or-equal", |o| o.is_le()),
            ];
            for (suffix, holds) in comparisons {
                library.define(strict(
                    name(suffix),
                    both_primitive(),
                    None,
                    Param::primitive(types::BOOLEAN),
                    move |a| {
                        let order = row
                            .compare(a[0].value()?, a[1].value()?)
                            .ok_or_else(|| {
                            XacmlError::processing(format!(
                                "Two {} values are not comparable: one \
                                     carries a timezone and the other does \
                                     not, and the ordering differs across \
                                     the range a missing timezone could be.",
                                row.name()
                            ))
                        })?;
                        Ok(Bag::boolean(holds(order)))
                    },
                ));
            }
        }

        library.define(strict(
            name("bag"),
            Vec::new(),
            Some(Param::primitive(uri)),
            Param::bag(uri),
            move |a| {
                let values = a
                    .iter()
                    .map(|arg| arg.value().cloned())
                    .collect::<XacmlResult<Vec<Value>>>()?;
                Ok(Bag::new(uri, values))
            },
        ));

        library.define(strict(
            name("bag-size"),
            vec![Param::bag(uri)],
            None,
            Param::primitive(types::INTEGER),
            |a| Ok(int_bag(BigInt::from(a[0].bag()?.values.len()))),
        ));

        library.define(strict(
            name("one-and-only"),
            vec![Param::bag(uri)],
            None,
            Param::primitive(uri),
            move |a| {
                // Nought and two are BOTH errors and different ones: nothing
                // was there, or too much was.
                let contents = &a[0].bag()?.values;
                match contents.len() {
                    1 => Ok(Bag::singleton(uri, contents[0].clone())),
                    0 => Err(XacmlError::missing_attribute(format!(
                        "{}-one-and-only was given an empty bag.",
                        row.name()
                    ))),
                    n => Err(XacmlError::processing(format!(
                        "{}-one-and-only was given a bag of {} values and \
                         requires exactly one.",
                        row.name(),
                        n
                    ))),
                }
            },
        ));

        library.define(strict(
            name("is-in"),
            vec![Param::primitive(uri), Param::bag(uri)],
            None,
            Param::primitive(types::BOOLEAN),
            move |a| {
                Ok(Bag::boolean(bag_has(
                    row,
                    &a[1].bag()?.values,
                    a[0].value()?,
                )?))
            },
        ));

        library.define(strict(
            name("intersection"),
            both_bags(),
            None,
            Param::bag(uri),
            move |a| {
                // The result is a SET: a value already taken is not taken
                // twice, even when the left bag holds it twice.
                let mut result: Vec<Value> = Vec::new();
                for candidate in &a[0].bag()?.values {
                    if bag_has(row, &a[1].bag()?.values, candidate)?
                        && !bag_has(row, &result, candidate)?
                    {
                        result.push(candidate.clone());
                    }
                }
                Ok(Bag::new(uri, result))
            },
        ));

        library.define(strict(
            name("union"),
            both_bags(),
            None,
            Param::bag(uri),
            move |a| {
                let mut result: Vec<Value> = Vec::new();
                for source in a {
                    for candidate in &source.bag()?.values {
                        if !bag_has(row, &result, candidate)? {
                            result.push(candidate.clone());
                        }
                    }
                }
                Ok(Bag::new(uri, result))
            },
        ));

        library.define(strict(
            name("at-least-one-member-of"),
            both_bags(),
            None,
            Param::primitive(types::BOOLEAN),
            move |a| {
                for candidate in &a[0].bag()?.values {
                    if bag_has(row, &a[1].bag()?.values, candidate)? {
                        return Ok(Bag::boolean(true));
                    }
                }
                Ok(Bag::boolean(false))
            },
        ));

        library.define(strict(
            name("subset"),
            both_bags(),
            None,
            Param::primitive(types::BOOLEAN),
            move |a| {
                Ok(Bag::boolean(subset(
                    row,
                    &a[0].bag()?.values,
                    &a[1].bag()?.values,
                )?))
            },
        ));

        library.define(strict(
            name("set-equals"),
            both_bags(),
            None,
            Param::primitive(types::BOOLEAN),
            move |a| {
                // SET equality: two subset tests, not a length check, because
                // {a, a, b} and {a, b} are equal sets.
                let (left, right) = (&a[0].bag()?.values, &a[1].bag()?.values);
                Ok(Bag::boolean(
                    subset(row, left, right)? && subset(row, right, left)?,
                ))
            },
        ));
    }
}

fn subset(
    row: &dyn DataType,
    left: &[Value],
    right: &[Value],
) -> XacmlResult<bool> {
    for candidate in left {
        if !bag_has(row, right, candidate)? {
            return Ok(false);
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Logical functions: three of the ten lazy ones.
// ---------------------------------------------------------------------------
fn register_logical(library: &mut FunctionLibrary) {
    let boolean = || Param::primitive(types::BOOLEAN);

    // A.3.5: evaluation stops at the first False, so `and(false, <missing>)`
    // is False. An empty `and` is True.
    library.define(lazy(
        format!("{}and", F1),
        Vec::new(),
        Some(boolean()),
        boolean(),
        |call| {
            for expression in call.args {
                if !as_boolean(&(call.evaluate)(expression)?, "and")? {
                    return Ok(Bag::boolean(false));
                }
            }
            Ok(Bag::boolean(true))
        },
    ));

    library.define(lazy(
        format!("{}or", F1),
        Vec::new(),
        Some(boolean()),
        boolean(),
        |call| {
            for expression in call.args {
                if as_boolean(&(call.evaluate)(expression)?, "or")? {
                    return Ok(Bag::boolean(true));
                }
            }
            Ok(Bag::boolean(false))
        },
    ));

    library.define(strict(
        format!("{}not", F1),
        vec![boolean()],
        None,
        boolean(),
        |a| {
            let value =
                a[0].value()?.as_bool().ok_or_else(|| mismatch("boolean"))?;
            Ok(Bag::boolean(!value))
        },
    ));

    // Lazy for `and`'s reason: evaluation stops once `n` arguments are true.
    library.define(lazy(
        format!("{}n-of", F1),
        vec![Param::primitive(types::INTEGER)],
        Some(boolean()),
        boolean(),
        |call| {
            let Some(first) = call.args.first() else {
                return Err(XacmlError::processing(
                    "n-of requires at least one argument: the count.",
                ));
            };
            let count = (call.evaluate)(first)?;
            let needed =
                match (count.values.as_slice(), count.type_uri.as_str()) {
                    ([Value::Integer(n)], t)
                        if canonical_type(t) == types::INTEGER =>
                    {
                        n.clone()
                    }
                    _ => {
                        return Err(XacmlError::processing(
                        "n-of's first argument must be exactly one integer.",
                    ));
                    }
                };
            let available = BigInt::from(call.args.len() - 1);
            if needed < BigInt::zero() {
                return Err(XacmlError::processing(format!(
                    "n-of was asked for {} true arguments.",
                    needed
                )));
            }
            if needed > available {
                return Err(XacmlError::processing(format!(
                    "n-of was asked for {} true arguments out of {}, which \
                     cannot be satisfied.",
                    needed, available
                )));
            }
            if needed.is_zero() {
                return Ok(Bag::boolean(true));
            }
            let mut found = BigInt::zero();
            for expression in &call.args[1..] {
                if as_boolean(&(call.evaluate)(expression)?, "n-of")? {
                    found += 1;
                    if found >= needed {
                        return Ok(Bag::boolean(true));
                    }
                }
            }
            Ok(Bag::boolean(false))
        },
    ));
}

// ---------------------------------------------------------------------------
// Arithmetic. Integers are BigInt and doubles IEEE 754, registered
// separately rather than through a shared numeric type that would lose one.
// ---------------------------------------------------------------------------
fn register_arithmetic(library: &mut FunctionLibrary) {
    let int2 = || {
        vec![
            Param::primitive(types::INTEGER),
            Param::primitive(types::INTEGER),
        ]
    };
    let dbl2 = || {
        vec![
            Param::primitive(types::DOUBLE),
            Param::primitive(types::DOUBLE),
        ]
    };
    let int = || Param::primitive(types::INTEGER);
    let dbl = || Param::primitive(types::DOUBLE);

    let int_ops: [(&str, IntOp); 3] = [
        ("integer-add", |a, b| a + b),
        ("integer-subtract", |a, b| a - b),
        ("integer-multiply", |a, b| a * b),
    ];
    for (name, op) in int_ops {
        library.define(strict(
            format!("{}{}", F1, name),
            int2(),
            None,
            int(),
            move |a| Ok(int_bag(op(integer(&a[0])?, integer(&a[1])?))),
        ));
    }
    library.define(strict(
        format!("{}integer-abs", F1),
        vec![int()],
        None,
        int(),
        |a| {
            let v = integer(&a[0])?;
            Ok(int_bag(if *v < BigInt::zero() {
                -v.clone()
            } else {
                v.clone()
            }))
        },
    ));

    let dbl_ops: [(&str, DoubleOp); 3] = [
        ("double-add", |a, b| a + b),
        ("double-subtract", |a, b| a - b),
        ("double-multiply", |a, b| a * b),
    ];
    for (name, op) in dbl_ops {
        library.define(strict(
            format!("{}{}", F1, name),
            dbl2(),
            None,
            dbl(),
            move |a| Ok(double_bag(op(double(&a[0])?, double(&a[1])?))),
        ));
    }
    library.define(strict(
        format!("{}double-abs", F1),
        vec![dbl()],
        None,
        dbl(),
        |a| Ok(double_bag(double(&a[0])?.abs())),
    ));

    // Division by zero is an error (A.3.4), never an Infinity no comparison
    // could do anything sensible with. BigInt division truncates toward
    // zero, as xs:integer division does.
    library.define(strict(
        format!("{}integer-divide", F1),
        int2(),
        None,
        int(),
        |a| {
            let (x, y) = (integer(&a[0])?, integer(&a[1])?);
            if y.is_zero() {
                return Err(XacmlError::processing("integer-divide by zero."));
            }
            Ok(int_bag(x / y))
        },
    ));
    library.define(strict(
        format!("{}double-divide", F1),
        dbl2(),
        None,
        dbl(),
        |a| {
            let (x, y) = (double(&a[0])?, double(&a[1])?);
            if y == 0.0 {
                return Err(XacmlError::processing("double-divide by zero."));
            }
            Ok(double_bag(x / y))
        },
    ));
    library.define(strict(
        format!("{}integer-mod", F1),
        int2(),
        None,
        int(),
        |a| {
            let (x, y) = (integer(&a[0])?, integer(&a[1])?);
            if y.is_zero() {
                return Err(XacmlError::processing("integer-mod by zero."));
            }
            Ok(int_bag(x % y))
        },
    ));

    // xs:double rounding is round-half-to-EVEN: 0.5 is 0 and 2.5 is 2.
    library.define(strict(
        format!("{}round", F1),
        vec![dbl()],
        None,
        dbl(),
        |a| {
            let value = double(&a[0])?;
            if !value.is_finite() {
                return Ok(double_bag(value));
            }
            let floor = value.floor();
            let difference = value - floor;
            let up =
                difference > 0.5 || (difference == 0.5 && floor % 2.0 != 0.0);
            let result = if up { floor + 1.0 } else { floor };
            Ok(double_bag(result))
        },
    ));
    library.define(strict(
        format!("{}floor", F1),
        vec![dbl()],
        None,
        dbl(),
        |a| Ok(double_bag(double(&a[0])?.floor())),
    ));
    // Truncation toward zero, per A.3.4 — not rounding.
    library.define(strict(
        format!("{}double-to-integer", F1),
        vec![dbl()],
        None,
        int(),
        |a| {
            let value = double(&a[0])?;
            BigInt::from_f64(value.trunc()).map(int_bag).ok_or_else(|| {
                XacmlError::processing(format!(
                    "double-to-integer cannot convert {}.",
                    value
                ))
            })
        },
    ));
    library.define(strict(
        format!("{}integer-to-double", F1),
        vec![int()],
        None,
        dbl(),
        |a| Ok(double_bag(integer(&a[0])?.to_f64().unwrap_or(f64::NAN))),
    ));
}

// ---------------------------------------------------------------------------
// String and anyURI operations. The anyURI forms take a STRING needle and an
// anyURI haystack — the specification's asymmetry, which is why these are
// registered explicitly rather than generated.
// ---------------------------------------------------------------------------
fn utf16(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn register_strings(library: &mut FunctionLibrary) {
    let predicates: [(&str, &'static str, TextTest); 6] = [
        ("string-contains", types::STRING, |n, h| h.contains(n)),
        ("string-starts-with", types::STRING, |n, h| h.starts_with(n)),
        ("string-ends-with", types::STRING, |n, h| h.ends_with(n)),
        ("anyURI-contains", types::ANYURI, |n, h| h.contains(n)),
        ("anyURI-starts-with", types::ANYURI, |n, h| h.starts_with(n)),
        ("anyURI-ends-with", types::ANYURI, |n, h| h.ends_with(n)),
    ];
    for (name, haystack_type, holds) in predicates {
        library.define(strict(
            format!("{}{}", F3, name),
            vec![
                Param::primitive(types::STRING),
                Param::primitive(haystack_type),
            ],
            None,
            Param::primitive(types::BOOLEAN),
            move |a| Ok(Bag::boolean(holds(text(&a[0])?, text(&a[1])?))),
        ));
    }

    for (name, subject_type) in [
        ("string-substring", types::STRING),
        ("anyURI-substring", types::ANYURI),
    ] {
        let mut definition = strict(
            format!("{}{}", F3, name),
            vec![
                Param::primitive(subject_type),
                Param::primitive(types::INTEGER),
                Param::primitive(types::INTEGER),
            ],
            None,
            Param::primitive(types::STRING),
            move |a| {
                // Zero-based, `to` may be -1 for "to the end", and an index
                // outside the string is an ERROR rather than a clamped slice
                // (A.3.10). Indices count UTF-16 units, as in the Node
                // engine.
                let subject = utf16(text(&a[0])?);
                let len = subject.len() as i64;
                let from = integer(&a[1])?.to_i64().unwrap_or(i64::MIN);
                let to = integer(&a[2])?.to_i64().unwrap_or(i64::MIN);
                let end = if to == -1 { len } else { to };
                if from < 0
                    || from > len
                    || end > len
                    || (to != -1 && to < from)
                {
                    return Err(XacmlError::processing(format!(
                        "{} was given indices {} and {} for a value of \
                         length {}.",
                        name, from, to, len
                    )));
                }
                let slice = &subject[from as usize..end.max(from) as usize];
                Ok(string_bag(String::from_utf16_lossy(slice)))
            },
        );
        // A LITERAL index out of range is a STATIC error: the policy is
        // refused at load (cases IIC332 and IIC335) rather than going
        // Indeterminate for every request forever.
        definition.static_check =
            Some(Box::new(move |args, report| {
                let from = args.get(1).and_then(literal_integer);
                let to = args.get(2).and_then(literal_integer);
                if let Some(from) = from.filter(|f| *f < 0) {
                    report.push(format!(
                    "{}'s second argument is {}; a substring start index may \
                     not be negative.", name, from));
                }
                if let Some(to) = to.filter(|t| *t < -1) {
                    report.push(format!(
                        "{}'s third argument is {}; a substring end index may \
                     not be below -1 (-1 means \"to the end\").",
                        name, to
                    ));
                }
                if let (Some(from), Some(to)) = (from, to) {
                    if to != -1 && to < from {
                        report.push(format!(
                            "{} was given the range {}..{}, which runs \
                         backwards.",
                            name, from, to
                        ));
                    }
                }
            }));
        library.define(definition);
    }

    // Leading and trailing whitespace only, despite the name.
    library.define(strict(
        format!("{}string-normalize-space", F1),
        vec![Param::primitive(types::STRING)],
        None,
        Param::primitive(types::STRING),
        |a| Ok(string_bag(text(&a[0])?.trim().to_string())),
    ));
    library.define(strict(
        format!("{}string-normalize-to-lower-case", F1),
        vec![Param::primitive(types::STRING)],
        None,
        Param::primitive(types::STRING),
        |a| Ok(string_bag(text(&a[0])?.to_lowercase())),
    ));
    library.define(strict(
        format!("{}string-concatenate", F3),
        Vec::new(),
        Some(Param::primitive(types::STRING)),
        Param::primitive(types::STRING),
        |a| {
            let mut out = String::new();
            for arg in a {
                out.push_str(text(arg)?);
            }
            Ok(string_bag(out))
        },
    ));
}

/// A literal integer argument, or `None` when it is not a literal — a range
/// rule is checkable at load exactly when the value is written into the
/// policy.
fn literal_integer(expression: &Expression) -> Option<i64> {
    let Expression::Value(value) = expression else {
        return None;
    };
    if canonical_type(&value.type_uri) != types::INTEGER {
        return None;
    }
    let text = value.lexical.trim();
    let digits = text.strip_prefix('+').unwrap_or(text);
    if digits.trim_start_matches('-').is_empty()
        || !digits
            .trim_start_matches('-')
            .chars()
            .all(|c| c.is_ascii_digit())
    {
        return None;
    }
    digits.parse().ok()
}

/// The `-from-string` and `string-from-` pair for every type: the datatype
/// table's own parse and write, so `integer-from-string` and an
/// `<AttributeValue>` of the same lexical form cannot disagree.
fn register_conversions(library: &mut FunctionLibrary) {
    for row in family_types() {
        let uri = row.uri();
        library.define(strict(
            format!("{}string-from-{}", F3, row.name()),
            vec![Param::primitive(uri)],
            None,
            Param::primitive(types::STRING),
            move |a| Ok(string_bag(row.write(a[0].value()?))),
        ));
        library.define(strict(
            format!("{}{}-from-string", F3, row.name()),
            vec![Param::primitive(types::STRING)],
            None,
            Param::primitive(uri),
            move |a| Ok(Bag::singleton(uri, row.parse(text(&a[0])?)?)),
        ));
    }
}

// ---------------------------------------------------------------------------
// Date and time arithmetic. On the LOCAL components with the timezone
// carried through unchanged: `2002-03-22T08:23:47-05:00` plus `P5DT2H` is
// `2002-03-27T10:23:47-05:00` (cases IIC102, IIC104). A month added to the
// 31st CLAMPS to the last day of the target month.
// ---------------------------------------------------------------------------
fn days_in_month(year: i64, month: i64) -> i64 {
    const LENGTHS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    if month == 2 && leap {
        29
    } else {
        LENGTHS[(month - 1).clamp(0, 11) as usize]
    }
}

pub(crate) fn add_months(value: &Temporal, months: i64) -> Temporal {
    let total = value.year * 12 + (value.month - 1) + months;
    let year = total.div_euclid(12);
    let month = total.rem_euclid(12) + 1;
    let day = value.day.min(days_in_month(year, month));
    Temporal {
        year,
        month,
        day,
        ..value.clone()
    }
}

fn add_seconds(value: &Temporal, seconds: f64) -> Temporal {
    let date_part = if value.shape == TemporalShape::Time {
        0.0
    } else {
        (days_from_civil(value.year, value.month, value.day) * 86400) as f64
    };
    let local = date_part
        + (value.hour * 3600 + value.minute * 60) as f64
        + value.second;
    let total = local + seconds;
    let days = (total / 86400.0).floor();
    let mut rest = total - days * 86400.0;
    let hour = (rest / 3600.0).floor();
    rest -= hour * 3600.0;
    let minute = (rest / 60.0).floor();
    let second = rest - minute * 60.0;
    let (year, month, day) = civil_from_days(days as i64);
    Temporal {
        shape: value.shape,
        year,
        month,
        day,
        hour: hour as i64,
        minute: minute as i64,
        second,
        tz: value.tz,
    }
}

fn register_temporal_arithmetic(library: &mut FunctionLibrary) {
    let rows: [(&str, &'static str, &'static str, i64); 6] = [
        (
            "dateTime-add-dayTimeDuration",
            types::DATETIME,
            types::DAYTIME_DURATION,
            1,
        ),
        (
            "dateTime-subtract-dayTimeDuration",
            types::DATETIME,
            types::DAYTIME_DURATION,
            -1,
        ),
        (
            "dateTime-add-yearMonthDuration",
            types::DATETIME,
            types::YEARMONTH_DURATION,
            1,
        ),
        (
            "dateTime-subtract-yearMonthDuration",
            types::DATETIME,
            types::YEARMONTH_DURATION,
            -1,
        ),
        (
            "date-add-yearMonthDuration",
            types::DATE,
            types::YEARMONTH_DURATION,
            1,
        ),
        (
            "date-subtract-yearMonthDuration",
            types::DATE,
            types::YEARMONTH_DURATION,
            -1,
        ),
    ];
    for (name, subject_type, duration_type, sign) in rows {
        library.define(strict(
            format!("{}{}", F3, name),
            vec![
                Param::primitive(subject_type),
                Param::primitive(duration_type),
            ],
            None,
            Param::primitive(subject_type),
            move |a| {
                let subject = a[0]
                    .value()?
                    .as_temporal()
                    .ok_or_else(|| mismatch("date or dateTime"))?;
                let result = match a[1].value()? {
                    Value::YearMonthDuration(months) => {
                        add_months(subject, sign * months)
                    }
                    Value::DayTimeDuration(seconds) => {
                        add_seconds(subject, sign as f64 * seconds)
                    }
                    _ => return Err(mismatch("duration")),
                };
                Ok(Bag::singleton(subject_type, Value::Temporal(result)))
            },
        ));
    }
}

// ---------------------------------------------------------------------------
// Regular expressions (see `xsd_regex.rs`), and the two special matches.
// ---------------------------------------------------------------------------
fn register_regex(library: &mut FunctionLibrary) {
    let rows: [(&str, &'static str); 6] = [
        ("string-regexp-match", types::STRING),
        ("anyURI-regexp-match", types::ANYURI),
        ("rfc822Name-regexp-match", types::RFC822NAME),
        ("x500Name-regexp-match", types::X500NAME),
        ("dnsName-regexp-match", types::DNSNAME),
        ("ipAddress-regexp-match", types::IPADDRESS),
    ];
    for (name, subject_type) in rows {
        let prefix = if subject_type == types::STRING {
            F1
        } else {
            F2
        };
        library.define(strict(
            format!("{}{}", prefix, name),
            vec![
                Param::primitive(types::STRING),
                Param::primitive(subject_type),
            ],
            None,
            Param::primitive(types::BOOLEAN),
            move |a| {
                let expression = xml_schema_regex(text(&a[0])?)?;
                let subject =
                    DataTypes::standard().write(subject_type, a[1].value()?)?;
                Ok(Bag::boolean(expression.is_match(&subject)))
            },
        ));
    }
}

fn register_name_matches(library: &mut FunctionLibrary) {
    // A.3.14: three shapes of pattern. A whole address (local part exact,
    // domain folded); `.acme.com`, meaning strictly BELOW acme.com; or a
    // bare domain, which must equal the value's.
    library.define(strict(
        format!("{}rfc822Name-match", F1),
        vec![
            Param::primitive(types::STRING),
            Param::primitive(types::RFC822NAME),
        ],
        None,
        Param::primitive(types::BOOLEAN),
        |a| {
            let pattern = text(&a[0])?;
            let Value::Rfc822Name { local, domain } = a[1].value()? else {
                return Err(mismatch("rfc822Name"));
            };
            let matched = if let Some(at) = pattern.rfind('@') {
                &pattern[..at] == local
                    && pattern[at + 1..].to_lowercase() == *domain
            } else if pattern.starts_with('.') {
                domain.ends_with(&pattern.to_lowercase())
            } else {
                *domain == pattern.to_lowercase()
            };
            Ok(Bag::boolean(matched))
        },
    ));

    // A.3.13: the first name is a terminal sequence of the second — an
    // ancestor of, or equal to, it in the directory tree.
    library.define(strict(
        format!("{}x500Name-match", F1),
        vec![
            Param::primitive(types::X500NAME),
            Param::primitive(types::X500NAME),
        ],
        None,
        Param::primitive(types::BOOLEAN),
        |a| {
            let (Value::X500Name(pattern), Value::X500Name(subject)) =
                (a[0].value()?, a[1].value()?)
            else {
                return Err(mismatch("x500Name"));
            };
            if pattern.len() > subject.len() {
                return Ok(Bag::boolean(false));
            }
            let tail = &subject[subject.len() - pattern.len()..];
            Ok(Bag::boolean(x500_equal(pattern, tail)))
        },
    ));
}

// ---------------------------------------------------------------------------
// The higher-order functions. `all-of-any` quantifies ALL over the FIRST
// bag; `any-of-all` is its mirror. The names read backwards from what they
// do, and these two are the pair that gets swapped.
// ---------------------------------------------------------------------------
fn function_reference<'a>(
    call: &LazyCall<'a>,
    place: &str,
) -> XacmlResult<&'a FunctionDef> {
    let Some(Expression::Function(id)) = call.args.first() else {
        return Err(XacmlError::processing(format!(
            "{} requires a <Function> as its first argument.",
            place
        )));
    };
    call.library.get(id).ok_or_else(|| {
        XacmlError::processing(format!(
            "Unknown function \"{}\" passed to {}.",
            id, place
        ))
    })
}

/// Applies a function to two single values and insists on one boolean.
fn apply_pair(
    library: &FunctionLibrary,
    definition: &FunctionDef,
    left: (&str, &Value),
    right: (&str, &Value),
) -> XacmlResult<bool> {
    let result = library.invoke(
        definition,
        &[
            Bag::singleton(left.0, left.1.clone()),
            Bag::singleton(right.0, right.1.clone()),
        ],
    )?;
    as_boolean(&result, &definition.uri)
}

fn evaluated_bags(call: &LazyCall<'_>) -> XacmlResult<Vec<Bag>> {
    call.args[1..].iter().map(|e| (call.evaluate)(e)).collect()
}

fn two_bags(call: &LazyCall<'_>, place: &str) -> XacmlResult<(Bag, Bag)> {
    let mut bags = evaluated_bags(call)?;
    if bags.len() != 2 {
        return Err(XacmlError::processing(format!(
            "{} takes a function and two arguments.",
            place
        )));
    }
    let second = bags.remove(1);
    Ok((bags.remove(0), second))
}

/// Short-circuiting `any` and `all` over a fallible predicate, matching the
/// Node engine's `some` / `every`: the first error stops the walk.
fn any_of<T>(
    items: &[T],
    mut test: impl FnMut(&T) -> XacmlResult<bool>,
) -> XacmlResult<bool> {
    for item in items {
        if test(item)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn all_of<T>(
    items: &[T],
    mut test: impl FnMut(&T) -> XacmlResult<bool>,
) -> XacmlResult<bool> {
    for item in items {
        if !test(item)? {
            return Ok(false);
        }
    }
    Ok(true)
}

type Combine =
    fn(&FunctionLibrary, &FunctionDef, &Bag, &Bag) -> XacmlResult<bool>;

fn register_higher_order(library: &mut FunctionLibrary) {
    // `any-of`, `all-of` and `any-of-any` are 3.0; the other three existed in
    // 1.0 and kept that segment.
    let rows: [(&str, &str, Combine); 6] = [
        (F3, "any-of", |l, d, a, b| one_against_bag(l, d, a, b, true)),
        (F3, "all-of", |l, d, a, b| {
            one_against_bag(l, d, a, b, false)
        }),
        (F3, "any-of-any", |l, d, a, b| {
            any_of(&a.values, |x| {
                any_of(&b.values, |y| {
                    apply_pair(l, d, (&a.type_uri, x), (&b.type_uri, y))
                })
            })
        }),
        (F1, "all-of-all", |l, d, a, b| {
            all_of(&a.values, |x| {
                all_of(&b.values, |y| {
                    apply_pair(l, d, (&a.type_uri, x), (&b.type_uri, y))
                })
            })
        }),
        // For EVERY member of the first bag, SOME member of the second.
        (F1, "all-of-any", |l, d, a, b| {
            all_of(&a.values, |x| {
                any_of(&b.values, |y| {
                    apply_pair(l, d, (&a.type_uri, x), (&b.type_uri, y))
                })
            })
        }),
        // For EVERY member of the SECOND bag, SOME member of the first.
        (F1, "any-of-all", |l, d, a, b| {
            all_of(&b.values, |y| {
                any_of(&a.values, |x| {
                    apply_pair(l, d, (&a.type_uri, x), (&b.type_uri, y))
                })
            })
        }),
    ];
    for (prefix, name, combine) in rows {
        // The two value parameters are `Any`: XACML 3.0 lets `any-of` take
        // its bag either way round, and a stricter declaration would REFUSE
        // a legal policy at load.
        library.define(lazy(
            format!("{}{}", prefix, name),
            vec![
                Param::untyped(ParamKind::Function),
                Param::untyped(ParamKind::Any),
                Param::untyped(ParamKind::Any),
            ],
            None,
            Param::primitive(types::BOOLEAN),
            move |call| {
                let definition = function_reference(call, name)?;
                let (a, b) = two_bags(call, name)?;
                Ok(Bag::boolean(combine(call.library, definition, &a, &b)?))
            },
        ));
    }

    library.define(lazy(
        format!("{}map", F3),
        vec![
            Param::untyped(ParamKind::Function),
            Param::untyped(ParamKind::Bag),
        ],
        None,
        // A bag of whatever the mapped function returns, which this
        // declaration cannot name.
        Param::untyped(ParamKind::Bag),
        |call| {
            let definition = function_reference(call, "map")?;
            let mut bags = evaluated_bags(call)?;
            let Some(target) = bags.pop() else {
                return Err(XacmlError::processing(
                    "map takes a function and a bag.",
                ));
            };
            // The LAST bag is mapped over; earlier ones are passed through
            // to every application.
            let mut result_type: Option<String> = None;
            let mut values = Vec::with_capacity(target.values.len());
            for candidate in &target.values {
                let mut args = bags.clone();
                args.push(Bag::singleton(&target.type_uri, candidate.clone()));
                let produced = call.library.invoke(definition, &args)?;
                if produced.values.len() != 1 {
                    return Err(XacmlError::processing(format!(
                        "map expects its function to produce exactly one \
                         value per member; {} produced {}.",
                        definition.uri,
                        produced.values.len()
                    )));
                }
                result_type = Some(produced.type_uri.clone());
                values.extend(produced.values);
            }
            let type_uri = result_type
                .or_else(|| definition.signature.returns.type_uri.clone())
                .unwrap_or_else(|| target.type_uri.clone());
            Ok(Bag::new(&type_uri, values))
        },
    ));
}

/// `any-of` and `all-of`: one value against a bag, either way round —
/// whichever argument is not a bag of one is the bag.
fn one_against_bag(
    library: &FunctionLibrary,
    definition: &FunctionDef,
    first: &Bag,
    second: &Bag,
    any: bool,
) -> XacmlResult<bool> {
    let value_first = first.values.len() == 1 && second.values.len() != 1;
    let (single, many) = if value_first {
        (first, second)
    } else {
        (second, first)
    };
    let Some(one) = single.values.first() else {
        return Err(XacmlError::processing(
            "any-of and all-of need a single value against a bag.",
        ));
    };
    // The Node engine applies the function to EVERY member before
    // quantifying, so an error on any member is the result even when an
    // earlier one already settled it. Kept, for identical answers.
    let mut results = Vec::with_capacity(many.values.len());
    for candidate in &many.values {
        let (left, right) = if value_first {
            (
                (single.type_uri.as_str(), one),
                (many.type_uri.as_str(), candidate),
            )
        } else {
            (
                (many.type_uri.as_str(), candidate),
                (single.type_uri.as_str(), one),
            )
        };
        results.push(apply_pair(library, definition, left, right)?);
    }
    Ok(if any {
        results.iter().any(|r| *r)
    } else {
        results.iter().all(|r| *r)
    })
}

/// `xpath-node-count` needs the request's `<Content>`, and no XPath is
/// evaluated by this crate (as in the Node engine). It refuses rather than
/// answering 0, which is an ordinary count that would make every XPath
/// policy quietly evaluate against an empty document.
fn register_xpath(library: &mut FunctionLibrary) {
    library.define(strict(
        format!("{}xpath-node-count", F3),
        vec![Param::primitive(types::XPATH_EXPRESSION)],
        None,
        Param::primitive(types::INTEGER),
        |_| {
            Err(XacmlError::processing(
                "This PDP has no XPath support wired up, so xpath-node-count \
                 and AttributeSelector cannot be evaluated.",
            ))
        },
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_addition_clamps() {
        let jan31 = Temporal {
            shape: TemporalShape::Date,
            year: 2024,
            month: 1,
            day: 31,
            hour: 0,
            minute: 0,
            second: 0.0,
            tz: None,
        };
        let feb = add_months(&jan31, 1);
        assert_eq!((feb.year, feb.month, feb.day), (2024, 2, 29));
        let back = add_months(&jan31, -2);
        assert_eq!((back.year, back.month, back.day), (2023, 11, 30));
    }

    #[test]
    fn boolean_has_no_ordering_functions() {
        let library = FunctionLibrary::standard();
        assert!(library
            .get(&format!("{}boolean-greater-than", F1))
            .is_none());
        assert!(library
            .get(&format!("{}integer-greater-than", F1))
            .is_some());
        assert!(library
            .get(&format!("{}dayTimeDuration-equal", F3))
            .is_some());
    }
}
