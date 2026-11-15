// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! ONE LIST'S PAGING (`admin-core/admin_views.ts`'s `pagingOf()` and
//! `pagingJson()`): the page, the rows per page — capped, and shared by
//! every list of a reply through `per` — and the offset, from the query; and
//! the members a reply publishes for it. A page carrying several lists names
//! each one's page parameter after the list (`certificatesPage`).

use serde_json::{json, Value as Json};

use crate::request::Query;

/// `DEFAULT_PER_PAGE`.
pub const DEFAULT_PER_PAGE: i64 = 50;

/// `MAX_ROWS`: the most rows any list draws on one page.
pub const MAX_ROWS: i64 = 300;

/// `pagingOf()`'s options.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options<'a> {
    /// The list's name, when a page has several: its parameter is
    /// `<name>Page`, else `page`.
    pub name: &'a str,
    /// What a row of the list is, for the summary line; `rows` for none.
    pub noun: &'a str,
    /// The list's own default rows per page, under `DEFAULT_PER_PAGE`.
    pub default_per: Option<i64>,
    /// The list's own ceiling under `MAX_ROWS`.
    pub max_per: Option<i64>,
}

/// `pagingOf()`'s answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paging {
    pub page: i64,
    pub per_page: i64,
    pub pages: i64,
    pub offset: i64,
    pub total: i64,
    pub first_row: i64,
    pub last_row: i64,
    pub param: String,
    pub noun: String,
}

/// `parseInt(String(value || ''), 10)`: the leading integer of the text,
/// `None` for NaN.
fn parse_int(value: Option<&Json>) -> Option<i64> {
    let text = match value {
        None | Some(Json::Null) => return None,
        Some(Json::String(s)) => s.clone(),
        Some(Json::Number(n)) => n.to_string(),
        Some(Json::Bool(_)) => return None,
        Some(other) => other.to_string(),
    };
    let t = text.trim_start();
    let (sign, digits) = match t.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, t.strip_prefix('+').unwrap_or(t)),
    };
    let leading: String =
        digits.chars().take_while(char::is_ascii_digit).collect();
    if leading.is_empty() {
        return None;
    }
    leading.parse::<i64>().ok().map(|n| sign * n)
}

impl Paging {
    /// `pagingOf(query, total, options)`.
    #[tracing::instrument(level = "trace", skip(query))]
    pub fn of(query: &Query, total: usize, options: Options<'_>) -> Paging {
        let total = total as i64;
        let param = if options.name.is_empty() {
            "page".to_string()
        } else {
            format!("{}Page", options.name)
        };
        let ceiling = MAX_ROWS.min(options.max_per.unwrap_or(MAX_ROWS));
        let per_page = match parse_int(query.get("per")) {
            Some(asked) if asked > 0 => asked.min(ceiling),
            _ => options.default_per.unwrap_or(DEFAULT_PER_PAGE).min(ceiling),
        };
        let pages = 1.max((total + per_page - 1) / per_page);
        let page = parse_int(query.get(&param)).unwrap_or(1).max(1).min(pages);
        let offset = (page - 1) * per_page;
        Paging {
            page,
            per_page,
            pages,
            offset,
            total,
            first_row: if total > 0 { offset + 1 } else { 0 },
            last_row: (offset + per_page).min(total),
            param,
            noun: if options.noun.is_empty() {
                "rows".to_string()
            } else {
                options.noun.to_string()
            },
        }
    }

    /// `pagingJson(pg)`: the members a reply publishes.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn to_json(&self) -> Json {
        json!({
            "page": self.page, "pages": self.pages, "perPage": self.per_page,
            "firstRow": self.first_row, "lastRow": self.last_row,
            "total": self.total, "param": self.param, "noun": self.noun,
        })
    }

    /// The rows of the page asked for: `rows.slice(offset, offset + per)`.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn slice<T: Clone>(&self, rows: &[T]) -> Vec<T> {
        let start = (self.offset.max(0) as usize).min(rows.len());
        let end = (start + self.per_page.max(0) as usize).min(rows.len());
        rows[start..end].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(pairs: &[(&str, Json)]) -> Query {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn an_empty_list_is_page_one_of_one() {
        let p = Paging::of(&query(&[]), 0, Options::default());
        assert_eq!((p.page, p.pages, p.first_row, p.last_row), (1, 1, 0, 0));
        assert_eq!(p.per_page, 50);
    }

    #[test]
    fn per_is_capped_and_the_page_clamped() {
        let q = query(&[("per", json!("7")), ("certificatesPage", json!(9))]);
        let p = Paging::of(
            &q,
            20,
            Options {
                name: "certificates",
                noun: "certificates",
                ..Options::default()
            },
        );
        assert_eq!((p.page, p.pages, p.offset), (3, 3, 14));
        assert_eq!((p.first_row, p.last_row), (15, 20));
        let five = Paging::of(
            &query(&[("per", json!(100))]),
            20,
            Options {
                max_per: Some(5),
                ..Options::default()
            },
        );
        assert_eq!(five.per_page, 5);
    }
}
