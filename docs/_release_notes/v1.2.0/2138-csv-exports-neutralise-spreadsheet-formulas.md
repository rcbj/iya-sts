---
title: "CSV exports neutralise spreadsheet formulas"
kind: behaviour-change
issue: 2138
---

A report exported as CSV, and the passkey report's CSV export, now put a
single quote (`'`) in front of any text value whose first character is
`=`, `+`, `-`, `@`, a tab, a carriage return or NUL, so a value someone
chose (a username, a display name) cannot run as a formula when the file
is opened in a spreadsheet (ASVS 5.0.0 1.2.10). The quote is visible in
the cell. Numbers are not touched: a negative count is still a number.
Until 1.2.0 a report's CSV quoted only per RFC 4180, and the passkey
export did not catch a leading NUL. A program that reads these files and
compared a text cell starting with one of those characters byte for byte
now sees the quote in front. See [Reporting](reporting.md#formats).
