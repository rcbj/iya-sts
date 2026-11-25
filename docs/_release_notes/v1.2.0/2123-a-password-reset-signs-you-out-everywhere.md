---
title: "a password reset signs you out everywhere"
kind: behaviour-change
issue: 2123
---

Setting a new password from a reset link a person asked for at
`/portal/forgot-password` now ends every session they had, on every device,
as a reset an administrator issues already did. A reset usually follows a
password somebody else may know, and a session opened with it should not
outlive the new one (ASVS 5.0.0 7.4.3). The page that confirms the new
password says so. If the sessions cannot be ended, the password is still set
and `STS-PORTAL-0638` is logged.
