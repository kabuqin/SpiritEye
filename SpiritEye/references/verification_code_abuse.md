---
name: verification-code-abuse
description: Detect OTP, captcha, and verification-code flaws such as predictable generation, disclosure, brute force, and shared state.
---

# Verification Code / OTP / Captcha Abuse

Verification codes must be treated as security-critical tokens. Raise findings only when concrete code evidence supports the claim.

## High-signal patterns

- `java.util.Random`, `Math.random()`, or low-entropy generators used for OTP, captcha, SMS codes, password reset codes, or session verification: report as `CWE-330` when the code protects an account, login, or sensitive action.
- Generated verification code is echoed back to the client, added to the response model, returned in JSON, or printed in a way the attacker can trivially obtain it: report as information disclosure or logic weakness.
- Verification state stored in a shared field/static variable instead of per-user/per-session storage.
- Validation endpoint has no observable expiry, attempt counter, lockout, throttling, or one-time invalidation logic.
- GET endpoint triggers code generation or verification state change without protective controls.

## Evidence expectations

- Show where the code is generated.
- Show where it is stored or exposed.
- Show where verification is checked without expiry or attempt controls.
- Prefer one finding per concrete issue; do not merge weak randomness and disclosure into one if they are separate locations.

## Common False Alarms

- Do not report a page that only renders a captcha/OTP template unless the backend code actually generates, stores, exposes, or verifies a code.
- FALSE POSITIVE guard: do not emit `verification_code` for demo message/code pages unless the benchmark taxonomy explicitly treats the flow as OTP/captcha abuse rather than weak random or generic logic.
- FALSE POSITIVE guard: demo code-echo flows outside `/captcha`, `/sms`, `/otp`, `/verify`, password-reset, or login-protection paths should not emit `verification_code` unless the benchmark explicitly scores that module as verification abuse.
