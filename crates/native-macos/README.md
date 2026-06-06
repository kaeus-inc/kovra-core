# kovra-native-macos

The macOS **Touch ID `Confirmer`** for kovra (spec §8, §14.1; layer L8, `[host]`).

This crate is the native half of the confirmation broker. It renders the
**core-authored** `ConfirmRequest` in a macOS LocalAuthentication (`LAContext`)
dialog and returns `Approved | Denied | TimedOut`. It is a third `Confirmer`
implementation beside `CliApproveConfirmer` and `FileConfirmer`.

- **Free core**, not enterprise: `core` never depends on this crate; injection
  points the other way (this crate depends on `kovra-core`).
- **No invariant is touched.** The dialog only shows what the core put in the
  request (I16); approval happens at the sensor, outside the model's process
  (§8.2, no self-approve); timeout fails safe to denial (§8); no secret value is
  ever rendered or logged (I7/I12).
- **Cross-platform:** the `LAContext` binding is gated under
  `cfg(target_os = "macos")`. Off-macOS the crate compiles to a no-op stub
  (`biometrics_available()` → `false`, `prompt()` → `Denied`), so Linux CI builds
  the whole workspace and the CLI auto-falls-back to the file broker.

## Confirmer selection (`KOVRA_CONFIRMER`)

Selection lives in the CLI's `Ctx::confirmer()` factory:

| `KOVRA_CONFIRMER` | Behavior |
|---|---|
| unset (default) | `biometric` on macOS **with automatic fallback to `file`** when biometrics is unavailable; always `file` on non-macOS |
| `biometric`      | native Touch ID prompt **if** the host can prompt; otherwise fall back to `file` |
| `file`           | always the cross-process `kovra approve <id>` file broker |

"Biometrics unavailable" = not macOS, or no biometric hardware, or the user is
not enrolled (`LAContext canEvaluatePolicy:` fails). Any unrecognized value uses
the default.

## `[host]` hardware-validation checklist (M4) — blocking sign-off for Done

The real `LAContext` path is **not** exercised by automated tests (no hardware in
CI). A human must validate the following on an M4 with Touch ID enrolled. This is
the blocking gate for marking KOV-15 Done.

Setup: a throwaway vault in passphrase mode, a `high`/`prod` secret, and
`KOVRA_CONFIRMER` unset (default biometric) unless noted.

1. **Approve (happy path).** `kovra show secret:prod/db/password` → Touch ID
   dialog appears → touch the sensor → the value is revealed. Audit log records
   an approval (no value).
2. **Deny.** Trigger the prompt again → tap **Cancel** / use the wrong finger →
   the operation is denied, no value revealed, audit records a denial.
3. **Timeout ⇒ deny.** Trigger the prompt and **do not respond** until the
   `confirm_timeout` (CLI default 120s) elapses → the operation fails closed
   (timed out, treated as denial), no value revealed.
4. **I16 dialog content.** For an injection (`kovra run … -- /usr/bin/deploy …`
   against a `prod`/`high` ref), confirm the dialog shows:
   - the **exact resolved command/argv** as the prominent first line (not
     paraphrased),
   - the coordinate address, sensitivity, environment (with `prod` highlighted),
     and origin,
   - any requester description rendered **only** under the
     "provided by requester (untrusted)" fence — never as the headline.
5. **No self-approve (§8.2).** Confirm there is no way for the invoking process
   (the agent / `kovra run`) to satisfy the prompt programmatically — only a
   human touch at the sensor approves.
6. **Biometric-disabled fallback.** Disable/disenroll Touch ID (or run on a Mac
   without it) → with `KOVRA_CONFIRMER` unset or `=biometric`, the CLI must
   **fall back to the file broker** (`kovra approve --list` shows the pending
   request; approving in another terminal releases the blocked `show`/`run`).
7. **No leak (I7/I12).** Across all of the above, confirm the secret **value**
   never appears in: the dialog text, the audit log, stdout/stderr of the prompt,
   or any file written by the confirm path. Only addresses/commands appear.

## Threading & shim notes

- The native prompt is invoked from the **CLI main thread** (the CLI is
  synchronous). `evaluatePolicy:reply:` is non-blocking and fires its reply on a
  private framework queue; we block the main thread on an `mpsc` channel the reply
  signals — **no dedicated runloop pump** is built.
- **No `extern "C"` shim was needed:** `objc2-local-authentication` 0.3.2 exposes
  the full surface used (`LAContext::new`, `canEvaluatePolicy:`,
  `evaluatePolicy:localizedReason:reply:`).
