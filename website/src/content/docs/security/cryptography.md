---
title: Cryptography
description: Every cryptographic algorithm kovra uses, the exact parameters, the library behind it, and why each choice was made.
---

kovra rolls **no cryptography of its own**. Every primitive below is a vetted,
widely-used Rust implementation — the [RustCrypto](https://github.com/RustCrypto)
family, [`age`](https://age-encryption.org/), and [BLAKE3](https://github.com/BLAKE3-team/BLAKE3).
kovra's job is to *compose* them correctly: the right primitive for each task,
the right parameters, and no plaintext left where it shouldn't be.

This page documents exactly what runs, with the real parameters from the source.

## At a glance

| Purpose | Algorithm | Key / parameters | Library |
| --- | --- | --- | --- |
| Encryption at rest | ChaCha20-Poly1305 (AEAD) | 256-bit key, 96-bit random nonce per write | `chacha20poly1305` |
| Master-key custody | OS keyring | — (Keychain / Credential Manager / Secret Service) | `keyring` |
| Headless key derivation | Argon2id | 19 MiB memory, 2 passes, 1 lane → 256-bit key | `argon2` |
| Value fingerprint | BLAKE3 (truncated) | first 4 bytes → 8 hex chars | `blake3` |
| Coordinate addressing | BLAKE3 | full digest of the canonical path | `blake3` |
| Sharing / sealed packages | `age` (X25519 + ChaCha20-Poly1305) | sealed to a recipient public key | `age`, `ssh-key` |
| Master-key backup | `age` scrypt (passphrase) | ASCII-armored | `age` |
| Signing keypairs | ed25519 / RSA-3072 (PKCS#1 v1.5 + SHA-2) | OpenSSH format | `ssh-key`, `rsa` |
| Asymmetric encryption | X25519 (via `age`, ed25519 keys only) | — | `age`, `ssh-key` |
| TOTP codes | RFC-6238 HMAC-SHA1 (SHA-256/512 optional) | 6 digits, 30-second period | `hmac`, `sha1`/`sha2` |
| Randomness | OS CSPRNG | — | `getrandom` / `OsRng` |
| In-memory hygiene | zeroize + secrecy | — | `zeroize`, `secrecy` |

## Encryption at rest

Every vault record — and the metadata index — is independently sealed with
**ChaCha20-Poly1305**, an AEAD (authenticated encryption with associated data)
cipher, under the vault's **256-bit master key**. Each write generates a **fresh
random 96-bit nonce**, so two seals of the same record always differ and a nonce
is never reused. The metadata and the value are sealed **together**, so neither
the secret nor even its coordinate appears as plaintext on disk. The
authentication tag (Poly1305) means a tampered record fails to open rather than
returning garbage, and decryption failures are **opaque** — a wrong key, a
corrupt ciphertext, and a malformed nonce are indistinguishable, so the error
can't act as an oracle. The transient plaintext buffer is zeroized after use.

**Why ChaCha20-Poly1305.** It's a modern, constant-time AEAD that is fast in
pure software without special CPU instructions (unlike AES, which leans on
AES-NI for both speed and side-channel resistance) — the right default for a tool
that runs on whatever laptop you have. AEAD gives confidentiality *and* integrity
in one pass, and the per-record random nonce sidesteps the catastrophic
nonce-reuse failure mode.

## Master-key custody

The 256-bit master key is never typed, displayed, or written to a project file.
By default it lives in the **OS keyring** — the macOS Keychain, the Windows
Credential Manager, or the Linux Secret Service — and kovra loads it only to seal
and open records.

For headless use (CI, containers, no keyring), kovra derives the key instead with
**Argon2id**, the memory-hard password KDF, from a passphrase plus a stable
per-vault salt. It runs at the library's defaults — **19 MiB of memory, 2 passes,
1 lane** — producing the 256-bit key deterministically, so the same vault unlocks
across runs with nothing secret stored on disk (only the non-secret salt).

**Why Argon2id.** Memory-hardness makes brute-forcing a stolen passphrase
expensive on GPUs and custom hardware; Argon2id is the current standard (and the
winner of the Password Hashing Competition). The OS keyring is preferred when
present because it binds the key to the user's login session and the platform's
own protections; Argon2id is the portable fallback that needs nothing but a
passphrase.

## Hashing and fingerprints

kovra uses **BLAKE3** in two places:

- **Value fingerprints.** `kovra list` and `doctor` show a **truncated**
  fingerprint — the first **4 bytes** of the BLAKE3 digest, as 8 lowercase hex
  characters. It's deterministic (no salt), so you can answer "did this value
  change?" or "is this the same secret as before?" without ever seeing the value.
  It is deliberately too short to help brute-force the value, and it is **never**
  the full hash.
- **Coordinate addressing.** A record's on-disk identifier is the BLAKE3 digest
  of its canonical `env/component/key` path, so coordinates aren't leaked as
  plaintext filenames.

**Why BLAKE3.** It's fast, modern, and has a clean, hard-to-misuse API. The
fingerprint's security comes from *truncation plus determinism*: long enough to
detect a change, short enough that it reveals essentially nothing about the
value.

## Sharing — sealed packages

A [sealed package](/guides/sharing/) is an **`age`** box. `age` uses **X25519**
key agreement with **ChaCha20-Poly1305** for the payload; kovra seals to the
recipient's **ed25519** public key via `age`'s SSH-recipient path. Only the
holder of the matching private key can open it — possession of the file is not
authorization.

Unattended delivery of sensitive entries adds a **second factor** without a
second key: the package embeds a `BLAKE3(token_secret)` **commitment** inside the
sealed payload, and the separately-delivered **access token** is the preimage. An
unattended open therefore needs *both* the recipient identity (to decrypt and
read the commitment) *and* the out-of-band token (to satisfy it). Production
secrets are refused at sealing time and re-checked on open.

**Honest limit.** A package is **confidentiality only**. `age`'s AEAD tag
guarantees integrity — a tampered package won't open — but the format carries
**no signature**, so it proves *who can read it*, not *who wrote it*. If you need
sender authenticity, sign the payload with a [keypair](/guides/keypairs/) out of
band.

## Master-key backup

`kovra key export` writes a disaster-recovery backup of the master key as an
**ASCII-armored `age` scrypt** blob — encrypted under a recovery passphrase you
choose, decryptable by any `age` implementation in an emergency. The transient
plaintext is wiped after the call; only the encrypted blob is ever returned.

## Keypairs and signing

Custodied [keypairs](/guides/keypairs/) are stored in **OpenSSH** format and used
only *through* kovra:

- **ed25519** — signing (Edwards-curve) **and** asymmetric encryption (X25519,
  via the `age` path above).
- **RSA-3072** — signing and SSH only, using **PKCS#1 v1.5 with SHA-2**.
  Deliberately **no RSA encryption** — when you need to encrypt to a key, use
  ed25519.

Signatures are made under a fixed SSH signature namespace, so a signature kovra
produces verifies with standard `ssh-keygen -Y verify`. The private half is
generated inside the vault, sealed under the master key with the same
ChaCha20-Poly1305 path as every other secret, and **never written to disk or
printed**.

**Why ed25519 first.** Small keys, fast signatures, no parameter foot-guns, and a
clean bridge to encryption through X25519. RSA-3072 (≈128-bit security) is kept
for interoperability with systems that still require RSA.

## TOTP

A [TOTP enrollment](/guides/totp/) custodies the shared seed and computes codes
per **RFC-6238**: **HMAC-SHA1** by default (the RFC default), with **SHA-256** and
**SHA-512** available, **6 digits**, **30-second** period. The HMAC is built on
the `hmac` + `sha1`/`sha2` crates. The **seed is sealed like any other secret and
never revealed** — only the derived, time-limited code is ever produced.

## Randomness

All nonces, generated secrets (`kovra generate`), and freshly created keypairs
draw from the **operating system's CSPRNG** (`getrandom` / `OsRng`) — never a
userspace PRNG seeded from a guessable source.

## In-memory hygiene

Secret-bearing types are wrapped in `secrecy` and implement `zeroize`: their
`Debug`/`Display` are redacted (a value can't leak into a log line or a panic
message), and the underlying bytes are **wiped from memory** when dropped.
Transient plaintext buffers — the decrypted record, the serialized payload before
sealing — are zeroized explicitly as soon as they're no longer needed.

## What kovra deliberately does *not* do

- **No home-rolled cryptography.** Every primitive is a vetted, widely-reviewed
  library; kovra only composes them.
- **No nonce reuse.** Every AEAD seal uses a fresh random nonce.
- **No value oracle.** Fingerprints are truncated and errors are opaque.
- **No sender authentication on packages.** Sealed packages are confidentiality
  only; add a signature if you need to prove authorship.
- **No protection past delivery.** Once a value is handed to the process that
  needs it, it lives in that process's memory under that program's rules — kovra's
  cryptography secures custody and delivery, not what a program does with a value
  after it receives it.
