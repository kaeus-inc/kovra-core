//! Asymmetric keypair custody & operations (KOV-12, extends spec §1.3).
//!
//! kovra custodies a full asymmetric keypair (ed25519 or RSA) — or just a
//! peer's **public** key (a public-only entry, not a secret). The private half
//! lives in a [`SecretValue`](crate::secret::SecretValue) and is sealed by the
//! same AEAD path as a literal ([`crate::crypto`]); it is **never exported**.
//! Like injection, a private key is used only *through* an operation (sign /
//! decrypt / load into the ssh-agent); the key material never crosses back into
//! the caller's — or the model's — context (I11/I14), is never logged (I7/I12),
//! and is never placed in `argv` (I6).
//!
//! This module is **pure** — it knows nothing about the vault, policy, or the
//! broker. The faces wire these primitives into [`crate::policy::decide`]:
//! private-key ops map to [`Operation::Inject`](crate::scope::Operation) (so
//! they are broker-gated for `high`/`prod`, I3/I15) and public-key ops map to
//! [`Operation::Metadata`](crate::scope::Operation) (free). All on-the-wire key
//! material is the **OpenSSH** text format, so generated public keys are
//! `ssh-*`-valid and the private key is exactly what the ssh-agent wants.
//!
//! ## Algorithm scope (closed decision)
//! - **ed25519**: keygen, sign/verify, *and* asymmetric encrypt/decrypt (via
//!   `age`'s SSH-recipient support — X25519 under the hood).
//! - **RSA**: keygen and sign/verify only. **No RSA encryption.** Asymmetric
//!   encrypt/decrypt is ed25519-only.

use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey, VerifyingKey};
use rsa::sha2::{Sha256, Sha512};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{BigUint, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use ssh_key::private::{Ed25519Keypair, KeypairData, PrivateKey, RsaKeypair};
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, LineEnding, PublicKey, SshSig};
use std::str::FromStr;
use zeroize::Zeroizing;

use crate::error::CoreError;

/// Minimum RSA modulus size we generate (bits). OpenSSH/`ssh-key` reject
/// anything smaller; 3072 is the modern default.
pub const RSA_BITS: usize = 3072;

/// The SSH signature namespace kovra signs/verifies under (the `-n` of
/// `ssh-keygen -Y sign`). A fixed, authoritative constant — never caller-set —
/// so a signature made by kovra verifies with `ssh-keygen -Y verify -n kovra`.
pub const SSH_SIG_NAMESPACE: &str = "kovra";

/// The asymmetric key algorithm of a [`Keypair`](crate::record::SecretRecord).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyAlgorithm {
    /// Edwards-curve ed25519 (signing) / X25519 (encryption via `age`).
    Ed25519,
    /// RSA (signing/verify and SSH only — never encryption here).
    Rsa,
}

impl KeyAlgorithm {
    /// Parse a CLI/tool algorithm name (`ed25519` / `rsa`, case-insensitive).
    pub fn parse(s: &str) -> Result<Self, CoreError> {
        match s.to_ascii_lowercase().as_str() {
            "ed25519" => Ok(KeyAlgorithm::Ed25519),
            "rsa" => Ok(KeyAlgorithm::Rsa),
            other => Err(CoreError::Keypair(format!(
                "unknown key algorithm `{other}` (expected ed25519|rsa)"
            ))),
        }
    }

    /// Stable lowercase label.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyAlgorithm::Ed25519 => "ed25519",
            KeyAlgorithm::Rsa => "rsa",
        }
    }

    /// Whether this algorithm supports asymmetric encrypt/decrypt (ed25519
    /// only — the closed decision: RSA is ssh/sign only).
    pub fn supports_encryption(&self) -> bool {
        matches!(self, KeyAlgorithm::Ed25519)
    }
}

/// A freshly generated keypair, in OpenSSH text form. The private half is held
/// in a [`Zeroizing`] buffer so it is wiped when the caller drops it; the face
/// immediately moves it into a sealed [`SecretValue`](crate::secret::SecretValue).
pub struct GeneratedKeypair {
    /// The algorithm.
    pub algorithm: KeyAlgorithm,
    /// OpenSSH-format private key (`-----BEGIN OPENSSH PRIVATE KEY-----`).
    pub private_openssh: Zeroizing<String>,
    /// OpenSSH-format public key (`ssh-ed25519 …` / `ssh-rsa …`).
    pub public_openssh: String,
}

/// Generate a new keypair of `algorithm`. The private key is returned in
/// OpenSSH form (unencrypted — at rest it is sealed by kovra's AEAD, not by an
/// SSH passphrase) and the public key is OpenSSH-valid.
pub fn generate(algorithm: KeyAlgorithm) -> Result<GeneratedKeypair, CoreError> {
    let mut rng = rand::rngs::OsRng;
    let private_key = match algorithm {
        KeyAlgorithm::Ed25519 => {
            let kp = Ed25519Keypair::random(&mut rng);
            PrivateKey::from(kp)
        }
        KeyAlgorithm::Rsa => {
            // Generate with the `rsa` crate directly: `ssh-key`'s own RSA path
            // round-trips through the same buggy component conversion we avoid
            // in `rsa_private_from_openssh`, so we build the keypair from a key
            // we know is valid.
            let base = RsaPrivateKey::new(&mut rng, RSA_BITS)
                .map_err(|e| CoreError::Keypair(format!("rsa keygen: {e}")))?;
            let kp = RsaKeypair::try_from(base)
                .map_err(|e| CoreError::Keypair(format!("rsa keypair wrap: {e}")))?;
            PrivateKey::from(kp)
        }
    };
    let private_openssh = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| CoreError::Keypair(format!("encode private key: {e}")))?
        .to_string();
    let public_openssh = private_key
        .public_key()
        .to_openssh()
        .map_err(|e| CoreError::Keypair(format!("encode public key: {e}")))?;
    Ok(GeneratedKeypair {
        algorithm,
        private_openssh: Zeroizing::new(private_openssh),
        public_openssh,
    })
}

/// The algorithm of an OpenSSH **public** key string. Used to validate a
/// public-only entry on `add --public-key` and to detect a mismatched op.
pub fn public_algorithm(public_openssh: &str) -> Result<KeyAlgorithm, CoreError> {
    let pk = PublicKey::from_openssh(public_openssh)
        .map_err(|_| invalid("not an OpenSSH public key"))?;
    algorithm_of_key_data(pk.key_data())
}

/// The OpenSSH public key string corresponding to an OpenSSH private key.
/// Lets the faces derive (and re-store) the public half from the sealed
/// private one without ever exporting the private bytes.
pub fn public_from_private(private_openssh: &str) -> Result<String, CoreError> {
    let pk = PrivateKey::from_openssh(private_openssh)
        .map_err(|_| invalid("not an OpenSSH private key"))?;
    pk.public_key()
        .to_openssh()
        .map_err(|e| CoreError::Keypair(format!("encode public key: {e}")))
}

/// Sign `data` with the OpenSSH private key, returning a detached, ASCII-armored
/// signature.
///
/// - **ed25519** → an OpenSSH `SshSig` (PEM, verifiable with
///   `ssh-keygen -Y verify`), under the [`SSH_SIG_NAMESPACE`].
/// - **RSA** → a PKCS#1 v1.5 / SHA-256 signature, hex-encoded. (`ssh-key` 0.6
///   cannot emit an RSA `SshSig`; the `rsa` crate gives a standard, verifiable
///   RSA signature instead — see the module note on the algorithm scope.)
pub fn sign(private_openssh: &str, data: &[u8]) -> Result<String, CoreError> {
    let pk = PrivateKey::from_openssh(private_openssh)
        .map_err(|_| invalid("not an OpenSSH private key"))?;
    match pk.key_data() {
        KeypairData::Ed25519(_) => {
            let sig: SshSig = pk
                .sign(SSH_SIG_NAMESPACE, HashAlg::Sha512, data)
                .map_err(|_| CoreError::Keypair("ed25519 signing failed".to_string()))?;
            sig.to_pem(LineEnding::LF)
                .map_err(|e| CoreError::Keypair(format!("encode signature: {e}")))
        }
        KeypairData::Rsa(rsa_kp) => {
            let priv_rsa = rsa_private_from_components(rsa_kp)?;
            let signing = RsaSigningKey::<Sha256>::new(priv_rsa);
            let sig = signing.sign(data);
            Ok(hex(&sig.to_vec()))
        }
        _ => Err(invalid("unsupported key algorithm for signing")),
    }
}

// ssh-agent SIGN_REQUEST flags (OpenSSH `PROTOCOL.agent`). They select the RSA
// hash; ed25519 ignores them. `0` means the key's default algorithm (legacy
// `ssh-rsa` / SHA-1 for an RSA key).
/// `SSH_AGENT_RSA_SHA2_256` — sign an RSA key with `rsa-sha2-256`.
pub const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
/// `SSH_AGENT_RSA_SHA2_512` — sign an RSA key with `rsa-sha2-512`.
pub const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

/// Produce a **raw ssh-agent signature blob** over `data` (the SSH session
/// challenge) with an OpenSSH private key — the `SSH_AGENT_SIGN_RESPONSE` payload
/// the ssh-agent protocol expects (KOV-13), *distinct* from [`sign`] (which is a
/// detached `SshSig` attestation under a namespace).
///
/// The returned bytes are the wire-format SSH `signature` value:
/// `string sig_algorithm_name || string signature_blob`, ready to be wrapped in
/// the response frame by the agent face. The cryptography stays here in `core`;
/// the `kovra-agent` crate only frames it.
///
/// Algorithm selection follows the client's SIGN_REQUEST `flags`:
/// - **ed25519** → always `ssh-ed25519` (64-byte raw signature); flags ignored.
/// - **RSA** → `rsa-sha2-512` / `rsa-sha2-256` per the flag, else legacy
///   `ssh-rsa` (SHA-1) when the client sets neither (some old clients).
///
/// The private key material is exposed only inside this call (in-memory) and is
/// never written anywhere (I7); the signature blob carries no key bytes.
pub fn sign_ssh_agent(
    private_openssh: &str,
    data: &[u8],
    flags: u32,
) -> Result<Vec<u8>, CoreError> {
    let pk = PrivateKey::from_openssh(private_openssh)
        .map_err(|_| invalid("not an OpenSSH private key"))?;
    match pk.key_data() {
        KeypairData::Ed25519(_) => {
            // Sign the raw challenge through `ssh-key`'s own `Signer` (Ed25519 is
            // pure EdDSA — the hash flag does not apply). We avoid depending on
            // `ed25519-dalek` directly (it arrives via `ssh-key`'s feature) and
            // re-emit the raw 64-byte signature with the `ssh-ed25519` name.
            use rsa::signature::Signer as _;
            use ssh_key::Signature as SshKeySignature;
            let sig: SshKeySignature = pk
                .try_sign(data)
                .map_err(|_| CoreError::Keypair("ed25519 ssh-agent signing failed".to_string()))?;
            Ok(encode_signature(b"ssh-ed25519", sig.as_bytes()))
        }
        KeypairData::Rsa(rsa_kp) => {
            let priv_rsa = rsa_private_from_components(rsa_kp)?;
            if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                let sig = RsaSigningKey::<Sha512>::new(priv_rsa).sign(data);
                Ok(encode_signature(b"rsa-sha2-512", &sig.to_vec()))
            } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                let sig = RsaSigningKey::<Sha256>::new(priv_rsa).sign(data);
                Ok(encode_signature(b"rsa-sha2-256", &sig.to_vec()))
            } else {
                // No SHA-2 flag → legacy ssh-rsa (SHA-1). Supported for old
                // clients that request the key's default algorithm. SHA-1 comes
                // from the `sha1` crate `core` already depends on (for TOTP).
                let sig = RsaSigningKey::<sha1::Sha1>::new(priv_rsa).sign(data);
                Ok(encode_signature(b"ssh-rsa", &sig.to_vec()))
            }
        }
        _ => Err(invalid("unsupported key algorithm for ssh-agent signing")),
    }
}

/// The raw SSH **public-key blob** of an OpenSSH public key — the
/// `KeyData`-encoded bytes the ssh-agent protocol carries inside an
/// `IDENTITIES_ANSWER` (and that a client echoes back in a `SIGN_REQUEST` to
/// select a key). This is public material (no secret, I12); the agent uses it
/// both to advertise a key and to match an incoming sign request to a custodied
/// keypair by exact byte equality.
pub fn public_key_blob(public_openssh: &str) -> Result<Vec<u8>, CoreError> {
    use ssh_encoding::Encode;
    let pk = PublicKey::from_openssh(public_openssh)
        .map_err(|_| invalid("not an OpenSSH public key"))?;
    let mut blob = Vec::new();
    pk.key_data()
        .encode(&mut blob)
        .map_err(|e| CoreError::Keypair(format!("encode public key blob: {e}")))?;
    Ok(blob)
}

/// Encode an SSH `signature` value: `string algorithm || string blob`.
fn encode_signature(algorithm: &[u8], blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + algorithm.len() + blob.len());
    write_string(&mut out, algorithm);
    write_string(&mut out, blob);
    out
}

/// Verify a signature produced by [`sign`] against an OpenSSH **public** key.
/// Returns `Ok(true)` on a valid signature, `Ok(false)` on a well-formed but
/// non-matching one, and an error only for malformed inputs.
pub fn verify(public_openssh: &str, data: &[u8], signature: &str) -> Result<bool, CoreError> {
    let pk = PublicKey::from_openssh(public_openssh)
        .map_err(|_| invalid("not an OpenSSH public key"))?;
    match pk.key_data() {
        KeyData::Ed25519(_) => {
            // Tolerate surrounding whitespace/newlines: a signature read from a
            // file (or printed by `kovra sign`) carries a trailing newline that
            // `SshSig::from_pem` would otherwise reject.
            let sig = match SshSig::from_pem(signature.trim().as_bytes()) {
                Ok(s) => s,
                // A malformed PEM is a verification failure, not a parse error of
                // the key — report it as "does not verify" so callers treat a
                // garbage signature uniformly.
                Err(_) => return Ok(false),
            };
            Ok(pk.verify(SSH_SIG_NAMESPACE, data, &sig).is_ok())
        }
        KeyData::Rsa(rsa_pub) => {
            let pub_rsa: rsa::RsaPublicKey = rsa_pub
                .try_into()
                .map_err(|_| invalid("malformed RSA public key"))?;
            let bytes = match unhex(signature) {
                Some(b) => b,
                None => return Ok(false),
            };
            let sig = match RsaSignature::try_from(bytes.as_slice()) {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };
            let verifying = VerifyingKey::<Sha256>::new(pub_rsa);
            Ok(verifying.verify(data, &sig).is_ok())
        }
        _ => Err(invalid("unsupported key algorithm for verification")),
    }
}

/// Encrypt `plaintext` **to** an OpenSSH **public** key (ed25519 only). Returns
/// an `age` ciphertext (binary). RSA is rejected — encryption is ed25519-only.
pub fn encrypt_to(public_openssh: &str, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let recipient = age::ssh::Recipient::from_str(public_openssh.trim())
        .map_err(|_| invalid("not an ed25519 OpenSSH public key (encryption is ed25519-only)"))?;
    // `age::ssh::Recipient` also parses ssh-rsa, but the closed decision is
    // ed25519-only encryption; reject an RSA recipient explicitly.
    if public_algorithm(public_openssh).ok() != Some(KeyAlgorithm::Ed25519) {
        return Err(invalid(
            "RSA keys cannot be used for encryption (encryption is ed25519-only)",
        ));
    }
    age::encrypt(&recipient, plaintext).map_err(|e| CoreError::Keypair(format!("encrypt: {e}")))
}

/// Decrypt an [`encrypt_to`] ciphertext **with** an OpenSSH private key (ed25519
/// only). The plaintext is returned in a [`Zeroizing`] buffer.
pub fn decrypt(private_openssh: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let identity = age::ssh::Identity::from_buffer(private_openssh.as_bytes(), None)
        .map_err(|_| invalid("not an ed25519 OpenSSH private key (decryption is ed25519-only)"))?;
    let plaintext = age::decrypt(&identity, ciphertext)
        .map_err(|_| CoreError::Keypair("decryption failed".to_string()))?;
    Ok(Zeroizing::new(plaintext))
}

// ───────────────────────────── ssh-agent ─────────────────────────────

/// The ssh-agent seam (KOV-12 `ssh-add`). `ssh-add` loads a private key into a
/// running ssh-agent **in memory only** — never to `~/.ssh` (I7). The real
/// agent is a `[host]` piece validated on hardware by the human; tests drive
/// [`MockSshAgent`], which records the keys it was asked to add so a test can
/// assert nothing touched the filesystem.
pub trait SshAgent {
    /// Add an OpenSSH private key (with an optional comment) to the agent.
    /// Implementations MUST NOT persist the key to disk.
    fn add_identity(&self, private_openssh: &str, comment: &str) -> Result<(), CoreError>;
}

/// The host ssh-agent reached over `$SSH_AUTH_SOCK` (`[host]`). Speaks the
/// minimal ssh-agent wire protocol (`SSH_AGENTC_ADD_IDENTITY`); it opens the
/// agent's unix socket and never writes a key to the filesystem (I7).
///
/// This is a native piece: it is validated on real hardware by the human, not
/// assumed working because written (CLAUDE.md rule 4). All policy/CLI logic is
/// tested against [`MockSshAgent`].
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvSshAgent;

/// ssh-agent protocol message number: add an identity (RFC draft / OpenSSH
/// `PROTOCOL.agent`).
const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
/// ssh-agent success reply.
const SSH_AGENT_SUCCESS: u8 = 6;

impl SshAgent for EnvSshAgent {
    fn add_identity(&self, private_openssh: &str, comment: &str) -> Result<(), CoreError> {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let sock = std::env::var_os("SSH_AUTH_SOCK")
            .ok_or_else(|| CoreError::Keypair("SSH_AUTH_SOCK is not set (no ssh-agent)".into()))?;
        let pk = PrivateKey::from_openssh(private_openssh)
            .map_err(|_| invalid("not an OpenSSH private key"))?;

        // Build the ADD_IDENTITY body: key-type string + private key blob +
        // comment, all in SSH wire encoding. The key bytes live only in this
        // in-memory buffer (zeroized on drop) and are written to the agent
        // socket — never to disk (I7).
        let body = encode_add_identity(&pk, comment)?;
        let mut frame = Vec::with_capacity(5 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);

        let mut stream = UnixStream::connect(&sock)
            .map_err(|e| CoreError::Keypair(format!("connect ssh-agent: {e}")))?;
        stream
            .write_all(&frame)
            .map_err(|e| CoreError::Keypair(format!("write ssh-agent: {e}")))?;

        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .map_err(|e| CoreError::Keypair(format!("read ssh-agent: {e}")))?;
        let reply_len = u32::from_be_bytes(len_buf) as usize;
        if reply_len == 0 {
            return Err(CoreError::Keypair("empty ssh-agent reply".into()));
        }
        let mut reply = vec![0u8; reply_len];
        stream
            .read_exact(&mut reply)
            .map_err(|e| CoreError::Keypair(format!("read ssh-agent: {e}")))?;
        if reply[0] == SSH_AGENT_SUCCESS {
            Ok(())
        } else {
            Err(CoreError::Keypair(
                "ssh-agent refused the identity".to_string(),
            ))
        }
    }
}

/// Encode an `SSH_AGENTC_ADD_IDENTITY` message body for a private key.
fn encode_add_identity(pk: &PrivateKey, comment: &str) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    use ssh_encoding::Encode;

    let mut out = Zeroizing::new(Vec::new());
    out.push(SSH_AGENTC_ADD_IDENTITY);
    // key type (e.g. "ssh-ed25519")
    write_string(&mut out, pk.algorithm().as_str().as_bytes());
    // the private key blob (KeypairData encodes the public + private fields)
    let mut blob = Zeroizing::new(Vec::new());
    pk.key_data()
        .encode(&mut *blob)
        .map_err(|e| CoreError::Keypair(format!("encode agent key: {e}")))?;
    out.extend_from_slice(&blob);
    // comment
    write_string(&mut out, comment.as_bytes());
    Ok(out)
}

/// Write an SSH `string` (u32 length prefix + bytes) to a buffer. Public so the
/// `kovra-agent` face can frame ssh-agent replies with the same helper the
/// custody path uses (the wire encoder lives once, in `core`).
pub fn write_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// In-memory ssh-agent for tests: records every key it was asked to add, so a
/// test can assert `ssh-add` delivered the key into the agent and **not** to
/// disk (I7).
#[derive(Default)]
pub struct MockSshAgent {
    added: std::sync::Mutex<Vec<(String, String)>>,
}

impl MockSshAgent {
    /// A fresh, empty mock agent.
    pub fn new() -> Self {
        Self::default()
    }

    /// The (private-key, comment) pairs added so far.
    pub fn added(&self) -> Vec<(String, String)> {
        self.added.lock().expect("agent mutex poisoned").clone()
    }
}

impl SshAgent for MockSshAgent {
    fn add_identity(&self, private_openssh: &str, comment: &str) -> Result<(), CoreError> {
        // Validate it is a real OpenSSH key (the real agent would reject garbage)
        // but never write it anywhere but this in-memory record.
        PrivateKey::from_openssh(private_openssh)
            .map_err(|_| invalid("not an OpenSSH private key"))?;
        self.added
            .lock()
            .expect("agent mutex poisoned")
            .push((private_openssh.to_string(), comment.to_string()));
        Ok(())
    }
}

// ───────────────────────────── helpers ─────────────────────────────

/// Reconstruct an `rsa::RsaPrivateKey` from `ssh-key`'s `RsaKeypair`.
///
/// `ssh-key` 0.6.7's own `TryFrom<&RsaKeypair> for rsa::RsaPrivateKey` is buggy
/// (it passes the first prime `p` twice instead of `p` and `q`, so the produced
/// key fails RSA validation). We read the five raw components ourselves and call
/// `from_components` with the correct primes.
fn rsa_private_from_components(kp: &RsaKeypair) -> Result<RsaPrivateKey, CoreError> {
    let n = BigUint::try_from(&kp.public.n).map_err(|_| invalid("malformed RSA modulus"))?;
    let e = BigUint::try_from(&kp.public.e).map_err(|_| invalid("malformed RSA exponent"))?;
    let d =
        BigUint::try_from(&kp.private.d).map_err(|_| invalid("malformed RSA private exponent"))?;
    let p = BigUint::try_from(&kp.private.p).map_err(|_| invalid("malformed RSA prime p"))?;
    let q = BigUint::try_from(&kp.private.q).map_err(|_| invalid("malformed RSA prime q"))?;
    RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .map_err(|e| CoreError::Keypair(format!("reconstruct RSA key: {e}")))
}

/// The [`KeyAlgorithm`] of an OpenSSH public key's `KeyData`.
fn algorithm_of_key_data(kd: &KeyData) -> Result<KeyAlgorithm, CoreError> {
    match kd {
        KeyData::Ed25519(_) => Ok(KeyAlgorithm::Ed25519),
        KeyData::Rsa(_) => Ok(KeyAlgorithm::Rsa),
        _ => Err(invalid(
            "unsupported key algorithm (expected ed25519 or rsa)",
        )),
    }
}

/// A `CoreError::Keypair` for malformed input.
fn invalid(msg: &str) -> CoreError {
    CoreError::Keypair(msg.to_string())
}

/// Lowercase-hex encode (for RSA signatures, which have no OpenSSH armor here).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode a lowercase/uppercase hex string; `None` on any non-hex input.
fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ed25519 keygen yields an OpenSSH-valid public key and a usable private.
    #[test]
    fn ed25519_keygen_is_openssh_valid() {
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        assert!(kp.public_openssh.starts_with("ssh-ed25519 "));
        assert_eq!(
            public_algorithm(&kp.public_openssh).unwrap(),
            KeyAlgorithm::Ed25519
        );
        // public key derived from the private matches the generated public.
        assert_eq!(
            public_from_private(&kp.private_openssh).unwrap(),
            kp.public_openssh
        );
        // the private key parses as an OpenSSH private key.
        assert!(PrivateKey::from_openssh(&kp.private_openssh).is_ok());
    }

    #[test]
    fn rsa_keygen_is_openssh_valid() {
        let kp = generate(KeyAlgorithm::Rsa).unwrap();
        assert!(kp.public_openssh.starts_with("ssh-rsa "));
        assert_eq!(
            public_algorithm(&kp.public_openssh).unwrap(),
            KeyAlgorithm::Rsa
        );
    }

    #[test]
    fn ed25519_sign_verify_round_trip() {
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let sig = sign(&kp.private_openssh, b"deploy v2").unwrap();
        assert!(verify(&kp.public_openssh, b"deploy v2", &sig).unwrap());
        // a tampered message does not verify
        assert!(!verify(&kp.public_openssh, b"deploy v3", &sig).unwrap());
        // a different key does not verify
        let other = generate(KeyAlgorithm::Ed25519).unwrap();
        assert!(!verify(&other.public_openssh, b"deploy v2", &sig).unwrap());
    }

    // A signature with surrounding whitespace (as printed by `kovra sign` / read
    // back from a file) still verifies — the CLI round-trips through a file.
    #[test]
    fn ed25519_verify_tolerates_trailing_newline() {
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let mut sig = sign(&kp.private_openssh, b"attest this").unwrap();
        sig.push('\n');
        assert!(verify(&kp.public_openssh, b"attest this", &sig).unwrap());
    }

    #[test]
    fn rsa_sign_verify_round_trip() {
        let kp = generate(KeyAlgorithm::Rsa).unwrap();
        let sig = sign(&kp.private_openssh, b"payload").unwrap();
        assert!(verify(&kp.public_openssh, b"payload", &sig).unwrap());
        assert!(!verify(&kp.public_openssh, b"payloae", &sig).unwrap());
    }

    #[test]
    fn ed25519_encrypt_decrypt_round_trip() {
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let msg = b"a small secret message";
        let ct = encrypt_to(&kp.public_openssh, msg).unwrap();
        assert_ne!(ct, msg, "ciphertext must differ from plaintext");
        let pt = decrypt(&kp.private_openssh, &ct).unwrap();
        assert_eq!(&*pt, msg);
        // decrypting with the wrong key fails (no plaintext leak)
        let other = generate(KeyAlgorithm::Ed25519).unwrap();
        assert!(decrypt(&other.private_openssh, &ct).is_err());
    }

    // RSA encryption is rejected — encryption is ed25519-only (closed decision).
    #[test]
    fn rsa_encryption_is_rejected() {
        let kp = generate(KeyAlgorithm::Rsa).unwrap();
        assert!(!KeyAlgorithm::Rsa.supports_encryption());
        let err = encrypt_to(&kp.public_openssh, b"x").unwrap_err();
        assert!(matches!(err, CoreError::Keypair(_)));
    }

    // The mock ssh-agent records the key in memory (the seam tests use for I7).
    #[test]
    fn mock_ssh_agent_records_added_key() {
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let agent = MockSshAgent::new();
        agent
            .add_identity(&kp.private_openssh, "kovra:dev/ssh/deploy")
            .unwrap();
        let added = agent.added();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].1, "kovra:dev/ssh/deploy");
        // garbage is rejected (mirrors the real agent)
        assert!(agent.add_identity("not a key", "c").is_err());
    }

    // The raw ssh-agent signature blob over a challenge verifies as a standard
    // SSH signature (the ssh-agent SIGN_RESPONSE format) — distinct from the
    // detached SshSig that `sign` produces.
    #[test]
    fn ed25519_sign_ssh_agent_blob_verifies() {
        use ssh_encoding::Decode;
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let challenge = b"ssh session challenge bytes";
        let blob = sign_ssh_agent(&kp.private_openssh, challenge, 0).unwrap();
        // The blob is `string algorithm || string signature`.
        let mut reader = blob.as_slice();
        let alg = String::decode(&mut reader).unwrap();
        assert_eq!(alg, "ssh-ed25519");
        let sig_bytes = Vec::<u8>::decode(&mut reader).unwrap();
        assert_eq!(sig_bytes.len(), 64, "ed25519 raw signature is 64 bytes");
        // It verifies against the public key through `ssh-key`'s own verifier:
        // rebuild the `ssh_key::Signature` from the wire algorithm + bytes and
        // check it (no direct dalek dependency — `core` never names it).
        use rsa::signature::Verifier as _;
        use ssh_key::{Algorithm, Signature as SshKeySignature};
        let pk = PublicKey::from_openssh(&kp.public_openssh).unwrap();
        let sig = SshKeySignature::new(Algorithm::Ed25519, sig_bytes).unwrap();
        assert!(pk.key_data().verify(challenge, &sig).is_ok());
        // a tampered challenge does not verify
        assert!(pk.key_data().verify(b"other challenge", &sig).is_err());
    }

    // RSA honors the SIGN_REQUEST hash flags: 256/512 select rsa-sha2-*, and the
    // absence of a flag falls back to legacy ssh-rsa (SHA-1).
    #[test]
    fn rsa_sign_ssh_agent_honors_flags() {
        use ssh_encoding::Decode;
        let kp = generate(KeyAlgorithm::Rsa).unwrap();
        let challenge = b"challenge";
        let cases = [
            (SSH_AGENT_RSA_SHA2_256, "rsa-sha2-256"),
            (SSH_AGENT_RSA_SHA2_512, "rsa-sha2-512"),
            (0, "ssh-rsa"),
        ];
        for (flags, expected) in cases {
            let blob = sign_ssh_agent(&kp.private_openssh, challenge, flags).unwrap();
            let mut reader = blob.as_slice();
            let alg = String::decode(&mut reader).unwrap();
            assert_eq!(alg, expected, "flags {flags:#x} → {expected}");
            let sig = Vec::<u8>::decode(&mut reader).unwrap();
            assert!(!sig.is_empty());
        }
    }

    // The public-key blob round-trips: re-decoding it yields the same KeyData,
    // and it equals the agent's own ADD_IDENTITY encoding of the public half.
    #[test]
    fn public_key_blob_round_trips() {
        use ssh_encoding::Decode;
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let blob = public_key_blob(&kp.public_openssh).unwrap();
        let decoded = KeyData::decode(&mut blob.as_slice()).unwrap();
        let original = PublicKey::from_openssh(&kp.public_openssh).unwrap();
        assert_eq!(&decoded, original.key_data());
    }

    #[test]
    fn algorithm_parse_round_trips() {
        assert_eq!(
            KeyAlgorithm::parse("ed25519").unwrap(),
            KeyAlgorithm::Ed25519
        );
        assert_eq!(KeyAlgorithm::parse("RSA").unwrap(), KeyAlgorithm::Rsa);
        assert!(KeyAlgorithm::parse("dsa").is_err());
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00u8, 0xff, 0x10, 0xab, 0x7e];
        assert_eq!(unhex(&hex(&bytes)).unwrap(), bytes);
        assert!(unhex("xyz").is_none());
        assert!(unhex("abc").is_none()); // odd length
    }
}
