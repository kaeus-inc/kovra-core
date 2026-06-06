//! The ssh-agent **wire protocol** — the isolated, untrusted parsing/encoding
//! surface (KOV-13, decision Q1: a minimal in-crate parser, synchronous, no
//! `ssh-agent-lib`, no tokio).
//!
//! This module is the agent's attack surface: any local process that can reach
//! the socket speaks it. It is therefore deliberately **small** (exactly the two
//! request opcodes kovra answers) and **defensive**:
//! - every length prefix is bounds-checked against the remaining buffer and a
//!   hard [`MAX_FRAME_LEN`] cap, so a malicious length cannot trigger a huge
//!   allocation or an over-read;
//! - any malformed / oversized / unknown message is rejected with an `Err`,
//!   which the daemon turns into a single `SSH_AGENT_FAILURE` byte — it never
//!   panics and never indexes out of bounds;
//! - it sees **no key bytes** except at the final response-encoding step, and
//!   even there only the public blob and the (already-produced) signature blob.
//!
//! FUZZ TARGET (Phase 4): [`parse_request`] and [`read_frame`] are the entry
//! points to fuzz — feed arbitrary bytes, assert they never panic and only ever
//! return `Ok(Request)` or `Err(AgentError::Protocol)`.

use crate::error::AgentError;

// ── ssh-agent message numbers (OpenSSH `PROTOCOL.agent`) ──
/// Client → agent: list identities.
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// Agent → client: identities answer.
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// Client → agent: sign request.
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
/// Agent → client: sign response.
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
/// Agent → client: generic failure (also our reply to anything unknown/malformed).
pub const SSH_AGENT_FAILURE: u8 = 5;

/// Hard cap on a single agent frame (length-prefix value). The ssh-agent
/// protocol's own limit is 256 KiB; we use the same so a hostile peer cannot ask
/// us to allocate gigabytes from a 4-byte length. Anything larger is rejected.
pub const MAX_FRAME_LEN: usize = 256 * 1024;

/// A parsed client request — only the two opcodes kovra answers. Everything else
/// is rejected before this type is constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `SSH_AGENTC_REQUEST_IDENTITIES` — enumerate identities (no body).
    RequestIdentities,
    /// `SSH_AGENTC_SIGN_REQUEST` — sign `data` with the key whose public blob is
    /// `key_blob`, honoring the SIGN `flags`.
    SignRequest {
        /// The public-key blob selecting the key (matched by exact bytes).
        key_blob: Vec<u8>,
        /// The data to sign (the SSH session challenge).
        data: Vec<u8>,
        /// SIGN_REQUEST flags (RSA SHA-2 selection); 0 for ed25519 / default.
        flags: u32,
    },
}

/// One advertised identity (a public-key blob + comment) for the answer.
pub struct Identity {
    /// The public-key blob.
    pub key_blob: Vec<u8>,
    /// A human comment (e.g. the coordinate). Public metadata, never a secret.
    pub comment: String,
}

/// A bounds-checked reader over a borrowed byte slice. Every read validates
/// against the remaining length; it can never panic or over-read.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Read a `u8`.
    fn u8(&mut self) -> Result<u8, AgentError> {
        if self.remaining() < 1 {
            return Err(protocol("truncated: expected a byte"));
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Read a big-endian `u32`.
    fn u32(&mut self) -> Result<u32, AgentError> {
        if self.remaining() < 4 {
            return Err(protocol("truncated: expected a u32"));
        }
        let v = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    /// Read an SSH `string`: a `u32` length prefix followed by that many bytes.
    /// The length is checked against both the remaining buffer and the global
    /// cap, so a forged length is rejected rather than allocated.
    fn string(&mut self) -> Result<Vec<u8>, AgentError> {
        let len = self.u32()? as usize;
        if len > MAX_FRAME_LEN {
            return Err(protocol("string length exceeds the frame cap"));
        }
        if self.remaining() < len {
            return Err(protocol("string length exceeds the remaining buffer"));
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }
}

fn protocol(msg: &str) -> AgentError {
    AgentError::Protocol(msg.to_string())
}

/// Parse a single agent request **body** (the bytes after the 4-byte frame
/// length — i.e. starting at the message-type byte). Returns `Err` for any
/// unknown opcode, trailing garbage, or malformed field; the daemon maps that to
/// `SSH_AGENT_FAILURE`. Never panics (fuzz-target contract).
pub fn parse_request(body: &[u8]) -> Result<Request, AgentError> {
    let mut r = Reader::new(body);
    let msg_type = r.u8()?;
    match msg_type {
        SSH_AGENTC_REQUEST_IDENTITIES => {
            // The body is exactly the type byte; reject trailing bytes.
            if r.remaining() != 0 {
                return Err(protocol(
                    "REQUEST_IDENTITIES carries unexpected trailing bytes",
                ));
            }
            Ok(Request::RequestIdentities)
        }
        SSH_AGENTC_SIGN_REQUEST => {
            let key_blob = r.string()?;
            let data = r.string()?;
            let flags = r.u32()?;
            if r.remaining() != 0 {
                return Err(protocol("SIGN_REQUEST carries unexpected trailing bytes"));
            }
            Ok(Request::SignRequest {
                key_blob,
                data,
                flags,
            })
        }
        other => Err(AgentError::Protocol(format!(
            "unsupported ssh-agent opcode {other}"
        ))),
    }
}

/// Write an SSH `string` (u32 length + bytes). Re-exports `core`'s single wire
/// encoder so the encoding lives in one place.
fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    kovra_core::write_string(out, bytes);
}

/// Encode the **body** of an `SSH_AGENT_IDENTITIES_ANSWER`:
/// `byte type || u32 nkeys || (string key_blob || string comment)*`.
pub fn encode_identities_answer(identities: &[Identity]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(SSH_AGENT_IDENTITIES_ANSWER);
    out.extend_from_slice(&(identities.len() as u32).to_be_bytes());
    for id in identities {
        put_string(&mut out, &id.key_blob);
        put_string(&mut out, id.comment.as_bytes());
    }
    out
}

/// Encode the **body** of an `SSH_AGENT_SIGN_RESPONSE`:
/// `byte type || string signature`. The `signature` is the already-wrapped
/// `string algorithm || string blob` value produced by `core`.
pub fn encode_sign_response(signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(SSH_AGENT_SIGN_RESPONSE);
    put_string(&mut out, signature);
    out
}

/// Encode the single-byte `SSH_AGENT_FAILURE` body.
pub fn encode_failure() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

/// Frame a message body for the wire: a `u32` big-endian length prefix followed
/// by the body. The total frame is `4 + body.len()`.
pub fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Read one length-prefixed frame from `stream`, returning its **body** (the
/// bytes after the 4-byte length). Enforces [`MAX_FRAME_LEN`] before allocating,
/// so a forged length cannot exhaust memory. `Ok(None)` on a clean EOF at a
/// frame boundary (the peer closed the connection).
///
/// FUZZ TARGET (Phase 4): drive this with arbitrary stream contents.
pub fn read_frame<R: std::io::Read>(stream: &mut R) -> Result<Option<Vec<u8>>, AgentError> {
    let mut len_buf = [0u8; 4];
    if !read_exact_or_eof(stream, &mut len_buf)? {
        // Clean EOF before any byte of a new frame: the peer closed.
        return Ok(None);
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(protocol("zero-length frame"));
    }
    if len > MAX_FRAME_LEN {
        return Err(protocol("frame length exceeds the cap"));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|e| AgentError::Io(e.to_string()))?;
    Ok(Some(body))
}

/// Read exactly `buf.len()` bytes; `Ok(false)` if EOF occurs **before any** byte
/// (a clean connection close at a frame boundary), `Err` on a partial read.
fn read_exact_or_eof<R: std::io::Read>(stream: &mut R, buf: &mut [u8]) -> Result<bool, AgentError> {
    let mut read = 0;
    while read < buf.len() {
        match stream.read(&mut buf[read..]) {
            Ok(0) => {
                if read == 0 {
                    return Ok(false);
                }
                return Err(protocol("unexpected EOF mid-frame"));
            }
            Ok(n) => read += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(AgentError::Io(e.to_string())),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQUEST_IDENTITIES round-trips: a framed request parses back, and the
    // answer encodes to the documented shape.
    #[test]
    fn request_identities_round_trip() {
        let body = vec![SSH_AGENTC_REQUEST_IDENTITIES];
        assert_eq!(parse_request(&body).unwrap(), Request::RequestIdentities);

        let answer = encode_identities_answer(&[Identity {
            key_blob: vec![1, 2, 3],
            comment: "kovra:dev/ssh/deploy".into(),
        }]);
        assert_eq!(answer[0], SSH_AGENT_IDENTITIES_ANSWER);
        // nkeys = 1
        assert_eq!(&answer[1..5], &1u32.to_be_bytes());
    }

    // SIGN_REQUEST round-trips through frame → read_frame → parse_request.
    #[test]
    fn sign_request_round_trip() {
        let mut body = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut body, b"PUBKEYBLOB");
        put_string(&mut body, b"challenge-data");
        body.extend_from_slice(&2u32.to_be_bytes()); // flags = RSA_SHA2_256

        let framed = frame(&body);
        let mut cursor = std::io::Cursor::new(framed);
        let read_body = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(read_body, body);

        match parse_request(&read_body).unwrap() {
            Request::SignRequest {
                key_blob,
                data,
                flags,
            } => {
                assert_eq!(key_blob, b"PUBKEYBLOB");
                assert_eq!(data, b"challenge-data");
                assert_eq!(flags, 2);
            }
            other => panic!("expected SignRequest, got {other:?}"),
        }
    }

    #[test]
    fn sign_response_encodes_signature_string() {
        let resp = encode_sign_response(b"SIGBLOB");
        assert_eq!(resp[0], SSH_AGENT_SIGN_RESPONSE);
        assert_eq!(&resp[1..5], &(b"SIGBLOB".len() as u32).to_be_bytes());
        assert_eq!(&resp[5..], b"SIGBLOB");
    }

    // Defensive contract: a forged string length cannot over-read or panic.
    #[test]
    fn oversized_string_length_is_rejected_not_allocated() {
        let mut body = vec![SSH_AGENTC_SIGN_REQUEST];
        // Claim a 4 GiB string with no bytes following.
        body.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        let err = parse_request(&body).unwrap_err();
        assert!(matches!(err, AgentError::Protocol(_)));
    }

    #[test]
    fn unknown_opcode_is_rejected() {
        // 200 is not a request kovra answers.
        let err = parse_request(&[200]).unwrap_err();
        assert!(matches!(err, AgentError::Protocol(_)));
    }

    #[test]
    fn empty_body_is_rejected() {
        assert!(matches!(
            parse_request(&[]).unwrap_err(),
            AgentError::Protocol(_)
        ));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let body = vec![SSH_AGENTC_REQUEST_IDENTITIES, 0xAA];
        assert!(matches!(
            parse_request(&body).unwrap_err(),
            AgentError::Protocol(_)
        ));
    }

    // read_frame caps the length before allocating.
    #[test]
    fn read_frame_rejects_oversized_length() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((MAX_FRAME_LEN + 1) as u32).to_be_bytes());
        let mut cursor = std::io::Cursor::new(bytes);
        assert!(matches!(
            read_frame(&mut cursor).unwrap_err(),
            AgentError::Protocol(_)
        ));
    }

    // A clean EOF at a frame boundary yields Ok(None), not an error.
    #[test]
    fn read_frame_eof_at_boundary_is_none() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        assert!(read_frame(&mut cursor).unwrap().is_none());
    }

    // A truncated length prefix mid-frame is an error, not a silent close.
    #[test]
    fn read_frame_partial_length_is_error() {
        let mut cursor = std::io::Cursor::new(vec![0u8, 0u8]); // 2 of 4 length bytes
        assert!(read_frame(&mut cursor).is_err());
    }

    // Fuzz-style smoke: a spread of arbitrary inputs never panics; each is
    // either a valid request or a Protocol error.
    #[test]
    fn arbitrary_inputs_never_panic() {
        let samples: &[&[u8]] = &[
            &[],
            &[0],
            &[5],
            &[11],
            &[11, 0],
            &[13],
            &[13, 0, 0, 0, 4],
            &[13, 0, 0, 0, 4, 1, 2, 3, 4],
            &[13, 255, 255, 255, 255],
            &[13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        for s in samples {
            let _ = parse_request(s); // must not panic
        }
    }
}
