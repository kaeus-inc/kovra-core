//! Error mapping from the Rust core to Python exceptions.
//!
//! The single I13-critical rule lives here: an **out-of-scope** coordinate and a
//! **genuinely absent** one map to the *same* exception ([`KovraNotFound`]), so
//! a model can never distinguish "you may not address this" from "this does not
//! exist". A policy refusal of an addressable secret is a distinct
//! [`KovraDenied`] (used by the reveal/inject surfaces).

use kovra_core::CoreError;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(
    kovra_ffi,
    KovraError,
    PyException,
    "Base class for all kovra binding errors."
);
create_exception!(
    kovra_ffi,
    KovraNotFound,
    KovraError,
    "The coordinate is not addressable in this session — either out of scope \
     (I13) or absent. The two are deliberately indistinguishable."
);
create_exception!(
    kovra_ffi,
    KovraDenied,
    KovraError,
    "An addressable secret was refused by policy (e.g. an MCP reveal of a \
     high/prod/inject-only value, I11/I14)."
);

/// The binding-side error type. Converts into the right Python exception.
#[derive(Debug, thiserror::Error)]
pub enum FfiError {
    /// Out-of-scope (I13) or genuinely absent — indistinguishable on purpose.
    #[error("not addressable")]
    NotFound,
    /// Policy refused an addressable operation; carries the reason for the
    /// message only (never a value, I12).
    #[error("denied: {0}")]
    Denied(String),
    /// A configuration / input problem (bad scope, bad coordinate, missing init).
    #[error("{0}")]
    Config(String),
    /// An error from the core.
    #[error(transparent)]
    Core(#[from] CoreError),
}

impl From<FfiError> for PyErr {
    fn from(e: FfiError) -> Self {
        match e {
            FfiError::NotFound => KovraNotFound::new_err("not addressable"),
            FfiError::Denied(reason) => KovraDenied::new_err(reason),
            FfiError::Config(msg) => KovraError::new_err(msg),
            FfiError::Core(err) => KovraError::new_err(err.to_string()),
        }
    }
}

/// Register the exception types on the module.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("KovraError", m.py().get_type::<KovraError>())?;
    m.add("KovraNotFound", m.py().get_type::<KovraNotFound>())?;
    m.add("KovraDenied", m.py().get_type::<KovraDenied>())?;
    Ok(())
}
