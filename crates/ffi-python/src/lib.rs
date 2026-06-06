//! PyO3 bindings exposing `kovra-core` to Python — the native half of the L9
//! MCP server (spec §9.4, §14). This crate is a **thin adapter**: it builds
//! requests, calls the core's policy funnel, and marshals results to Python.
//! It re-derives no policy (spec §2/§15); every reveal/scope rule lives in
//! `kovra_core::policy`.
//!
//! Surface so far (commit 3): the read/metadata tools — `list`, `status`,
//! `fingerprint` — all routed through `decide(Surface::Mcp)`. Write, reveal,
//! and inject land in the following commits.

mod errors;
mod scope;
mod session;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use session::{RecordView, Session};

/// The native binding version (the crate version). The Python package asserts
/// this on import as a smoke test that the compiled extension matches.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// An agent session bound to a fixed [`scope`](session::Session) and a vault.
///
/// Constructed once per MCP session; the scope cannot be widened afterwards
/// (I13). All methods enforce policy through the core funnel — the binding
/// never decides anything itself.
#[pyclass]
struct KovraSession {
    inner: Session,
}

#[pymethods]
impl KovraSession {
    /// `KovraSession(scope, vault_dir=None, passphrase=None)`.
    ///
    /// `scope` is a dict: `{"operations": ["metadata", ...],
    /// "projects": None|"*"|[...], "environments": None|"*"|[...]}`. `vault_dir`
    /// and `passphrase` fall back to `KOVRA_VAULT_DIR` / `KOVRA_PASSPHRASE`.
    #[new]
    #[pyo3(signature = (scope, vault_dir=None, passphrase=None))]
    fn new(
        scope: &Bound<'_, PyDict>,
        vault_dir: Option<String>,
        passphrase: Option<String>,
    ) -> PyResult<Self> {
        let scope = scope::scope_from_dict(scope)?;
        let inner = Session::open(vault_dir.map(Into::into), scope, passphrase)?;
        Ok(Self { inner })
    }

    /// List metadata for every secret addressable in this session. Out-of-scope
    /// coordinates never appear (I13). No values are returned.
    fn list<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let views = self.inner.list_visible()?;
        let dicts: Vec<Bound<'py, PyDict>> = views
            .iter()
            .map(|v| view_to_dict(py, v))
            .collect::<PyResult<_>>()?;
        PyList::new(py, dicts)
    }

    /// Metadata for one coordinate (diagnose). Raises `KovraNotFound` for an
    /// out-of-scope *or* absent coordinate — the two are indistinguishable (I13).
    #[pyo3(signature = (coordinate, project=None))]
    fn status<'py>(
        &self,
        py: Python<'py>,
        coordinate: &str,
        project: Option<&str>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let view = self.inner.status_of(coordinate, project)?;
        view_to_dict(py, &view)
    }

    /// The truncated fingerprint of a coordinate's value. Raises `KovraNotFound`
    /// when not addressable (I13).
    #[pyo3(signature = (coordinate, project=None))]
    fn fingerprint(&self, coordinate: &str, project: Option<&str>) -> PyResult<String> {
        Ok(self.inner.fingerprint_of(coordinate, project)?)
    }

    /// Resolve an `.env.refs` (provided inline) and run `program args...` with
    /// the values injected into the child's environment — never into the model's
    /// context (I7). High/prod injection needs the executor allowlisted (I15) and
    /// an attended `kovra approve` (I3/I16). Returns `{status, stdout, stderr}`
    /// with vault values masked (§5.1).
    ///
    /// `client_identity` is the trusted caller identity the MCP server passes for
    /// the I16 confirmation prompt (§8.3) — e.g. the agent/client/session name it
    /// authenticated. It is rendered as the *requesting process* on the attended
    /// dialog so the human sees who is asking, rather than always "kovra". It
    /// must be a server-authored fact, never the agent's own free text (which is
    /// the separately fenced `requester_description`), and never a secret value.
    // Each parameter is a distinct Python keyword argument, so they cannot be
    // folded into a struct without changing the tool's call signature.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (refs, env, program, args=Vec::new(), project=None, client_identity=None))]
    fn inject_run<'py>(
        &self,
        py: Python<'py>,
        refs: &str,
        env: &str,
        program: &str,
        args: Vec<String>,
        project: Option<&str>,
        client_identity: Option<&str>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let out = self
            .inner
            .inject_run(refs, env, program, &args, project, client_identity)?;
        let d = PyDict::new(py);
        d.set_item("status", out.status)?;
        d.set_item("stdout", PyBytes::new(py, &out.stdout))?;
        d.set_item("stderr", PyBytes::new(py, &out.stderr))?;
        Ok(d)
    }

    /// Reveal a value into the agent's context — returns raw `bytes`. Only a
    /// `revealable`, non-prod, non-high literal is ever returned (I11); `prod`,
    /// `high`, and `inject-only` raise `KovraDenied` (I14), and an out-of-scope
    /// coordinate raises `KovraNotFound` (I13).
    #[pyo3(signature = (coordinate, project=None))]
    fn reveal<'py>(
        &self,
        py: Python<'py>,
        coordinate: &str,
        project: Option<&str>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let value = self.inner.reveal(coordinate, project)?;
        Ok(PyBytes::new(py, &value))
    }

    /// Create or update a literal value. The value crosses as a tool argument,
    /// never argv (I6). Returns the new metadata (no value). `prod` is born
    /// `high` (I5).
    #[pyo3(signature = (coordinate, value, project=None))]
    fn set<'py>(
        &self,
        py: Python<'py>,
        coordinate: &str,
        value: &str,
        project: Option<&str>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let view = self.inner.set(coordinate, value, project)?;
        view_to_dict(py, &view)
    }

    /// Generate a random value server-side and store it. Returns metadata only —
    /// the value is never returned to the model (I6, AC3).
    #[pyo3(signature = (coordinate, length=32, sensitivity=None, description=None, project=None))]
    fn generate<'py>(
        &self,
        py: Python<'py>,
        coordinate: &str,
        length: usize,
        sensitivity: Option<&str>,
        description: Option<String>,
        project: Option<&str>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let view = self
            .inner
            .generate(coordinate, length, sensitivity, description, project)?;
        view_to_dict(py, &view)
    }

    /// Delete a secret. Raises `KovraNotFound` when out of scope or absent (I13).
    #[pyo3(signature = (coordinate, project=None))]
    fn delete(&self, coordinate: &str, project: Option<&str>) -> PyResult<()> {
        self.inner.delete(coordinate, project)?;
        Ok(())
    }

    /// Edit metadata (sensitivity / description / revealable / reference). A
    /// sensitivity downgrade is separately audited (I5). Returns the new metadata.
    // Each parameter is a distinct Python keyword argument, so they cannot be
    // folded into a struct without changing the tool's call signature.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (coordinate, sensitivity=None, description=None, revealable=None, reference=None, project=None))]
    fn edit_metadata<'py>(
        &self,
        py: Python<'py>,
        coordinate: &str,
        sensitivity: Option<&str>,
        description: Option<String>,
        revealable: Option<bool>,
        reference: Option<String>,
        project: Option<&str>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let view = self.inner.edit_metadata(
            coordinate,
            sensitivity,
            description,
            revealable,
            reference,
            project,
        )?;
        view_to_dict(py, &view)
    }
}

/// Marshal a value-free [`RecordView`] into a Python dict.
fn view_to_dict<'py>(py: Python<'py>, v: &RecordView) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("coordinate", &v.coordinate)?;
    d.set_item("environment", &v.environment)?;
    d.set_item("component", &v.component)?;
    d.set_item("key", &v.key)?;
    d.set_item("sensitivity", &v.sensitivity)?;
    d.set_item("mode", &v.mode)?;
    d.set_item("fingerprint", &v.fingerprint)?;
    d.set_item("revealable", v.revealable)?;
    d.set_item("origin", &v.origin)?;
    d.set_item("reference", &v.reference)?;
    Ok(d)
}

/// The `kovra_ffi` extension module.
#[pymodule]
fn kovra_ffi(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_class::<KovraSession>()?;
    errors::register(m)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_matches_crate() {
        assert_eq!(super::version(), env!("CARGO_PKG_VERSION"));
        assert!(!super::version().is_empty());
    }
}
