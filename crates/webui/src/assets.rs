//! Static front-end assets, embedded into the binary (KOV-29).
//!
//! The Web UI ships **no build step and no runtime CDN**: the vendored Tabulator
//! grid and the first-party `app.js`/`app.css` are compiled into the binary via
//! [`include_str!`], so `kovra ui` is a single self-contained binary that works
//! offline and inside the L11 Docker image unchanged (I9/I10). Updating an asset
//! is a reviewed dependency bump — see `assets/VENDORED.md` for pinned versions
//! and SHA-256/SRI.
//!
//! These routes carry **no secrets**, so they sit *outside* the `/api` session
//! layer (a browser cannot attach the `x-kovra-session` header to a
//! `<script src>` / `<link href>` load) but *inside* the loopback guard, like
//! every other route.

use axum::{Router, http::header, response::IntoResponse, routing::get};

use crate::AppState;

const TABULATOR_JS: &str = include_str!("../assets/tabulator/tabulator.min.js");
const TABULATOR_CSS: &str = include_str!("../assets/tabulator/tabulator.min.css");
const APP_JS: &str = include_str!("../assets/app.js");
const APP_CSS: &str = include_str!("../assets/app.css");

// Brand assets, vendored on purpose (no runtime CDN — see `assets/VENDORED.md`):
// the cobra/keyhole icon (sidebar logo + favicon) and the Sora/Inter latin-subset
// woff2 faces. Binary, so embedded via `include_bytes!`.
const ICON_PNG: &[u8] = include_bytes!("../assets/kovra-icon.png");
const SORA_600: &[u8] = include_bytes!("../assets/fonts/sora-latin-600-normal.woff2");
const INTER_400: &[u8] = include_bytes!("../assets/fonts/inter-latin-400-normal.woff2");
const INTER_500: &[u8] = include_bytes!("../assets/fonts/inter-latin-500-normal.woff2");
const INTER_600: &[u8] = include_bytes!("../assets/fonts/inter-latin-600-normal.woff2");

const JS: &str = "text/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const PNG: &str = "image/png";
const WOFF2: &str = "font/woff2";

/// The `/assets/*` static routes (vendored Tabulator + first-party app shell +
/// brand icon + brand fonts).
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/assets/tabulator/tabulator.min.js", get(tabulator_js))
        .route("/assets/tabulator/tabulator.min.css", get(tabulator_css))
        .route("/assets/app.js", get(app_js))
        .route("/assets/app.css", get(app_css))
        .route("/assets/kovra-icon.png", get(icon_png))
        .route("/assets/fonts/sora-latin-600-normal.woff2", get(sora_600))
        .route("/assets/fonts/inter-latin-400-normal.woff2", get(inter_400))
        .route("/assets/fonts/inter-latin-500-normal.woff2", get(inter_500))
        .route("/assets/fonts/inter-latin-600-normal.woff2", get(inter_600))
}

/// A static text asset response: the embedded body plus its content type.
/// `no-store` keeps the loopback/ephemeral session model honest — nothing is
/// cached to disk.
fn asset(content_type: &'static str, body: &'static str) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
}

/// A static binary asset response (icon / fonts). Same caching posture as
/// [`asset`]; the body is an embedded byte slice.
fn binary(content_type: &'static str, body: &'static [u8]) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
}

async fn tabulator_js() -> impl IntoResponse {
    asset(JS, TABULATOR_JS)
}
async fn tabulator_css() -> impl IntoResponse {
    asset(CSS, TABULATOR_CSS)
}
async fn app_js() -> impl IntoResponse {
    asset(JS, APP_JS)
}
async fn app_css() -> impl IntoResponse {
    asset(CSS, APP_CSS)
}
async fn icon_png() -> impl IntoResponse {
    binary(PNG, ICON_PNG)
}
async fn sora_600() -> impl IntoResponse {
    binary(WOFF2, SORA_600)
}
async fn inter_400() -> impl IntoResponse {
    binary(WOFF2, INTER_400)
}
async fn inter_500() -> impl IntoResponse {
    binary(WOFF2, INTER_500)
}
async fn inter_600() -> impl IntoResponse {
    binary(WOFF2, INTER_600)
}
