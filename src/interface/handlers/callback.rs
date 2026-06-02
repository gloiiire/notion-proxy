use axum::{
    extract::Query,
    response::{IntoResponse, Redirect},
};
use serde::Deserialize;

// Notion requires HTTPS redirect URIs since 2024, so the iOS app's custom
// `pinkha://` scheme can no longer be registered directly with Notion.
// Instead, this HTTPS endpoint is what Notion redirects to after the user
// consents, and we immediately bounce the browser to `pinkha://oauth/notion`
// with the same query string. iOS's `ASWebAuthenticationSession` is watching
// for that scheme and snaps back into the app.
//
// No HMAC: this is a browser-initiated GET, not a signed app request. The
// `code` carried by Notion is single-use and short-lived, so there's nothing
// for an attacker to replay.

#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub async fn oauth_callback(Query(q): Query<OAuthCallbackQuery>) -> impl IntoResponse {
    let mut target = String::from("pinkha://oauth/notion");
    let mut sep = '?';
    for (name, value) in [
        ("code", q.code.as_deref()),
        ("state", q.state.as_deref()),
        ("error", q.error.as_deref()),
    ] {
        if let Some(v) = value {
            let encoded = urlencoding::encode(v);
            target.push(sep);
            target.push_str(name);
            target.push('=');
            target.push_str(&encoded);
            sep = '&';
        }
    }
    Redirect::temporary(&target)
}
