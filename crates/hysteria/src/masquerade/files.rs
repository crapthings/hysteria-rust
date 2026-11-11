//! Directory indexes supplement `ServeDir`; file streaming and range handling stay upstream.
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Method, Request, Response, StatusCode, header},
    middleware::{self, Next},
    response::IntoResponse,
};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, percent_encode};
use std::{
    fmt::Write as _,
    path::{Component, PathBuf},
};
use tower_http::services::ServeDir;

const MAX_DIRECTORY_ENTRIES: usize = 10_000;

pub(super) fn router(root: PathBuf) -> Router {
    let listing = Router::new().fallback(serve).with_state(root.clone());
    Router::new()
        .fallback_service(ServeDir::new(root).fallback(listing))
        .layer(middleware::from_fn(directory_redirect))
}

// ServeDir uses 307 for directory slash redirects; Go FileServer uses 301.
// Preserve query strings but never emit a scheme-relative redirect from // paths.
async fn directory_redirect(request: Request<Body>, next: Next) -> Response<Body> {
    let uri = request.uri().clone();
    let mut response = next.run(request).await;
    if response.status() == StatusCode::TEMPORARY_REDIRECT {
        let mut location = format!("/{}/", uri.path().trim_start_matches('/'));
        if let Some(query) = uri.query() {
            location.push('?');
            location.push_str(query);
        }
        let Ok(location) = http::HeaderValue::from_str(&location) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        *response.status_mut() = StatusCode::MOVED_PERMANENTLY;
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

fn local_path(root: &std::path::Path, uri: &http::Uri) -> Option<PathBuf> {
    let decoded = percent_decode_str(uri.path()).decode_utf8().ok()?;
    let mut path = root.to_path_buf();
    for segment in decoded.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        // Match ServeDir's traversal rejection and reject Windows separators
        // on every platform rather than giving URLs platform-dependent meaning.
        if segment == ".."
            || segment.contains(['\\', '\0'])
            || !std::path::Path::new(segment)
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
        {
            return None;
        }
        path.push(segment);
    }
    Some(path)
}

async fn serve(State(root): State<PathBuf>, request: Request<Body>) -> Response<Body> {
    let Some(path) = local_path(&root, request.uri()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if matches!(*request.method(), Method::GET | Method::HEAD)
        && tokio::fs::metadata(&path)
            .await
            .is_ok_and(|meta| meta.is_dir())
        && matches!(tokio::fs::metadata(path.join("index.html")).await, Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return directory(&path, request).await;
    }
    StatusCode::NOT_FOUND.into_response()
}

async fn directory(path: &std::path::Path, request: Request<Body>) -> Response<Body> {
    let Ok(mut directory) = tokio::fs::read_dir(path).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let mut entries = Vec::new();
    loop {
        match directory.next_entry().await {
            Ok(Some(entry)) => {
                if entries.len() == MAX_DIRECTORY_ENTRIES {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                let is_dir = entry.metadata().await.is_ok_and(|meta| meta.is_dir());
                let mut href = percent_encode(name.as_bytes(), NON_ALPHANUMERIC).to_string();
                if is_dir {
                    href.push('/');
                }
                entries.push((name, href, is_dir));
            }
            Ok(None) => break,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
    entries.sort_unstable();
    let mut html = String::from(
        "<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n",
    );
    for (mut name, href, is_dir) in entries {
        if is_dir {
            name.push('/');
        }
        writeln!(html, "<a href=\"{href}\">{}</a>", super::html_escape(&name))
            .expect("writing a String cannot fail");
    }
    html.push_str("</pre>\n");
    let length = html.len().to_string();
    let body = if request.method() == Method::HEAD {
        Body::empty()
    } else {
        Body::from(html)
    };
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CONTENT_LENGTH, &length),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt;

    async fn get(root: &std::path::Path, method: &str, uri: &str) -> Response<Body> {
        router(root.to_path_buf())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn directory_lists_sorted_escaped_entries_and_preserves_file_semantics() {
        let root = tempfile::tempdir().unwrap();
        tokio::fs::write(root.path().join("z.txt"), "abcdef")
            .await
            .unwrap();
        tokio::fs::write(root.path().join("a & b.txt"), "space")
            .await
            .unwrap();
        tokio::fs::create_dir(root.path().join("nested"))
            .await
            .unwrap();
        let listing = get(root.path(), "GET", "/").await;
        assert_eq!(listing.status(), StatusCode::OK);
        assert_eq!(
            listing.headers()[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        let body = listing.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("href=\"a%20%26%20b%2Etxt\">a &amp; b.txt</a>"));
        assert!(text.find("a &amp;").unwrap() < text.find("nested/").unwrap());
        assert!(text.find("nested/").unwrap() < text.find("z.txt").unwrap());
        let head = get(root.path(), "HEAD", "/").await;
        assert_eq!(
            head.headers()[header::CONTENT_LENGTH],
            body.len().to_string()
        );
        assert!(
            head.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        let redirect = get(root.path(), "GET", "/nested?x=1").await;
        assert_eq!(redirect.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(redirect.headers()[header::LOCATION], "/nested/?x=1");
        let redirect = get(root.path(), "GET", "//nested?x=1").await;
        assert_eq!(redirect.headers()[header::LOCATION], "/nested/?x=1");
        assert_eq!(
            get(root.path(), "GET", "/missing/").await.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get(root.path(), "POST", "/").await.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            get(root.path(), "GET", "/a%20%26%20b.txt")
                .await
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            "space"
        );
        let range = router(root.path().to_path_buf())
            .oneshot(
                Request::builder()
                    .uri("/z.txt")
                    .header(header::RANGE, "bytes=1-3")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(range.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(range.into_body().collect().await.unwrap().to_bytes(), "bcd");
        tokio::fs::write(root.path().join("index.html"), "homepage")
            .await
            .unwrap();
        assert_eq!(
            get(root.path(), "GET", "/")
                .await
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            "homepage"
        );
    }

    #[tokio::test]
    async fn traversal_and_html_injection_are_not_served_as_paths_or_markup() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("public");
        tokio::fs::create_dir(&root).await.unwrap();
        tokio::fs::write(parent.path().join("private.txt"), "private")
            .await
            .unwrap();
        for uri in [
            "/../private.txt",
            "/%2e%2e/private.txt",
            "/%2e%2e%2fprivate.txt",
            "/%2e%2e%5cprivate.txt",
            "/%00",
        ] {
            assert_eq!(
                get(&root, "GET", uri).await.status(),
                StatusCode::NOT_FOUND,
                "{uri}"
            );
        }
        #[cfg(unix)]
        {
            tokio::fs::write(root.join("<script>.txt"), "x")
                .await
                .unwrap();
            let body = get(&root, "GET", "/")
                .await
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes();
            let text = std::str::from_utf8(&body).unwrap();
            assert!(!text.contains("<script>"));
            assert!(text.contains("&lt;script&gt;.txt"));
            assert!(text.contains("%3Cscript%3E%2Etxt"));
        }
    }
}
