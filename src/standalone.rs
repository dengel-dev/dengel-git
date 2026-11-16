//! Standalone listener over an operator-owned catalog of bare repositories.

use crate::http::{
    info_refs_response, presented_token, receive_pack_streaming_response, unauthorized,
    upload_pack_response, MAX_REQUEST_BODY_BYTES,
};
use crate::receive::session::{PublicationAdmission, ReceivePolicy};
use crate::repository_name::normalize_slug;
use axum::body::{to_bytes, Body};
use axum::extract::{Path as RequestPath, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{routing::get, routing::post, Router};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;

pub const MANAGED_BOOTSTRAP_LOCK_FILE: &str = ".managed-git-bootstrap.lock";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepoCredential {
    repository: String,
    token: String,
    access: Access,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Access {
    Read,
    Write,
}

struct Catalog {
    repos: BTreeMap<String, PathBuf>,
    credentials: HashMap<String, Vec<RepoCredential>>,
    loopback_token: Option<String>,
    open_loopback: bool,
    push_slots: Arc<Semaphore>,
}

fn invalid(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason.into())
}

fn repo_slug(raw: &str) -> Option<String> {
    let name = raw.get(..raw.len().checked_sub(4)?)?;
    raw.get(name.len()..)?
        .eq_ignore_ascii_case(".git")
        .then(|| normalize_slug(name))
        .flatten()
}

fn address(parts: &[&str]) -> Option<String> {
    match parts {
        [repo] => repo_slug(repo),
        [org, repo] => Some(format!("{}/{}", normalize_slug(org)?, repo_slug(repo)?)),
        _ => None,
    }
}

fn insert_repo(
    repos: &mut BTreeMap<String, PathBuf>,
    key: String,
    path: PathBuf,
) -> io::Result<()> {
    if !path.join("HEAD").is_file() || !path.join("objects").is_dir() {
        return Err(invalid(format!(
            "{} is not a bare Git repository",
            path.display()
        )));
    }
    if let Some(existing) = repos.insert(key.clone(), path.clone()) {
        return Err(invalid(format!(
            "repository address {key} collides: {} and {}",
            existing.display(),
            path.display()
        )));
    }
    Ok(())
}

fn scan_repositories(root: &Path) -> io::Result<BTreeMap<String, PathBuf>> {
    let mut repos = BTreeMap::new();
    let mut organizations = BTreeMap::new();
    for entry in root.read_dir()? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(repo) = repo_slug(name) {
            insert_repo(&mut repos, repo, entry.path())?;
        } else if let Some(org) = normalize_slug(name) {
            let org_path = entry.path();
            if let Some(existing) = organizations.insert(org.clone(), org_path.clone()) {
                return Err(invalid(format!(
                    "organization address {org} collides: {} and {}",
                    existing.display(),
                    org_path.display()
                )));
            }
            for child in org_path.read_dir()? {
                let child = child?;
                if !child.file_type()?.is_dir() {
                    continue;
                }
                if let Some(repo) = child.file_name().to_str().and_then(repo_slug) {
                    insert_repo(&mut repos, format!("{org}/{repo}"), child.path())?;
                }
            }
        }
    }
    Ok(repos)
}

impl Catalog {
    fn for_listener(
        addr: SocketAddr,
        root: &Path,
        credentials: Vec<RepoCredential>,
        loopback_token: Option<String>,
    ) -> io::Result<Self> {
        if root.join(MANAGED_BOOTSTRAP_LOCK_FILE).exists()
            || root
                .parent()
                .is_some_and(|parent| parent.join(MANAGED_BOOTSTRAP_LOCK_FILE).exists())
        {
            return Err(invalid("refusing to serve a managed Git root"));
        }
        let repos = scan_repositories(root)?;
        for repo in repos.values() {
            crate::receive::recover_repository(repo)?;
            crate::receive::quarantine::sweep_repository(repo);
        }
        let mut scoped: HashMap<String, Vec<RepoCredential>> = HashMap::new();
        for credential in credentials {
            let parts: Vec<_> = credential.repository.split('/').collect();
            let key =
                address(&parts).ok_or_else(|| invalid("invalid credential repository address"))?;
            if !repos.contains_key(&key) || credential.token.trim().is_empty() {
                return Err(invalid(
                    "credential requires a known repository and nonempty token",
                ));
            }
            scoped.entry(key).or_default().push(credential);
        }
        let loopback_token = loopback_token.filter(|token| !token.trim().is_empty());
        if !addr.ip().is_loopback() && (scoped.is_empty() || loopback_token.is_some()) {
            return Err(invalid(
                "network binds require repository-scoped credentials",
            ));
        }
        let open_loopback =
            addr.ip().is_loopback() && scoped.is_empty() && loopback_token.is_none();
        Ok(Self {
            repos,
            credentials: scoped,
            loopback_token,
            open_loopback,
            push_slots: Arc::new(Semaphore::new(2)),
        })
    }

    fn authorize(
        &self,
        path: &[String],
        headers: &HeaderMap,
        write: bool,
    ) -> Result<&Path, StatusCode> {
        let segments = path.iter().map(String::as_str).collect::<Vec<_>>();
        let key = address(&segments).ok_or(StatusCode::NOT_FOUND)?;
        let supplied = presented_token(headers);
        let allows_token = supplied.as_ref().is_some_and(|token| {
            self.loopback_token
                .as_ref()
                .is_some_and(|expected| token_eq(token, expected))
                || self.credentials.get(&key).is_some_and(|entries| {
                    entries.iter().any(|credential| {
                        token_eq(token, &credential.token)
                            && (!write || matches!(credential.access, Access::Write))
                    })
                })
        });
        if !self.open_loopback && !allows_token {
            return Err(StatusCode::UNAUTHORIZED);
        }
        self.repos
            .get(&key)
            .map(PathBuf::as_path)
            .ok_or(StatusCode::NOT_FOUND)
    }
}

fn token_eq(left: &str, right: &str) -> bool {
    crate::http::constant_time_eq(left.as_bytes(), right.as_bytes())
}

pub async fn serve(addr: SocketAddr, root: PathBuf) -> io::Result<()> {
    let root = root.canonicalize()?;
    let credentials = match std::env::var_os("DENGEL_GIT_TOKEN_FILE") {
        Some(path) => {
            let file = std::fs::File::open(path)?;
            let grants: Vec<RepoCredential> = serde_json::from_reader(file)
                .map_err(|_| invalid("invalid Git credential file"))?;
            if grants.is_empty() {
                return Err(invalid("configured Git credential file has no grants"));
            }
            grants
        }
        None => Vec::new(),
    };
    let catalog = Arc::new(Catalog::for_listener(
        addr,
        &root,
        credentials,
        std::env::var("DENGEL_GIT_TOKEN").ok(),
    )?);
    let app = Router::new()
        .route("/{repo}/info/refs", get(info_refs))
        .route("/{repo}/git-upload-pack", post(upload))
        .route("/{repo}/git-receive-pack", post(receive))
        .route("/{org}/{repo}/info/refs", get(info_refs))
        .route("/{org}/{repo}/git-upload-pack", post(upload))
        .route("/{org}/{repo}/git-receive-pack", post(receive))
        .with_state(catalog);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await
}

async fn serve_request(
    catalog: Arc<Catalog>,
    path: Vec<String>,
    headers: HeaderMap,
    write: bool,
    handle: impl FnOnce(&Path, HeaderMap) -> Response + Send + 'static,
) -> Response {
    let git_dir = match catalog.authorize(&path, &headers, write) {
        Ok(dir) => dir.to_owned(),
        Err(StatusCode::UNAUTHORIZED) => return unauthorized(),
        Err(status) => return status.into_response(),
    };
    tokio::task::spawn_blocking(move || handle(&git_dir, headers))
        .await
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn info_refs(
    State(catalog): State<Arc<Catalog>>,
    RequestPath(path): RequestPath<Vec<String>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let write = query.as_deref() == Some("service=git-receive-pack");
    serve_request(catalog, path, headers, write, move |dir, _| {
        info_refs_response(dir, query.as_deref())
    })
    .await
}

async fn upload(
    State(catalog): State<Arc<Catalog>>,
    RequestPath(path): RequestPath<Vec<String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let git_dir = match catalog.authorize(&path, &headers, false) {
        Ok(dir) => dir.to_owned(),
        Err(StatusCode::UNAUTHORIZED) => return unauthorized(),
        Err(status) => return status.into_response(),
    };
    let body = match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(error) => {
            let status = if std::error::Error::source(&error)
                .is_some_and(|cause| cause.is::<http_body_util::LengthLimitError>())
            {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            };
            return status.into_response();
        }
    };
    tokio::task::spawn_blocking(move || upload_pack_response(&git_dir, &headers, body))
        .await
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn receive(
    State(catalog): State<Arc<Catalog>>,
    RequestPath(path): RequestPath<Vec<String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let git_dir = match catalog.authorize(&path, &headers, true) {
        Ok(dir) => dir.to_owned(),
        Err(StatusCode::UNAUTHORIZED) => return unauthorized(),
        Err(status) => return status.into_response(),
    };
    let Ok(slot) = catalog.push_slots.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    tokio::task::spawn_blocking(move || {
        let _slot = slot;
        receive_pack_streaming_response(
            &git_dir,
            &headers,
            body,
            MAX_REQUEST_BODY_BYTES,
            &ReceivePolicy::default(),
            || Ok(PublicationAdmission::new(None, ())),
        )
    })
    .await
    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare(dir: &Path) {
        std::fs::create_dir_all(dir.join("objects")).unwrap();
        std::fs::write(dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    }

    #[test]
    fn mixed_case_addresses_resolve_and_collisions_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let existing = root.path().join("Foo/Bar.git");
        bare(&existing);
        let addr = "127.0.0.1:0".parse().unwrap();
        let catalog = Catalog::for_listener(addr, root.path(), vec![], None).unwrap();
        for path in [["Foo", "Bar.git"], ["foo", "bar.git"]] {
            assert_eq!(
                catalog.authorize(&path.map(str::to_owned), &HeaderMap::new(), true),
                Ok(existing.as_path())
            );
        }
        let duplicate = root.path().join("Foo/bar.git");
        if !duplicate.exists() {
            bare(&duplicate);
            let result = Catalog::for_listener(addr, root.path(), vec![], None);
            assert!(matches!(result, Err(error) if error.to_string().contains("collides")));
        }
    }

    #[test]
    fn scoped_read_token_cannot_push_or_access_another_repo() {
        let root = tempfile::tempdir().unwrap();
        bare(&root.path().join("Repo.git"));
        bare(&root.path().join("Other.git"));
        let addr = "0.0.0.0:0".parse().unwrap();
        assert!(Catalog::for_listener(addr, root.path(), vec![], None).is_err());
        let catalog = Catalog::for_listener(
            addr,
            root.path(),
            vec![RepoCredential {
                repository: "repo.git".into(),
                token: "test-read-token".into(),
                access: Access::Read,
            }],
            None,
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-read-token".parse().unwrap());
        assert!(catalog
            .authorize(&["Repo.git".into()], &headers, false)
            .is_ok());
        assert_eq!(
            catalog.authorize(&["Repo.git".into()], &headers, true),
            Err(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(
            catalog.authorize(&["Other.git".into()], &headers, false),
            Err(StatusCode::UNAUTHORIZED)
        );
    }
}
