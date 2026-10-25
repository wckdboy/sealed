//! Sealed API server.

use tracing_subscriber::EnvFilter;
use vault_api::{app, build_state, Config};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=warn".into()),
        )
        .with_target(false)
        .init();

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };

    if cfg.dev {
        tracing::warn!(
            "VAULT_DEV=1: relaxed defaults (premium tier, localhost bind). \
             Secrets are still generated once and persisted to {} — never deploy this mode silently.",
            cfg.secret_dir.display()
        );
    }
    tracing::info!(bind = %cfg.bind, blob_dir = %cfg.blob_dir.display(), "starting vault-api");

    let state = match build_state(cfg.clone()).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("startup failed: {e}");
            std::process::exit(1);
        }
    };

    let listener = match tokio::net::TcpListener::bind(&cfg.bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind {}: {e}", cfg.bind);
            std::process::exit(1);
        }
    };
    tracing::info!(
        "listening on http://{}",
        listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    );

    // `into_make_service_with_connect_info` gives every request its peer address,
    // which is what per-IP rate limiting keys on when there is no proxy in front.
    let service = app(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
    if let Err(e) = axum::serve(listener, service).await {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}
