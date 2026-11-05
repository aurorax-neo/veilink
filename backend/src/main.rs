use std::io::Write;
use std::process;

use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cancel = CancellationToken::new();
    let sig_cancel = cancel.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).ok();
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = async {
                    if let Some(ref mut s) = sigterm {
                        s.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        sig_cancel.cancel();
    });

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdout = std::io::stdout();
    if let Err(err) = veilink::cli::run(cancel, &args, &mut stdout).await {
        let _ = stdout.flush();
        eprintln!(
            "{{\"level\":\"ERROR\",\"msg\":\"veilink stopped\",\"error\":{}}}",
            serde_json::to_string(&err).unwrap_or_else(|_| "\"error\"".to_string())
        );
        process::exit(1);
    }
}
