pub mod auth;
pub mod buildinfo;
pub mod cli;
pub mod config;
pub mod control;
pub mod dbbackup;
pub mod httpapi;
pub mod logring;
pub mod master;
pub mod model;
pub mod node;
pub mod store;
pub mod tunnel;

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::sync::Arc;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    use crate::auth::{KeyStore, ROLE_ADMIN};
    use crate::cli;
    use crate::config::{self, Config};
    use crate::control::{
        EnrollRequest, EnrollResponse, EventsRequest, EventsResponse, PullRequest, PATH_ENROLL,
        PATH_EVENTS, PATH_PULL,
    };
    use crate::httpapi::{Api, WebPersistConfig};
    use crate::logring::Ring;
    use crate::master;
    use crate::model::{
        ConnectEndpoint, LocalTLS, Mapping, Node, Snapshot, XHTTP,
    };
    use crate::node;
    use crate::store::Store;
    use crate::tunnel;

    struct ForbiddenHelpInput;
    impl Read for ForbiddenHelpInput {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            panic!("help read stdin");
        }
    }

    #[tokio::test]
    async fn test_cli_help_and_keys() {
        let mut help_cases: Vec<Vec<String>> = vec![
            vec!["--help".into()],
            vec!["-h".into()],
            vec!["help".into()],
        ];
        for cmd in [
            "master", "server", "client", "keys", "version", "x25519", "mldsa65", "vlessenc",
        ] {
            for flag in ["--help", "-h", "help"] {
                help_cases.push(vec![cmd.into(), flag.into()]);
            }
            help_cases.push(vec!["help".into(), cmd.into()]);
        }

        for args in help_cases {
            let mut out = Vec::new();
            let res = cli::run_with_input(
                CancellationToken::new(),
                &args,
                &mut ForbiddenHelpInput,
                &mut out,
            )
            .await;
            assert!(res.is_ok(), "help case {:?} failed: {:?}", args, res);
            let text = String::from_utf8_lossy(&out);
            assert!(text.contains("Usage"), "missing Usage for {:?}: {}", args, text);
            assert!(!text.contains("Private key:"));
        }

        let invalid_cases: Vec<Vec<String>> = vec![
            vec![],
            vec!["help".into(), "unknown".into()],
            vec!["unknown".into(), "--help".into()],
            vec!["help".into(), "master".into(), "extra".into()],
            vec!["--help".into(), "master".into()],
            vec!["master".into(), "--bad".into(), "--help".into()],
            vec!["master".into(), "-embedded-server-port=bad".into(), "-h".into()],
            vec!["client".into(), "--".into(), "-h".into()],
            vec!["server".into(), "extra".into(), "--help".into()],
            vec!["version".into(), "--bad".into()],
            vec!["x25519".into(), "--help".into(), "extra".into()],
            vec!["keys".into(), "unknown".into()],
        ];
        for args in invalid_cases {
            let mut out = Vec::new();
            let res = cli::run_with_input(
                CancellationToken::new(),
                &args,
                &mut ForbiddenHelpInput,
                &mut out,
            )
            .await;
            assert!(res.is_err(), "invalid case {:?} should fail", args);
        }

        let dir = TempDir::new().unwrap();
        let db = dir.path().join("db").to_string_lossy().into_owned();
        let key = dir.path().join("key").to_string_lossy().into_owned();

        // keys list fails on missing database
        let mut out = Vec::new();
        assert!(cli::run(
            CancellationToken::new(),
            &[
                "keys".into(),
                "-database".into(),
                db.clone(),
                "-deployment-key".into(),
                key.clone(),
                "list".into()
            ],
            &mut out
        )
        .await
        .is_err());

        let s = Store::open(&db, &key).unwrap();
        drop(s);

        out.clear();
        cli::run(
            CancellationToken::new(),
            &[
                "keys".into(),
                "create".into(),
                "test-key".into(),
                "-database".into(),
                db.clone(),
                "-deployment-key".into(),
                key.clone(),
            ],
            &mut out,
        )
        .await
        .unwrap();
        assert!(String::from_utf8_lossy(&out).contains("vlk_"));

        out.clear();
        cli::run(
            CancellationToken::new(),
            &[
                "keys".into(),
                "list".into(),
                "-database".into(),
                db.clone(),
                "-deployment-key".into(),
                key.clone(),
            ],
            &mut out,
        )
        .await
        .unwrap();
        assert!(String::from_utf8_lossy(&out).contains("test-key"));
    }

    #[test]
    fn test_xhttp_auto_negotiation_and_validation() {
        let x_reality = XHTTP {
            path: "/veilink/".into(),
            mode: "auto".into(),
            ..Default::default()
        };
        assert_eq!(tunnel::xhttp_effective_mode(&x_reality, true), "stream-one");

        let x_h3 = XHTTP {
            path: "/veilink/".into(),
            mode: "auto".into(),
            http_version: "3".into(),
            tls: true,
            ..Default::default()
        };
        assert_eq!(tunnel::xhttp_effective_mode(&x_h3, false), "packet-up");

        let x_cdn = XHTTP {
            path: "/veilink/".into(),
            mode: "auto".into(),
            host: "cdn.example.com".into(),
            ..Default::default()
        };
        assert_eq!(tunnel::xhttp_effective_mode(&x_cdn, false), "packet-up");

        let x_download = XHTTP {
            path: "/veilink/".into(),
            mode: "auto".into(),
            download_endpoint_id: "down-ep".into(),
            ..Default::default()
        };
        assert_eq!(tunnel::xhttp_effective_mode(&x_download, true), "stream-up");
        assert_eq!(tunnel::xhttp_effective_mode(&x_download, false), "packet-up");

        let (dec, _, _, _) = tunnel::generate_vless_enc().unwrap();
        let tls_auto = LocalTLS {
            transport_security: "plain".into(),
            decryption: dec,
            listen_port: 18443,
            xhttp: x_cdn,
            ..Default::default()
        };
        assert!(tunnel::check_bootstrap("server", &tls_auto).is_ok());
    }

    #[tokio::test]
    async fn test_pure_http_control_plane_and_httpapi() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("veilink.db").to_string_lossy().into_owned();
        let key = dir.path().join("veilink.key").to_string_lossy().into_owned();
        let store = Arc::new(Store::open(&db, &key).unwrap());
        let ks = KeyStore::new(store.db());
        ks.migrate().unwrap();
        let admin_key = ks.create("admin", ROLE_ADMIN).unwrap();

        let ring = Arc::new(Ring::new(500));
        let api = Api::new(
            Arc::clone(&store),
            true,
            Some(Arc::clone(&ring)),
            WebPersistConfig {
                db_path: db.clone(),
                html_dir: String::new(),
            },
        );

        // 1. Create server & client nodes via management API
        let (dec, _, _, _) = tunnel::generate_vless_enc().unwrap();
        let srv_node = store
            .save_node(Node {
                id: "srv-1".into(),
                name: "Server 1".into(),
                role: "server".into(),
                address: "127.0.0.1".into(),
                port: 19443,
                tunnel: LocalTLS {
                    transport_security: "plain".into(),
                    decryption: dec,
                    listen_port: 19443,
                    ..Default::default()
                },
                connect_endpoints: vec![ConnectEndpoint {
                    id: "ep-1".into(),
                    name: "local".into(),
                    host: "127.0.0.1".into(),
                    port: 19443,
                    enabled: true,
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(srv_node.id, "srv-1");

        let token = store
            .enroll_token("srv-1", Duration::from_secs(300))
            .unwrap();

        // 2. Test pure HTTP control enroll (no API key needed, Nginx proxy friendly)
        let enroll_req = Request::builder()
            .method(Method::POST)
            .uri(PATH_ENROLL)
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EnrollRequest {
                    node_id: "srv-1".into(),
                    token,
                })
                .unwrap(),
            ))
            .unwrap();
        let enroll_resp = api.handle(enroll_req).await;
        assert_eq!(enroll_resp.status(), StatusCode::OK);
        let enroll_bytes = axum::body::to_bytes(enroll_resp.into_body(), 64 << 10)
            .await
            .unwrap();
        let enroll_out: EnrollResponse = serde_json::from_slice(&enroll_bytes).unwrap();
        assert!(!enroll_out.credential.is_empty());

        // 3. Test pure HTTP control pull
        let pull_req = Request::builder()
            .method(Method::POST)
            .uri(PATH_PULL)
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&PullRequest {
                    node_id: "srv-1".into(),
                    credential: enroll_out.credential.clone(),
                })
                .unwrap(),
            ))
            .unwrap();
        let pull_resp = api.handle(pull_req).await;
        assert_eq!(pull_resp.status(), StatusCode::OK);
        let pull_bytes = axum::body::to_bytes(pull_resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let snap: Snapshot = serde_json::from_slice(&pull_bytes).unwrap();
        assert_eq!(snap.node.id, "srv-1");

        // 4. Test pure HTTP control events & instant wakeup on request_refresh
        let api_clone = api.clone();
        let cred_clone = enroll_out.credential.clone();
        let rev = snap.revision;
        let poll_handle = tokio::spawn(async move {
            let ev_req = Request::builder()
                .method(Method::POST)
                .uri(format!("{}?wait_ms=5000", PATH_EVENTS))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&EventsRequest {
                        node_id: "srv-1".into(),
                        credential: cred_clone,
                        applied_revision: rev,
                        software_version: "0.4.12".into(),
                        software_commit: "abc1234".into(),
                        ..Default::default()
                    })
                    .unwrap(),
                ))
                .unwrap();
            let resp = api_clone.handle(ev_req).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let b = axum::body::to_bytes(resp.into_body(), 64 << 10)
                .await
                .unwrap();
            serde_json::from_slice::<EventsResponse>(&b).unwrap()
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(store.control_connected("srv-1"));

        let refresh_req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/nodes/srv-1/refresh")
            .header("Authorization", format!("Bearer {}", admin_key))
            .header("Content-Type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let refresh_resp = api.handle(refresh_req).await;
        assert_eq!(refresh_resp.status(), StatusCode::OK);

        let ev_out = tokio::time::timeout(Duration::from_secs(2), poll_handle)
            .await
            .unwrap()
            .unwrap();
        assert!(ev_out.refresh);
    }

    #[tokio::test]
    async fn test_three_roles_end_to_end_over_http_control_and_tunnel() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // 1. Start echo backend service for client to reach
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target_listener.local_addr().unwrap().port() as i32;
        tokio::spawn(async move {
            while let Ok((mut s, _)) = target_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = s.read(&mut buf).await {
                        let _ = s.write_all(&buf[..n]).await;
                    }
                });
            }
        });

        // Reserve free ports for server tunnel & public mapping
        let srv_tunnel_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port() as i64
        };
        let public_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port() as i64
        };
        let master_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let master_addr = format!("127.0.0.1:{}", master_port);

        let dir = TempDir::new().unwrap();
        let db = dir.path().join("master.db").to_string_lossy().into_owned();
        let key = dir.path().join("master.key").to_string_lossy().into_owned();

        let store = Store::open(&db, &key).unwrap();
        let (dec_e2e, _, _, _) = tunnel::generate_vless_enc().unwrap();
        store
            .save_node(Node {
                id: "srv-e2e".into(),
                name: "Server E2E".into(),
                role: "server".into(),
                address: "127.0.0.1".into(),
                port: srv_tunnel_port,
                tunnel: LocalTLS {
                    transport_security: "plain".into(),
                    decryption: dec_e2e,
                    listen_port: srv_tunnel_port,
                    ..Default::default()
                },
                connect_endpoints: vec![ConnectEndpoint {
                    id: "ep1".into(),
                    name: "local".into(),
                    host: "127.0.0.1".into(),
                    port: srv_tunnel_port,
                    enabled: true,
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
        store
            .save_node(Node {
                id: "cli-e2e".into(),
                name: "Client E2E".into(),
                role: "client".into(),
                ..Default::default()
            })
            .unwrap();
        store
            .save_mapping(Mapping {
                id: "map-e2e".into(),
                name: "Echo Mapping".into(),
                server_id: "srv-e2e".into(),
                client_id: "cli-e2e".into(),
                connect_endpoint_id: "ep1".into(),
                listen_host: "127.0.0.1".into(),
                listen_port: public_port,
                target_host: "127.0.0.1".into(),
                target_port: target_port as i64,
                network: "tcp".into(),
                pool: 1,
                enabled: true,
                ..Default::default()
            })
            .unwrap();
        let srv_token = store
            .enroll_token("srv-e2e", Duration::from_secs(300))
            .unwrap();
        let cli_token = store
            .enroll_token("cli-e2e", Duration::from_secs(300))
            .unwrap();
        drop(store);

        let cancel = CancellationToken::new();

        // Start Master
        let master_cfg = Config {
            listen_addr: master_addr.clone(),
            scheme: "http".into(),
            database: db.clone(),
            deployment_key: key.clone(),
            state_dir: dir.path().join("master-state").to_string_lossy().into_owned(),
            ..config::defaults()
        };
        let master_cancel = cancel.child_token();
        let master_handle = tokio::spawn(async move {
            master::run(master_cancel, master_cfg).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Start Server Node
        let srv_cfg = Config {
            master_addr: master_addr.clone(),
            node_id: "srv-e2e".into(),
            enroll_token: srv_token,
            state_dir: dir.path().join("srv-state").to_string_lossy().into_owned(),
            ..Default::default()
        };
        let srv_cancel = cancel.child_token();
        let srv_handle = tokio::spawn(async move {
            let _ = node::run(srv_cancel, srv_cfg, "server").await;
        });

        // Start Client Node
        let cli_cfg = Config {
            master_addr: master_addr.clone(),
            node_id: "cli-e2e".into(),
            enroll_token: cli_token,
            state_dir: dir.path().join("cli-state").to_string_lossy().into_owned(),
            ..Default::default()
        };
        let cli_cancel = cancel.child_token();
        let cli_handle = tokio::spawn(async move {
            let _ = node::run(cli_cancel, cli_cfg, "client").await;
        });

        // Wait until tunnel reverse link is established and public_port echoes payload
        let mut ok = false;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Ok(mut conn) =
                tokio::net::TcpStream::connect(format!("127.0.0.1:{}", public_port)).await
            {
                if conn.write_all(b"hello-veilink-rust").await.is_ok() {
                    let mut buf = [0u8; 18];
                    if conn.read_exact(&mut buf).await.is_ok() && &buf == b"hello-veilink-rust" {
                        ok = true;
                        break;
                    }
                }
            }
        }
        assert!(ok, "end-to-end tunnel echo failed");

        // Repeated short-lived connections must keep working over the same
        // session after per-stream cleanup on both ends.
        for i in 0..20u8 {
            let mut conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", public_port))
                .await
                .unwrap();
            let msg = [b'v', i];
            conn.write_all(&msg).await.unwrap();
            let mut buf = [0u8; 2];
            tokio::time::timeout(Duration::from_secs(2), conn.read_exact(&mut buf))
                .await
                .expect("echo timeout")
                .unwrap();
            assert_eq!(buf, msg);
        }

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(3), master_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(3), srv_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(3), cli_handle).await;
    }

    #[tokio::test]
    async fn test_https_h2_control_and_multi_node_logs_preserved() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("master.db").to_string_lossy().into_owned();
        let key = dir.path().join("master.key").to_string_lossy().into_owned();

        // Generate a self-signed TLS certificate for localhost
        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        let cert_path = dir.path().join("master.crt");
        let key_path = dir.path().join("master.key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        let srv_tunnel_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port() as i64
        };
        let emb_tunnel_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port() as i64
        };
        let public_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port() as i64
        };
        let master_port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let master_addr = format!("127.0.0.1:{}", master_port);

        let store = Store::open(&db, &key).unwrap();
        let ks = KeyStore::new(store.db());
        ks.migrate().unwrap();
        let admin_key = ks.create("admin", ROLE_ADMIN).unwrap();

        let (dec_e2e, _, _, _) = tunnel::generate_vless_enc().unwrap();
        store
            .save_node(Node {
                id: "srv-https".into(),
                name: "Server HTTPS".into(),
                role: "server".into(),
                address: "127.0.0.1".into(),
                port: srv_tunnel_port,
                tunnel: LocalTLS {
                    transport_security: "plain".into(),
                    decryption: dec_e2e,
                    listen_port: srv_tunnel_port,
                    ..Default::default()
                },
                connect_endpoints: vec![ConnectEndpoint {
                    id: "ep1".into(),
                    name: "local".into(),
                    host: "127.0.0.1".into(),
                    port: srv_tunnel_port,
                    enabled: true,
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
        store
            .save_node(Node {
                id: "cli-https".into(),
                name: "Client HTTPS".into(),
                role: "client".into(),
                ..Default::default()
            })
            .unwrap();
        store
            .save_mapping(Mapping {
                id: "map-https".into(),
                name: "HTTPS Mapping".into(),
                server_id: "srv-https".into(),
                client_id: "cli-https".into(),
                connect_endpoint_id: "ep1".into(),
                listen_host: "127.0.0.1".into(),
                listen_port: public_port,
                target_host: "127.0.0.1".into(),
                target_port: 9,
                network: "tcp".into(),
                pool: 1,
                enabled: true,
                ..Default::default()
            })
            .unwrap();
        let srv_token = store
            .enroll_token("srv-https", Duration::from_secs(300))
            .unwrap();
        let cli_token = store
            .enroll_token("cli-https", Duration::from_secs(300))
            .unwrap();
        drop(store);

        let cancel = CancellationToken::new();
        let mut master_cfg = Config {
            listen_addr: master_addr.clone(),
            scheme: "https".into(),
            cert_file: cert_path.to_string_lossy().into_owned(),
            key_file: key_path.to_string_lossy().into_owned(),
            control_ca: cert_path.to_string_lossy().into_owned(),
            control_server_name: "localhost".into(),
            database: db.clone(),
            deployment_key: key.clone(),
            state_dir: dir.path().join("master-state").to_string_lossy().into_owned(),
            ..config::defaults()
        };
        master_cfg.embedded_server.port = emb_tunnel_port;

        let master_cancel = cancel.child_token();
        let master_handle = tokio::spawn(async move {
            master::run(master_cancel, master_cfg).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(150)).await;

        let srv_cfg = Config {
            master_addr: master_addr.clone(),
            control_ca: cert_path.to_string_lossy().into_owned(),
            control_server_name: "localhost".into(),
            node_id: "srv-https".into(),
            enroll_token: srv_token,
            state_dir: dir.path().join("srv-state").to_string_lossy().into_owned(),
            ..Default::default()
        };
        let srv_cancel = cancel.child_token();
        let srv_handle = tokio::spawn(async move {
            let _ = node::run(srv_cancel, srv_cfg, "server").await;
        });

        let cli_cfg = Config {
            master_addr: master_addr.clone(),
            control_ca: cert_path.to_string_lossy().into_owned(),
            control_server_name: "localhost".into(),
            node_id: "cli-https".into(),
            enroll_token: cli_token,
            state_dir: dir.path().join("cli-state").to_string_lossy().into_owned(),
            ..Default::default()
        };
        let cli_cancel = cancel.child_token();
        let cli_handle = tokio::spawn(async move {
            let _ = node::run(cli_cancel, cli_cfg, "client").await;
        });

        // Wait across an embedded heartbeat interval (>2.2s) to ensure embedded default
        // node does not drain or overwrite srv-https / cli-https / master logs.
        tokio::time::sleep(Duration::from_millis(2400)).await;

        let probe_client = node::HttpControlClient::new(&Config {
            master_addr: master_addr.clone(),
            control_ca: cert_path.to_string_lossy().into_owned(),
            control_server_name: "localhost".into(),
            ..Default::default()
        })
        .unwrap();
        // Verify we can also query /api/v1/logs via HTTPS using rustls + hyper
        let mut root_store = rustls::RootCertStore::empty();
        let cert_pem = cert.cert.pem();
        let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut reader).map(|r| r.unwrap()).collect();
        root_store.add_parsable_certificates(certs);
        let mut tls_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
        let tcp = tokio::net::TcpStream::connect(&master_addr).await.unwrap();
        let sni = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
        let tls = connector.connect(sni, tcp).await.unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        let (mut sender, conn) =
            hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("https://localhost:{}/api/v1/logs?limit=200", master_port))
            .header("Authorization", format!("Bearer {}", admin_key))
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        use http_body_util::BodyExt as _;
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let entries: Vec<crate::logring::Entry> = serde_json::from_slice(&body_bytes).unwrap();

        assert!(
            entries.iter().any(|e| e.source == "master"),
            "master logs should be preserved: {:?}",
            entries
        );
        assert!(
            entries.iter().any(|e| e.node_id == "srv-https"),
            "srv-https logs should be preserved: {:?}",
            entries
        );
        assert!(
            entries.iter().any(|e| e.node_id == "cli-https"),
            "cli-https logs should be preserved: {:?}",
            entries
        );
        assert!(
            entries.iter().any(|e| e.node_id == "srv-https" && e.message.contains("server tunnel session established")),
            "server tunnel session log should be recorded: {:?}",
            entries
        );
        assert!(
            entries.iter().any(|e| e.node_id == "cli-https" && e.message.contains("client tunnel connected")),
            "client tunnel connected log should be recorded: {:?}",
            entries
        );

        // Verify manual node refresh (/api/v1/nodes/{id}/refresh) wakes the node and gets immediate report
        for nid in ["srv-https", "cli-https"] {
            let refresh_req = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "https://localhost:{}/api/v1/nodes/{}/refresh",
                    master_port, nid
                ))
                .header("Authorization", format!("Bearer {}", admin_key))
                .header("Content-Type", "application/json")
                .body(http_body_util::Full::new(bytes::Bytes::from_static(b"{}")))
                .unwrap();
            let refresh_resp = sender.send_request(refresh_req).await.unwrap();
            assert_eq!(refresh_resp.status(), StatusCode::OK);
            let refresh_bytes = refresh_resp
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes();
            let refresh_json: serde_json::Value =
                serde_json::from_slice(&refresh_bytes).unwrap();
            assert_eq!(
                refresh_json.get("connected").and_then(|v| v.as_bool()),
                Some(true),
                "node {} should be connected: {:?}",
                nid,
                refresh_json
            );
            assert_eq!(
                refresh_json.get("reported").and_then(|v| v.as_bool()),
                Some(true),
                "node {} should report immediately on refresh: {:?}",
                nid,
                refresh_json
            );
        }
        drop(probe_client);

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(3), master_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(3), srv_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(3), cli_handle).await;
    }

    #[tokio::test]
    async fn test_shared_mapping_bandwidth_limit_and_concurrent_streams() {
        // 8 Mbps = 1_000_000 bytes/sec (50ms burst = 50_000 bytes)
        let limiter = crate::tunnel::BandwidthLimiter::new(1_000_000);
        assert_eq!(limiter.read_size(16377), 16377);

        // Run 4 concurrent tasks each pushing 75_000 bytes (total 300_000 bytes).
        // With 50_000 byte burst, the remaining 250_000 bytes at 1_000_000 B/s must take ~250ms
        // (whereas per-connection unshared limiters would finish in ~25ms).
        let start = std::time::Instant::now();
        let mut handles = Vec::new();
        for _ in 0..4 {
            let lim = Arc::clone(&limiter);
            handles.push(tokio::spawn(async move {
                for _ in 0..5 {
                    lim.wait(15_000).await;
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(200),
            "shared limiter across 4 concurrent streams was too fast: {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_millis(600),
            "shared limiter across 4 concurrent streams was too slow: {:?}",
            elapsed
        );
    }
}
