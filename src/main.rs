use ct_tools::common::{sha256_hex, Log};
use ct_tools::crtsh;
use ct_tools::ct::submit_cert_to_logs;
use ct_tools::google::{fetch_all_ct_logs, fetch_trusted_ct_logs};
use futures::stream::{StreamExt, TryStreamExt};
use rustls::Session;
use std::fs::{self, File};
use std::io::Read;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

fn pems_to_chain(data: &[u8]) -> Vec<Vec<u8>> {
    pem::parse_many(data)
        .into_iter()
        .filter(|p| p.tag == "CERTIFICATE")
        .map(|p| p.contents)
        .collect()
}

fn compute_paths(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .flat_map(|p| {
            if fs::metadata(p).unwrap().is_dir() {
                fs::read_dir(p)
                    .unwrap()
                    .map(|d| d.unwrap().path().to_str().unwrap().to_string())
                    .collect()
            } else {
                vec![p.clone()]
            }
        })
        .collect()
}

async fn submit(paths: &[String], all_logs: bool) {
    let http_client = reqwest::Client::new();

    let logs = if all_logs {
        fetch_all_ct_logs(&http_client).await
    } else {
        fetch_trusted_ct_logs(&http_client).await
    };

    let all_paths = compute_paths(paths);

    let work = futures::stream::iter(all_paths.iter().map(|path| {
        let path = path.to_string();
        let mut contents = Vec::new();
        File::open(&path)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();

        let http_client = &http_client;
        let logs = &logs;
        let mut chain = pems_to_chain(&contents);
        async move {
            if chain.len() == 1 {
                // TODO: There's got to be some way to do this ourselves, instead of using crt.sh
                // as a glorified AIA chaser.
                println!(
                    "[{}] Only one certificate in chain, using crt.sh to build a full chain ...",
                    &path
                );
                let new_chain = crtsh::build_chain_for_cert(&http_client, &chain[0]).await;
                chain = match new_chain {
                    Ok(c) => c,
                    Err(()) => {
                        println!("[{}] Unable to build a chain", path);
                        return;
                    }
                }
            }
            println!("[{}] Submitting ...", &path);
            let timeout = Duration::from_secs(30);
            let scts = submit_cert_to_logs(&http_client, &logs, &chain, timeout).await;

            if !scts.is_empty() {
                println!(
                    "[{}] Find the cert on crt.sh: {}",
                    path,
                    crtsh::url_for_cert(&chain[0])
                );
                let mut table = prettytable::Table::new();
                table.add_row(prettytable::Row::new(vec![prettytable::Cell::new("Log")]));
                for (log_idx, _) in scts {
                    let log = &logs[log_idx];
                    table.add_row(prettytable::Row::new(vec![prettytable::Cell::new(
                        &log.description,
                    )]));
                }
                table.printstd();
                println!();
                println!();
            } else {
                println!("[{}] No SCTs obtained", &path);
            }
        }
    }))
    .buffer_unordered(4)
    .for_each(|_| async {});
    work.await;
}

async fn check(paths: &[String]) {
    let http_client = reqwest::Client::new();

    let all_paths = compute_paths(paths);

    let work = futures::stream::iter(all_paths.iter().map(|path| {
        let path = path.to_string();
        let mut contents = Vec::new();
        File::open(&path)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();

        let http_client = &http_client;
        let chain = pems_to_chain(&contents);
        async move {
            if !chain.is_empty() && crtsh::is_cert_logged(&http_client, &chain[0]).await {
                println!("{} was already logged", path);
            } else {
                println!("{} has not been logged", path);
            }
        }
    }))
    .buffer_unordered(16)
    .for_each(|_| async {});
    work.await;
}

async fn handle_request(
    request: hyper::Request<hyper::Body>,
    templates: Arc<tera::Tera>,
    http_client: Arc<reqwest::Client>,
    logs: Arc<[Log]>,
    client_cert: Option<rustls::Certificate>,
) -> Result<hyper::Response<hyper::Body>, hyper::Error> {
    let mut crtsh_url = None;
    let mut rendered_cert = None;
    if let Some(cert) = client_cert {
        if request.method() == hyper::Method::POST {
            if let Ok(chain) = crtsh::build_chain_for_cert(&http_client, &cert.0).await {
                let timeout = Duration::from_secs(5);
                let scts = submit_cert_to_logs(&http_client, &logs, &chain, timeout).await;
                if !scts.is_empty() {
                    crtsh_url = Some(crtsh::url_for_cert(&chain[0]));
                    println!("Successfully submitted: {}", sha256_hex(&chain[0]));
                }
            }
        }

        let mut process = Command::new("openssl")
            .arg("x509")
            .arg("-text")
            .arg("-noout")
            .arg("-inform")
            .arg("der")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let cert_bytes = cert.0.clone();
        AsyncWriteExt::write_all(&mut process.stdin.as_mut().unwrap(), &cert_bytes)
            .await
            .unwrap();
        let out = process.wait_with_output().await.unwrap();
        rendered_cert = Some(String::from_utf8_lossy(&out.stdout).into_owned());
    }

    let mut context = tera::Context::new();
    context.insert("cert", &rendered_cert);
    context.insert("crtsh_url", &crtsh_url);
    let body = templates.render("home.html", &context).unwrap();
    Ok(hyper::Response::builder()
        .status(hyper::StatusCode::OK)
        .body(body.into())
        .unwrap())
}

struct NoVerificationCertificateVerifier;
impl rustls::ClientCertVerifier for NoVerificationCertificateVerifier {
    fn client_auth_mandatory(&self, _: Option<&webpki::DNSName>) -> Option<bool> {
        Some(false)
    }

    fn verify_client_cert(
        &self,
        _: &[rustls::Certificate],
        _: Option<&webpki::DNSName>,
    ) -> Result<rustls::ClientCertVerified, rustls::TLSError> {
        Ok(rustls::ClientCertVerified::assertion())
    }

    fn client_auth_root_subjects(
        &self,
        _: Option<&webpki::DNSName>,
    ) -> Option<rustls::DistinguishedNames> {
        Some(rustls::DistinguishedNames::new())
    }
}

pub fn generate_temporary_cert(
    domain: &str,
) -> (
    openssl::x509::X509,
    openssl::pkey::PKey<openssl::pkey::Private>,
) {
    let pkey = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let mut cert_builder = openssl::x509::X509Builder::new().unwrap();
    cert_builder.set_version(2).unwrap();
    cert_builder.set_pubkey(&pkey).unwrap();

    let mut serial = openssl::bn::BigNum::new().unwrap();
    serial
        .rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    cert_builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    let mut subject_builder = openssl::x509::X509NameBuilder::new().unwrap();
    subject_builder
        .append_entry_by_text("CN", "ACME SNI Challenge Certificate")
        .unwrap();
    let subject = subject_builder.build();
    cert_builder.set_subject_name(&subject).unwrap();
    cert_builder.set_issuer_name(&subject).unwrap();

    cert_builder
        .set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert_builder
        .set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
        .unwrap();

    let mut san = openssl::x509::extension::SubjectAlternativeName::new();
    san.dns(domain);
    let san_ext = san.build(&cert_builder.x509v3_context(None, None)).unwrap();
    cert_builder.append_extension(san_ext).unwrap();

    cert_builder
        .sign(&pkey, openssl::hash::MessageDigest::sha256())
        .unwrap();

    (cert_builder.build(), pkey)
}

pub fn openssl_cert_to_rustls(cert: &openssl::x509::X509) -> rustls::Certificate {
    rustls::Certificate(cert.to_der().unwrap())
}

pub fn openssl_pkey_to_rustls(
    pkey: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> rustls::PrivateKey {
    rustls::PrivateKey(pkey.rsa().unwrap().private_key_to_der().unwrap())
}

async fn server(local_dev: bool, domain: Option<&str>) {
    // Disable certificate verification. In any normal context, this would be horribly insecure!
    // However, all we're doing is taking the certs and then turning around and submitting them to
    // CT logs, so it doesn't matter if they're verified.
    let mut tls_config = rustls::ServerConfig::new(Arc::new(NoVerificationCertificateVerifier));
    if local_dev {
        let (cert, pkey) = generate_temporary_cert(domain.unwrap_or("localhost"));
        tls_config
            .set_single_cert(
                vec![openssl_cert_to_rustls(&cert)],
                openssl_pkey_to_rustls(&pkey),
            )
            .unwrap();
    } else {
        panic!("Real TLS is not quite working at the moment");
    }
    tls_config.set_persistence(rustls::ServerSessionMemoryCache::new(1024));
    tls_config.ticketer = rustls::Ticketer::new();

    let http_client = Arc::new(reqwest::Client::new());
    let logs = Arc::from(fetch_trusted_ct_logs(&http_client).await);
    let templates = Arc::new(tera::Tera::new("templates/*").unwrap());

    let addr = if local_dev {
        "0.0.0.0:8000"
    } else {
        "0.0.0.0:443"
    }
    .parse()
    .unwrap();

    // If there aren't at least two threads, the Let's Encrypt integration will deadlock.
    println!("Listening on https://{} ...", addr);
    let sock_domain = match addr {
        SocketAddr::V4(_) => socket2::Domain::ipv4(),
        SocketAddr::V6(_) => socket2::Domain::ipv6(),
    };
    let socket = socket2::Socket::new(sock_domain, socket2::Type::stream(), None).unwrap();
    socket.set_reuse_port(true).unwrap();
    socket.set_reuse_address(true).unwrap();
    socket.bind(&socket2::SockAddr::from(addr)).unwrap();
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let listener = tokio::net::TcpListener::from_std(socket.into_tcp_listener()).unwrap();
    let connections = tokio_stream::wrappers::TcpListenerStream::new(listener)
        .and_then(move |sock| tls_acceptor.accept(sock))
        .filter(move |s| futures::future::ready(s.is_ok()))
        .boxed();
    let server = hyper::Server::builder(hyper::server::accept::from_stream(connections)).serve(
        hyper::service::make_service_fn(
            move |conn: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>| {
                let http_client = Arc::clone(&http_client);
                let templates = Arc::clone(&templates);
                let logs = Arc::clone(&logs);
                let client_cert = conn
                    .get_ref()
                    .1
                    .get_peer_certificates()
                    .map(|mut chain| chain.remove(0));

                async {
                    Ok::<_, hyper::Error>(hyper::service::service_fn(
                        move |r: hyper::Request<hyper::Body>| {
                            handle_request(
                                r,
                                Arc::clone(&templates),
                                Arc::clone(&http_client),
                                Arc::clone(&logs),
                                client_cert.clone(),
                            )
                        },
                    ))
                }
            },
        ),
    );

    server.await.unwrap()
}

#[derive(StructOpt)]
#[structopt(name = "ct-tools")]
enum Opt {
    #[structopt(name = "submit", about = "Directly submits certificates to CT logs")]
    Submit {
        #[structopt(
            long = "all-logs",
            help = "Submit to all logs, instead of just ones trusted by Chrome"
        )]
        all_logs: bool,
        #[structopt(help = "Path to certificate or chain")]
        paths: Vec<String>,
    },

    #[structopt(
        name = "check",
        about = "Checks whether a certificate exists in CT logs"
    )]
    Check {
        #[structopt(help = "Path to certificate or chain")]
        paths: Vec<String>,
    },

    #[structopt(
        name = "server",
        about = "Run an HTTPS server that submits client certificates to CT logs"
    )]
    Server {
        #[structopt(
            long = "--local-dev",
            help = "Local development, do not obtain a certificate"
        )]
        local_dev: bool,
        #[structopt(long = "domain", help = "Domain this is running as")]
        domain: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    match Opt::from_args() {
        Opt::Submit { paths, all_logs } => {
            submit(&paths, all_logs).await;
        }
        Opt::Check { paths } => {
            check(&paths).await;
        }
        Opt::Server { local_dev, domain } => {
            server(local_dev, domain.as_ref().map(|s| s.as_ref())).await;
        }
    }
}
