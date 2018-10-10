#![feature(generators, proc_macro_hygiene)]

extern crate dirs;
extern crate futures_await as futures;
extern crate hyper;
extern crate hyper_rustls;
extern crate net2;
extern crate pem;
#[macro_use]
extern crate prettytable;
extern crate rustls;
extern crate structopt;
extern crate structopt_derive;
#[macro_use]
extern crate tera;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_process;
extern crate tokio_rustls;
extern crate tokio_service;

extern crate ct_tools;

use ct_tools::common::{sha256_hex, Log};
use ct_tools::ct::submit_cert_to_logs;
use ct_tools::google::{fetch_all_ct_logs, fetch_trusted_ct_logs};
use ct_tools::{crtsh, letsencrypt};
use futures::prelude::await;
use futures::prelude::*;
use net2::unix::UnixTcpBuilderExt;
use rustls::Session;
use std::fs::{self, File};
use std::io::Read;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use structopt::StructOpt;
use tokio_core::reactor::Handle;
use tokio_process::CommandExt;

fn pems_to_chain(data: &[u8]) -> Vec<Vec<u8>> {
    pem::parse_many(data)
        .into_iter()
        .filter(|p| p.tag == "CERTIFICATE")
        .map(|p| p.contents)
        .collect()
}

fn new_http_client(
) -> hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>> {
    hyper::Client::builder().build(hyper_rustls::HttpsConnector::new(4))
}

fn compute_paths(paths: &[String]) -> Vec<String> {
    paths
        .into_iter()
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

fn submit(paths: &[String], all_logs: bool) {
    let mut core = tokio_core::reactor::Core::new().unwrap();
    let http_client = Rc::new(new_http_client());

    let logs = Rc::new(if all_logs {
        core.run(fetch_all_ct_logs(&http_client)).unwrap()
    } else {
        core.run(fetch_trusted_ct_logs(&http_client)).unwrap()
    });

    let all_paths = compute_paths(paths);

    let work: Box<Future<Item = (), Error = ()>> = Box::new(
        futures::stream::futures_ordered(all_paths.iter().map(|path| {
            let path = path.to_string();

            let mut contents = Vec::new();
            File::open(&path)
                .unwrap()
                .read_to_end(&mut contents)
                .unwrap();

            let mut chain = pems_to_chain(&contents);
            let http_client = Rc::clone(&http_client);
            let logs = Rc::clone(&logs);
            let handle = core.handle();
            async_block! {
                if chain.len() == 1 {
                    // TODO: There's got to be some way to do this ourselves, instead of using crt.sh
                    // as a glorified AIA chaser.
                    println!(
                        "[{}] Only one certificate in chain, using crt.sh to build a full chain ...",
                        &path
                    );
                    let new_chain = await!(crtsh::build_chain_for_cert(&http_client, &chain[0]));
                    chain = match new_chain {
                        Ok(c) => c,
                        Err(()) => {
                            println!("[{}] Unable to build a chain", path);
                            return Ok(futures::future::ok(()));
                        }
                    }
                }
                println!("[{}] Submitting ...", &path);
                let timeout = Duration::from_secs(30);
                let scts = await!(
                    submit_cert_to_logs(handle, &http_client, &logs, &chain, timeout)
                ).unwrap();

                if !scts.is_empty() {
                    println!(
                        "[{}] Find the cert on crt.sh: {}",
                        path,
                        crtsh::url_for_cert(&chain[0])
                    );
                    let mut table = prettytable::Table::new();
                    table.add_row(row!["Log"]);
                    for (log_idx, _) in scts {
                        let log = &logs[log_idx];
                        table.add_row(row![log.description]);
                    }
                    table.printstd();
                    println!();
                    println!();
                } else {
                    println!("[{}] No SCTs obtained", &path);
                }

                Ok(futures::future::ok(()))
            }
        })).buffered(4)
            .for_each(|()| futures::future::ok(())),
    );
    core.run(work).unwrap();
}

fn check(paths: &[String]) {
    let mut core = tokio_core::reactor::Core::new().unwrap();
    let http_client = new_http_client();

    let all_paths = compute_paths(paths);

    let work: Box<futures::Future<Item = (), Error = ()>> = Box::new(
        futures::stream::futures_ordered(all_paths.iter().map(|path| {
            let path = path.to_string();
            let mut contents = Vec::new();
            File::open(&path)
                .unwrap()
                .read_to_end(&mut contents)
                .unwrap();

            let chain = pems_to_chain(&contents);
            let is_logged: Box<Future<Item = bool, Error = ()>> = if chain.is_empty() {
                Box::new(futures::future::ok(false))
            } else {
                Box::new(crtsh::is_cert_logged(&http_client, &chain[0]))
            };
            async_block! {
                if await!(is_logged).unwrap() {
                    println!("{} was already logged", path);
                } else {
                    println!("{} has not been logged", path);
                }
                Ok(futures::future::ok(()))
            }
        }))
        .buffered(16)
        .for_each(|()| futures::future::ok(())),
    );
    core.run(work).unwrap();
}

struct HttpHandler<C: hyper::client::connect::Connect> {
    handle: tokio_core::reactor::Handle,
    templates: Arc<tera::Tera>,
    http_client: Arc<hyper::Client<C>>,
    logs: Arc<Vec<Log>>,

    client_certs: Option<Vec<rustls::Certificate>>,
}

#[async]
fn handle_request<C: hyper::client::connect::Connect + 'static>(
    request: hyper::Request<hyper::Body>,
    templates: Arc<tera::Tera>,
    http_client: Arc<hyper::Client<C>>,
    logs: Arc<Vec<Log>>,
    handle: tokio_core::reactor::Handle,
    client_certs: Option<Vec<rustls::Certificate>>,
) -> Result<hyper::Response<hyper::Body>, hyper::Error> {
    let mut crtsh_url = None;
    let mut rendered_cert = None;
    if let Some(peer_chain) = client_certs {
        if request.method() == &hyper::Method::POST {
            if let Ok(chain) = await!(crtsh::build_chain_for_cert(&http_client, &peer_chain[0].0)) {
                let timeout = Duration::from_secs(5);
                let scts = await!(submit_cert_to_logs(
                    handle.clone(),
                    &http_client,
                    &logs,
                    &chain,
                    timeout
                ))
                .unwrap();
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
            .spawn_async_with_handle(handle.new_tokio_handle())
            .unwrap();
        let cert_bytes = peer_chain[0].0.clone();
        await!(tokio_io::io::write_all(
            process.stdin().take().unwrap(),
            cert_bytes,
        ))
        .unwrap();
        let out = await!(process.wait_with_output()).unwrap();
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

impl<C: hyper::client::connect::Connect + 'static> hyper::service::Service for HttpHandler<C> {
    type ReqBody = hyper::Body;
    type ResBody = hyper::Body;
    type Error = hyper::Error;
    type Future = Box<Future<Item = hyper::Response<Self::ResBody>, Error = Self::Error>>;

    fn call(&mut self, request: hyper::Request<hyper::Body>) -> Self::Future {
        Box::new(handle_request(
            request,
            Arc::clone(&self.templates),
            Arc::clone(&self.http_client),
            Arc::clone(&self.logs),
            self.handle.clone(),
            self.client_certs.clone(),
        ))
    }
}

struct NoVerificationCertificateVerifier;
impl rustls::ClientCertVerifier for NoVerificationCertificateVerifier {
    fn verify_client_cert(
        &self,
        _: &[rustls::Certificate],
    ) -> Result<rustls::ClientCertVerified, rustls::TLSError> {
        Ok(rustls::ClientCertVerified::assertion())
    }

    fn client_auth_root_subjects(&self) -> rustls::DistinguishedNames {
        rustls::DistinguishedNames::new()
    }
}

fn server(local_dev: bool, domain: Option<&str>, letsencrypt_env: Option<&str>) {
    match (local_dev, domain, letsencrypt_env) {
        (true, Some(_), _) | (true, _, Some(_)) => {
            panic!("Can't use both --local-dev and --letsencrypt-env or --domain")
        }
        (_, Some(_), None) | (_, None, Some(_)) => {
            panic!("When using Let's Encrypt, must set both --letsencrypt-env and --domain")
        }
        (false, _, None) => panic!("Must set at least one of --local-dev or --letsencrypt-env"),
        _ => {}
    };

    // Disable certificate verification. In any normal context, this would be horribly insecure!
    // However, all we're doing is taking the certs and then turning around and submitting them to
    // CT logs, so it doesn't matter if they're verified.
    let mut tls_config = rustls::ServerConfig::new(Arc::new(NoVerificationCertificateVerifier));
    if local_dev {
        // TODO: not all the details on the cert are perfect, but it's fine.
        let (cert, pkey) = letsencrypt::generate_temporary_cert("localhost");
        tls_config.set_single_cert(
            vec![letsencrypt::openssl_cert_to_rustls(&cert)],
            letsencrypt::openssl_pkey_to_rustls(&pkey),
        );
    } else {
        let letsencrypt_url = match letsencrypt_env.unwrap() {
            "prod" => "https://acme-v01.api.letsencrypt.org/directory",
            "dev" => "https://acme-staging.api.letsencrypt.org/directory",
            _ => unreachable!(),
        };
        let cert_cache = letsencrypt::DiskCache::new(
            dirs::home_dir()
                .unwrap()
                .join(".ct-tools")
                .join("certificates"),
        );
        tls_config.cert_resolver = Arc::new(letsencrypt::AutomaticCertResolver::new(
            letsencrypt_url,
            vec![domain.unwrap().to_string()],
            cert_cache,
        ));
    }
    tls_config.set_persistence(rustls::ServerSessionMemoryCache::new(1024));
    tls_config.ticketer = rustls::Ticketer::new();

    let mut core = tokio_core::reactor::Core::new().unwrap();
    let http_client = new_http_client();
    let logs = Arc::new(core.run(fetch_trusted_ct_logs(&http_client)).unwrap());
    let templates = Arc::new(compile_templates!("templates/*"));

    let addr = if local_dev {
        "127.0.0.1:1337"
    } else {
        "0.0.0.0:443"
    };

    // If there aren't at least two threads, the Let's Encrypt integration will deadlock.
    println!("Listening on https://{} ...", addr);
    serve_https(
        addr.parse().unwrap(),
        tls_config,
        16,
        move |handle, tls_session| {
            let http_client = new_http_client();
            HttpHandler {
                templates: Arc::clone(&templates),
                http_client: Arc::new(http_client),
                logs: Arc::clone(&logs),
                handle: handle.clone(),

                client_certs: tls_session.get_peer_certificates(),
            }
        },
    );
}

fn serve_https<F, S>(
    addr: SocketAddr,
    tls_config: rustls::ServerConfig,
    threads: usize,
    new_service: F,
) where
    F: Fn(&Handle, &rustls::ServerSession) -> S + Sync + Send + 'static,
    S: hyper::service::Service<ReqBody = hyper::Body, ResBody = hyper::Body, Error = hyper::Error>
        + 'static,
    S::Future: Send,
{
    let tls_config = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let new_service = Arc::new(new_service);
    let threads = (0..threads - 1)
        .map(|i| {
            let new_service = Arc::clone(&new_service);
            thread::Builder::new()
                .name(format!("worker{}", i))
                .spawn(move || {
                    _serve(addr, tls_config, &*new_service);
                })
                .unwrap()
        })
        .collect::<Vec<_>>();

    _serve(addr, tls_config, &*new_service);
    for t in threads {
        t.join().unwrap();
    }
}

fn _serve<F, S>(addr: SocketAddr, tls_config: tokio_rustls::TlsAcceptor, new_service: &F)
where
    F: Fn(&Handle, &rustls::ServerSession) -> S,
    S: hyper::service::Service<ReqBody = hyper::Body, ResBody = hyper::Body, Error = hyper::Error>
        + 'static,
    S::Future: Send,
{
    let mut core = tokio_core::reactor::Core::new().unwrap();
    let handle = core.handle();

    let listener = match addr {
        SocketAddr::V4(_) => net2::TcpBuilder::new_v4().unwrap(),
        SocketAddr::V6(_) => net2::TcpBuilder::new_v6().unwrap(),
    };
    listener.reuse_port(true).unwrap();
    listener.reuse_address(true).unwrap();
    listener.bind(addr).unwrap();
    let work = tokio_core::net::TcpListener::from_listener(
        listener.listen(1024).unwrap(),
        &addr,
        &core.handle(),
    )
    .unwrap()
    .incoming()
    .for_each(move |(sock, addr)| {
        let handle = handle.clone();
        tls_config
            .accept(sock)
            .map_err(|_| ())
            .and_then(move |s| {
                let http = hyper::server::conn::Http::new();
                let service = new_service(&handle, s.get_ref().1);
                let conn = http.serve_connection(s, service);
                hyper::rt::spawn(conn);
                Ok(())
            })
            .or_else(|()| Ok(()))
    });
    core.run(work).unwrap();
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
        #[structopt(
            long = "letsencrypt-env",
            raw(possible_values = "&[\"dev\", \"prod\"]"),
            help = "Let's Encrypt environment to use"
        )]
        letsencrypt_env: Option<String>,
    },
}

fn main() {
    match Opt::from_args() {
        Opt::Submit { paths, all_logs } => {
            submit(&paths, all_logs);
        }
        Opt::Check { paths } => {
            check(&paths);
        }
        Opt::Server {
            local_dev,
            domain,
            letsencrypt_env,
        } => {
            server(
                local_dev,
                domain.as_ref().map(|s| s.as_ref()),
                letsencrypt_env.as_ref().map(|s| s.as_ref()),
            );
        }
    }
}
