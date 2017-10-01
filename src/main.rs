#![feature(conservative_impl_trait, generators, proc_macro)]

extern crate clap;
extern crate hyper;
extern crate hyper_rustls;
extern crate pem;
#[macro_use]
extern crate prettytable;
extern crate rustls;
#[macro_use]
extern crate tera;
extern crate tokio_core;
extern crate futures_await as futures;
extern crate tokio_process;
extern crate tokio_service;
extern crate net2;
extern crate tokio_rustls;
extern crate tokio_io;

extern crate ct_tools;

use ct_tools::{crtsh, letsencrypt};
use ct_tools::common::{Log, sha256_hex};
use ct_tools::ct::submit_cert_to_logs;
use ct_tools::google::{fetch_all_ct_logs, fetch_trusted_ct_logs};
use futures::prelude::*;
use net2::unix::UnixTcpBuilderExt;
use rustls::Session;
use std::env;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio_core::reactor::Handle;
use tokio_process::CommandExt;
use tokio_rustls::ServerConfigExt;

fn pems_to_chain(data: &[u8]) -> Vec<Vec<u8>> {
    pem::parse_many(data)
        .into_iter()
        .filter(|p| p.tag == "CERTIFICATE")
        .map(|p| p.contents)
        .collect()
}

fn new_http_client(
    handle: &tokio_core::reactor::Handle,
) -> hyper::Client<hyper_rustls::HttpsConnector> {
    hyper::Client::configure()
        .connector(hyper_rustls::HttpsConnector::new(4, handle))
        .build(handle)
}

fn submit(paths: clap::Values, all_logs: bool) {
    let mut core = tokio_core::reactor::Core::new().unwrap();
    let http_client = Rc::new(new_http_client(&core.handle()));

    let logs = Rc::new(if all_logs {
        core.run(fetch_all_ct_logs(&http_client)).unwrap()
    } else {
        core.run(fetch_trusted_ct_logs(&http_client)).unwrap()
    });

    let work: Box<Future<Item=(), Error=()>> =
            Box::new(futures::stream::futures_ordered(paths.map(|path| {
        let path = path.to_string();

        let mut contents = Vec::new();
        File::open(&path)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();

        let mut chain = pems_to_chain(&contents);
        let http_client = Rc::clone(&http_client);
        let logs = Rc::clone(&logs);
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
            let scts = await!(submit_cert_to_logs(&http_client, &logs, &chain, timeout)).unwrap();

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
    })).buffered(4).for_each(|()| { futures::future::ok(()) }));
    core.run(work).unwrap();
}

fn check(paths: clap::Values) {
    let mut core = tokio_core::reactor::Core::new().unwrap();
    let http_client = new_http_client(&core.handle());

    let work: Box<futures::Future<Item = (), Error = ()>> =
            Box::new(futures::stream::futures_ordered(paths.map(|path| {
        let path = path.to_string();
        let mut contents = Vec::new();
        File::open(&path)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();

        let chain = pems_to_chain(&contents);
        let is_logged: Box<Future<Item=bool, Error=()>> = if chain.is_empty() {
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
    })).buffered(16).for_each(|()| { futures::future::ok(()) }));
    core.run(work).unwrap();
}

struct HttpHandler<C: hyper::client::Connect> {
    handle: tokio_core::reactor::Handle,
    templates: Arc<tera::Tera>,
    http_client: Arc<hyper::Client<C>>,
    logs: Arc<Vec<Log>>,

    client_certs: Option<Vec<rustls::Certificate>>,
}

#[async]
fn handle_request<C: hyper::client::Connect>(
    request: hyper::server::Request,
    templates: Arc<tera::Tera>,
    http_client: Arc<hyper::Client<C>>,
    logs: Arc<Vec<Log>>,
    handle: tokio_core::reactor::Handle,
    client_certs: Option<Vec<rustls::Certificate>>,
) -> Result<hyper::server::Response, hyper::Error> {
    let mut crtsh_url = None;
    let mut rendered_cert = None;
    if let Some(peer_chain) = client_certs {
        if request.method() == &hyper::Method::Post {
            if let Ok(chain) = await!(crtsh::build_chain_for_cert(&http_client, &peer_chain[0].0)) {
                let timeout = Duration::from_secs(5);
                let scts = await!(submit_cert_to_logs(&http_client, &logs, &chain, timeout))
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
            .spawn_async(&handle)
            .unwrap();
        let cert_bytes = peer_chain[0].0.clone();
        await!(tokio_io::io::write_all(
            process.stdin().take().unwrap(),
            cert_bytes,
        )).unwrap();
        let out = await!(process.wait_with_output()).unwrap();
        rendered_cert = Some(String::from_utf8_lossy(&out.stdout).into_owned());
    }

    let mut context = tera::Context::new();
    context.add("cert", &rendered_cert);
    context.add("crtsh_url", &crtsh_url);
    let body = templates.render("home.html", &context).unwrap();
    Ok(hyper::server::Response::new().with_body(body))
}

impl<C: hyper::client::Connect> hyper::server::Service for HttpHandler<C> {
    type Request = hyper::server::Request;
    type Response = hyper::server::Response;
    type Error = hyper::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, request: hyper::server::Request) -> Self::Future {
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
        _: &rustls::RootCertStore,
        _: &[rustls::Certificate],
    ) -> Result<rustls::ClientCertVerified, rustls::TLSError> {
        Ok(rustls::ClientCertVerified::assertion())
    }
}


fn server(local_dev: bool, domain: Option<&str>, letsencrypt_env: Option<&str>) {
    match (local_dev, domain, letsencrypt_env) {
        (true, Some(_), _) |
        (true, _, Some(_)) => {
            panic!("Can't use both --local-dev and --letsencrypt-env or --domain")
        }
        (_, Some(_), None) |
        (_, None, Some(_)) => {
            panic!("When using Let's Encrypt, must set both --letsencrypt-env and --domain")
        }
        (false, _, None) => panic!("Must set at least one of --local-dev or --letsencrypt-env"),
        _ => {}
    };

    let mut tls_config = rustls::ServerConfig::new();
    tls_config.client_auth_offer = true;
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
        let cert_cache =
            letsencrypt::DiskCache::new(env::home_dir().unwrap().join(".ct-tools").join(
                "certificates",
            ));
        tls_config.cert_resolver = Arc::new(letsencrypt::AutomaticCertResolver::new(
            letsencrypt_url,
            vec![domain.unwrap().to_string()],
            cert_cache,
        ));
    }
    tls_config.set_persistence(rustls::ServerSessionMemoryCache::new(1024));
    tls_config.ticketer = rustls::Ticketer::new();
    // Disable certificate verification. In any normal context, this would be horribly insecure!
    // However, all we're doing is taking the certs and then turning around and submitting them to
    // CT logs, so it doesn't matter if they're verified.
    tls_config.dangerous().set_certificate_verifier(Arc::new(
        NoVerificationCertificateVerifier,
    ));

    let mut core = tokio_core::reactor::Core::new().unwrap();
    let http_client = new_http_client(&core.handle());
    let logs = Arc::new(core.run(fetch_trusted_ct_logs(&http_client)).unwrap());
    let templates = Arc::new(compile_templates!("templates/*"));

    let addr = if local_dev {
        "127.0.0.1:1337"
    } else {
        "0.0.0.0:443"
    };

    // If there aren't at least two threads, the Let's Encrypt integration will deadlock.
    println!("Listening on https://{} ...", addr);
    serve_https(addr.parse().unwrap(), tls_config, 16, move |handle,
          tls_session| {
        let http_client = new_http_client(handle);
        HttpHandler {
            templates: Arc::clone(&templates),
            http_client: Arc::new(http_client),
            logs: Arc::clone(&logs),
            handle: handle.clone(),

            client_certs: tls_session.get_peer_certificates(),
        }
    });
}

fn serve_https<F, S>(
    addr: SocketAddr,
    tls_config: rustls::ServerConfig,
    threads: usize,
    new_service: F,
) where
    F: Fn(&Handle, &rustls::ServerSession) -> S + Sync + Send + 'static,
    S: tokio_service::Service<
        Request = hyper::server::Request,
        Response = hyper::server::Response,
        Error = hyper::Error,
    >
        + 'static,
{
    let tls_config = Arc::new(tls_config);
    let new_service = Arc::new(new_service);
    let threads = (0..threads - 1)
        .map(|i| {
            let tls_config = Arc::clone(&tls_config);
            let new_service = Arc::clone(&new_service);
            thread::Builder::new()
                .name(format!("worker{}", i))
                .spawn(move || { _serve(addr, tls_config, &*new_service); })
                .unwrap()
        })
        .collect::<Vec<_>>();

    _serve(addr, tls_config, &*new_service);
    for t in threads {
        t.join().unwrap();
    }
}

fn _serve<F, S>(addr: SocketAddr, tls_config: Arc<rustls::ServerConfig>, new_service: &F)
where
    F: Fn(&Handle, &rustls::ServerSession) -> S,
    S: tokio_service::Service<
        Request = hyper::server::Request,
        Response = hyper::server::Response,
        Error = hyper::Error,
    >
        + 'static,
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
    ).unwrap()
        .incoming()
        .for_each(move |(sock, addr)| {
            let handle = handle.clone();
            tls_config.accept_async(sock).map_err(|_| ()).and_then(move |s| {
                let http = hyper::server::Http::new();
                let service = new_service(&handle, s.get_ref().1);
                http.bind_connection(&handle, s, addr, service);
                Ok(())
            }).or_else(|()| Ok(()))
        });
    core.run(work).unwrap();
}

fn main() {
    let matches = clap::App::new("ct-tools")
        .subcommand(
            clap::SubCommand::with_name("submit")
                .about("Directly submits certificates to CT logs")
                .arg(
                    clap::Arg::with_name("path")
                        .multiple(true)
                        .required(true)
                        .help("Path to certificate or chain"),
                )
                .arg(clap::Arg::with_name("all-logs").long("--all-logs").help(
                    "Submit to all logs, instead of just ones trusted by Chrome",
                )),
        )
        .subcommand(
            clap::SubCommand::with_name("check")
                .about("Checks whether a certificate exists in CT logs")
                .arg(
                    clap::Arg::with_name("path")
                        .multiple(true)
                        .required(true)
                        .help("Path to certificate or chain"),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("server")
                .about("Run an HTTPS server that submits client to CT logs")
                .arg(clap::Arg::with_name("local-dev").long("--local-dev").help(
                    "Local development, do not obtain a certificate",
                ))
                .arg(
                    clap::Arg::with_name("domain")
                        .takes_value(true)
                        .long("--domain")
                        .help("Domain this is running as"),
                )
                .arg(
                    clap::Arg::with_name("letsencrypt-env")
                        .takes_value(true)
                        .long("--letsencrypt-env")
                        .possible_values(&["dev", "prod"])
                        .help("Let's Encrypt environment to use"),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("submit") {
        submit(
            matches.values_of("path").unwrap(),
            matches.is_present("all-logs"),
        );
    } else if let Some(matches) = matches.subcommand_matches("check") {
        check(matches.values_of("path").unwrap());
    } else if let Some(matches) = matches.subcommand_matches("server") {
        server(
            matches.is_present("local-dev"),
            matches.value_of("domain"),
            matches.value_of("letsencrypt-env"),
        );
    }
}
