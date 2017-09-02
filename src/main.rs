#![feature(conservative_impl_trait, generators)]

extern crate base64;
extern crate clap;
extern crate hyper;
extern crate hyper_rustls;
extern crate pem;
#[macro_use]
extern crate prettytable;
extern crate rayon;
extern crate ring;
extern crate rustls;
extern crate serde_json;
#[macro_use]
extern crate tera;
extern crate tokio_core;
extern crate tokio_proto;
extern crate tokio_rustls;
extern crate futures_await as futures;
extern crate tokio_process;


extern crate ct_tools;

use ct_tools::{crtsh, letsencrypt};
use ct_tools::common::{Log, sha256_hex};
use ct_tools::ct::submit_cert_to_logs;
use ct_tools::google::fetch_trusted_ct_logs;
use futures::prelude::*;
use rayon::iter::ParallelIterator;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio_process::CommandExt;

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
    // TODO: pool?
    hyper::Client::configure()
        .connector(hyper_rustls::HttpsConnector::new(4, handle))
        .build(handle)
}

fn submit(paths: clap::Values, log_urls: Option<clap::Values>) {
    let core = tokio_core::reactor::Core::new().unwrap();
    let mut http_client = new_http_client(&core.handle());

    let logs = match log_urls {
        Some(urls) => {
            urls.map(|url| {
                Log {
                    url: url.to_string(),
                    description: url.to_string(),
                    is_google: false,
                }
            }).collect()
        }
        None => core.run(fetch_trusted_ct_logs(&http_client)).unwrap(),
    };

    for path in paths {
        println!("Submitting {} ...", path);

        let mut contents = Vec::new();
        File::open(path)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();

        let mut chain = pems_to_chain(&contents);
        if chain.len() == 1 {
            // TODO: There's got to be some way to do this ourselves, instead of using crt.sh as a
            // glorified AIA chaser.
            println!("Only one certificate in chain, using crt.sh to build a full chain ...");
            chain = match core.run(crtsh::build_chain_for_cert(&http_client, &chain[0])) {
                Ok(c) => c,
                Err(()) => {
                    println!("Unable to build a chain");
                    continue;
                }
            }
        }
        let scts = core.run(submit_cert_to_logs(&http_client, &logs, &chain))
            .unwrap();

        if !scts.is_empty() {
            println!(
                "Find the cert on crt.sh: {}",
                crtsh::url_for_cert(&chain[0])
            );
        }
        let mut table = prettytable::Table::new();
        table.add_row(row!["Log", "SCT"]);
        for (log, sct) in scts {
            table.add_row(row![log.description, base64::encode(&sct.to_raw_bytes())]);
        }
        table.printstd();
        println!();
        println!();
    }
}

fn check(paths: clap::Values) {
    let core = tokio_core::reactor::Core::new().unwrap();
    let http_client = new_http_client(&core.handle());

    let paths = paths.collect::<Vec<_>>();
    // TODO: parallelism
    for path in paths {
        let mut contents = Vec::new();
        File::open(path)
            .unwrap()
            .read_to_end(&mut contents)
            .unwrap();

        let chain = pems_to_chain(&contents);

        let is_logged = core.run(crtsh::is_cert_logged(&http_client, &chain[0]))
            .unwrap();
        if is_logged {
            println!("{} was already logged", path);
        } else {
            println!("{} has not been logged", path);
        }
    }
}

struct HttpHandler<C: hyper::client::Connect> {
    handle: tokio_core::reactor::Handle,
    templates: tera::Tera,
    http_client: hyper::Client<C>,
    logs: Vec<Log>,
}

impl<C: hyper::client::Connect> hyper::server::Service for HttpHandler<C> {
    type Request = hyper::server::Request;
    type Response = hyper::server::Response;
    type Error = hyper::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, request: hyper::server::Request) -> Self::Future {
        Box::new(async_block! {
            // TODO:
            // let peer_certs = request
            //     .ssl::<hyper_rustls::WrappedStream>()
            //     .unwrap()
            //     .to_tls_stream()
            //     .get_session()
            //     .get_peer_certificates();
            let peer_certs: Option<Vec<rustls::Certificate>> = None;

            let mut crtsh_url = None;
            if peer_certs.is_some() && request.method() == &hyper::Method::Post {
                if let Ok(chain) = await!(crtsh::build_chain_for_cert(
                    &self.http_client,
                    &peer_certs.as_ref().unwrap()[0].0,
                )) {
                    let scts = await!(submit_cert_to_logs(
                        &self.http_client, &self.logs, &chain)).unwrap();
                    if !scts.is_empty() {
                        crtsh_url = Some(crtsh::url_for_cert(&chain[0]));
                        println!("Successfully submitted: {}", sha256_hex(&chain[0]));
                    }
                }
            }

            let rendered_cert = match peer_certs {
                Some(chain) => {
                    let mut process = Command::new("openssl")
                        .arg("x509")
                        .arg("-text")
                        .arg("-noout")
                        .arg("-inform")
                        .arg("der")
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn_async(&self.handle).unwrap();
                    process
                        .stdin()
                        .as_mut()
                        .unwrap()
                        .write_all(&chain[0].0)
                        .unwrap();
                    let out = await!(process.wait_with_output()).unwrap();
                    Some(String::from_utf8_lossy(&out.stdout).into_owned())
                },
                None => None
            };

            let mut context = tera::Context::new();
            context.add("cert", &rendered_cert);
            context.add("crtsh_url", &crtsh_url);
            Ok(
                hyper::server::Response::new().with_body(
                    self.templates
                        .render("home.html", &context)
                        .unwrap()
                        .as_bytes(),
                ),
            )
        })
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

    let core = tokio_core::reactor::Core::new().unwrap();
    let mut http_client = new_http_client(&core.handle());
    let logs = core.run(fetch_trusted_ct_logs(&http_client)).unwrap();

    let addr = if local_dev {
        "127.0.0.1:1337"
    } else {
        "0.0.0.0:443"
    };

    let tls_server =
        tokio_rustls::proto::Server::new(hyper::server::Http::new(), Arc::new(tls_config));
    let tcp_server = tokio_proto::TcpServer::new(tls_server, addr.parse().unwrap());
    // If there aren't at least two threads, the Let's Encrypt integration will deadlock.
    tcp_server.threads(16);

    println!("Listening on https://{} ...", addr);
    tcp_server.serve(|| {
        Ok(HttpHandler {
            templates: compile_templates!("templates/*"),
            http_client: http_client,
            logs: logs,
        })
    });
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
                .arg(
                    clap::Arg::with_name("log-url")
                        .long("--log-url")
                        .takes_value(true)
                        .multiple(true)
                        .help("Log URL to submit certificate to"),
                ),
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
            matches.values_of("log-url"),
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
