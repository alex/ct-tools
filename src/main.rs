extern crate base64;
extern crate clap;
extern crate hyper;
extern crate hyper_rustls;
extern crate pem;
#[macro_use]
extern crate prettytable;
extern crate ring;
extern crate rustls;
extern crate serde_json;
extern crate tempfile;
#[macro_use]
extern crate tera;

extern crate ct_tools;

use ct_tools::{crtsh, letsencrypt};
use ct_tools::common::{Log, sha256_hex};
use ct_tools::ct::submit_cert_to_logs;
use ct_tools::google::fetch_trusted_ct_logs;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;


fn pems_to_chain(data: &str) -> Vec<Vec<u8>> {
    pem::parse_many(data)
        .into_iter()
        .filter(|p| p.tag == "CERTIFICATE")
        .map(|p| p.contents)
        .collect()
}

fn submit(paths: clap::Values, log_urls: Option<clap::Values>) {
    let mut http_client = hyper::Client::with_connector(
        hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())
    );
    http_client.set_read_timeout(Some(Duration::from_secs(15)));

    let logs = match log_urls {
        Some(urls) => {
            urls.map(|url| {
                         Log {
                             url: url.to_string(),
                             description: url.to_string(),
                             is_google: false,
                         }
                     })
                .collect()
        }
        None => fetch_trusted_ct_logs(&http_client),
    };

    for path in paths {
        println!("Submitting {} ...", path);

        let mut contents = String::new();
        File::open(path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();

        let mut chain = pems_to_chain(&contents);
        if chain.len() == 1 {
            // TODO: There's got to be some way to do this ourselves, instead of using crt.sh as a
            // glorified AIA chaser.
            println!("Only one certificate in chain, using crt.sh to build a full chain ...");
            chain = match crtsh::build_chain_for_cert(&http_client, &chain[0]) {
                Some(c) => c,
                None => {
                    println!("Unable to build a chain");
                    continue;
                }
            }
        }
        let scts = submit_cert_to_logs(&http_client, &logs, &chain);

        if !scts.is_empty() {
            println!("Find the cert on crt.sh: {}",
                     crtsh::url_for_cert(&chain[0]));
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
    let http_client = hyper::Client::with_connector(
        hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())
    );

    for path in paths {
        let mut contents = String::new();
        File::open(path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();

        let chain = pems_to_chain(&contents);

        let is_logged = crtsh::is_cert_logged(&http_client, &chain[0]);
        if is_logged {
            println!("{} was already logged", path);
        } else {
            println!("{} has not been logged", path);
        }
    }
}

struct HttpHandler {
    templates: tera::Tera,
    http_client: hyper::Client,
    logs: Vec<Log>,
}

impl hyper::server::Handler for HttpHandler {
    fn handle(&self, request: hyper::server::Request, response: hyper::server::Response) {
        let peer_certs = request
            .ssl::<hyper_rustls::WrappedStream>()
            .unwrap()
            .to_tls_stream()
            .get_session()
            .get_peer_certificates();

        let mut crtsh_url = None;
        if peer_certs.is_some() && request.method == hyper::method::Method::Post {
            if let Some(chain) = crtsh::build_chain_for_cert(&self.http_client,
                                                             &peer_certs.as_ref().unwrap()[0].0) {
                let scts = submit_cert_to_logs(&self.http_client, &self.logs, &chain);
                if !scts.is_empty() {
                    crtsh_url = Some(crtsh::url_for_cert(&chain[0]));
                    println!("Successfully submitted: {}", sha256_hex(&chain[0]));
                }
            }
        }

        let rendered_cert = peer_certs.map(|chain| {
            let mut tmp = tempfile::NamedTempFile::new().unwrap();
            tmp.write_all(&chain[0].0).unwrap();
            tmp.flush().unwrap();
            let stdout = Command::new("openssl")
                .arg("x509")
                .arg("-text")
                .arg("-noout")
                .arg("-inform")
                .arg("der")
                .arg("-in")
                .arg(tmp.path().as_os_str())
                .output()
                .unwrap()
                .stdout;
            String::from_utf8_lossy(&stdout).into_owned()
        });

        let mut context = tera::Context::new();
        context.add("cert", &rendered_cert);
        context.add("crtsh_url", &crtsh_url);
        response
            .send(self.templates
                      .render("home.html", &context)
                      .unwrap()
                      .as_bytes())
            .unwrap();
    }
}

struct NoVerificationCertificateVerifier;
impl rustls::ClientCertVerifier for NoVerificationCertificateVerifier {
    fn verify_client_cert(&self,
                          _: &rustls::RootCertStore,
                          _: &[rustls::Certificate])
                          -> Result<(), rustls::TLSError> {
        Ok(())
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
        tls_config.set_single_cert(vec![letsencrypt::openssl_cert_to_rustls(&cert)],
                                   letsencrypt::openssl_pkey_to_rustls(&pkey));
    } else {
        let letsencrypt_url = match letsencrypt_env.unwrap() {
            "prod" => "https://acme-v01.api.letsencrypt.org/directory",
            "dev" => "https://acme-staging.api.letsencrypt.org/directory",
            _ => unreachable!(),
        };
        let cert_cache = letsencrypt::DiskCache::new(env::home_dir()
                                                         .unwrap()
                                                         .join(".ct-tools")
                                                         .join("certificates"));
        tls_config.cert_resolver =
            Box::new(letsencrypt::AutomaticCertResolver::new(letsencrypt_url,
                                                             vec![domain.unwrap().to_string()],
                                                             cert_cache));
    }
    tls_config.set_persistence(rustls::ServerSessionMemoryCache::new(1024));
    tls_config.ticketer = rustls::Ticketer::new();
    // Disable certificate verification. In any normal context, this would be horribly insecure!
    // However, all we're doing is taking the certs and then turning around and submitting them to
    // CT logs, so it doesn't matter if they're verified.
    tls_config
        .dangerous()
        .set_certificate_verifier(Box::new(NoVerificationCertificateVerifier));
    let tls_server = hyper_rustls::TlsServer { cfg: Arc::new(tls_config) };

    let mut http_client = hyper::Client::with_connector(
        hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())
    );
    let logs = fetch_trusted_ct_logs(&http_client);
    http_client.set_write_timeout(Some(Duration::from_secs(5)));
    http_client.set_read_timeout(Some(Duration::from_secs(5)));
    let handler = HttpHandler {
        templates: compile_templates!("templates/*"),
        http_client: http_client,
        logs: logs,
    };

    let addr = if local_dev {
        "127.0.0.1:1337"
    } else {
        "0.0.0.0:443"
    };
    println!("Listening on https://{} ...", addr);
    hyper::Server::https(addr, tls_server)
        .unwrap()
        // If there aren't at least two threads, the Let's Encrypt integration will deadlock.
        .handle_threads(handler, 16)
        .unwrap();
}

fn main() {
    let matches = clap::App::new("ct-tools")
        .subcommand(clap::SubCommand::with_name("submit")
                        .about("Directly submits certificates to CT logs")
                        .arg(clap::Arg::with_name("path")
                                 .multiple(true)
                                 .required(true)
                                 .help("Path to certificate or chain"))
                        .arg(clap::Arg::with_name("log-url")
                                 .long("--log-url")
                                 .takes_value(true)
                                 .multiple(true)
                                 .help("Log URL to submit certificate to")))
        .subcommand(clap::SubCommand::with_name("check")
                        .about("Checks whether a certificate exists in CT logs")
                        .arg(clap::Arg::with_name("path")
                                 .multiple(true)
                                 .required(true)
                                 .help("Path to certificate or chain")))
        .subcommand(clap::SubCommand::with_name("server")
                        .about("Run an HTTPS server that submits client to CT logs")
                        .arg(clap::Arg::with_name("local-dev")
                                 .long("--local-dev")
                                 .help("Local development, do not obtain a certificate"))
                        .arg(clap::Arg::with_name("domain")
                                 .takes_value(true)
                                 .long("--domain")
                                 .help("Domain this is running as"))
                        .arg(clap::Arg::with_name("letsencrypt-env")
                                 .takes_value(true)
                                 .long("--letsencrypt-env")
                                 .possible_values(&["dev", "prod"])
                                 .help("Let's Encrypt environment to use")))
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("submit") {
        submit(matches.values_of("path").unwrap(),
               matches.values_of("log-url"));
    } else if let Some(matches) = matches.subcommand_matches("check") {
        check(matches.values_of("path").unwrap());
    } else if let Some(matches) = matches.subcommand_matches("server") {
        server(matches.is_present("local-dev"),
               matches.value_of("domain"),
               matches.value_of("letsencrypt-env"));
    }
}
