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
#[macro_use]
extern crate tera;

extern crate ct_tools;

use ct_tools::{censys, crtsh};
use ct_tools::common::Log;
use ct_tools::ct::submit_cert_to_logs;
use ct_tools::google::fetch_trusted_ct_logs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::Arc;


fn pems_to_chain(data: &str) -> Vec<Vec<u8>> {
    pem::parse_many(data)
        .into_iter()
        .filter(|p| p.tag == "CERTIFICATE")
        .map(|p| p.contents)
        .collect()
}

fn submit(paths: clap::Values) {
    let http_client = hyper::Client::with_connector(
        hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())
    );
    // TODO: timeout on the http_client, but for submit_cert_to_logs only, not build_chain
    let logs = fetch_trusted_ct_logs(&http_client);

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
            chain = crtsh::build_chain_for_cert(&http_client, &chain[0]);
        }
        let scts = submit_cert_to_logs(&http_client, &logs, &chain);

        println!("Find the cert on crt.sh: {}",
                 crtsh::url_for_cert(&chain[0]));
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

        let is_logged = censys::is_cert_logged(&http_client, &chain[0]);
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
        let certs = request.ssl::<hyper_rustls::WrappedStream>().unwrap();
        // .to_tls_stream()
        // .get_session()
        // .get_peer_certificates();
        response
            .send(self.templates
                      .render("home.html", &tera::Context::new())
                      .unwrap()
                      .as_bytes())
            .unwrap();
    }
}

fn server(private_key_path: &str, certificate_path: &str, client_trust_store_path: &str) {
    let mut tls_config = rustls::ServerConfig::new();
    tls_config.client_auth_offer = true;
    tls_config
        .client_auth_roots
        .add_pem_file(&mut BufReader::new(File::open(client_trust_store_path).unwrap()))
        .unwrap();
    tls_config.set_single_cert(hyper_rustls::util::load_certs(certificate_path).unwrap(),
                               hyper_rustls::util::load_private_key(private_key_path).unwrap());
    tls_config.set_persistence(rustls::ServerSessionMemoryCache::new(1024));
    tls_config.ticketer = rustls::Ticketer::new();
    let tls_server = hyper_rustls::TlsServer { cfg: Arc::new(tls_config) };

    let http_client = hyper::Client::with_connector(
        hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())
    );
    let logs = fetch_trusted_ct_logs(&http_client);
    let handler = HttpHandler {
        templates: compile_templates!("templates/*"),
        http_client: http_client,
        logs: logs,
    };

    let addr = "127.0.0.1:1337";
    println!("Listening on https://{} ...", addr);
    hyper::Server::https(addr, tls_server)
        .unwrap()
        .handle(handler)
        .unwrap();
}

fn main() {
    let matches = clap::App::new("ct-tools")
        .subcommand(clap::SubCommand::with_name("submit")
                        .about("Directly submits certificates to CT logs")
                        .arg(clap::Arg::with_name("path")
                                 .multiple(true)
                                 .required(true)
                                 .help("Path to certificate or chain")))
        .subcommand(clap::SubCommand::with_name("check")
                        .about("Checks whether a certificate exists in CT logs")
                        .arg(clap::Arg::with_name("path")
                                 .multiple(true)
                                 .required(true)
                                 .help("Path to certificate or chain")))
        .subcommand(clap::SubCommand::with_name("server")
                        .about("Run an HTTPS server that submits client to CT logs")
                        .arg(clap::Arg::with_name("private-key")
                                 .takes_value(true)
                                 .long("--private-key")
                                 .required(true)
                                 .help("Path to private key for the server"))
                        .arg(clap::Arg::with_name("certificate")
                                 .takes_value(true)
                                 .long("--certificate")
                                 .required(true)
                                 .help("Path to certificate for the server"))
                        .arg(clap::Arg::with_name("client-trust-store")
                                 .takes_value(true)
                                 .long("--client-trust-store")
                                 .required(true)
                                 .help("Path to trust store for client certificates")))
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("submit") {
        submit(matches.values_of("path").unwrap());
    } else if let Some(matches) = matches.subcommand_matches("check") {
        check(matches.values_of("path").unwrap());
    } else if let Some(matches) = matches.subcommand_matches("server") {
        server(matches.value_of("private-key").unwrap(),
               matches.value_of("certificate").unwrap(),
               matches.value_of("client-trust-store").unwrap());
    }
}
