extern crate base64;
extern crate clap;
extern crate hyper;
extern crate hyper_rustls;
extern crate pem;
#[macro_use]
extern crate prettytable;
extern crate serde_json;

extern crate ct_tools;

use std::fs::File;
use std::io::Read;

use ct_tools::{censys, crtsh};
use ct_tools::ct::submit_cert_to_logs;
use ct_tools::google::fetch_trusted_ct_logs;


fn pems_to_chain(data: &str) -> Vec<Vec<u8>> {
    return pem::parse_many(data)
               .into_iter()
               .filter(|p| p.tag == "CERTIFICATE")
               .map(|p| p.contents)
               .collect();
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

fn check(path: &str) {
    let http_client = hyper::Client::with_connector(
        hyper::net::HttpsConnector::new(hyper_rustls::TlsClient::new())
    );

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

fn main() {
    let matches = clap::App::new("ct-submitter")
        .subcommand(clap::SubCommand::with_name("submit")
                        .about("Directly submits certificates to CT logs")
                        .arg(clap::Arg::with_name("path")
                                 .multiple(true)
                                 .required(true)
                                 .help("Path to certificate or chain")))
        .subcommand(clap::SubCommand::with_name("check")
                        .about("Checks whether a certificate exists in CT logs")
                        .arg(clap::Arg::with_name("path")
                                 .required(true)
                                 .help("Path to certificate or chain")))
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("submit") {
        submit(matches.values_of("path").unwrap());
    } else if let Some(matches) = matches.subcommand_matches("check") {
        check(matches.value_of("path").unwrap());
    }
}
