extern crate base64;
extern crate clap;
extern crate hex;
extern crate hyper;
extern crate hyper_native_tls;
extern crate pem;
#[macro_use]
extern crate prettytable;
extern crate ring;
extern crate serde_json;
extern crate url;

extern crate ct_submitter;

use std::fs::File;
use std::io::Read;

use hex::ToHex;

use ring::digest;

use ct_submitter::{fetch_trusted_ct_logs, submit_cert_to_logs, AddChainRequest};


fn pems_to_chain(data: &str) -> Vec<Vec<u8>> {
    return pem::parse_many(data)
               .into_iter()
               .filter(|p| p.tag == "CERTIFICATE")
               .map(|p| p.contents)
               .collect();
}

fn build_chain_for_cert(http_client: &hyper::Client, cert: &[u8]) -> Vec<Vec<u8>> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("b64cert", &base64::encode(cert))
        .finish();
    let body_bytes = body.as_bytes();
    let response = http_client
        .post("https://crt.sh/gen-add-chain")
        .header(hyper::header::ContentType::form_url_encoded())
        .body(hyper::client::Body::BufBody(body_bytes, body_bytes.len()))
        .send()
        .unwrap();

    let add_chain_request: AddChainRequest = serde_json::from_reader(response).unwrap();
    return add_chain_request
               .chain
               .iter()
               .map(|c| base64::decode(c).unwrap())
               .collect();
}

fn crtsh_url_for_cert(cert: &[u8]) -> String {
    return format!("https://crt.sh?q={}",
                   digest::digest(&digest::SHA256, &cert)
                       .as_ref()
                       .to_hex()
                       .to_uppercase());
}

fn submit(paths: clap::Values) {
    let http_client = hyper::Client::with_connector(
        hyper::net::HttpsConnector::new(hyper_native_tls::NativeTlsClient::new().unwrap())
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
            chain = build_chain_for_cert(&http_client, &chain[0]);
        }
        let scts = submit_cert_to_logs(&http_client, &logs, &chain);

        println!("Find the cert on crt.sh: {}", crtsh_url_for_cert(&chain[0]));
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

fn main() {
    let matches = clap::App::new("ct-submitter")
        .subcommand(clap::SubCommand::with_name("submit")
                        .about("Directly submits certificates to CT logs")
                        .arg(clap::Arg::with_name("path")
                                 .multiple(true)
                                 .required(true)
                                 .help("path to certificate or chain")))
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("submit") {
        submit(matches.values_of("path").unwrap());
    }
}
