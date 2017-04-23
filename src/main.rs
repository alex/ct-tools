extern crate base64;
extern crate hyper;
extern crate hyper_native_tls;
extern crate pem;
#[macro_use]
extern crate prettytable;
extern crate serde_json;
extern crate url;

extern crate ct_submitter;

use std::{env, process};
use std::fs::File;
use std::io::Read;
use std::time::Duration;

use ct_submitter::{fetch_trusted_ct_logs, submit_cert_to_logs, AddChainRequest};


fn pems_to_chain(data: &str) -> Vec<Vec<u8>> {
    return pem::parse_many(data)
               .into_iter()
               .filter(|p| p.tag == "CERTIFICATE")
               .map(|p| p.contents)
               .collect::<Vec<_>>();
}

fn main() {
    let path = match env::args().skip(1).next() {
        Some(p) => p,
        None => {
            println!("Usage: {} <path/to/chain.pem>", env::args().next().unwrap());
            process::exit(1);
        }
    };

    let mut contents = String::new();
    File::open(path)
        .unwrap()
        .read_to_string(&mut contents)
        .unwrap();

    let mut chain = pems_to_chain(&contents);

    let mut http_client = hyper::Client::with_connector(
        hyper::net::HttpsConnector::new(hyper_native_tls::NativeTlsClient::new().unwrap())
    );
    http_client.set_read_timeout(Some(Duration::from_secs(5)));
    let logs = fetch_trusted_ct_logs(&http_client);

    if chain.len() == 1 {
        // TODO: There's got to be some way to do this ourselves, instead of using crt.sh as a
        // glorified AIA chaser.
        println!("Only one certificate in chain, using crt.sh to build a full chain");
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("b64cert", &base64::encode(&chain[0]))
            .finish();
        let body_bytes = body.as_bytes();
        let mut response = http_client
            .post("https://crt.sh/gen-add-chain")
            .header(hyper::header::ContentType::form_url_encoded())
            .body(hyper::client::Body::BufBody(body_bytes, body_bytes.len()))
            .send()
            .unwrap();

        let add_chain_request: AddChainRequest = serde_json::from_reader(response).unwrap();
        chain = add_chain_request
            .chain
            .iter()
            .map(|c| base64::decode(c).unwrap())
            .collect();
    }

    let scts = submit_cert_to_logs(&http_client, &logs, chain);

    let mut table = prettytable::Table::new();
    table.add_row(row!["Log", "SCT"]);
    for (log, sct) in scts {
        table.add_row(row![log.description, base64::encode(&sct.to_raw_bytes())]);
    }
    table.printstd();
}
