extern crate base64;
extern crate hyper;
extern crate hyper_native_tls;
extern crate pem;
#[macro_use]
extern crate prettytable;

extern crate ct_submitter;

use std::{env, process};
use std::fs::File;
use std::io::Read;
use std::time::Duration;

use ct_submitter::{fetch_trusted_ct_logs, submit_cert_to_logs};


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

    let chain = pem::parse_many(contents)
        .into_iter()
        .filter(|p| p.tag == "CERTIFICATE")
        .map(|p| p.contents)
        .collect();

    let mut http_client = hyper::Client::with_connector(
        hyper::net::HttpsConnector::new(hyper_native_tls::NativeTlsClient::new().unwrap())
    );
    http_client.set_read_timeout(Some(Duration::from_secs(5)));
    let logs = fetch_trusted_ct_logs(&http_client);

    let scts = submit_cert_to_logs(&http_client, &logs, chain);

    let mut table = prettytable::Table::new();
    table.add_row(row!["Log", "SCT"]);
    for (log, sct) in scts {
        table.add_row(row![log.description, base64::encode(&sct.to_raw_bytes())]);
    }
    table.printstd();
}
