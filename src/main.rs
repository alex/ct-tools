extern crate base64;

extern crate byteorder;

extern crate hyper;
extern crate hyper_native_tls;

extern crate rayon;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;

extern crate pem;

#[macro_use]
extern crate prettytable;

use std::{env, process};
use std::fs::File;
use std::io::{Read, Write};

use byteorder::{BigEndian, WriteBytesExt};

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};


#[derive(Deserialize)]
struct LogsResponseLogs {
    description: String,
    url: String,
    operated_by: Vec<u32>,
    disqualified_at: Option<u64>,
}

#[derive(Deserialize)]
struct LogsResponseOperators {
    name: String,
    id: u32,
}

#[derive(Deserialize)]
struct LogsResponse {
    logs: Vec<LogsResponseLogs>,
    operators: Vec<LogsResponseOperators>,
}

#[derive(Debug, Clone)]
struct Log {
    description: String,
    url: String,
    is_google: bool,
}


const LOG_LIST_URL: &'static str = "https://www.gstatic.com/ct/log_list/log_list.json";

fn fetch_trusted_ct_logs(http_client: &hyper::Client) -> Vec<Log> {
    let response = http_client.get(LOG_LIST_URL).send().unwrap();
    let logs_response: LogsResponse = serde_json::from_reader(response).unwrap();

    let google_id = logs_response
        .operators
        .iter()
        .find(|o| o.name == "Google")
        .map(|o| o.id);

    return logs_response
               .logs
               .into_iter()
               .filter(|log| log.disqualified_at.is_none())
               .map(|log| {
                        Log {
                            url: log.url,
                            description: log.description,
                            is_google: log.operated_by.contains(&google_id.unwrap()),
                        }
                    })
               .collect();
}

#[derive(Debug, Deserialize)]
struct SignedCertificateTimestamp {
    sct_version: u8,
    id: String,
    timestamp: u64,
    extensions: String,
    signature: String,
}

impl SignedCertificateTimestamp {
    fn to_raw_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.write_u8(self.sct_version).unwrap();

        let log_id = base64::decode(&self.id).unwrap();
        b.write(&log_id).unwrap();

        b.write_u64::<BigEndian>(self.timestamp).unwrap();

        let extensions = base64::decode(&self.extensions).unwrap();
        assert!(extensions.len() <= 65535);
        b.write_u16::<BigEndian>(extensions.len() as u16)
            .unwrap();
        b.write(&extensions).unwrap();

        let signature = base64::decode(&self.signature).unwrap();
        b.write(&signature).unwrap();

        return b;
    }
}

fn submit_to_log(http_client: &hyper::Client,
                 url: &str,
                 payload: &[u8])
                 -> Option<SignedCertificateTimestamp> {
    let mut url = "https://".to_string() + url;
    if !url.ends_with("/") {
        url += "/";
    }
    url += "ct/v1/add-chain";
    let response = http_client
        .post(&url)
        .body(hyper::client::Body::BufBody(payload, payload.len()))
        .header(hyper::header::ContentType::json())
        .send();
    let response = match response {
        Ok(r) => r,
        // TODO: maybe not all of these should be silently ignored.
        Err(_) => return None,
    };

    // 400, 403, and probably some others generally indicate a log doesn't accept certs from this
    // root, or that the log isn't accepting new submissions.
    if response.status.is_client_error() {
        return None;
    }

    let parsed_response: SignedCertificateTimestamp = serde_json::from_reader(response).unwrap();

    return Some(parsed_response);
}

#[derive(Serialize)]
struct AddChainRequest {
    chain: Vec<String>,
}

fn submit_cert_to_logs<'a>(http_client: &hyper::Client,
                           logs: &'a [Log],
                           cert: Vec<Vec<u8>>)
                           -> Vec<(&'a Log, SignedCertificateTimestamp)> {
    let payload = serde_json::to_vec(&AddChainRequest {
                                          chain: cert.iter().map(|r| base64::encode(r)).collect(),
                                      })
            .unwrap();

    return logs.par_iter()
               .filter_map(|ref log| {
                               let sct = submit_to_log(http_client, &log.url, &payload);
                               return sct.map(|s| (log.clone(), s));
                           })
               .collect();
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

    let chain = pem::parse_many(contents)
        .into_iter()
        .filter(|p| p.tag == "CERTIFICATE")
        .map(|p| p.contents)
        .collect();

    let http_client = hyper::Client::with_connector(
        hyper::net::HttpsConnector::new(hyper_native_tls::NativeTlsClient::new().unwrap())
    );
    let logs = fetch_trusted_ct_logs(&http_client);

    let scts = submit_cert_to_logs(&http_client, &logs, chain);

    let mut table = prettytable::Table::new();
    table.add_row(row!["Log", "SCT"]);
    for (log, sct) in scts {
        table.add_row(row![log.description, base64::encode(&sct.to_raw_bytes())]);
    }
    table.printstd();
}
