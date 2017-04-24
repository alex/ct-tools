extern crate base64;
extern crate byteorder;
extern crate hyper;
extern crate rayon;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use byteorder::{BigEndian, WriteBytesExt};

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use std::io::{Read, Write};


#[derive(Debug)]
pub struct Log {
    pub description: String,
    url: String,
    is_google: bool,
}

#[derive(Debug, Deserialize)]
pub struct SignedCertificateTimestamp {
    sct_version: u8,
    id: String,
    timestamp: u64,
    extensions: String,
    signature: String,
}

impl SignedCertificateTimestamp {
    pub fn to_raw_bytes(&self) -> Vec<u8> {
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

const LOG_LIST_URL: &'static str = "https://www.gstatic.com/ct/log_list/log_list.json";

pub fn fetch_trusted_ct_logs(http_client: &hyper::Client) -> Vec<Log> {
    let response = http_client.get(LOG_LIST_URL).send().unwrap();
    // Limit the response to 10MB at most, to be resillient to DoS.
    let logs_response: LogsResponse = serde_json::from_reader(response.take(10 * 1024 * 1024))
        .unwrap();

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

    // Limt the response to 10MB (well above what would ever be needed) to be resilient to DoS in
    // the face of a dumb or malicious log.
    return Some(serde_json::from_reader(response.take(10 * 1024 * 1024)).unwrap());
}

#[derive(Serialize, Deserialize)]
pub struct AddChainRequest {
    pub chain: Vec<String>,
}

pub fn submit_cert_to_logs<'a>(http_client: &hyper::Client,
                               logs: &'a [Log],
                               cert: Vec<Vec<u8>>)
                               -> Vec<(&'a Log, SignedCertificateTimestamp)> {
    let payload = serde_json::to_vec(&AddChainRequest {
                                          chain: cert.iter().map(|r| base64::encode(r)).collect(),
                                      })
            .unwrap();

    return logs.par_iter()
               .filter_map(|log| {
                               let sct = submit_to_log(http_client, &log.url, &payload);
                               return sct.map(|s| (log, s));
                           })
               .collect();
}
