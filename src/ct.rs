use super::common::Log;

use base64;
use byteorder::{BigEndian, WriteBytesExt};
use hyper;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use serde_json;
use std::io::{Read, Write};


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
        b.write_u16::<BigEndian>(extensions.len() as u16).unwrap();
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
                               cert: &[Vec<u8>])
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
