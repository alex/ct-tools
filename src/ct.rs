use super::common::Log;

use base64;
use byteorder::{BigEndian, WriteBytesExt};

use futures;
use futures::compat::Future01CompatExt;
use futures::FutureExt;
use hyper;
use hyper::rt::Stream;
use serde_json;
use std::io::Write;
use std::time::Duration;
use tokio::future::FutureExt as _;

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
        b.write_all(&log_id).unwrap();

        b.write_u64::<BigEndian>(self.timestamp).unwrap();

        let extensions = base64::decode(&self.extensions).unwrap();
        assert!(extensions.len() <= 65_535);
        b.write_u16::<BigEndian>(extensions.len() as u16).unwrap();
        b.write_all(&extensions).unwrap();

        let signature = base64::decode(&self.signature).unwrap();
        b.write_all(&signature).unwrap();

        b
    }
}

async fn submit_to_log<C: hyper::client::connect::Connect + 'static>(
    http_client: &hyper::Client<C>,
    log: &Log,
    payload: Vec<u8>,
) -> Result<SignedCertificateTimestamp, ()> {
    let mut url = "https://".to_string() + &log.url;
    if !url.ends_with('/') {
        url += "/";
    }
    url += "ct/v1/add-chain";

    let request = hyper::Request::builder()
        .method("POST")
        .uri(url)
        .header("Content-Type", "application/json")
        .body(payload.into())
        .unwrap();
    let r = http_client.request(request);
    let response = match r.compat().await {
        Ok(r) => r,
        // TODO: maybe not all of these should be silently ignored.
        Err(_) => return Err(()),
    };

    // 400, 403, and probably some others generally indicate a log doesn't accept certs from
    // this root, or that the log isn't accepting new submissions. Server errors mean there's
    // nothing we can do.
    if response.status().is_client_error() || response.status().is_server_error() {
        return Err(());
    }

    // Limt the response to 10MB (well above what would ever be needed) to be resilient to DoS
    // in the face of a dumb or malicious log.
    let body = response
        .into_body()
        .take(10 * 1024 * 1024)
        .concat2()
        .compat()
        .await
        .unwrap();
    Ok(serde_json::from_slice(&body).unwrap())
}

#[derive(Serialize, Deserialize)]
pub struct AddChainRequest {
    pub chain: Vec<String>,
}

pub async fn submit_cert_to_logs<C: hyper::client::connect::Connect + 'static>(
    http_client: &hyper::Client<C>,
    logs: &[Log],
    cert: &[Vec<u8>],
    timeout: Duration,
) -> Vec<(usize, SignedCertificateTimestamp)> {
    let payload = serde_json::to_vec(&AddChainRequest {
        chain: cert.iter().map(|r| base64::encode(r)).collect(),
    })
    .unwrap();

    let futures = logs
        .iter()
        .enumerate()
        .map(|(idx, log)| (idx, log, payload.clone()))
        .map(async move |(idx, log, payload)| {
            let s = submit_to_log(http_client, log, payload).timeout(timeout);
            match s.await {
                Ok(Ok(sct)) => Some((idx, sct)),
                _ => None,
            }
        })
        .collect::<Vec<_>>();

    futures::future::join_all(futures)
        .map(|scts| scts.into_iter().filter_map(|s| s).collect())
        .await
}
