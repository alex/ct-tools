use super::common::Log;

use base64;
use futures;
use serde::{Deserialize, Serialize};
use serde_json;
use std::convert::TryFrom;
use std::io::Write;
use std::time::Duration;

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
        b.write_all(&[self.sct_version]).unwrap();

        let log_id = base64::decode(&self.id).unwrap();
        b.write_all(&log_id).unwrap();

        b.write_all(&self.timestamp.to_be_bytes()).unwrap();

        let extensions = base64::decode(&self.extensions).unwrap();
        b.write_all(&u16::try_from(extensions.len()).unwrap().to_be_bytes())
            .unwrap();
        b.write_all(&extensions).unwrap();

        let signature = base64::decode(&self.signature).unwrap();
        b.write_all(&signature).unwrap();

        b
    }
}

async fn submit_to_log(
    http_client: &reqwest::Client,
    log: &Log,
    payload: Vec<u8>,
) -> Result<SignedCertificateTimestamp, ()> {
    let mut url = "https://".to_string() + &log.url;
    if !url.ends_with('/') {
        url += "/";
    }
    url += "ct/v1/add-chain";

    let response = http_client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await
        .map_err(|_| ())?;

    // 400, 403, and probably some others generally indicate a log doesn't accept certs from
    // this root, or that the log isn't accepting new submissions. Server errors mean there's
    // nothing we can do.
    if response.status().is_client_error() || response.status().is_server_error() {
        return Err(());
    }

    Ok(response.json().await.unwrap())
}

#[derive(Serialize, Deserialize)]
pub struct AddChainRequest {
    pub chain: Vec<String>,
}

pub async fn submit_cert_to_logs(
    http_client: &reqwest::Client,
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
        .map(move |(idx, log)| {
            let s = tokio::time::timeout(timeout, submit_to_log(http_client, log, payload.clone()));
            async move {
                match s.await {
                    Ok(Ok(sct)) => Some((idx, sct)),
                    _ => None,
                }
            }
        })
        .collect::<Vec<_>>();

    let scts = futures::future::join_all(futures).await;
    scts.into_iter().filter_map(|s| s).collect()
}
