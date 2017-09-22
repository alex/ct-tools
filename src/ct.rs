use super::common::Log;

use base64;
use byteorder::{BigEndian, WriteBytesExt};

use futures;
use futures::prelude::*;
use hyper;
use serde_json;
use std::io::Write;
use std::time::Duration;
use tokio_core::reactor::Timeout;


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


fn submit_to_log<C: hyper::client::Connect>(
    http_client: &hyper::Client<C>,
    log: &Log,
    payload: Vec<u8>,
) -> impl Future<Item = SignedCertificateTimestamp, Error = ()> {
    let mut url = "https://".to_string() + &log.url;
    if !url.ends_with('/') {
        url += "/";
    }
    url += "ct/v1/add-chain";
    let mut request = hyper::Request::new(hyper::Method::Post, url.parse().unwrap());
    request.headers_mut().set(
        hyper::header::ContentType::json(),
    );
    request.set_body(payload);
    let r = http_client.request(request);
    async_block! {
        let response = match await!(r) {
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
        let body = await!(response.body().take(10 * 1024 * 1024).concat2())
            .unwrap();
        Ok(serde_json::from_slice(&body).unwrap())
    }
}

#[derive(Serialize, Deserialize)]
pub struct AddChainRequest {
    pub chain: Vec<String>,
}

pub fn submit_cert_to_logs<C: hyper::client::Connect>(
    http_client: &hyper::Client<C>,
    logs: &[Log],
    cert: &[Vec<u8>],
) -> impl Future<Item = Vec<(usize, SignedCertificateTimestamp)>, Error = ()> {
    let payload = serde_json::to_vec(&AddChainRequest {
        chain: cert.iter().map(|r| base64::encode(r)).collect(),
    }).unwrap();

    let futures = logs.iter()
        .enumerate()
        .map(move |(idx, log)| {
            let timeout = Timeout::new(Duration::from_secs(5), http_client.handle()).unwrap();

            let payload = payload.clone();
            let s = submit_to_log(http_client, log, payload).select2(timeout);
            async_block! {
                match await!(s) {
                    Ok(futures::future::Either::A((sct, _))) => Ok(Some((idx, sct))),
                    _ => Ok(None),
                }
            }
        })
        .collect::<Vec<_>>();

    futures::future::join_all(futures).map(|scts| scts.into_iter().filter_map(|s| s).collect())
}
