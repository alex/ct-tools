use super::common::sha256_hex;
use super::ct::AddChainRequest;
use base64;
use futures::prelude::*;
use hyper;
use serde_json;
use url;

pub fn build_chain_for_cert<C: hyper::client::Connect>(
    http_client: &hyper::Client<C>,
    cert: &[u8],
) -> impl Future<Item = Vec<Vec<u8>>, Error = ()> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("b64cert", &base64::encode(&cert))
        .append_pair("onlyonechain", "Y")
        .finish();
    let mut request = hyper::Request::new(
        hyper::Method::Post,
        "https://crt.sh/gen-add-chain".parse().unwrap(),
    );
    request.headers_mut().set(
        hyper::header::ContentType::form_url_encoded(),
    );
    request.headers_mut().set(
        hyper::header::Connection::keep_alive(),
    );
    request.set_body(body.into_bytes());
    // TODO: undo this once lifetime bugs are fixed
    let r = http_client.request(request);
    async_block! {
        let response = match await!(r) {
            Ok(response) => response,
            // TODO: maybe be more selective in error handling
            Err(_) => return Err(()),
        };

        if response.status() == hyper::StatusCode::NotFound {
            return Err(());
        }

        let body = await!(response.body().concat2()).unwrap();
        let add_chain_request: AddChainRequest = serde_json::from_slice(&body).unwrap();
        Ok(
            add_chain_request
                .chain
                .iter()
                .map(|c| base64::decode(c).unwrap())
                .collect(),
        )
    }
}

pub fn is_cert_logged<C: hyper::client::Connect>(
    http_client: &hyper::Client<C>,
    cert: &[u8],
) -> impl Future<Item = bool, Error = ()> {
    let mut request = hyper::Request::new(
        hyper::Method::Get,
        format!("https://crt.sh/?d={}", sha256_hex(cert))
            .parse()
            .unwrap(),
    );
    request.headers_mut().set(
        hyper::header::Connection::keep_alive(),
    );
    let r = http_client.request(request);
    async_block! {
        let response = await!(r).unwrap();
        Ok(response.status() == hyper::StatusCode::Ok)
    }
}

pub fn url_for_cert(cert: &[u8]) -> String {
    format!("https://crt.sh?q={}", sha256_hex(cert).to_uppercase())
}
