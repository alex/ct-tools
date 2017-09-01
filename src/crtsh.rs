use super::common::sha256_hex;
use super::ct::AddChainRequest;
use base64;
use futures::prelude::*;
use hyper;
use serde_json;
use url;

pub fn build_chain_for_cert<'a, C: hyper::client::Connect>(
    http_client: &'a hyper::Client<C>,
    cert: &'a [u8],
) -> impl Future<Item=Vec<Vec<u8>>, Error=()> + 'a {
    async_block! {
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
        let response = match await!(http_client.request(request)) {
            Ok(response) => response,
            // TODO: maybe be more selective in error handling
            Err(_) => return Err(()),
        };

        if response.status() == hyper::StatusCode::NotFound {
            return Err(());
        }

        let body = await!(response.body().concat2()).unwrap();
        let add_chain_request: AddChainRequest = serde_json::from_slice(&body).unwrap();
        let res = Ok(
            add_chain_request
                .chain
                .iter()
                .map(|c| base64::decode(c).unwrap())
                .collect(),
        );
        res
    }
}

pub fn is_cert_logged<'a, C: hyper::client::Connect>(
    http_client: &'a hyper::Client<C>,
    cert: &'a [u8],
) -> impl Future<Item=bool, Error=()> + 'a {
    async_block! {
        let mut request = hyper::Request::new(
            hyper::Method::Get,
            format!("https://crt.sh/?d={}", sha256_hex(&cert))
                .parse()
                .unwrap(),
        );
        request.headers_mut().set(
            hyper::header::Connection::keep_alive(),
        );
        let response = await!(http_client.request(request)).unwrap();
        let res = Ok(response.status() == hyper::StatusCode::Ok);
        res
    }
}

pub fn url_for_cert(cert: &[u8]) -> String {
    format!("https://crt.sh?q={}", sha256_hex(cert).to_uppercase())
}
