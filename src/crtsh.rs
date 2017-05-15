use super::common::sha256_hex;
use super::ct::AddChainRequest;
use base64;
use hyper;
use serde_json;
use url;

pub fn build_chain_for_cert(http_client: &hyper::Client, cert: &[u8]) -> Vec<Vec<u8>> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("b64cert", &base64::encode(cert))
        .finish();
    let body_bytes = body.as_bytes();
    let response = http_client
        .post("https://crt.sh/gen-add-chain")
        .header(hyper::header::ContentType::form_url_encoded())
        .body(hyper::client::Body::BufBody(body_bytes, body_bytes.len()))
        .send()
        .unwrap();

    let add_chain_request: AddChainRequest = serde_json::from_reader(response).unwrap();
    add_chain_request
        .chain
        .iter()
        .map(|c| base64::decode(c).unwrap())
        .collect()
}

pub fn is_cert_logged(http_client: &hyper::Client, cert: &[u8]) -> bool {
    let response = http_client.get(&format!("https://crt.sh/?d={}", sha256_hex(cert))).send().unwrap();
    return response.status == hyper::status::StatusCode::Ok;
}

pub fn url_for_cert(cert: &[u8]) -> String {
    format!("https://crt.sh?q={}", sha256_hex(cert).to_uppercase())
}
