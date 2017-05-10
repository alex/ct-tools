use base64;
use hyper;
use serde_json;
use url;

use hex::ToHex;

use ring::digest;

use super::ct::AddChainRequest;


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
    return add_chain_request
               .chain
               .iter()
               .map(|c| base64::decode(c).unwrap())
               .collect();
}

pub fn url_for_cert(cert: &[u8]) -> String {
    return format!("https://crt.sh?q={}",
                   digest::digest(&digest::SHA256, &cert)
                       .as_ref()
                       .to_hex()
                       .to_uppercase());
}
