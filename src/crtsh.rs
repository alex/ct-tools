use super::common::sha256_hex;
use super::ct::AddChainRequest;
use base64;
use url;

pub async fn build_chain_for_cert(
    http_client: &reqwest::Client,
    cert: &[u8],
) -> Result<Vec<Vec<u8>>, ()> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("b64cert", &base64::encode(&cert))
        .append_pair("onlyonechain", "Y")
        .finish();
    let response = http_client
        .post("https://crt.sh/gen-add-chain")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Connection", "keep-alive")
        .body(body.into_bytes())
        .send()
        .await
        .map_err(|_| ())?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(());
    }

    let add_chain_request: AddChainRequest = response.json().await.unwrap();
    Ok(add_chain_request
        .chain
        .iter()
        .map(|c| base64::decode(c).unwrap())
        .collect())
}

pub async fn is_cert_logged(http_client: &reqwest::Client, cert: &[u8]) -> bool {
    let response = http_client
        .get(&format!("https://crt.sh/?d={}", sha256_hex(cert)))
        .send()
        .await
        .unwrap();
    response.status() == reqwest::StatusCode::OK
}

pub fn url_for_cert(cert: &[u8]) -> String {
    format!("https://crt.sh?q={}", sha256_hex(cert).to_uppercase())
}
