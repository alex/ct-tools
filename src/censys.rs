use super::common::sha256_hex;

use hyper;
use serde_json;
use std::collections::HashMap;


const CENSYS_USER: &'static str = "57ece743-1f12-42a0-9dc6-51811cf4be65";
const CENSYS_PASSWORD: &'static str = "3bTj4aP9jQjuoNiTOGBBNMyNz1hUS4OJ";

#[derive(Deserialize)]
struct CtDetails {}

#[derive(Deserialize)]
struct CensysViewCertificateResponse {
    ct: Option<HashMap<String, CtDetails>>,
}

pub fn is_cert_logged(http_client: &hyper::Client, cert: &[u8]) -> bool {
    let response = http_client
        .get(&format!("https://censys.io/api/v1/view/certificates/{}",
                     sha256_hex(cert)))
        .header(hyper::header::Authorization(hyper::header::Basic {
                                                 username: CENSYS_USER.to_string(),
                                                 password: Some(CENSYS_PASSWORD.to_string()),
                                             }))
        .send()
        .unwrap();

    // The certificate isn't known to Censys at all
    if response.status == hyper::status::StatusCode::NotFound {
        return false;
    }
    assert_eq!(response.status, hyper::status::StatusCode::Ok);

    let certificate_details: CensysViewCertificateResponse = serde_json::from_reader(response)
        .unwrap();
    match certificate_details.ct {
        Some(ct) => !ct.is_empty(),
        None => false,
    }
}
