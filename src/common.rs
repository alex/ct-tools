use hex::ToHex;

use ring::digest;


#[derive(Debug)]
pub struct Log {
    pub description: String,
    pub url: String,
    pub is_google: bool,
}

pub fn sha256_hex(data: &[u8]) -> String {
    digest::digest(&digest::SHA256, data).as_ref().to_hex()
}
