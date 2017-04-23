extern crate base64;
extern crate byteorder;
extern crate hyper;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use byteorder::{BigEndian, WriteBytesExt};

use std::io::{Read, Write};


#[derive(Debug, Clone)]
pub struct Log {
    pub description: String,
    pub url: String,
    is_google: bool,
}

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
        b.write(&log_id).unwrap();

        b.write_u64::<BigEndian>(self.timestamp).unwrap();

        let extensions = base64::decode(&self.extensions).unwrap();
        assert!(extensions.len() <= 65535);
        b.write_u16::<BigEndian>(extensions.len() as u16)
            .unwrap();
        b.write(&extensions).unwrap();

        let signature = base64::decode(&self.signature).unwrap();
        b.write(&signature).unwrap();

        return b;
    }
}


#[derive(Deserialize)]
struct LogsResponseLogs {
    description: String,
    url: String,
    operated_by: Vec<u32>,
    disqualified_at: Option<u64>,
}

#[derive(Deserialize)]
struct LogsResponseOperators {
    name: String,
    id: u32,
}

#[derive(Deserialize)]
struct LogsResponse {
    logs: Vec<LogsResponseLogs>,
    operators: Vec<LogsResponseOperators>,
}

const LOG_LIST_URL: &'static str = "https://www.gstatic.com/ct/log_list/log_list.json";

pub fn fetch_trusted_ct_logs(http_client: &hyper::Client) -> Vec<Log> {
    let response = http_client.get(LOG_LIST_URL).send().unwrap();
    // Limit the response to 10MB at most, to be resillient to DoS.
    let logs_response: LogsResponse = serde_json::from_reader(response.take(10 * 1024 * 1024))
        .unwrap();

    let google_id = logs_response
        .operators
        .iter()
        .find(|o| o.name == "Google")
        .map(|o| o.id);

    return logs_response
               .logs
               .into_iter()
               .filter(|log| log.disqualified_at.is_none())
               .map(|log| {
                        Log {
                            url: log.url,
                            description: log.description,
                            is_google: log.operated_by.contains(&google_id.unwrap()),
                        }
                    })
               .collect();
}
