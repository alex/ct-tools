use super::common::Log;

use hyper;
use serde_json;
use std::io::Read;


const LOG_LIST_URL: &'static str = "https://www.gstatic.com/ct/log_list/log_list.json";
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

    logs_response
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
        .collect()
}
