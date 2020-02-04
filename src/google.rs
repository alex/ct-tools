use super::common::Log;

use serde::Deserialize;

const TRUSTED_LOG_LIST_URL: &str = "https://www.gstatic.com/ct/log_list/log_list.json";
const ALL_LOG_LIST_URL: &str = "https://www.gstatic.com/ct/log_list/all_logs_list.json";

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

pub async fn fetch_trusted_ct_logs(http_client: &reqwest::Client) -> Vec<Log> {
    fetch_log_list(http_client, TRUSTED_LOG_LIST_URL.parse().unwrap()).await
}

pub async fn fetch_all_ct_logs(http_client: &reqwest::Client) -> Vec<Log> {
    fetch_log_list(http_client, ALL_LOG_LIST_URL.parse().unwrap()).await
}

async fn fetch_log_list(http_client: &reqwest::Client, url: url::Url) -> Vec<Log> {
    let response = http_client.get(url).send().await.unwrap();
    let logs_response: LogsResponse = response.json().await.unwrap();

    let google_id = logs_response
        .operators
        .iter()
        .find(|o| o.name == "Google")
        .map(|o| o.id)
        .unwrap();

    logs_response
        .logs
        .into_iter()
        .filter(|log| log.disqualified_at.is_none())
        .map(move |log| Log {
            url: log.url,
            description: log.description,
            is_google: log.operated_by.contains(&google_id),
        })
        .collect()
}
