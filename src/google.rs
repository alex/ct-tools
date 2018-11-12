use super::common::Log;

use futures::compat::Future01CompatExt;
use futures::prelude::*;

use hyper;
use hyper::rt::Stream;
use serde_json;

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

pub fn fetch_trusted_ct_logs<'a, C: hyper::client::connect::Connect + 'static>(
    http_client: &'a hyper::Client<C>,
) -> impl Future<Item = Vec<Log>, Error = ()> + 'a {
    fetch_log_list(http_client, TRUSTED_LOG_LIST_URL.parse().unwrap())
}

pub fn fetch_all_ct_logs<'a, C: hyper::client::connect::Connect + 'static>(
    http_client: &'a hyper::Client<C>,
) -> impl Future<Item = Vec<Log>, Error = ()> + 'a {
    fetch_log_list(http_client, ALL_LOG_LIST_URL.parse().unwrap())
}

fn fetch_log_list<'a, C: hyper::client::connect::Connect + 'static>(
    http_client: &'a hyper::Client<C>,
    uri: hyper::Uri,
) -> impl Future<Output = Result<Vec<Log>, ()>> + 'a {
    async {
        let request = hyper::Request::builder()
            .method("GET")
            .uri(uri)
            .body(hyper::Body::empty())
            .unwrap();
        let response = await!(http_client.request(request).compat()).unwrap();
        // Limit the response to 10MB at most, to be resillient to DoS.
        let body = await!(response.into_body().take(10 * 1024 * 1024).concat2().compat()).unwrap();
        let logs_response: LogsResponse = serde_json::from_slice(&body).unwrap();

        let google_id = logs_response
            .operators
            .iter()
            .find(|o| o.name == "Google")
            .map(|o| o.id)
            .unwrap();

        Ok(
            logs_response
                .logs
                .into_iter()
                .filter(|log| log.disqualified_at.is_none())
                .map(move |log| {
                    Log {
                        url: log.url,
                        description: log.description,
                        is_google: log.operated_by.contains(&google_id),
                    }
                })
                .collect(),
        )
    }
}
