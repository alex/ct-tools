use ct_tools::crtsh;
use ct_tools::ct::submit_cert_to_logs;
use ct_tools::google::{fetch_all_ct_logs, fetch_trusted_ct_logs};
use futures::stream::StreamExt;
use pem;
use std::fs::{self, File};
use std::io::Read;
use std::time::Duration;
use structopt;
use structopt::StructOpt;

fn pems_to_chain(data: &[u8]) -> Vec<Vec<u8>> {
    pem::parse_many(data)
        .into_iter()
        .filter(|p| p.tag == "CERTIFICATE")
        .map(|p| p.contents)
        .collect()
}

fn compute_paths(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .flat_map(|p| {
            if fs::metadata(p).unwrap().is_dir() {
                fs::read_dir(p)
                    .unwrap()
                    .map(|d| d.unwrap().path().to_str().unwrap().to_string())
                    .collect()
            } else {
                vec![p.clone()]
            }
        })
        .collect()
}

async fn submit(paths: &[String], all_logs: bool) {
    let http_client = reqwest::Client::new();

    let logs = if all_logs {
        fetch_all_ct_logs(&http_client).await
    } else {
        fetch_trusted_ct_logs(&http_client).await
    };

    let all_paths = compute_paths(paths);

    let work = all_paths
        .iter()
        .map(|path| {
            let path = path.to_string();
            let mut contents = Vec::new();
            File::open(&path)
                .unwrap()
                .read_to_end(&mut contents)
                .unwrap();

            let http_client = &http_client;
            let logs = &logs;
            let mut chain = pems_to_chain(&contents);
            async move {
                if chain.len() == 1 {
                    // TODO: There's got to be some way to do this ourselves, instead of using crt.sh
                    // as a glorified AIA chaser.
                    println!(
                    "[{}] Only one certificate in chain, using crt.sh to build a full chain ...",
                    &path
                );
                    let new_chain = crtsh::build_chain_for_cert(&http_client, &chain[0]).await;
                    chain = match new_chain {
                        Ok(c) => c,
                        Err(()) => {
                            println!("[{}] Unable to build a chain", path);
                            return futures::future::ready(());
                        }
                    }
                }
                println!("[{}] Submitting ...", &path);
                let timeout = Duration::from_secs(30);
                let scts = submit_cert_to_logs(&http_client, &logs, &chain, timeout).await;

                if !scts.is_empty() {
                    println!(
                        "[{}] Find the cert on crt.sh: {}",
                        path,
                        crtsh::url_for_cert(&chain[0])
                    );
                    let mut table = prettytable::Table::new();
                    table.add_row(prettytable::Row::new(vec![prettytable::Cell::new("Log")]));
                    for (log_idx, _) in scts {
                        let log = &logs[log_idx];
                        table.add_row(prettytable::Row::new(vec![prettytable::Cell::new(
                            &log.description,
                        )]));
                    }
                    table.printstd();
                    println!();
                    println!();
                } else {
                    println!("[{}] No SCTs obtained", &path);
                }

                futures::future::ready(())
            }
        })
        .collect::<futures::stream::FuturesOrdered<_>>()
        .buffered(4)
        .for_each(move |()| async {});
    work.await;
}

async fn check(paths: &[String]) {
    let http_client = reqwest::Client::new();

    let all_paths = compute_paths(paths);

    let work = all_paths
        .iter()
        .map(|path| {
            let path = path.to_string();
            let mut contents = Vec::new();
            File::open(&path)
                .unwrap()
                .read_to_end(&mut contents)
                .unwrap();

            let http_client = &http_client;
            let chain = pems_to_chain(&contents);
            async move {
                if !chain.is_empty() && crtsh::is_cert_logged(&http_client, &chain[0]).await {
                    println!("{} was already logged", path);
                } else {
                    println!("{} has not been logged", path);
                }

                futures::future::ready(())
            }
        })
        .collect::<futures::stream::FuturesOrdered<_>>()
        .buffered(16)
        .for_each(move |()| async {});
    work.await;
}

#[derive(StructOpt)]
#[structopt(name = "ct-tools")]
enum Opt {
    #[structopt(name = "submit", about = "Directly submits certificates to CT logs")]
    Submit {
        #[structopt(
            long = "all-logs",
            help = "Submit to all logs, instead of just ones trusted by Chrome"
        )]
        all_logs: bool,
        #[structopt(help = "Path to certificate or chain")]
        paths: Vec<String>,
    },

    #[structopt(
        name = "check",
        about = "Checks whether a certificate exists in CT logs"
    )]
    Check {
        #[structopt(help = "Path to certificate or chain")]
        paths: Vec<String>,
    },
}

#[tokio::main]
async fn main() {
    match Opt::from_args() {
        Opt::Submit { paths, all_logs } => {
            submit(&paths, all_logs).await;
        }
        Opt::Check { paths } => {
            check(&paths).await;
        }
    }
}
