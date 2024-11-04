use std::path::{Path, PathBuf};
use std::sync::Arc;
use regex::bytes::Regex;
use walkdir::WalkDir;
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::Value as JsonValue;
use anyhow::{Result, anyhow};
use yup_oauth2::{parse_service_account_key, ServiceAccountAuthenticator};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio::fs;
use futures::StreamExt;

const MAX_CONCURRENT_VALIDATIONS: usize = 500;
const CHANNEL_BUFFER_SIZE: usize = 1000;

#[derive(Debug, Clone)]
struct ValidationResult {
    path: String,
    metadata: Vec<String>,
}

struct GcpValidator {
    regex: Regex,
    semaphore: Arc<Semaphore>,
}

impl GcpValidator {
    pub fn new() -> Result<Self> {
        let regex = Regex::new(r#"(?m)(?mis)(\{[^{}]*"auth_provider_x509_cert_url":.{0,512}?})|\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*"auth_provider_x509_cert_url":\s*".+?"(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}"#)
            .map_err(|e| anyhow!("Failed to compile regex: {}", e))?;

        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_VALIDATIONS));

        Ok(Self { 
            regex,
            semaphore,
        })
    }

    pub async fn validate_gcp_credentials(&self, gcp_json: &[u8]) -> Result<(bool, Vec<String>)> {
        let _permit = self.semaphore.acquire().await?;

        let gcp_json_str = String::from_utf8_lossy(gcp_json);
        let token_info: JsonValue = serde_json::from_str(&gcp_json_str)?;
        
        let project_id = token_info["project_id"].as_str().unwrap_or("Unknown");
        let client_email = token_info["client_email"].as_str().unwrap_or("Unknown");
        let credential_type = token_info["type"].as_str().unwrap_or("Unknown");

        if project_id == "Unknown" || client_email == "Unknown" || credential_type == "Unknown" {
            return Ok((false, vec![]));
        }

        let gcp_json_string = gcp_json_str.to_string();
        let sa_key = parse_service_account_key(gcp_json_string)
            .map_err(|e| anyhow!("Failed to parse service account key: {}", e))?;

        let auth = ServiceAccountAuthenticator::builder(sa_key)
            .build()
            .await
            .map_err(|e| anyhow!("Failed to build authenticator: {}", e))?;

        let scopes = vec!["https://www.googleapis.com/auth/cloud-platform"];
        
        match auth.token(&scopes).await {
            Ok(_) => {
                let metadata = vec![
                    format!("GCP Credential Type == {}", credential_type),
                    format!("GCP Project ID == {}", project_id),
                    format!("GCP Client Email == {}", client_email),
                ];
                Ok((true, metadata))
            },
            Err(e) => {
                Err(anyhow!("Failed to validate GCP credentials: {}", e))
            },
        }
    }

    pub fn extract_credentials<'a>(&self, content: &'a [u8]) -> Vec<Vec<u8>> {
        self.regex
            .find_iter(content)
            .map(|m| m.as_bytes().to_vec())
            .collect()
    }
}

async fn process_file(
    path: PathBuf,
    validator: Arc<GcpValidator>,
    tx: mpsc::Sender<ValidationResult>,
) -> Result<()> {
    let buffer = fs::read(&path).await?;
    let credentials = validator.extract_credentials(&buffer);

    for credential in credentials {
        if let Ok((true, metadata)) = validator.validate_gcp_credentials(&credential).await {
            let result = ValidationResult {
                path: path.to_string_lossy().to_string(),
                metadata,
            };
            let _ = tx.send(result).await;
        }
    }

    Ok(())
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <directory_to_scan>", args[0]);
        std::process::exit(1);
    }

    let top_level_dir = &args[1];
    let validator = Arc::new(GcpValidator::new()?);

    let files: Vec<PathBuf> = WalkDir::new(top_level_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_owned())
        .collect();

    let total_files = files.len();
    println!("Found {} files to scan", total_files);

    let pb = ProgressBar::new(total_files as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files processed ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let (tx, mut rx) = mpsc::channel::<ValidationResult>(CHANNEL_BUFFER_SIZE);

    let printer_handle = tokio::spawn(async move {
        let mut found = 0;
        while let Some(result) = rx.recv().await {
            found += 1;
            println!("\nValid credentials found ({}) in {}:", found, result.path);
            for item in result.metadata {
                println!("{}", item);
            }
            pb.inc(1);
        }
        pb.finish_with_message("Scan complete!");
        println!("\nFound {} valid credentials", found);
    });

    let mut join_set = JoinSet::new();
    for path in files {
        let validator = Arc::clone(&validator);
        let tx = tx.clone();
        
        join_set.spawn(async move {
            if let Err(e) = process_file(path, validator, tx).await {
                eprintln!("Error processing file: {}", e);
            }
        });
    }

    while let Some(result) = join_set.join_next().await {
        if let Err(e) = result {
            eprintln!("Task failed: {}", e);
        }
    }

    drop(tx);
    printer_handle.await?;

    Ok(())
}

#[tokio::main(worker_threads = 32)]
async fn main() -> Result<()> {
    run().await
}
