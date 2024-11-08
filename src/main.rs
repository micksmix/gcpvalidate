use std::sync::Arc;
use regex::bytes::Regex;
use walkdir::WalkDir;
use serde_json::Value as JsonValue;
use anyhow::{Result, anyhow};
use tokio::sync::Semaphore;
use tokio::fs;
use futures::stream::{self, StreamExt};
use yup_oauth2::{parse_service_account_key, ServiceAccountAuthenticator};

const MAX_CONCURRENT_VALIDATIONS: usize = 500;
const MAX_CONCURRENT_FILES: usize = 100; // Limit the number of concurrent file processing tasks

struct GcpValidator {
    regex: Regex,
    semaphore: Arc<Semaphore>,
}

impl GcpValidator {
    pub fn new() -> Result<Self> {
        let regex = Regex::new(r#"(?m)(?mis)(\{[^{}]*"auth_provider_x509_cert_url":.{0,512}?})|\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*"auth_provider_x509_cert_url":\s*".+?"(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}"#)
            .map_err(|e| anyhow!("Failed to compile regex: {}", e))?;
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_VALIDATIONS));
        Ok(Self { regex, semaphore })
    }

    async fn validate_gcp_credentials(&self, gcp_json: Vec<u8>) -> Result<Option<Vec<String>>> {
        let _permit = self.semaphore.acquire().await?;

        // Parse JSON from the credential
        let gcp_json_str = String::from_utf8_lossy(&gcp_json);
        let token_info: JsonValue = serde_json::from_str(&gcp_json_str)?;
        let project_id = token_info["project_id"].as_str().unwrap_or("Unknown").to_string();
        let client_email = token_info["client_email"].as_str().unwrap_or("Unknown").to_string();
        let credential_type = token_info["type"].as_str().unwrap_or("Unknown").to_string();

        if project_id == "Unknown" || client_email == "Unknown" || credential_type == "Unknown" {
            return Ok(None);
        }

        // Parse the service account key
        let sa_key = parse_service_account_key(gcp_json_str.to_string())
            .map_err(|e| anyhow!("Failed to parse service account key: {}", e))?;

        // Build the authenticator
        let auth = ServiceAccountAuthenticator::builder(sa_key)
            .build()
            .await
            .map_err(|e| anyhow!("Failed to build authenticator: {}", e))?;

        let scopes = vec!["https://www.googleapis.com/auth/cloud-platform"];

        // Attempt to get a token to validate the credentials
        match auth.token(&scopes).await {
            Ok(_) => {
                let metadata = vec![
                    format!("GCP Credential Type == {}", credential_type),
                    format!("GCP Project ID == {}", project_id),
                    format!("GCP Client Email == {}", client_email),
                ];
                Ok(Some(metadata))
            },
            Err(e) => Err(anyhow!("Failed to validate GCP credentials: {}", e)),
        }
    }

    fn extract_credentials(&self, content: &[u8]) -> Vec<Vec<u8>> {
        self.regex
            .find_iter(content)
            .map(|m| m.as_bytes().to_vec())
            .collect()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <directory_to_scan>", args[0]);
        std::process::exit(1);
    }

    let dir = &args[1];
    let validator = Arc::new(GcpValidator::new()?);

    let entries = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_owned())
        .collect::<Vec<_>>();

    let validator = Arc::clone(&validator);

    stream::iter(entries)
        .map(|path| {
            let validator = Arc::clone(&validator);
            async move {
                let content = fs::read(&path).await?;
                let credentials = validator.extract_credentials(&content);

                for credential in credentials {
                    if let Some(metadata) = validator.validate_gcp_credentials(credential).await? {
                        println!("\nValid credentials found in {}:", path.display());
                        for item in metadata {
                            println!("{}", item);
                        }
                    }
                }

                Ok::<(), anyhow::Error>(())
            }
        })
        .buffer_unordered(MAX_CONCURRENT_FILES)
        .for_each(|result| async {
            if let Err(e) = result {
                eprintln!("Error processing file: {:?}", e);
            }
        })
        .await;

    println!("Scan complete!");
    Ok(())
}

// use std::path::PathBuf;
// use std::sync::Arc;
// use regex::bytes::Regex;
// use walkdir::WalkDir;
// use serde_json::Value as JsonValue;
// use anyhow::{Result, anyhow};
// use yup_oauth2::{parse_service_account_key, ServiceAccountAuthenticator};
// use tokio::sync::{Semaphore, mpsc};
// use tokio::task::JoinSet;
// use tokio::fs;

// const MAX_CONCURRENT_VALIDATIONS: usize = 500;
// const CHANNEL_BUFFER_SIZE: usize = 1000;

// #[derive(Debug, Clone)]
// struct ValidationResult {
//     path: String,
//     metadata: Vec<String>,
// }

// struct GcpValidator {
//     regex: Regex,
//     semaphore: Arc<Semaphore>,
// }

// impl GcpValidator {
//     pub fn new() -> Result<Self> {
//         let regex = Regex::new(r#"(?m)(?mis)(\{[^{}]*"auth_provider_x509_cert_url":.{0,512}?})|\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*"auth_provider_x509_cert_url":\s*".+?"(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}"#)
//             .map_err(|e| anyhow!("Failed to compile regex: {}", e))?;
//         let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_VALIDATIONS));
//         Ok(Self { regex, semaphore })
//     }

    // pub async fn validate_gcp_credentials(&self, gcp_json: &[u8]) -> Result<(bool, Vec<String>)> {
    //     let _permit = self.semaphore.acquire().await?;
    //     let gcp_json_str = String::from_utf8_lossy(gcp_json);
    //     let token_info: JsonValue = serde_json::from_str(&gcp_json_str)?;
    //     let project_id = token_info["project_id"].as_str().unwrap_or("Unknown");
    //     let client_email = token_info["client_email"].as_str().unwrap_or("Unknown");
    //     let credential_type = token_info["type"].as_str().unwrap_or("Unknown");

    //     if project_id == "Unknown" || client_email == "Unknown" || credential_type == "Unknown" {
    //         return Ok((false, vec![]));
    //     }

    //     let gcp_json_string = gcp_json_str.to_string();
    //     let sa_key = parse_service_account_key(gcp_json_string)
    //         .map_err(|e| anyhow!("Failed to parse service account key: {}", e))?;
    //     let auth = ServiceAccountAuthenticator::builder(sa_key)
    //         .build()
    //         .await
    //         .map_err(|e| anyhow!("Failed to build authenticator: {}", e))?;
    //     let scopes = vec!["https://www.googleapis.com/auth/cloud-platform"];
        
    //     match auth.token(&scopes).await {
    //         Ok(_) => {
    //             let metadata = vec![
    //                 format!("GCP Credential Type == {}", credential_type),
    //                 format!("GCP Project ID == {}", project_id),
    //                 format!("GCP Client Email == {}", client_email),
    //             ];
    //             Ok((true, metadata))
    //         },
    //         Err(e) => Err(anyhow!("Failed to validate GCP credentials: {}", e)),
    //     }
    // }

//     pub fn extract_credentials<'a>(&self, content: &'a [u8]) -> Vec<Vec<u8>> {
//         self.regex
//             .find_iter(content)
//             .map(|m| m.as_bytes().to_vec())
//             .collect()
//     }
// }

// async fn run() -> Result<()> {
//     let args: Vec<String> = std::env::args().collect();
//     if args.len() != 2 {
//         eprintln!("Usage: {} <directory_to_scan>", args[0]);
//         std::process::exit(1);
//     }

//     let top_level_dir = &args[1];
//     let validator = Arc::new(GcpValidator::new()?);

//     let files: Vec<PathBuf> = WalkDir::new(top_level_dir)
//         .into_iter()
//         .filter_map(|e| e.ok())
//         .filter(|e| e.file_type().is_file())
//         .map(|e| e.path().to_owned())
//         .collect();

//     let (read_tx, mut read_rx) = mpsc::channel::<(PathBuf, Vec<u8>)>(CHANNEL_BUFFER_SIZE);
//     let (validate_tx, mut validate_rx) = mpsc::channel::<(PathBuf, Vec<u8>)>(CHANNEL_BUFFER_SIZE);
//     let (result_tx, mut result_rx) = mpsc::channel::<ValidationResult>(CHANNEL_BUFFER_SIZE);

//     // File Reading Pool
//     let reader_handle = tokio::spawn(async move {
//         let mut join_set = JoinSet::new();
//         for path in files {
//             let tx = read_tx.clone();
//             join_set.spawn(async move {
//                 if let Ok(buffer) = fs::read(&path).await {
//                     let _ = tx.send((path, buffer)).await;
//                 }
//             });
//         }
//         while join_set.join_next().await.is_some() {}
//     });

//     // Extraction Pool
//     let validator_clone = Arc::clone(&validator);
//     let extraction_handle = tokio::spawn(async move {
//         while let Some((path, buffer)) = read_rx.recv().await {
//             let validator = Arc::clone(&validator_clone);
//             let tx = validate_tx.clone();
//             tokio::spawn(async move {
//                 let credentials = validator.extract_credentials(&buffer);
//                 for credential in credentials {
//                     let _ = tx.send((path.clone(), credential)).await;
//                 }
//             });
//         }
//     });

//     // Validation Pool
//     let validator_clone = Arc::clone(&validator);
//     let validation_handle = tokio::spawn(async move {
//         while let Some((path, credential)) = validate_rx.recv().await {
//             let validator = Arc::clone(&validator_clone);
//             let tx = result_tx.clone();
//             tokio::spawn(async move {
//                 if let Ok((true, metadata)) = validator.validate_gcp_credentials(&credential).await {
//                     let result = ValidationResult {
//                         path: path.to_string_lossy().to_string(),
//                         metadata,
//                     };
//                     let _ = tx.send(result).await;
//                 }
//             });
//         }
//     });

//     // Printing Results
//     let printer_handle = tokio::spawn(async move {
//         while let Some(result) = result_rx.recv().await {
//             println!("\nValid credentials found in {}:", result.path);
//             for item in result.metadata {
//                 println!("{}", item);
//             }
//         }
//         println!("Scan complete!");
//     });

//     // Await all handles
//     reader_handle.await?;
//     extraction_handle.await?;
//     validation_handle.await?;
//     printer_handle.await?;

//     Ok(())
// }

// #[tokio::main(worker_threads = 64)]
// async fn main() -> Result<()> {
//     run().await
// }