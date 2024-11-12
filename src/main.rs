use std::path::PathBuf;
use std::sync::Arc;
use regex::bytes::Regex;
use walkdir::WalkDir;
use serde_json::Value as JsonValue;
use anyhow::{Result, anyhow};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio::fs;
use reqwest::Client;
use ring::{rand, signature};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Utc, Duration};
use pem::parse;

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
        Ok(Self { regex, semaphore })
    }

    pub async fn validate_gcp_credentials(&self, gcp_json: &[u8]) -> Result<(bool, Vec<String>)> {
        let _permit = self.semaphore.acquire().await?;
        let gcp_json_str = String::from_utf8_lossy(gcp_json);
        let token_info: JsonValue = serde_json::from_str(&gcp_json_str)?;
        let project_id = token_info["project_id"].as_str().unwrap_or("Unknown");
        let client_email = token_info["client_email"].as_str().unwrap_or("Unknown");
        let private_key = token_info["private_key"].as_str().unwrap_or("Unknown");
        let token_uri = token_info["token_uri"].as_str().unwrap_or("Unknown");

        if project_id == "Unknown" || client_email == "Unknown" || private_key == "Unknown" || token_uri == "Unknown" {
            return Ok((false, vec![]));
        }

        // Generate JWT
        let jwt = self.create_jwt(client_email, private_key, token_uri)?;

        // Request an access token
        let client = Client::new();
        let response = client
            .post(token_uri)
            .form(&[("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"), ("assertion", &jwt)])
            .send()
            .await?;

        if response.status().is_success() {
            let metadata = vec![
                format!("GCP Credential Type == {}", "service_account"),
                format!("GCP Project ID == {}", project_id),
                format!("GCP Client Email == {}", client_email),
            ];
            Ok((true, metadata))
        } else {
            Err(anyhow!("Failed to validate GCP credentials"))
        }
    }

    fn create_jwt(&self, client_email: &str, private_key_pem: &str, token_uri: &str) -> Result<String> {
        let now = Utc::now();
        let iat = now.timestamp();
        let exp = (now + Duration::hours(1)).timestamp();

        // JWT Header
        let header = URL_SAFE_NO_PAD.encode(
            r#"{"alg":"RS256","typ":"JWT"}"#
        );

        // JWT Claims
        let claims = format!(
            r#"{{
                "iss": "{}",
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "aud": "{}",
                "exp": {},
                "iat": {}
            }}"#,
            client_email, token_uri, exp, iat
        );
        let claims = URL_SAFE_NO_PAD.encode(claims);

        // Create message to sign
        let message = format!("{}.{}", header, claims);

        // Parse PEM private key
        let pem = parse(private_key_pem)
            .map_err(|e| anyhow!("Failed to parse PEM: {}", e))?;
        
        // Create key pair from the DER-encoded private key
        let key_pair = signature::RsaKeyPair::from_pkcs8(&pem.contents())
            .map_err(|_| anyhow!("Invalid RSA private key"))?;

        // Sign the message
        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; key_pair.public_modulus_len()];
        key_pair
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &rng,
                message.as_bytes(),
                &mut signature,
            )
            .map_err(|_| anyhow!("Failed to sign JWT"))?;

        let signature = URL_SAFE_NO_PAD.encode(&signature);

        // JWT Token
        Ok(format!("{}.{}.{}", header, claims, signature))
    }

    pub fn extract_credentials<'a>(&self, content: &'a [u8]) -> Vec<Vec<u8>> {
        self.regex
            .find_iter(content)
            .map(|m| m.as_bytes().to_vec())
            .collect()
    }
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

    let (read_tx, mut read_rx) = mpsc::channel::<(PathBuf, Vec<u8>)>(CHANNEL_BUFFER_SIZE);
    let (validate_tx, mut validate_rx) = mpsc::channel::<(PathBuf, Vec<u8>)>(CHANNEL_BUFFER_SIZE);
    let (result_tx, mut result_rx) = mpsc::channel::<ValidationResult>(CHANNEL_BUFFER_SIZE);

    // File Reading Pool
    let reader_handle = tokio::spawn(async move {
        let mut join_set = JoinSet::new();
        for path in files {
            let tx = read_tx.clone();
            join_set.spawn(async move {
                if let Ok(buffer) = fs::read(&path).await {
                    let _ = tx.send((path, buffer)).await;
                }
            });
        }
        while join_set.join_next().await.is_some() {}
    });

    // Extraction Pool
    let validator_clone = Arc::clone(&validator);
    let extraction_handle = tokio::spawn(async move {
        while let Some((path, buffer)) = read_rx.recv().await {
            let validator = Arc::clone(&validator_clone);
            let tx = validate_tx.clone();
            tokio::spawn(async move {
                let credentials = validator.extract_credentials(&buffer);
                for credential in credentials {
                    let _ = tx.send((path.clone(), credential)).await;
                }
            });
        }
    });

    // Validation Pool
    let validator_clone = Arc::clone(&validator);
    let validation_handle = tokio::spawn(async move {
        while let Some((path, credential)) = validate_rx.recv().await {
            let validator = Arc::clone(&validator_clone);
            let tx = result_tx.clone();
            tokio::spawn(async move {
                if let Ok((true, metadata)) = validator.validate_gcp_credentials(&credential).await {
                    let result = ValidationResult {
                        path: path.to_string_lossy().to_string(),
                        metadata,
                    };
                    let _ = tx.send(result).await;
                }
            });
        }
    });

    // Printing Results
    let printer_handle = tokio::spawn(async move {
        while let Some(result) = result_rx.recv().await {
            println!("\nValid credentials found in {}:", result.path);
            for item in result.metadata {
                println!("{}", item);
            }
        }
        println!("Scan complete!");
    });

    // Await all handles
    reader_handle.await?;
    extraction_handle.await?;
    validation_handle.await?;
    printer_handle.await?;

    Ok(())
}

#[tokio::main(worker_threads = 64)]
async fn main() -> Result<()> {
    run().await
}






//////////////////////////////////////////////////////////////////

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

//     pub async fn validate_gcp_credentials(&self, gcp_json: &[u8]) -> Result<(bool, Vec<String>)> {
//         let _permit = self.semaphore.acquire().await?;
//         let gcp_json_str = String::from_utf8_lossy(gcp_json);
//         let token_info: JsonValue = serde_json::from_str(&gcp_json_str)?;
//         let project_id = token_info["project_id"].as_str().unwrap_or("Unknown");
//         let client_email = token_info["client_email"].as_str().unwrap_or("Unknown");
//         let credential_type = token_info["type"].as_str().unwrap_or("Unknown");

//         if project_id == "Unknown" || client_email == "Unknown" || credential_type == "Unknown" {
//             return Ok((false, vec![]));
//         }

//         let gcp_json_string = gcp_json_str.to_string();
//         let sa_key = parse_service_account_key(gcp_json_string)
//             .map_err(|e| anyhow!("Failed to parse service account key: {}", e))?;
//         let auth = ServiceAccountAuthenticator::builder(sa_key)
//             .build()
//             .await
//             .map_err(|e| anyhow!("Failed to build authenticator: {}", e))?;
//         let scopes = vec!["https://www.googleapis.com/auth/cloud-platform"];
        
//         match auth.token(&scopes).await {
//             Ok(_) => {
//                 let metadata = vec![
//                     format!("GCP Credential Type == {}", credential_type),
//                     format!("GCP Project ID == {}", project_id),
//                     format!("GCP Client Email == {}", client_email),
//                 ];
//                 Ok((true, metadata))
//             },
//             Err(e) => Err(anyhow!("Failed to validate GCP credentials: {}", e)),
//         }
//     }

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