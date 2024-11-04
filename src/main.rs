use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};
use std::thread;
use regex::Regex;
use walkdir::WalkDir;
use rayon::prelude::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use serde_json::Value as JsonValue;
use anyhow::{Result, anyhow};
use yup_oauth2::{parse_service_account_key, ServiceAccountAuthenticator};
use num_cpus;
use tokio::runtime::Runtime;
use tokio::sync::Semaphore;

const MAX_CONCURRENT_VALIDATIONS: usize = 500; // Adjust this value based on your needs

#[derive(Debug, Clone)]
struct ValidationResult {
    path: String,
    metadata: Vec<String>,
}

struct GcpValidator {
    regex: Regex,
    runtime: Arc<Runtime>,
    semaphore: Arc<Semaphore>,
    active_tasks: Arc<AtomicUsize>,
}

impl GcpValidator {
    pub fn new() -> Result<Self> {
        let regex = Regex::new(r#"(?m)(?mis)(\{[^{}]*"auth_provider_x509_cert_url":.{0,512}?})|\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*"auth_provider_x509_cert_url":\s*".+?"(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}"#)
            .map_err(|e| anyhow!("Failed to compile regex: {}", e))?;

        // Use a dedicated multi-threaded Tokio runtime for async operations
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(num_cpus::get())  // Sets threads based on available CPUs
                .enable_all()  // Enables all Tokio runtime components
                .build()?  // Builds the runtime
        );

        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_VALIDATIONS));

        Ok(Self { 
            regex,
            runtime,
            semaphore,
            active_tasks: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub async fn validate_gcp_credentials(&self, gcp_json: &str) -> Result<(bool, Vec<String>)> {
        // Acquire semaphore asynchronously
        let _permit = self.semaphore.acquire().await?;

        let token_info: JsonValue = serde_json::from_str(gcp_json)?;
        let project_id = token_info["project_id"].as_str().unwrap_or("Unknown");
        let client_email = token_info["client_email"].as_str().unwrap_or("Unknown");
        let credential_type = token_info["type"].as_str().unwrap_or("Unknown");

        if project_id == "Unknown" || client_email == "Unknown" || credential_type == "Unknown" {
            return Ok((false, vec![]));
        }

        let sa_key = parse_service_account_key(gcp_json)
            .map_err(|e| anyhow!("Failed to parse service account key: {}", e))?;

        // Authenticate asynchronously
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


    pub fn extract_credentials(&self, content: &str) -> Vec<String> {
        self.regex
            .find_iter(content)
            .map(|m| m.as_str().to_string())
            .collect()
    }
}

fn process_file(
    path: &Path,
    validator: Arc<GcpValidator>,
    tx: Sender<ValidationResult>,
    concurrent_pb: Arc<ProgressBar>,
) -> Result<()> {
    validator.active_tasks.fetch_add(1, Ordering::SeqCst);
    concurrent_pb.set_position(validator.active_tasks.load(Ordering::SeqCst) as u64);

    let content = std::fs::read_to_string(path)?;
    let credentials = validator.extract_credentials(&content);

    // Set up batching
    let batch_size = 10;
    let batched_credentials: Vec<Vec<String>> = credentials.chunks(batch_size)
        .map(|chunk| chunk.to_vec())
        .collect();

    // Spawn async tasks for each batch
    validator.runtime.block_on(async {
        for batch in batched_credentials {
            let mut batch_results = Vec::new();

            let validation_tasks: Vec<_> = batch.into_iter()
                .map(|credential| {
                    let validator = Arc::clone(&validator);
                    async move {
                        validator.validate_gcp_credentials(&credential).await
                    }
                })
                .collect();

            // Await all validations in the batch
            let results = futures::future::join_all(validation_tasks).await;

            for result in results {
                if let Ok((true, metadata)) = result {
                    batch_results.push(ValidationResult {
                        path: path.to_string_lossy().to_string(),
                        metadata,
                    });
                }
            }

            // Send batch results if any credentials are valid
            for result in batch_results {
                tx.send(result).map_err(|e| anyhow!(e))?; // Explicitly handle the SendError here
            }
        }
        Ok::<_, anyhow::Error>(()) // Return Ok(()) as the Result for the async block
    })?;

    validator.active_tasks.fetch_sub(1, Ordering::SeqCst);
    concurrent_pb.set_position(validator.active_tasks.load(Ordering::SeqCst) as u64);

    Ok(())
}


fn main() -> Result<()> {
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

    let multi = MultiProgress::new();
    
    let completed_pb = multi.add(ProgressBar::new(total_files as u64));
    completed_pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files completed ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let concurrent_pb = Arc::new(multi.add(ProgressBar::new(MAX_CONCURRENT_VALIDATIONS as u64)));
    concurrent_pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.yellow} Active validations: {pos}/{len}")
            .unwrap()
            .progress_chars("=>-"),
    );

    let (tx, rx) = mpsc::channel::<ValidationResult>();

    let printer_handle = thread::spawn(move || {
        let mut found = 0;
        while let Ok(result) = rx.recv() {
            found += 1;
            println!("\nValid credentials found ({}) in {}:", found, result.path);
            for item in result.metadata {
                println!("{}", item);
            }
            completed_pb.inc(1);
        }
        completed_pb.finish_with_message("Scan complete!");
        println!("\nFound {} valid credentials", found);
    });

    println!("Processing with Rayon’s default thread pool and up to {} concurrent validations", 
             MAX_CONCURRENT_VALIDATIONS);

    let active_tasks = Arc::clone(&validator.active_tasks);
    let concurrent_pb_clone = Arc::clone(&concurrent_pb);
    let progress_handle = thread::spawn(move || {
        while active_tasks.load(Ordering::SeqCst) > 0 || concurrent_pb_clone.position() > 0 {
            let current = active_tasks.load(Ordering::SeqCst);
            concurrent_pb_clone.set_position(current as u64);
            thread::sleep(std::time::Duration::from_millis(100));
        }
        concurrent_pb_clone.finish();
    });

    // Use Rayon’s default global thread pool with .into_par_iter()
    files.into_par_iter()
        .for_each(|path| {
            let validator = Arc::clone(&validator);
            let tx = tx.clone();
            
            if let Err(e) = process_file(&path, validator.clone(), tx.clone(), concurrent_pb.clone()) {
                eprintln!("Error processing {}: {}", path.display(), e);
            }
        });

    drop(tx);
    printer_handle.join().unwrap();
    progress_handle.join().unwrap();

    Ok(())
}
