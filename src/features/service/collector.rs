use crate::shared::traits::{AsyncDataCollector, DataCollector};
use crate::shared::error::CollectionError;
use crate::features::service::models::{ServiceInformation, ServiceInformationBuilder};
use encoding_rs::GBK;
use log::{error, info, warn};
use regex::Regex;
use std::process::Command;
use which::which;
use chrono::Utc;
use uuid::Uuid;

pub struct ServiceCollector {
    hostname: String,
}

impl ServiceCollector {
    pub fn new() -> Self {
        Self {
            hostname: whoami::hostname(),
        }
    }

    fn collect_services(&self) -> Result<Vec<ServiceInformation>, CollectionError> {
        let mut services = Vec::new();
        
        if cfg!(target_os = "windows") {
            info!("Collecting Windows services");
            match Command::new("sc").args(["query"]).output() {
                Ok(output) => {
                    let (cow, _encoding_used, had_errors) = GBK.decode(&output.stdout);
                    if had_errors {
                        error!("Error decoding sc command output with GBK encoding");
                    }

                    let output_str = cow.into_owned();
                    let service_name_re = Regex::new(r"SERVICE_NAME:\s*(.+)").unwrap();
                    let display_name_re = Regex::new(r"DISPLAY_NAME:\s*(.+)").unwrap();
                    let state_re = Regex::new(r"STATE\s*:\s*\d+\s*(.+)").unwrap();
                    
                    let mut current_service = None;
                    let mut current_name = String::new();
                    
                    for line in output_str.lines() {
                        if let Some(cap) = service_name_re.captures(line) {
                            if let Some(service) = current_service.take() {
                                services.push(service);
                            }
                            current_name = cap[1].trim().to_string();
                        } else if let Some(cap) = display_name_re.captures(line) {
                            let display_name = cap[1].trim().to_string();
                            current_service = Some(ServiceInformationBuilder::new()
                                .id(Uuid::new_v4().to_string())
                                .timestamp(Utc::now())
                                .source(self.hostname.clone())
                                .category(String::from("service"))
                                .name(current_name.clone())
                                .display_name(display_name)
                                .status(String::from("Unknown"))
                                .startup_type(String::from("Unknown"))
                                .build()
                                .map_err(|e| CollectionError::Parse(e))?);
                        } else if let Some(cap) = state_re.captures(line) {
                            if let Some(service) = &mut current_service {
                                service.status = cap[1].trim().to_string();
                            }
                        }
                    }
                    
                    if let Some(service) = current_service {
                        services.push(service);
                    }
                    info!("Found {} Windows services", services.len());
                }
                Err(e) => {
                    error!("Failed to execute sc command: {}", e);
                }
            }
        } else if cfg!(target_os = "linux") {
            info!("Collecting Linux services");
            if let Ok(systemctl_path) = which("systemctl") {
                match Command::new(systemctl_path)
                    .args(["list-units", "--type=service", "--all", "--no-pager", "--plain"])
                    .output() 
                {
                    Ok(output) => {
                        if let Ok(output_str) = String::from_utf8(output.stdout) {
                            for line in output_str.lines().skip(1) {
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if parts.len() >= 4 {
                                    let name = parts[0].trim_end_matches(".service").to_string();
                                    let service = ServiceInformationBuilder::new()
                                        .id(Uuid::new_v4().to_string())
                                        .timestamp(Utc::now())
                                        .source(self.hostname.clone())
                                        .category(String::from("service"))
                                        .name(name.clone())
                                        .display_name(name)
                                        .status(parts[3].to_string())
                                        .startup_type(String::from("Unknown"))
                                        .build()
                                        .map_err(|e| CollectionError::Parse(e))?;
                                    services.push(service);
                                }
                            }
                            info!("Found {} Linux services", services.len());
                        } else {
                            error!("Failed to parse systemctl output");
                        }
                    }
                    Err(e) => {
                        error!("Failed to execute systemctl command: {}", e);
                    }
                }
            } else {
                warn!("systemctl command not found");
            }
        }
        
        Ok(services)
    }

    fn internal_validate(&self) -> Result<(), CollectionError> {
        if cfg!(target_os = "windows") {
            if which("sc").is_err() {
                return Err(CollectionError::SystemApi(
                    "sc command not found".to_string()
                ));
            }
        } else if cfg!(target_os = "linux") {
            if which("systemctl").is_err() {
                return Err(CollectionError::SystemApi(
                    "systemctl command not found".to_string()
                ));
            }
        }
        Ok(())
    }
}

impl DataCollector<Vec<ServiceInformation>> for ServiceCollector {
    fn collect(&mut self) -> Result<Vec<ServiceInformation>, CollectionError> {
        let services = self.collect_services()?;
        info!("Collected information for {} services", services.len());
        Ok(services)
    }

    fn validate(&self) -> Result<(), CollectionError> {
        self.internal_validate()
    }

    fn health_check(&self) -> bool {
        self.internal_validate().is_ok()
    }
}

#[async_trait::async_trait]
impl AsyncDataCollector<Vec<ServiceInformation>> for ServiceCollector {
    async fn collect(&mut self) -> Result<Vec<ServiceInformation>, CollectionError> {
        DataCollector::collect(self)
    }

    async fn validate(&self) -> Result<(), CollectionError> {
        self.internal_validate()
    }

    async fn health_check(&self) -> bool {
        self.internal_validate().is_ok()
    }
}

impl Default for ServiceCollector {
    fn default() -> Self {
        Self::new()
    }
}
