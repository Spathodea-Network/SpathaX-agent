use crate::features::{
    network::{NetworkInformation, NetworkConnectionInformation},
    process::ProcessInformation,
    service::ServiceInformation,
    system_metrics::{CpuInformation, MemoryInformation, DiskInformation, SystemLoadInformation},
    filesystem::FileEvent,
    registry::{RegistryEvent, SuspiciousRegistryOperation},
};
use elasticsearch::{
    auth::Credentials,
    http::transport::{TransportBuilder, SingleNodeConnectionPool},
    Elasticsearch, IndexParts,
};
use log::{error, info};
use serde::Serialize;
use serde_json::{json, Value};
use std::time::SystemTime;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Failed to store data: {0}")]
    StoreError(String),
    #[error("Failed to connect to Elasticsearch: {0}")]
    ConnectionError(String),
}

pub struct ElasticsearchStorage {
    client: Elasticsearch,
}

#[derive(Serialize)]
pub struct SystemInformation {
    pub timestamp: SystemTime,
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub cpu_info: CpuInformation,
    pub memory_info: MemoryInformation,
    pub disk_info: Vec<DiskInformation>,
    pub network_info: Vec<NetworkInformation>,
    pub process_info: Vec<ProcessInformation>,
    pub system_load: SystemLoadInformation,
    pub network_connections: Vec<NetworkConnectionInformation>,
    pub services: Vec<ServiceInformation>,
}

impl ElasticsearchStorage {
    pub fn new(
        host: &str,
        port: u16,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Self, StorageError> {
        let url = format!("http://{}:{}", host, port);
        let url = Url::parse(&url)
            .map_err(|e| StorageError::ConnectionError(e.to_string()))?;
        
        let conn_pool = SingleNodeConnectionPool::new(url);
        let mut builder = TransportBuilder::new(conn_pool);

        if let (Some(username), Some(password)) = (username, password) {
            builder = builder.auth(Credentials::Basic(
                username.to_string(),
                password.to_string(),
            ));
        }

        let transport = builder
            .build()
            .map_err(|e| StorageError::ConnectionError(e.to_string()))?;

        Ok(Self {
            client: Elasticsearch::new(transport),
        })
    }

    pub async fn store_system_info(&self, info: &SystemInformation) -> Result<(), StorageError> {
        let response = self
            .client
            .index(IndexParts::Index("system_metrics"))
            .body(json!(info))
            .send()
            .await
            .map_err(|e| StorageError::StoreError(e.to_string()))?;

        if !response.status_code().is_success() {
            error!("Failed to store metrics: {:?}", response);
            return Err(StorageError::StoreError(format!(
                "Elasticsearch returned error status: {}",
                response.status_code()
            )));
        }

        let response_body: Value = response
            .json()
            .await
            .map_err(|e| StorageError::StoreError(e.to_string()))?;

        info!("Successfully stored metrics: {:?}", response_body);
        Ok(())
    }

    pub async fn store_file_events(&self, events: &[FileEvent]) -> Result<(), StorageError> {
        for event in events {
            let response = self
                .client
                .index(IndexParts::Index("file_events"))
                .body(json!(event))
                .send()
                .await
                .map_err(|e| StorageError::StoreError(e.to_string()))?;

            if !response.status_code().is_success() {
                error!("Failed to store file event: {:?}", response);
                return Err(StorageError::StoreError(format!(
                    "Elasticsearch returned error status: {}",
                    response.status_code()
                )));
            }

            let response_body: Value = response
                .json()
                .await
                .map_err(|e| StorageError::StoreError(e.to_string()))?;

            info!("Successfully stored file event: {:?}", response_body);
        }
        Ok(())
    }

    pub async fn store_registry_events(&self, events: &[RegistryEvent]) -> Result<(), StorageError> {
        for event in events {
            let response = self
                .client
                .index(IndexParts::Index("registry_events"))
                .body(json!(event))
                .send()
                .await
                .map_err(|e| StorageError::StoreError(e.to_string()))?;

            if !response.status_code().is_success() {
                error!("Failed to store registry event: {:?}", response);
                return Err(StorageError::StoreError(format!(
                    "Elasticsearch returned error status: {}",
                    response.status_code()
                )));
            }

            let response_body: Value = response
                .json()
                .await
                .map_err(|e| StorageError::StoreError(e.to_string()))?;

            info!("Successfully stored registry event: {:?}", response_body);
        }
        Ok(())
    }

    pub async fn store_suspicious_registry_operations(&self, operations: &[SuspiciousRegistryOperation]) -> Result<(), StorageError> {
        for operation in operations {
            let response = self
                .client
                .index(IndexParts::Index("suspicious_registry_operations"))
                .body(json!(operation))
                .send()
                .await
                .map_err(|e| StorageError::StoreError(e.to_string()))?;

            if !response.status_code().is_success() {
                error!("Failed to store suspicious registry operation: {:?}", response);
                return Err(StorageError::StoreError(format!(
                    "Elasticsearch returned error status: {}",
                    response.status_code()
                )));
            }

            let response_body: Value = response
                .json()
                .await
                .map_err(|e| StorageError::StoreError(e.to_string()))?;

            info!("Successfully stored suspicious registry operation: {:?}", response_body);
        }
        Ok(())
    }
}
