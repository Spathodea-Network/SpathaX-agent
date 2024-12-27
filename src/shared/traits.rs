use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use crate::shared::error::{CollectionError, ProcessingError, StorageError};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

pub trait Event {
    fn timestamp(&self) -> DateTime<Utc>;
    fn source(&self) -> &str;
    fn event_type(&self) -> &str;
    fn severity(&self) -> Severity;
}

pub trait DataCollector<T> {
    fn collect(&mut self) -> Result<T, CollectionError>;
    fn validate(&self) -> Result<(), CollectionError>;
    fn health_check(&self) -> bool;
}

pub trait DataProcessor<T, U> {
    fn process(&self, data: T) -> Result<U, ProcessingError>;
    fn validate_input(&self, data: &T) -> Result<(), ProcessingError>;
    fn validate_output(&self, data: &U) -> Result<(), ProcessingError>;
}

#[async_trait]
pub trait DataStorage<T: Send + Sync> {
    async fn store(&self, data: T) -> Result<(), StorageError>;
    async fn batch_store(&self, data: Vec<T>) -> Result<(), StorageError>;
    async fn health_check(&self) -> bool;
}

pub trait MetadataProvider {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn description(&self) -> &str;
}

#[async_trait]
pub trait AsyncDataCollector<T: Send> {
    async fn collect(&mut self) -> Result<T, CollectionError>;
    async fn validate(&self) -> Result<(), CollectionError>;
    async fn health_check(&self) -> bool;
}

pub trait Identifiable {
    fn id(&self) -> &str;
    fn category(&self) -> &str;
}

pub trait Validatable {
    fn validate(&self) -> Result<(), String>;
    fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }
}
