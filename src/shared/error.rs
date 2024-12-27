use thiserror::Error;
use std::io;

#[derive(Error, Debug)]
pub enum XdrError {
    #[error("Collection failed: {0}")]
    Collection(#[from] CollectionError),
    
    #[error("Processing failed: {0}")]
    Processing(#[from] ProcessingError),
    
    #[error("Storage failed: {0}")]
    Storage(#[from] StorageError),
}

#[derive(Error, Debug)]
pub enum CollectionError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Failed to parse data: {0}")]
    Parse(String),
    
    #[error("System API error: {0}")]
    SystemApi(String),
    
    #[error("Rate limit exceeded")]
    RateLimit,
}

#[derive(Error, Debug)]
pub enum ProcessingError {
    #[error("Invalid data format: {0}")]
    InvalidFormat(String),
    
    #[error("Data validation failed: {0}")]
    Validation(String),
    
    #[error("Transformation error: {0}")]
    Transform(String),
}

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Connection failed: {0}")]
    Connection(String),
    
    #[error("Write operation failed: {0}")]
    Write(String),
    
    #[error("Read operation failed: {0}")]
    Read(String),
}
