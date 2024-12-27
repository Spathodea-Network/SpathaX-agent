use thiserror::Error;

#[derive(Debug, Error)]
pub enum CollectorError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Failed to parse output: {0}")]
    ParseError(String),
    #[error("Command execution failed: {0}")]
    CommandError(String),
}

pub trait Collector {
    type Output;
    
    fn collect(&mut self) -> Result<Self::Output, CollectorError>;
}
