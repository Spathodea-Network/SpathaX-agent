use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::shared::traits::{Event, Severity, Validatable, Identifiable};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileEventType {
    Created,
    Modified,
    Deleted,
    Renamed,
    AttributesModified,
    Accessed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub category: String,
    pub event_type: FileEventType,
    pub path: String,
    pub new_path: Option<String>,
    pub file_type: String,
    pub file_size: Option<u64>,
    pub permissions: Option<String>,
    pub hash: Option<String>,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
}

impl Event for FileEvent {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    fn source(&self) -> &str {
        &self.source
    }

    fn event_type(&self) -> &str {
        match self.event_type {
            FileEventType::Created => "file_created",
            FileEventType::Modified => "file_modified",
            FileEventType::Deleted => "file_deleted",
            FileEventType::Renamed => "file_renamed",
            FileEventType::AttributesModified => "file_attributes_modified",
            FileEventType::Accessed => "file_accessed",
        }
    }

    fn severity(&self) -> Severity {
        match self.event_type {
            FileEventType::Created | FileEventType::Deleted => Severity::High,
            FileEventType::Modified | FileEventType::Renamed => Severity::Medium,
            FileEventType::AttributesModified | FileEventType::Accessed => Severity::Low,
        }
    }
}

impl Identifiable for FileEvent {
    fn id(&self) -> &str {
        &self.id
    }

    fn category(&self) -> &str {
        &self.category
    }
}

impl Validatable for FileEvent {
    fn validate(&self) -> Result<(), String> {
        if self.path.is_empty() {
            return Err("File path cannot be empty".to_string());
        }

        if let Some(ref new_path) = self.new_path {
            if new_path.is_empty() {
                return Err("New file path cannot be empty when provided".to_string());
            }
        }

        if self.file_type.is_empty() {
            return Err("File type cannot be empty".to_string());
        }

        if let Some(size) = self.file_size {
            if size == 0 {
                return Err("File size cannot be zero when provided".to_string());
            }
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct FileEventBuilder {
    id: Option<String>,
    timestamp: Option<DateTime<Utc>>,
    source: Option<String>,
    category: Option<String>,
    event_type: Option<FileEventType>,
    path: Option<String>,
    new_path: Option<String>,
    file_type: Option<String>,
    file_size: Option<u64>,
    permissions: Option<String>,
    hash: Option<String>,
    process_id: Option<u32>,
    process_name: Option<String>,
}

impl FileEventBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    pub fn timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn source(mut self, source: String) -> Self {
        self.source = Some(source);
        self
    }

    pub fn category(mut self, category: String) -> Self {
        self.category = Some(category);
        self
    }

    pub fn event_type(mut self, event_type: FileEventType) -> Self {
        self.event_type = Some(event_type);
        self
    }

    pub fn path(mut self, path: String) -> Self {
        self.path = Some(path);
        self
    }

    pub fn new_path(mut self, new_path: String) -> Self {
        self.new_path = Some(new_path);
        self
    }

    pub fn file_type(mut self, file_type: String) -> Self {
        self.file_type = Some(file_type);
        self
    }

    pub fn file_size(mut self, file_size: u64) -> Self {
        self.file_size = Some(file_size);
        self
    }

    pub fn permissions(mut self, permissions: String) -> Self {
        self.permissions = Some(permissions);
        self
    }

    pub fn hash(mut self, hash: String) -> Self {
        self.hash = Some(hash);
        self
    }

    pub fn process_id(mut self, process_id: u32) -> Self {
        self.process_id = Some(process_id);
        self
    }

    pub fn process_name(mut self, process_name: String) -> Self {
        self.process_name = Some(process_name);
        self
    }

    pub fn build(self) -> Result<FileEvent, String> {
        let event = FileEvent {
            id: self.id.ok_or("id is required")?,
            timestamp: self.timestamp.ok_or("timestamp is required")?,
            source: self.source.ok_or("source is required")?,
            category: self.category.ok_or("category is required")?,
            event_type: self.event_type.ok_or("event_type is required")?,
            path: self.path.ok_or("path is required")?,
            new_path: self.new_path,
            file_type: self.file_type.ok_or("file_type is required")?,
            file_size: self.file_size,
            permissions: self.permissions,
            hash: self.hash,
            process_id: self.process_id,
            process_name: self.process_name,
        };

        event.validate()?;
        Ok(event)
    }
}
