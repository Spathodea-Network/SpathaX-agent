use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::shared::traits::{Event, Severity, Validatable, Identifiable};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryEventType {
    Created,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub category: String,
    pub event_type: RegistryEventType,
    pub key_path: String,
    pub value_name: Option<String>,
    pub old_data: Option<String>,
    pub new_data: Option<String>,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
}

impl Event for RegistryEvent {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    fn source(&self) -> &str {
        &self.source
    }

    fn event_type(&self) -> &str {
        match self.event_type {
            RegistryEventType::Created => "registry_created",
            RegistryEventType::Modified => "registry_modified",
            RegistryEventType::Deleted => "registry_deleted",
        }
    }

    fn severity(&self) -> Severity {
        match self.event_type {
            RegistryEventType::Created | RegistryEventType::Deleted => Severity::High,
            RegistryEventType::Modified => Severity::Medium,
        }
    }
}

impl Identifiable for RegistryEvent {
    fn id(&self) -> &str {
        &self.id
    }

    fn category(&self) -> &str {
        &self.category
    }
}

impl Validatable for RegistryEvent {
    fn validate(&self) -> Result<(), String> {
        if self.key_path.is_empty() {
            return Err("Registry key path cannot be empty".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoRunEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub category: String,
    pub location: String,
    pub name: String,
    pub command: String,
    pub enabled: bool,
    pub last_modified: DateTime<Utc>,
}

impl Event for AutoRunEntry {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    fn source(&self) -> &str {
        &self.source
    }

    fn event_type(&self) -> &str {
        "autorun_entry"
    }

    fn severity(&self) -> Severity {
        if self.enabled {
            Severity::High
        } else {
            Severity::Low
        }
    }
}

impl Identifiable for AutoRunEntry {
    fn id(&self) -> &str {
        &self.id
    }

    fn category(&self) -> &str {
        &self.category
    }
}

impl Validatable for AutoRunEntry {
    fn validate(&self) -> Result<(), String> {
        if self.location.is_empty() {
            return Err("Location cannot be empty".to_string());
        }
        if self.name.is_empty() {
            return Err("Name cannot be empty".to_string());
        }
        if self.command.is_empty() {
            return Err("Command cannot be empty".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousRegistryOperation {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub category: String,
    pub operation: String,
    pub key_path: String,
    pub value_name: Option<String>,
    pub data: Option<String>,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub severity_level: Severity,
    pub reason: String,
}

impl Event for SuspiciousRegistryOperation {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    fn source(&self) -> &str {
        &self.source
    }

    fn event_type(&self) -> &str {
        "suspicious_registry_operation"
    }

    fn severity(&self) -> Severity {
        self.severity_level
    }
}

impl Identifiable for SuspiciousRegistryOperation {
    fn id(&self) -> &str {
        &self.id
    }

    fn category(&self) -> &str {
        &self.category
    }
}

impl Validatable for SuspiciousRegistryOperation {
    fn validate(&self) -> Result<(), String> {
        if self.operation.is_empty() {
            return Err("Operation cannot be empty".to_string());
        }
        if self.key_path.is_empty() {
            return Err("Registry key path cannot be empty".to_string());
        }
        if self.reason.is_empty() {
            return Err("Reason cannot be empty".to_string());
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct RegistryEventBuilder {
    id: Option<String>,
    timestamp: Option<DateTime<Utc>>,
    source: Option<String>,
    category: Option<String>,
    event_type: Option<RegistryEventType>,
    key_path: Option<String>,
    value_name: Option<String>,
    old_data: Option<String>,
    new_data: Option<String>,
    process_name: Option<String>,
    process_id: Option<u32>,
}

impl RegistryEventBuilder {
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

    pub fn event_type(mut self, event_type: RegistryEventType) -> Self {
        self.event_type = Some(event_type);
        self
    }

    pub fn key_path(mut self, key_path: String) -> Self {
        self.key_path = Some(key_path);
        self
    }

    pub fn value_name(mut self, value_name: String) -> Self {
        self.value_name = Some(value_name);
        self
    }

    pub fn old_data(mut self, old_data: String) -> Self {
        self.old_data = Some(old_data);
        self
    }

    pub fn new_data(mut self, new_data: String) -> Self {
        self.new_data = Some(new_data);
        self
    }

    pub fn process_name(mut self, process_name: String) -> Self {
        self.process_name = Some(process_name);
        self
    }

    pub fn process_id(mut self, process_id: u32) -> Self {
        self.process_id = Some(process_id);
        self
    }

    pub fn build(self) -> Result<RegistryEvent, String> {
        let event = RegistryEvent {
            id: self.id.unwrap_or_else(|| Uuid::new_v4().to_string()),
            timestamp: self.timestamp.ok_or("timestamp is required")?,
            source: self.source.ok_or("source is required")?,
            category: self.category.ok_or("category is required")?,
            event_type: self.event_type.ok_or("event_type is required")?,
            key_path: self.key_path.ok_or("key_path is required")?,
            value_name: self.value_name,
            old_data: self.old_data,
            new_data: self.new_data,
            process_name: self.process_name,
            process_id: self.process_id,
        };

        event.validate()?;
        Ok(event)
    }
}

#[derive(Default)]
pub struct SuspiciousRegistryOperationBuilder {
    id: Option<String>,
    timestamp: Option<DateTime<Utc>>,
    source: Option<String>,
    category: Option<String>,
    operation: Option<String>,
    key_path: Option<String>,
    value_name: Option<String>,
    data: Option<String>,
    process_name: Option<String>,
    process_id: Option<u32>,
    severity_level: Option<Severity>,
    reason: Option<String>,
}

impl SuspiciousRegistryOperationBuilder {
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

    pub fn operation(mut self, operation: String) -> Self {
        self.operation = Some(operation);
        self
    }

    pub fn key_path(mut self, key_path: String) -> Self {
        self.key_path = Some(key_path);
        self
    }

    pub fn value_name(mut self, value_name: String) -> Self {
        self.value_name = Some(value_name);
        self
    }

    pub fn data(mut self, data: String) -> Self {
        self.data = Some(data);
        self
    }

    pub fn process_name(mut self, process_name: String) -> Self {
        self.process_name = Some(process_name);
        self
    }

    pub fn process_id(mut self, process_id: u32) -> Self {
        self.process_id = Some(process_id);
        self
    }

    pub fn severity_level(mut self, severity_level: Severity) -> Self {
        self.severity_level = Some(severity_level);
        self
    }

    pub fn reason(mut self, reason: String) -> Self {
        self.reason = Some(reason);
        self
    }

    pub fn build(self) -> Result<SuspiciousRegistryOperation, String> {
        let operation = SuspiciousRegistryOperation {
            id: self.id.unwrap_or_else(|| Uuid::new_v4().to_string()),
            timestamp: self.timestamp.ok_or("timestamp is required")?,
            source: self.source.ok_or("source is required")?,
            category: self.category.ok_or("category is required")?,
            operation: self.operation.ok_or("operation is required")?,
            key_path: self.key_path.ok_or("key_path is required")?,
            value_name: self.value_name,
            data: self.data,
            process_name: self.process_name,
            process_id: self.process_id,
            severity_level: self.severity_level.ok_or("severity_level is required")?,
            reason: self.reason.ok_or("reason is required")?,
        };

        operation.validate()?;
        Ok(operation)
    }
}
