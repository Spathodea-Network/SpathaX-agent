use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::shared::traits::{Event, Severity, Validatable, Identifiable};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInformation {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub category: String,
    pub name: String,
    pub display_name: String,
    pub status: String,
    pub startup_type: String,
    pub process_id: Option<u32>,
    pub dependencies: Vec<String>,
}

impl Event for ServiceInformation {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    fn source(&self) -> &str {
        &self.source
    }

    fn event_type(&self) -> &str {
        "service_metrics"
    }

    fn severity(&self) -> Severity {
        match self.status.as_str() {
            "Stopped" => Severity::High,
            "Starting" | "Stopping" => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

impl Identifiable for ServiceInformation {
    fn id(&self) -> &str {
        &self.id
    }

    fn category(&self) -> &str {
        &self.category
    }
}

impl Validatable for ServiceInformation {
    fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Service name cannot be empty".to_string());
        }
        if self.display_name.is_empty() {
            return Err("Display name cannot be empty".to_string());
        }
        if self.status.is_empty() {
            return Err("Status cannot be empty".to_string());
        }
        if self.startup_type.is_empty() {
            return Err("Startup type cannot be empty".to_string());
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct ServiceInformationBuilder {
    id: Option<String>,
    timestamp: Option<DateTime<Utc>>,
    source: Option<String>,
    category: Option<String>,
    name: Option<String>,
    display_name: Option<String>,
    status: Option<String>,
    startup_type: Option<String>,
    process_id: Option<u32>,
    dependencies: Option<Vec<String>>,
}

impl ServiceInformationBuilder {
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

    pub fn name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn display_name(mut self, display_name: String) -> Self {
        self.display_name = Some(display_name);
        self
    }

    pub fn status(mut self, status: String) -> Self {
        self.status = Some(status);
        self
    }

    pub fn startup_type(mut self, startup_type: String) -> Self {
        self.startup_type = Some(startup_type);
        self
    }

    pub fn process_id(mut self, process_id: u32) -> Self {
        self.process_id = Some(process_id);
        self
    }

    pub fn dependencies(mut self, dependencies: Vec<String>) -> Self {
        self.dependencies = Some(dependencies);
        self
    }

    pub fn build(self) -> Result<ServiceInformation, String> {
        let service = ServiceInformation {
            id: self.id.unwrap_or_else(|| Uuid::new_v4().to_string()),
            timestamp: self.timestamp.ok_or("timestamp is required")?,
            source: self.source.ok_or("source is required")?,
            category: self.category.ok_or("category is required")?,
            name: self.name.ok_or("name is required")?,
            display_name: self.display_name.ok_or("display_name is required")?,
            status: self.status.ok_or("status is required")?,
            startup_type: self.startup_type.ok_or("startup_type is required")?,
            process_id: self.process_id,
            dependencies: self.dependencies.unwrap_or_default(),
        };

        service.validate()?;
        Ok(service)
    }
}
