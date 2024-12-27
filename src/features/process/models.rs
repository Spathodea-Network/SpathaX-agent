use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::shared::traits::{Event, Severity, Validatable, Identifiable};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInformation {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub category: String,
    pub pid: u32,
    pub name: String,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub status: String,
    pub user: String,
    pub command: String,
    pub threads: u32,
}

impl Event for ProcessInformation {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    fn source(&self) -> &str {
        &self.source
    }

    fn event_type(&self) -> &str {
        "process_metrics"
    }

    fn severity(&self) -> Severity {
        if self.cpu_usage > 90.0 || self.memory_usage > 1_000_000_000 { // 1GB
            Severity::High
        } else if self.cpu_usage > 70.0 || self.memory_usage > 500_000_000 { // 500MB
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

impl Identifiable for ProcessInformation {
    fn id(&self) -> &str {
        &self.id
    }

    fn category(&self) -> &str {
        &self.category
    }
}

impl Validatable for ProcessInformation {
    fn validate(&self) -> Result<(), String> {
        #[cfg(not(target_os = "windows"))]
        if self.pid == 0 {
            return Err("Process ID cannot be zero".to_string());
        }
        if self.name.is_empty() {
            return Err("Process name cannot be empty".to_string());
        }
        if self.cpu_usage < 0.0 {
            return Err("CPU usage cannot be negative".to_string());
        }
        if self.memory_usage == 0 {
            return Err("Memory usage cannot be zero".to_string());
        }
        if self.status.is_empty() {
            return Err("Process status cannot be empty".to_string());
        }
        if self.user.is_empty() {
            return Err("User cannot be empty".to_string());
        }
        if self.command.is_empty() {
            return Err("Command cannot be empty".to_string());
        }
        if self.threads == 0 {
            return Err("Thread count cannot be zero".to_string());
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct ProcessInformationBuilder {
    id: Option<String>,
    timestamp: Option<DateTime<Utc>>,
    source: Option<String>,
    category: Option<String>,
    pid: Option<u32>,
    name: Option<String>,
    cpu_usage: Option<f32>,
    memory_usage: Option<u64>,
    status: Option<String>,
    user: Option<String>,
    command: Option<String>,
    threads: Option<u32>,
}

impl ProcessInformationBuilder {
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

    pub fn pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    pub fn name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn cpu_usage(mut self, cpu_usage: f32) -> Self {
        self.cpu_usage = Some(cpu_usage);
        self
    }

    pub fn memory_usage(mut self, memory_usage: u64) -> Self {
        self.memory_usage = Some(memory_usage);
        self
    }

    pub fn status(mut self, status: String) -> Self {
        self.status = Some(status);
        self
    }

    pub fn user(mut self, user: String) -> Self {
        self.user = Some(user);
        self
    }

    pub fn command(mut self, command: String) -> Self {
        self.command = Some(command);
        self
    }

    pub fn threads(mut self, threads: u32) -> Self {
        self.threads = Some(threads);
        self
    }

    pub fn build(self) -> Result<ProcessInformation, String> {
        let process = ProcessInformation {
            id: self.id.unwrap_or_else(|| Uuid::new_v4().to_string()),
            timestamp: self.timestamp.ok_or("timestamp is required")?,
            source: self.source.ok_or("source is required")?,
            category: self.category.ok_or("category is required")?,
            pid: self.pid.ok_or("pid is required")?,
            name: self.name.ok_or("name is required")?,
            cpu_usage: self.cpu_usage.ok_or("cpu_usage is required")?,
            memory_usage: self.memory_usage.ok_or("memory_usage is required")?,
            status: self.status.ok_or("status is required")?,
            user: self.user.ok_or("user is required")?,
            command: self.command.ok_or("command is required")?,
            threads: self.threads.ok_or("threads is required")?,
        };

        process.validate()?;
        Ok(process)
    }
}
