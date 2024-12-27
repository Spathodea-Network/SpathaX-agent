use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::shared::traits::{Event, Severity, Validatable, Identifiable};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInformation {
    pub brand: String,
    pub frequency: u64,
    pub cpu_cores: usize,
    pub cpu_usage: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInformation {
    pub total_memory: u64,
    pub used_memory: u64,
    pub total_swap: u64,
    pub used_swap: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInformation {
    pub name: String,
    pub mount_point: String,
    pub total_space: u64,
    pub available_space: u64,
    pub file_system: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemLoadInformation {
    pub one_minute: f32,
    pub five_minutes: f32,
    pub fifteen_minutes: f32,
    pub running_processes: u32,
    pub total_processes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub category: String,
    pub cpu_info: CpuInformation,
    pub memory_info: MemoryInformation,
    pub disk_info: Vec<DiskInformation>,
    pub system_load: SystemLoadInformation,
}

impl Event for SystemMetrics {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    fn source(&self) -> &str {
        &self.source
    }

    fn event_type(&self) -> &str {
        "system_metrics"
    }

    fn severity(&self) -> Severity {
        // Determine severity based on metrics
        if self.cpu_info.cpu_usage > 90.0 || 
           (self.memory_info.used_memory as f64 / self.memory_info.total_memory as f64) > 0.95 {
            Severity::Critical
        } else if self.cpu_info.cpu_usage > 75.0 || 
                  (self.memory_info.used_memory as f64 / self.memory_info.total_memory as f64) > 0.85 {
            Severity::High
        } else if self.cpu_info.cpu_usage > 60.0 || 
                  (self.memory_info.used_memory as f64 / self.memory_info.total_memory as f64) > 0.75 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

impl Identifiable for SystemMetrics {
    fn id(&self) -> &str {
        &self.id
    }

    fn category(&self) -> &str {
        &self.category
    }
}

impl Validatable for SystemMetrics {
    fn validate(&self) -> Result<(), String> {
        if self.cpu_info.cpu_cores == 0 {
            return Err("CPU cores cannot be zero".to_string());
        }
        if self.cpu_info.cpu_usage < 0.0 || self.cpu_info.cpu_usage > 100.0 {
            return Err("CPU usage must be between 0 and 100".to_string());
        }
        if self.memory_info.used_memory > self.memory_info.total_memory {
            return Err("Used memory cannot exceed total memory".to_string());
        }
        if self.memory_info.used_swap > self.memory_info.total_swap {
            return Err("Used swap cannot exceed total swap".to_string());
        }
        for disk in &self.disk_info {
            if disk.available_space > disk.total_space {
                return Err(format!("Available space cannot exceed total space for disk {}", disk.name));
            }
        }
        Ok(())
    }
}

// Builder pattern for SystemMetrics
#[derive(Default)]
pub struct SystemMetricsBuilder {
    id: Option<String>,
    timestamp: Option<DateTime<Utc>>,
    source: Option<String>,
    category: Option<String>,
    cpu_info: Option<CpuInformation>,
    memory_info: Option<MemoryInformation>,
    disk_info: Option<Vec<DiskInformation>>,
    system_load: Option<SystemLoadInformation>,
}

impl SystemMetricsBuilder {
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

    pub fn cpu_info(mut self, cpu_info: CpuInformation) -> Self {
        self.cpu_info = Some(cpu_info);
        self
    }

    pub fn memory_info(mut self, memory_info: MemoryInformation) -> Self {
        self.memory_info = Some(memory_info);
        self
    }

    pub fn disk_info(mut self, disk_info: Vec<DiskInformation>) -> Self {
        self.disk_info = Some(disk_info);
        self
    }

    pub fn system_load(mut self, system_load: SystemLoadInformation) -> Self {
        self.system_load = Some(system_load);
        self
    }

    pub fn build(self) -> Result<SystemMetrics, String> {
        let metrics = SystemMetrics {
            id: self.id.ok_or("id is required")?,
            timestamp: self.timestamp.ok_or("timestamp is required")?,
            source: self.source.ok_or("source is required")?,
            category: self.category.ok_or("category is required")?,
            cpu_info: self.cpu_info.ok_or("cpu_info is required")?,
            memory_info: self.memory_info.ok_or("memory_info is required")?,
            disk_info: self.disk_info.ok_or("disk_info is required")?,
            system_load: self.system_load.ok_or("system_load is required")?,
        };

        metrics.validate()?;
        Ok(metrics)
    }
}
