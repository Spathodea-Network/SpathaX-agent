use crate::shared::traits::{AsyncDataCollector, DataCollector};
use crate::shared::error::CollectionError;
use crate::features::system_metrics::models::{
    SystemMetrics, CpuInformation, MemoryInformation,
    DiskInformation, SystemLoadInformation, SystemMetricsBuilder
};
use log::info;
use sysinfo::{System, Disks};
use chrono::Utc;
use uuid::Uuid;

pub struct SystemMetricsCollector {
    sys: System,
    hostname: String,
}

impl SystemMetricsCollector {
    pub fn new() -> Self {
        let sys = System::new();
        let hostname = whoami::hostname();
        Self { sys, hostname }
    }

    pub fn collect_cpu_info(&self) -> Result<CpuInformation, CollectionError> {
        Ok(CpuInformation {
            brand: self.sys.cpus().first()
                .map(|cpu| cpu.brand().to_string())
                .unwrap_or_else(|| String::from("unknown")),
            frequency: self.sys.cpus().first()
                .map(|cpu| cpu.frequency())
                .unwrap_or(0),
            cpu_cores: self.sys.cpus().len(),
            cpu_usage: self.sys.global_cpu_usage() as f32,
        })
    }

    pub fn collect_memory_info(&self) -> Result<MemoryInformation, CollectionError> {
        Ok(MemoryInformation {
            total_memory: self.sys.total_memory(),
            used_memory: self.sys.used_memory(),
            total_swap: self.sys.total_swap(),
            used_swap: self.sys.used_swap(),
        })
    }

    pub fn collect_disk_info(&self) -> Result<Vec<DiskInformation>, CollectionError> {
        let mut disks_info = Vec::new();
        let disks = Disks::new_with_refreshed_list();
        
        for disk in disks.list() {
            disks_info.push(DiskInformation {
                name: disk.name().to_string_lossy().into_owned(),
                mount_point: disk.mount_point().to_string_lossy().into_owned(),
                file_system: disk.file_system().to_string_lossy().into_owned(),
                total_space: disk.total_space(),
                available_space: disk.available_space(),
            });
        }

        info!("Found {} disks", disks_info.len());
        Ok(disks_info)
    }

    pub fn collect_system_load(&self) -> Result<SystemLoadInformation, CollectionError> {
        let load_avg = System::load_average();
        Ok(SystemLoadInformation {
            one_minute: load_avg.one as f32,
            five_minutes: load_avg.five as f32,
            fifteen_minutes: load_avg.fifteen as f32,
            running_processes: self.sys.processes().len() as u32,
            total_processes: self.sys.processes().len() as u32,
        })
    }

    fn internal_validate(&self) -> Result<(), CollectionError> {
        if !self.sys.cpus().is_empty() {
            Ok(())
        } else {
            Err(CollectionError::SystemApi("No CPU information available".to_string()))
        }
    }
}

impl DataCollector<SystemMetrics> for SystemMetricsCollector {
    fn collect(&mut self) -> Result<SystemMetrics, CollectionError> {
        self.sys.refresh_all();

        let metrics = SystemMetricsBuilder::new()
            .id(Uuid::new_v4().to_string())
            .timestamp(Utc::now())
            .source(self.hostname.clone())
            .category(String::from("system"))
            .cpu_info(self.collect_cpu_info()?)
            .memory_info(self.collect_memory_info()?)
            .disk_info(self.collect_disk_info()?)
            .system_load(self.collect_system_load()?)
            .build()
            .map_err(|e| CollectionError::Parse(e))?;

        info!("Collected system metrics");
        Ok(metrics)
    }

    fn validate(&self) -> Result<(), CollectionError> {
        self.internal_validate()
    }

    fn health_check(&self) -> bool {
        self.internal_validate().is_ok()
    }
}

#[async_trait::async_trait]
impl AsyncDataCollector<SystemMetrics> for SystemMetricsCollector {
    async fn collect(&mut self) -> Result<SystemMetrics, CollectionError> {
        DataCollector::collect(self)
    }

    async fn validate(&self) -> Result<(), CollectionError> {
        self.internal_validate()
    }

    async fn health_check(&self) -> bool {
        self.internal_validate().is_ok()
    }
}

impl Default for SystemMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
