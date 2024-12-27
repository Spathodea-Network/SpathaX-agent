use crate::shared::traits::{AsyncDataCollector, DataCollector};
use crate::shared::error::CollectionError;
use crate::features::process::models::{ProcessInformation, ProcessInformationBuilder};
use log::info;
use sysinfo::System;
use chrono::Utc;
use uuid::Uuid;

pub struct ProcessCollector {
    sys: System,
    hostname: String,
}

impl ProcessCollector {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_all();
        let hostname = whoami::hostname();
        Self { sys, hostname }
    }

    fn collect_processes(&mut self) -> Result<Vec<ProcessInformation>, CollectionError> {
        self.sys.refresh_all();
        
        let processes = self
            .sys
            .processes()
            .iter()
            .map(|(pid, process)| {
                ProcessInformationBuilder::new()
                    .id(Uuid::new_v4().to_string())
                    .timestamp(Utc::now())
                    .source(self.hostname.clone())
                    .category(String::from("process"))
                    .pid(pid.as_u32())
                    .name(process.name().to_string_lossy().into_owned())
                    .cpu_usage(process.cpu_usage())
                    .memory_usage(process.memory())
                    .status(format!("{:?}", process.status()))
                    .user(process.user_id()
                        .map(|uid| uid.to_string())
                        .unwrap_or_else(|| String::from("unknown")))
                    .command(process.exe()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|| process.name().to_string_lossy().into_owned()))
                    .threads(if cfg!(target_os = "linux") {
                        process.tasks().map(|tasks| tasks.len() as u32).unwrap_or(1)
                    } else {
                        // On Windows and other platforms, we'll need to implement
                        // platform-specific thread counting in the future
                        1
                    })
                    .build()
                    .map_err(|e| CollectionError::Parse(e))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(processes)
    }

    fn internal_validate(&self) -> Result<(), CollectionError> {
        if self.sys.processes().is_empty() {
            return Err(CollectionError::SystemApi(
                "No processes available".to_string()
            ));
        }
        Ok(())
    }
}

impl DataCollector<Vec<ProcessInformation>> for ProcessCollector {
    fn collect(&mut self) -> Result<Vec<ProcessInformation>, CollectionError> {
        let processes = self.collect_processes()?;
        info!("Collected information for {} processes", processes.len());
        Ok(processes)
    }

    fn validate(&self) -> Result<(), CollectionError> {
        self.internal_validate()
    }

    fn health_check(&self) -> bool {
        self.internal_validate().is_ok()
    }
}

#[async_trait::async_trait]
impl AsyncDataCollector<Vec<ProcessInformation>> for ProcessCollector {
    async fn collect(&mut self) -> Result<Vec<ProcessInformation>, CollectionError> {
        DataCollector::collect(self)
    }

    async fn validate(&self) -> Result<(), CollectionError> {
        self.internal_validate()
    }

    async fn health_check(&self) -> bool {
        self.internal_validate().is_ok()
    }
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}
