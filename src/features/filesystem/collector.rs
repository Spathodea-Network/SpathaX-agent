use crate::shared::traits::{AsyncDataCollector, DataCollector};
use crate::shared::error::CollectionError;
use crate::features::filesystem::models::{FileEvent, FileEventType, FileEventBuilder};
use log::{info, warn, debug};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use tokio::sync::mpsc::{channel, Receiver};
use std::time::Duration;
use chrono::Utc;
use sha2::{Sha256, Digest};
use std::fs;
use serde::{Deserialize, Serialize};
use sysinfo::{System, Pid, ProcessRefreshKind, ProcessesToUpdate};
use uuid::Uuid;
use std::sync::Arc;
use tokio::runtime::Handle;

#[derive(Debug, Serialize, Deserialize)]
struct MonitorConfig {
    paths: Vec<String>,
    settings: MonitorSettings,
}

#[derive(Debug, Serialize, Deserialize)]
struct MonitorSettings {
    recursive: bool,
    extensions: Vec<String>,
}

pub struct FileSystemCollector {
    event_receiver: Receiver<notify::Result<Event>>,
    config: MonitorConfig,
    sys: System,
    _watcher: RecommendedWatcher,
    hostname: String,
}

impl FileSystemCollector {
    fn normalize_path(path: &str) -> String {
        path.replace('\\', "/")
    }

    fn expand_env_vars(path: &str) -> String {
        let mut result = path.to_string();
        if path.contains("${USERPROFILE}") {
            if let Ok(user_profile) = std::env::var("USERPROFILE") {
                result = path.replace("${USERPROFILE}", &Self::normalize_path(&user_profile));
            }
        }
        Self::normalize_path(&result)
    }

    pub fn new() -> Result<Self, CollectionError> {
        let config_path = "config/monitor.yaml";
        info!("Reading config from: {}", config_path);
        let config_content = fs::read_to_string(config_path)
            .map_err(|e| CollectionError::Parse(format!("Failed to read config: {}", e)))?;
        
        let mut config: MonitorConfig = serde_yaml::from_str(&config_content)
            .map_err(|e| CollectionError::Parse(format!("Failed to parse config: {}", e)))?;
        
        info!("Loaded config: {:?}", config);
        
        for path in &mut config.paths {
            let expanded_path = Self::expand_env_vars(path);
            info!("Expanded path: {} -> {}", path, expanded_path);
            *path = expanded_path;
        }
        
        let (tx, rx) = channel(100);
        let tx_clone = tx.clone();
        let runtime = Arc::new(tokio::runtime::Runtime::new().unwrap());
        
        let mut watcher = notify::recommended_watcher(move |res| {
            let tx = tx_clone.clone();
            let handle = runtime.handle().clone();
            handle.spawn(async move {
                if let Err(e) = tx.send(res).await {
                    warn!("Failed to send event: {}", e);
                }
            });
        })
        .map_err(|e| CollectionError::SystemApi(e.to_string()))?;

        for path in &config.paths {
            let recursive_mode = if config.settings.recursive {
                RecursiveMode::Recursive
            } else {
                RecursiveMode::NonRecursive
            };
            
            info!("Attempting to watch path: {}", path);
            if let Ok(metadata) = fs::metadata(path) {
                if metadata.is_dir() {
                    match watcher.watch(Path::new(path), recursive_mode) {
                        Ok(_) => info!("Successfully watching path: {}", path),
                        Err(e) => warn!("Failed to watch path {}: {}", path, e),
                    }
                } else {
                    warn!("Path is not a directory: {}", path);
                }
            } else {
                warn!("Path does not exist or is not accessible: {}", path);
            }
        }

        Ok(Self {
            event_receiver: rx,
            config,
            sys: System::new(),
            _watcher: watcher,
            hostname: whoami::hostname(),
        })
    }

    fn calculate_file_hash(path: &Path) -> Option<String> {
        if let Ok(mut file) = fs::File::open(path) {
            let mut hasher = Sha256::new();
            if std::io::copy(&mut file, &mut hasher).is_ok() {
                let hash = hasher.finalize();
                return Some(format!("{:x}", hash));
            }
        }
        None
    }

    fn get_file_info(&self, path: &Path) -> Option<(String, u64)> {
        if let Ok(metadata) = fs::metadata(path) {
            let file_type = if metadata.is_dir() {
                "directory"
            } else {
                "file"
            };
            
            let size = metadata.len();
            Some((file_type.to_string(), size))
        } else {
            None
        }
    }

    fn should_monitor_file(&self, path: &Path) -> bool {
        if let Some(extension) = path.extension() {
            if let Some(ext_str) = extension.to_str() {
                let ext = format!(".{}", ext_str);
                let should_monitor = self.config.settings.extensions.contains(&ext);
                debug!("Checking file {}: extension {} -> monitor: {}", 
                    path.display(), ext, should_monitor);
                return should_monitor;
            }
        }
        false
    }

    fn get_process_info(&mut self, pid: u32) -> Option<(u32, String)> {
        let pid = Pid::from_u32(pid);
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::everything(),
        );
        
        self.sys.process(pid).map(|process| {
            (pid.as_u32(), process.name().to_string_lossy().into_owned())
        })
    }

    async fn process_event(&mut self, event: Event) -> Option<FileEvent> {
        let path = event.paths.first()?;
        
        debug!("Processing event for path: {}", path.display());
        
        if !path.is_dir() && !self.should_monitor_file(path) {
            debug!("Skipping file: {}", path.display());
            return None;
        }
        
        let event_type = match event.kind {
            EventKind::Create(_) => FileEventType::Created,
            EventKind::Modify(_) => FileEventType::Modified,
            EventKind::Remove(_) => FileEventType::Deleted,
            _ => return None,
        };

        debug!("Event type: {:?} for path: {}", event_type, path.display());

        let (file_type, file_size) = self.get_file_info(path)?;
        let file_hash = Self::calculate_file_hash(path);
        let (process_id, process_name) = self.get_process_info(std::process::id())
            .unwrap_or((0, "unknown".to_string()));

        let path_str = path.to_string_lossy().to_string();

        let event = FileEventBuilder::new()
            .id(Uuid::new_v4().to_string())
            .timestamp(Utc::now())
            .source(self.hostname.clone())
            .category(String::from("filesystem"))
            .event_type(event_type)
            .path(path_str)
            .file_type(file_type)
            .file_size(file_size)
            .hash(file_hash.unwrap_or_default())
            .process_id(process_id)
            .process_name(process_name)
            .build()
            .ok()?;

        Some(event)
    }

    fn internal_validate(&self) -> Result<(), CollectionError> {
        for path in &self.config.paths {
            if !Path::new(path).exists() {
                return Err(CollectionError::SystemApi(
                    format!("Monitored path does not exist: {}", path)
                ));
            }
        }
        Ok(())
    }
}

impl DataCollector<Vec<FileEvent>> for FileSystemCollector {
    fn collect(&mut self) -> Result<Vec<FileEvent>, CollectionError> {
        let mut events = Vec::new();
        
        while let Ok(Ok(event)) = self.event_receiver.try_recv() {
            if let Some(file_event) = Handle::current().block_on(self.process_event(event)) {
                debug!("Collected event: {:?}", file_event);
                events.push(file_event);
            }
        }

        info!("Collected {} filesystem events", events.len());
        Ok(events)
    }

    fn validate(&self) -> Result<(), CollectionError> {
        self.internal_validate()
    }

    fn health_check(&self) -> bool {
        self.internal_validate().is_ok()
    }
}

#[async_trait::async_trait]
impl AsyncDataCollector<Vec<FileEvent>> for FileSystemCollector {
    async fn collect(&mut self) -> Result<Vec<FileEvent>, CollectionError> {
        let mut events = Vec::new();
        
        while let Ok(Ok(event)) = self.event_receiver.try_recv() {
            if let Some(file_event) = self.process_event(event).await {
                debug!("Collected event: {:?}", file_event);
                events.push(file_event);
            }
        }

        info!("Collected {} filesystem events", events.len());
        Ok(events)
    }

    async fn validate(&self) -> Result<(), CollectionError> {
        self.internal_validate()
    }

    async fn health_check(&self) -> bool {
        self.internal_validate().is_ok()
    }
}

impl Default for FileSystemCollector {
    fn default() -> Self {
        Self::new().expect("Failed to create default FileSystemCollector")
    }
}
