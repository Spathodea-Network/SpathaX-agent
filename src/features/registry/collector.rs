use crate::shared::traits::{AsyncDataCollector, DataCollector};
use crate::shared::error::CollectionError;
use crate::features::registry::models::{
    RegistryEvent, RegistryEventType, SuspiciousRegistryOperation,
    RegistryEventBuilder, SuspiciousRegistryOperationBuilder
};
use log::{info, warn, error};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use windows::Win32::System::Registry::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::Threading::*;
use windows::Win32::Security::*;
use windows::core::{PCSTR, PSTR};
use std::collections::HashMap;
use tokio::sync::mpsc::{channel, Sender, Receiver};
use std::thread;
use sysinfo::{System, Pid, ProcessRefreshKind, ProcessesToUpdate};
use std::ffi::CString;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct MonitorConfig {
    paths: Vec<String>,
    settings: FileSystemSettings,
    registry: RegistryConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FileSystemSettings {
    recursive: bool,
    extensions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RegistryConfig {
    autorun_paths: Vec<String>,
    suspicious_patterns: Vec<String>,
    settings: RegistrySettings,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RegistrySettings {
    check_interval_ms: u64,
    max_events_per_collection: usize,
}

pub struct RegistryCollector {
    config: RegistryConfig,
    sys: System,
    autorun_cache: HashMap<String, String>,
    last_check: chrono::DateTime<Utc>,
    event_receiver: Option<Receiver<RegistryEvent>>,
    _monitor_thread: Option<thread::JoinHandle<()>>,
    hostname: String,
}

impl RegistryCollector {
    const AUTORUN_LOCATIONS: &'static [(&'static str, &'static str)] = &[
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKEY_LOCAL_MACHINE"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKEY_LOCAL_MACHINE"),
        (r"Software\Microsoft\Windows\CurrentVersion\Run", "HKEY_CURRENT_USER"),
        (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKEY_CURRENT_USER"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", "HKEY_LOCAL_MACHINE"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce", "HKEY_LOCAL_MACHINE"),
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit", "HKEY_LOCAL_MACHINE"),
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", "HKEY_LOCAL_MACHINE"),
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs", "HKEY_LOCAL_MACHINE"),
    ];

    const SENSITIVE_KEYS: &'static [(&'static str, &'static str)] = &[
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies", "HKEY_LOCAL_MACHINE"),
        (r"SOFTWARE\Policies\Microsoft\Windows\System", "HKEY_LOCAL_MACHINE"),
        (r"SYSTEM\CurrentControlSet\Services", "HKEY_LOCAL_MACHINE"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks", "HKEY_LOCAL_MACHINE"),
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "HKEY_LOCAL_MACHINE"),
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit", "HKEY_LOCAL_MACHINE"),
    ];

    pub fn new() -> Result<Self, CollectionError> {
        let config_path = "config/monitor.yaml";
        info!("Reading config from: {}", config_path);
        let config_content = std::fs::read_to_string(config_path)
            .map_err(|e| CollectionError::Parse(format!("Failed to read config: {}", e)))?;
        
        let config: MonitorConfig = serde_yaml::from_str(&config_content)
            .map_err(|e| CollectionError::Parse(format!("Failed to parse config: {}", e)))?;
        
        info!("Loaded registry monitor config: {:?}", config.registry);

        let (tx, rx) = channel(100);
        let registry_config = config.registry.clone();
        let hostname = whoami::hostname();
        let hostname_clone = hostname.clone();
        
        // Start registry monitoring thread
        let monitor_thread = thread::spawn(move || {
            Self::monitor_registry_changes(tx, &registry_config, &hostname_clone);
        });

        Ok(Self {
            config: config.registry,
            sys: System::new(),
            autorun_cache: HashMap::new(),
            last_check: Utc::now(),
            event_receiver: Some(rx),
            _monitor_thread: Some(monitor_thread),
            hostname,
        })
    }

    fn monitor_registry_changes(tx: Sender<RegistryEvent>, config: &RegistryConfig, hostname: &str) {
        let mut change_handles = Vec::new();

        // Monitor autorun and sensitive keys
        for (subkey, hive) in Self::AUTORUN_LOCATIONS.iter().chain(Self::SENSITIVE_KEYS.iter()) {
            let hkey = match *hive {
                "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
                "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
                _ => continue,
            };

            unsafe {
                let mut key = HKEY::default();
                let subkey_cstr = CString::new(*subkey).unwrap();
                if RegOpenKeyExA(
                    hkey,
                    PCSTR(subkey_cstr.as_ptr() as *const u8),
                    0,
                    KEY_NOTIFY | KEY_READ,
                    &mut key,
                ).is_ok() {
                    if let Ok(event) = CreateEventA(None, true, false, None) {
                        if RegNotifyChangeKeyValue(
                            key,
                            true,
                            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                            event,
                            true,
                        ).is_ok() {
                            change_handles.push((key, event, format!("{}\\{}", hive, subkey)));
                        }
                    }
                }
            }
        }

        loop {
            for (key, event, path) in &change_handles {
                unsafe {
                    if WaitForSingleObject(*event, 0) == WAIT_OBJECT_0 {
                        let registry_event = RegistryEventBuilder::new()
                            .id(Uuid::new_v4().to_string())
                            .timestamp(Utc::now())
                            .source(hostname.to_string())
                            .category(String::from("registry"))
                            .event_type(RegistryEventType::Modified)
                            .key_path(path.clone())
                            .build()
                            .unwrap_or_else(|e| {
                                error!("Failed to build registry event: {}", e);
                                panic!("Failed to build registry event");
                            });

                        if let Err(e) = tx.blocking_send(registry_event) {
                            error!("Failed to send registry event: {}", e);
                            return;
                        }

                        ResetEvent(*event);
                        RegNotifyChangeKeyValue(
                            *key,
                            true,
                            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                            *event,
                            true,
                        ).ok();
                    }
                }
            }
            thread::sleep(Duration::from_millis(config.settings.check_interval_ms));
        }
    }

    fn get_process_info(&mut self, pid: u32) -> (String, u32) {
        let pid = Pid::from_u32(pid);
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::everything(),
        );
        
        if let Some(process) = self.sys.process(pid) {
            (process.name().to_string_lossy().into_owned(), pid.as_u32())
        } else {
            ("unknown".to_string(), 0)
        }
    }

    fn check_autorun_entries(&mut self) -> Vec<RegistryEvent> {
        let mut events = Vec::new();
        
        for (subkey, hive) in Self::AUTORUN_LOCATIONS {
            let hkey = match *hive {
                "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
                "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
                _ => continue,
            };

            unsafe {
                let mut key = HKEY::default();
                let subkey_cstr = CString::new(*subkey).unwrap();
                if RegOpenKeyExA(
                    hkey,
                    PCSTR(subkey_cstr.as_ptr() as *const u8),
                    0,
                    KEY_READ,
                    &mut key,
                ).is_ok() {
                    let mut index = 0u32;
                    let mut name_buf = vec![0u8; 256];
                    let mut data_buf = vec![0u8; 1024];
                    
                    loop {
                        let mut name_size = name_buf.len() as u32;
                        let mut data_size = data_buf.len() as u32;
                        let mut value_type = 0u32;
                        
                        let status = RegEnumValueA(
                            key,
                            index,
                            PSTR(name_buf.as_mut_ptr()),
                            &mut name_size,
                            None,
                            Some(&mut value_type),
                            Some(data_buf.as_mut_ptr()),
                            Some(&mut data_size),
                        );

                        if status == ERROR_NO_MORE_ITEMS {
                            break;
                        }

                        if status.is_ok() {
                            if let (Ok(name), Ok(data)) = (
                                String::from_utf8(name_buf[..name_size as usize].to_vec()),
                                String::from_utf8(data_buf[..data_size as usize].to_vec())
                            ) {
                                let key_path = format!("{}\\{}", hive, subkey);
                                let cache_key = format!("{}\\{}", key_path, name);
                                
                                let event = if let Some(old_data) = self.autorun_cache.get(&cache_key) {
                                    if old_data != &data {
                                        Some(RegistryEventBuilder::new()
                                            .id(Uuid::new_v4().to_string())
                                            .timestamp(Utc::now())
                                            .source(self.hostname.clone())
                                            .category(String::from("registry"))
                                            .event_type(RegistryEventType::Modified)
                                            .key_path(key_path)
                                            .value_name(name)
                                            .old_data(old_data.clone())
                                            .new_data(data.clone())
                                            .build()
                                            .ok())
                                    } else {
                                        None
                                    }
                                } else {
                                    Some(RegistryEventBuilder::new()
                                        .id(Uuid::new_v4().to_string())
                                        .timestamp(Utc::now())
                                        .source(self.hostname.clone())
                                        .category(String::from("registry"))
                                        .event_type(RegistryEventType::Created)
                                        .key_path(key_path)
                                        .value_name(name)
                                        .new_data(data.clone())
                                        .build()
                                        .ok())
                                };
                                
                                if let Some(event) = event.flatten() {
                                    events.push(event);
                                }
                                
                                self.autorun_cache.insert(cache_key, data);
                            }
                            index += 1;
                        } else {
                            break;
                        }
                    }
                    RegCloseKey(key);
                }
            }
        }
        
        events
    }

    fn check_suspicious_operations(&self, event: &RegistryEvent) -> Option<SuspiciousRegistryOperation> {
        // Check suspicious registry operation patterns
        if let Some(data) = event.new_data.as_ref() {
            for pattern in &self.config.suspicious_patterns {
                if data.to_lowercase().contains(&pattern.to_lowercase()) {
                    return SuspiciousRegistryOperationBuilder::new()
                        .id(Uuid::new_v4().to_string())
                        .timestamp(event.timestamp)
                        .source(self.hostname.clone())
                        .category(String::from("registry_suspicious"))
                        .operation(format!("{:?}", event.event_type))
                        .key_path(event.key_path.clone())
                        .value_name(event.value_name.clone().unwrap_or_default())
                        .data(data.clone())
                        .process_name(event.process_name.clone().unwrap_or_default())
                        .process_id(event.process_id.unwrap_or_default())
                        .severity_level(crate::shared::traits::Severity::High)
                        .reason(format!("Suspicious command pattern detected: {}", pattern))
                        .build()
                        .ok();
                }
            }
        }

        // Check sensitive registry paths
        for path in &self.config.autorun_paths {
            if event.key_path.contains(path) {
                return SuspiciousRegistryOperationBuilder::new()
                    .id(Uuid::new_v4().to_string())
                    .timestamp(event.timestamp)
                    .source(self.hostname.clone())
                    .category(String::from("registry_suspicious"))
                    .operation(format!("{:?}", event.event_type))
                    .key_path(event.key_path.clone())
                    .value_name(event.value_name.clone().unwrap_or_default())
                    .data(event.new_data.clone().unwrap_or_default())
                    .process_name(event.process_name.clone().unwrap_or_default())
                    .process_id(event.process_id.unwrap_or_default())
                    .severity_level(crate::shared::traits::Severity::Medium)
                    .reason(format!("Modification to sensitive registry path: {}", path))
                    .build()
                    .ok();
            }
        }

        None
    }

    fn internal_validate(&self) -> Result<(), CollectionError> {
        if self.event_receiver.is_none() {
            return Err(CollectionError::SystemApi(
                "Registry event receiver not initialized".to_string()
            ));
        }
        Ok(())
    }
}

impl DataCollector<Vec<RegistryEvent>> for RegistryCollector {
    fn collect(&mut self) -> Result<Vec<RegistryEvent>, CollectionError> {
        let mut events = Vec::new();
        
        // Collect real-time registry change events
        if let Some(rx) = &mut self.event_receiver {
            while let Ok(event) = rx.try_recv() {
                events.push(event);
                if events.len() >= self.config.settings.max_events_per_collection {
                    break;
                }
            }
        }
        
        // Check autorun entry changes
        let autorun_events = self.check_autorun_entries();
        events.extend(autorun_events);

        info!("Collected {} registry events", events.len());
        
        // Check suspicious operations
        for event in &events {
            if let Some(suspicious_op) = self.check_suspicious_operations(event) {
                warn!("Detected suspicious registry operation: {:?}", suspicious_op);
            }
        }

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
impl AsyncDataCollector<Vec<RegistryEvent>> for RegistryCollector {
    async fn collect(&mut self) -> Result<Vec<RegistryEvent>, CollectionError> {
        DataCollector::collect(self)
    }

    async fn validate(&self) -> Result<(), CollectionError> {
        self.internal_validate()
    }

    async fn health_check(&self) -> bool {
        self.internal_validate().is_ok()
    }
}

impl Drop for RegistryCollector {
    fn drop(&mut self) {
        if let Some(handle) = self._monitor_thread.take() {
            handle.join().ok();
        }
    }
}
