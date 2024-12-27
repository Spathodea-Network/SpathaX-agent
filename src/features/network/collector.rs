use crate::shared::traits::{AsyncDataCollector, DataCollector};
use crate::shared::error::CollectionError;
use crate::features::network::models::{
    NetworkInformation, NetworkConnectionInformation, 
    NetworkMetrics, NetworkMetricsBuilder
};
use log::info;
use sysinfo::{System, Networks};
use chrono::Utc;
use uuid::Uuid;

pub struct NetworkCollector {
    sys: System,
    hostname: String,
}

impl NetworkCollector {
    pub fn new() -> Self {
        let sys = System::new();
        let hostname = whoami::hostname();
        Self { sys, hostname }
    }

    pub fn collect_interface_info(&self) -> Result<Vec<NetworkInformation>, CollectionError> {
        let mut networks = Networks::new();
        networks.refresh(true);
        let mut interfaces = Vec::new();
        
        // Get network interfaces using sysinfo
        interfaces = networks
            .iter()
            .map(|(interface_name, data)| NetworkInformation {
                interface_name: interface_name.to_string(),
                mac_address: data.mac_address().to_string(),
                ipv4_addresses: Vec::new(), // Will be populated below
                ipv6_addresses: Vec::new(), // Will be populated below
                received_bytes: data.received(),
                transmitted_bytes: data.transmitted(),
                received_packets: data.packets_received(),
                transmitted_packets: data.packets_transmitted(),
                errors: data.errors_on_received() + data.errors_on_transmitted(),
            })
            .collect();

        // Get IP addresses using ipconfig on Windows
        if cfg!(target_os = "windows") {
            let output = std::process::Command::new("ipconfig")
                .output()
                .map_err(|e| CollectionError::SystemApi(format!("Failed to execute ipconfig: {}", e)))?;
            
            let output_str = String::from_utf8_lossy(&output.stdout);
            let mut current_interface = None;
            let mut current_ipv4 = Vec::new();
            let mut current_ipv6 = Vec::new();
            
            for line in output_str.lines() {
                let line = line.trim();
                if line.ends_with(':') {
                    // New interface section
                    if let Some(interface_name) = current_interface.take() {
                        if let Some(interface) = interfaces.iter_mut()
                            .find(|i| i.interface_name.contains(&interface_name)) {
                            interface.ipv4_addresses = current_ipv4.clone();
                            interface.ipv6_addresses = current_ipv6.clone();
                        }
                        current_ipv4.clear();
                        current_ipv6.clear();
                    }
                    current_interface = Some(line[..line.len()-1].to_string());
                } else if let Some(_) = &current_interface {
                    if line.contains("IPv4") && line.contains(':') {
                        if let Some(ip) = line.split(':').nth(1) {
                            current_ipv4.push(ip.trim().to_string());
                        }
                    } else if line.contains("IPv6") && line.contains(':') {
                        if let Some(ip) = line.split(':').nth(1) {
                            current_ipv6.push(ip.trim().to_string());
                        }
                    }
                }
            }
            
            // Handle the last interface
            if let Some(interface_name) = current_interface {
                if let Some(interface) = interfaces.iter_mut()
                    .find(|i| i.interface_name.contains(&interface_name)) {
                    interface.ipv4_addresses = current_ipv4;
                    interface.ipv6_addresses = current_ipv6;
                }
            }
        }

        Ok(interfaces)
    }

    pub fn collect_connections(&self) -> Result<Vec<NetworkConnectionInformation>, CollectionError> {
        let mut connections = Vec::new();
        
        if cfg!(target_os = "windows") {
            let output = std::process::Command::new("netstat")
                .args(["-n", "-o"])
                .output()
                .map_err(|e| CollectionError::SystemApi(format!("Failed to execute netstat: {}", e)))?;
            
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            for line in output_str.lines().skip(4) { // Skip header lines
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let protocol = parts[0].to_string();
                    if let Some((local_addr, local_p)) = parts[1].rsplit_once(':') {
                        if let Some((remote_addr, remote_p)) = parts[2].rsplit_once(':') {
                            if let (Ok(local_port), Ok(remote_port)) = (local_p.parse::<u16>(), remote_p.parse::<u16>()) {
                                let mut conn = NetworkConnectionInformation {
                                    protocol,
                                    local_address: local_addr.to_string(),
                                    local_port,
                                    remote_address: remote_addr.to_string(),
                                    remote_port,
                                    state: parts[3].to_string(),
                                    process_id: parts.get(4).and_then(|pid| pid.parse().ok()),
                                };
                                connections.push(conn);
                            }
                        }
                    }
                }
            }
        }

        info!("Found {} network connections", connections.len());
        Ok(connections)
    }

    fn internal_validate(&self) -> Result<(), CollectionError> {
        // Skip validation since a system may legitimately have no network interfaces
        // The collection itself will handle empty interfaces appropriately
        Ok(())
    }
}

impl DataCollector<NetworkMetrics> for NetworkCollector {
    fn collect(&mut self) -> Result<NetworkMetrics, CollectionError> {
        self.sys.refresh_all();

        let metrics = NetworkMetricsBuilder::new()
            .id(Uuid::new_v4().to_string())
            .timestamp(Utc::now())
            .source(self.hostname.clone())
            .category(String::from("network"))
            .interfaces(self.collect_interface_info()?)
            .connections(self.collect_connections()?)
            .build()
            .map_err(|e| CollectionError::Parse(e))?;

        info!("Collected network metrics");
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
impl AsyncDataCollector<NetworkMetrics> for NetworkCollector {
    async fn collect(&mut self) -> Result<NetworkMetrics, CollectionError> {
        DataCollector::collect(self)
    }

    async fn validate(&self) -> Result<(), CollectionError> {
        self.internal_validate()
    }

    async fn health_check(&self) -> bool {
        self.internal_validate().is_ok()
    }
}

impl Default for NetworkCollector {
    fn default() -> Self {
        Self::new()
    }
}
