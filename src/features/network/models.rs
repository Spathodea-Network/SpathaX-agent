use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::shared::traits::{Event, Severity, Validatable, Identifiable};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInformation {
    pub interface_name: String,
    pub mac_address: String,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub received_bytes: u64,
    pub transmitted_bytes: u64,
    pub received_packets: u64,
    pub transmitted_packets: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionInformation {
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub process_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub category: String,
    pub interfaces: Vec<NetworkInformation>,
    pub connections: Vec<NetworkConnectionInformation>,
}

impl Event for NetworkMetrics {
    fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    fn source(&self) -> &str {
        &self.source
    }

    fn event_type(&self) -> &str {
        "network_metrics"
    }

    fn severity(&self) -> Severity {
        // Determine severity based on network metrics
        let has_errors = self.interfaces.iter().any(|interface| interface.errors > 0);
        let high_usage = self.interfaces.iter().any(|interface| {
            // Consider high usage if transmitted or received bytes are above certain threshold
            interface.transmitted_bytes > 1_000_000_000 || // 1GB
            interface.received_bytes > 1_000_000_000
        });

        if has_errors {
            Severity::High
        } else if high_usage {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

impl Identifiable for NetworkMetrics {
    fn id(&self) -> &str {
        &self.id
    }

    fn category(&self) -> &str {
        &self.category
    }
}

impl Validatable for NetworkMetrics {
    fn validate(&self) -> Result<(), String> {
        if self.interfaces.is_empty() {
            return Err("No network interfaces found".to_string());
        }

        for interface in &self.interfaces {
            if interface.interface_name.is_empty() {
                return Err("Interface name cannot be empty".to_string());
            }
            if interface.mac_address.is_empty() {
                return Err(format!("MAC address cannot be empty for interface {}", interface.interface_name));
            }
        }

        for conn in &self.connections {
            if conn.local_port == 0 {
                return Err("Local port cannot be 0".to_string());
            }
            if conn.protocol.is_empty() {
                return Err("Protocol cannot be empty".to_string());
            }
            if conn.state.is_empty() {
                return Err("Connection state cannot be empty".to_string());
            }
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct NetworkMetricsBuilder {
    id: Option<String>,
    timestamp: Option<DateTime<Utc>>,
    source: Option<String>,
    category: Option<String>,
    interfaces: Option<Vec<NetworkInformation>>,
    connections: Option<Vec<NetworkConnectionInformation>>,
}

impl NetworkMetricsBuilder {
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

    pub fn interfaces(mut self, interfaces: Vec<NetworkInformation>) -> Self {
        self.interfaces = Some(interfaces);
        self
    }

    pub fn connections(mut self, connections: Vec<NetworkConnectionInformation>) -> Self {
        self.connections = Some(connections);
        self
    }

    pub fn build(self) -> Result<NetworkMetrics, String> {
        let metrics = NetworkMetrics {
            id: self.id.ok_or("id is required")?,
            timestamp: self.timestamp.ok_or("timestamp is required")?,
            source: self.source.ok_or("source is required")?,
            category: self.category.ok_or("category is required")?,
            interfaces: self.interfaces.ok_or("interfaces are required")?,
            connections: self.connections.ok_or("connections are required")?,
        };

        metrics.validate()?;
        Ok(metrics)
    }
}
