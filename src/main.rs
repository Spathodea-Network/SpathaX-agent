use env_logger;
use lsedr::{
    shared::{
        storage::{ElasticsearchStorage, SystemInformation},
        traits::{AsyncDataCollector, DataCollector},
        error::CollectionError,
    },
    features::{
        network::NetworkCollector,
        process::{ProcessCollector, ProcessInformation},
        service::{ServiceCollector, ServiceInformation},
        system_metrics::SystemMetricsCollector,
        filesystem::FileSystemCollector,
        registry::{RegistryCollector, RegistryEvent},
    },
};
use log::{error, info, warn};
use std::time::{Duration, SystemTime};
use tokio::time;

#[tokio::main]
async fn main() {
    // Initialize logger with more detailed output
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    // Initialize Elasticsearch storage
    info!("Connecting to Elasticsearch at localhost:9200");
    let storage = match ElasticsearchStorage::new("localhost", 9200, None, None) {
        Ok(storage) => {
            info!("Successfully connected to Elasticsearch");
            storage
        }
        Err(e) => {
            error!("Failed to initialize Elasticsearch storage: {}", e);
            return;
        }
    };

    // Create collectors
    let mut metrics_collector = SystemMetricsCollector::new();
    let mut network_collector = NetworkCollector::new();
    let mut process_collector = ProcessCollector::new();
    let mut service_collector = ServiceCollector::new();
    let mut filesystem_collector = match FileSystemCollector::new() {
        Ok(collector) => {
            info!("Successfully initialized filesystem collector");
            collector
        }
        Err(e) => {
            error!("Failed to initialize filesystem collector: {}", e);
            return;
        }
    };
    let mut registry_collector = match RegistryCollector::new() {
        Ok(collector) => {
            info!("Successfully initialized registry collector");
            collector
        }
        Err(e) => {
            error!("Failed to initialize registry collector: {}", e);
            return;
        }
    };

    let hostname = whoami::hostname();
    let os_name = whoami::distro();
    let os_version = os_name.clone(); // For now, we'll use distro as version
    let kernel_version = whoami::platform().to_string();
    
    info!("Starting system metrics collection...");
    
    let mut interval = time::interval(Duration::from_secs(60));
    
    loop {
        interval.tick().await;

        // Collect metrics from all collectors
        let metrics_result = AsyncDataCollector::collect(&mut metrics_collector).await;
        let network_result = AsyncDataCollector::collect(&mut network_collector).await;
        let process_result = AsyncDataCollector::collect(&mut process_collector).await;
        let service_result = AsyncDataCollector::collect(&mut service_collector).await;
        let filesystem_result = AsyncDataCollector::collect(&mut filesystem_collector).await;
        let registry_result = AsyncDataCollector::collect(&mut registry_collector).await;

        match (metrics_result, network_result, process_result, service_result, filesystem_result, registry_result) {
            (Ok(metrics), Ok(network), Ok(processes), Ok(services), Ok(file_events), Ok(registry_events)) => {
                // Create system information
                let system_info = SystemInformation {
                    timestamp: SystemTime::now(),
                    hostname: hostname.clone(),
                    os_name: os_name.clone(),
                    os_version: os_version.clone(),
                    kernel_version: kernel_version.clone(),
                    cpu_info: metrics.cpu_info,
                    memory_info: metrics.memory_info,
                    disk_info: metrics.disk_info,
                    network_info: network.interfaces,
                    process_info: processes,
                    system_load: metrics.system_load,
                    network_connections: network.connections,
                    services,
                };
                
                // Log collection details
                info!("Collected system information:");
                info!("- {} network interfaces", system_info.network_info.len());
                info!("- {} network connections", system_info.network_connections.len());
                info!("- {} services", system_info.services.len());
                info!("- {} processes", system_info.process_info.len());
                info!("- {} disks", system_info.disk_info.len());
                info!("- {} file events", file_events.len());
                info!("- {} registry events", registry_events.len());
                
                // Store metrics in Elasticsearch
                if let Err(e) = storage.store_system_info(&system_info).await {
                    error!("Failed to store system metrics in Elasticsearch: {}", e);
                    error!("Error details: {:?}", e);
                    
                    if e.to_string().contains("connection") {
                        warn!("Elasticsearch connection might be lost. Please check if Elasticsearch is running.");
                    }
                } else {
                    info!("Successfully stored system metrics in Elasticsearch");
                }

                // Store file events
                if !file_events.is_empty() {
                    match storage.store_file_events(&file_events).await {
                        Ok(_) => {
                            info!("Successfully stored {} file events in Elasticsearch", file_events.len());
                        }
                        Err(e) => {
                            error!("Failed to store file events in Elasticsearch: {}", e);
                            error!("Error details: {:?}", e);
                        }
                    }
                }

                // Store registry events
                if !registry_events.is_empty() {
                    match storage.store_registry_events(&registry_events).await {
                        Ok(_) => {
                            info!("Successfully stored {} registry events in Elasticsearch", registry_events.len());
                        }
                        Err(e) => {
                            error!("Failed to store registry events in Elasticsearch: {}", e);
                            error!("Error details: {:?}", e);
                        }
                    }
                }
            }
            (Err(e), _, _, _, _, _) => {
                error!("Error collecting system metrics: {}", e);
            }
            (_, Err(e), _, _, _, _) => {
                error!("Error collecting network information: {}", e);
            }
            (_, _, Err(e), _, _, _) => {
                error!("Error collecting process information: {}", e);
            }
            (_, _, _, Err(e), _, _) => {
                error!("Error collecting service information: {}", e);
            }
            (_, _, _, _, Err(e), _) => {
                error!("Error collecting filesystem events: {}", e);
            }
            (_, _, _, _, _, Err(e)) => {
                error!("Error collecting registry events: {}", e);
            }
        }

        info!("Waiting 60 seconds before next collection...");
    }
}
