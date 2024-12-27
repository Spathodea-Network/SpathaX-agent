pub mod features;
pub mod shared;

// Re-export commonly used items from features
pub use features::network::{NetworkCollector, NetworkInformation};
pub use features::process::{ProcessCollector, ProcessInformation};
pub use features::service::{ServiceCollector, ServiceInformation};
pub use features::system_metrics::{
    SystemMetricsCollector,
    SystemMetrics,
    CpuInformation,
    MemoryInformation,
    DiskInformation,
    SystemLoadInformation,
};
pub use features::filesystem::{
    FileSystemCollector,
    FileEvent,
    FileEventType,
};
pub use features::registry::{
    RegistryCollector,
    RegistryEvent,
    RegistryEventType,
    SuspiciousRegistryOperation,
};

// Re-export shared functionality
pub use shared::traits::{
    Event,
    Severity,
    Validatable,
    Identifiable,
    DataCollector,
    AsyncDataCollector,
};
pub use shared::error::{
    CollectionError,
    ProcessingError,
    StorageError,
};
pub use shared::storage::{ElasticsearchStorage, SystemInformation};

// Utils module will be moved to shared in future refactoring
pub mod utils;
