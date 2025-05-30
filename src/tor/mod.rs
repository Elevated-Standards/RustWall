//! Tor Network Security Features
//! 
//! This module provides specialized security features for hosting sites on the Tor network.
//! It includes protection mechanisms specifically designed for .onion services and hidden services.

pub mod onion_service;
pub mod ddos_mitigation;
pub mod circuit_analysis;
pub mod exit_node_filter;
pub mod rendezvous_security;

use std::error::Error;
use std::fmt;

/// Common error types for Tor security features
#[derive(Debug)]
pub enum TorSecurityError {
    ConfigurationError(String),
    NetworkError(String),
    SecurityViolation(String),
    InvalidOnionAddress(String),
    CircuitError(String),
}

impl fmt::Display for TorSecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TorSecurityError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            TorSecurityError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            TorSecurityError::SecurityViolation(msg) => write!(f, "Security violation: {}", msg),
            TorSecurityError::InvalidOnionAddress(msg) => write!(f, "Invalid onion address: {}", msg),
            TorSecurityError::CircuitError(msg) => write!(f, "Circuit error: {}", msg),
        }
    }
}

impl Error for TorSecurityError {}

/// Result type for Tor security operations
pub type TorSecurityResult<T> = Result<T, TorSecurityError>;

/// Configuration for Tor security features
#[derive(Debug, Clone)]
pub struct TorSecurityConfig {
    pub enable_onion_protection: bool,
    pub enable_ddos_mitigation: bool,
    pub enable_circuit_analysis: bool,
    pub enable_exit_node_filtering: bool,
    pub enable_rendezvous_security: bool,
    pub max_connections_per_circuit: u32,
    pub rate_limit_window_seconds: u64,
    pub max_requests_per_window: u32,
}

impl Default for TorSecurityConfig {
    fn default() -> Self {
        Self {
            enable_onion_protection: true,
            enable_ddos_mitigation: true,
            enable_circuit_analysis: true,
            enable_exit_node_filtering: true,
            enable_rendezvous_security: true,
            max_connections_per_circuit: 10,
            rate_limit_window_seconds: 60,
            max_requests_per_window: 100,
        }
    }
}

/// Main Tor security manager
pub struct TorSecurityManager {
    config: TorSecurityConfig,
    onion_service: onion_service::OnionServiceProtection,
    ddos_mitigation: ddos_mitigation::DDoSMitigation,
    circuit_analysis: circuit_analysis::CircuitAnalysis,
    exit_node_filter: exit_node_filter::ExitNodeFilter,
    rendezvous_security: rendezvous_security::RendezvousPointSecurity,
}

impl TorSecurityManager {
    /// Create a new Tor security manager with default configuration
    pub fn new() -> TorSecurityResult<Self> {
        Self::with_config(TorSecurityConfig::default())
    }

    /// Create a new Tor security manager with custom configuration
    pub fn with_config(config: TorSecurityConfig) -> TorSecurityResult<Self> {
        Ok(Self {
            onion_service: onion_service::OnionServiceProtection::new(&config)?,
            ddos_mitigation: ddos_mitigation::DDoSMitigation::new(&config)?,
            circuit_analysis: circuit_analysis::CircuitAnalysis::new(&config)?,
            exit_node_filter: exit_node_filter::ExitNodeFilter::new(&config)?,
            rendezvous_security: rendezvous_security::RendezvousPointSecurity::new(&config)?,
            config,
        })
    }

    /// Initialize all security features
    pub fn initialize(&mut self) -> TorSecurityResult<()> {
        if self.config.enable_onion_protection {
            self.onion_service.initialize()?;
        }
        if self.config.enable_ddos_mitigation {
            self.ddos_mitigation.initialize()?;
        }
        if self.config.enable_circuit_analysis {
            self.circuit_analysis.initialize()?;
        }
        if self.config.enable_exit_node_filtering {
            self.exit_node_filter.initialize()?;
        }
        if self.config.enable_rendezvous_security {
            self.rendezvous_security.initialize()?;
        }
        Ok(())
    }

    /// Shutdown all security features
    pub fn shutdown(&mut self) -> TorSecurityResult<()> {
        self.onion_service.shutdown()?;
        self.ddos_mitigation.shutdown()?;
        self.circuit_analysis.shutdown()?;
        self.exit_node_filter.shutdown()?;
        self.rendezvous_security.shutdown()?;
        Ok(())
    }
}

impl Default for TorSecurityManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default TorSecurityManager")
    }
}
