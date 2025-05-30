//! Onion Service Protection
//! 
//! Provides automatic rate limiting and connection management specifically for .onion domains.
//! This module implements specialized protection mechanisms for Tor hidden services.

use crate::tor::{TorSecurityConfig, TorSecurityError, TorSecurityResult};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Represents an onion address
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OnionAddress(String);

impl OnionAddress {
    /// Create a new onion address
    pub fn new(address: String) -> TorSecurityResult<Self> {
        if !Self::is_valid_onion_address(&address) {
            return Err(TorSecurityError::InvalidOnionAddress(
                format!("Invalid onion address format: {}", address)
            ));
        }
        Ok(OnionAddress(address))
    }

    /// Validate onion address format
    fn is_valid_onion_address(address: &str) -> bool {
        // Basic validation for .onion addresses
        address.ends_with(".onion") && address.len() >= 22
    }

    /// Get the raw address string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Connection information for rate limiting
#[derive(Debug, Clone)]
struct ConnectionInfo {
    count: u32,
    last_connection: Instant,
    first_connection: Instant,
}

/// Onion service protection configuration
#[derive(Debug, Clone)]
pub struct OnionServiceConfig {
    pub max_connections_per_ip: u32,
    pub connection_window: Duration,
    pub max_concurrent_connections: u32,
    pub enable_circuit_isolation: bool,
}

impl Default for OnionServiceConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: 10,
            connection_window: Duration::from_secs(60),
            max_concurrent_connections: 1000,
            enable_circuit_isolation: true,
        }
    }
}

/// Main onion service protection system
pub struct OnionServiceProtection {
    config: OnionServiceConfig,
    connection_tracker: HashMap<IpAddr, ConnectionInfo>,
    protected_onions: HashMap<OnionAddress, OnionServiceConfig>,
    active_connections: u32,
}

impl OnionServiceProtection {
    /// Create a new onion service protection instance
    pub fn new(tor_config: &TorSecurityConfig) -> TorSecurityResult<Self> {
        let config = OnionServiceConfig {
            max_connections_per_ip: tor_config.max_connections_per_circuit,
            connection_window: Duration::from_secs(tor_config.rate_limit_window_seconds),
            max_concurrent_connections: tor_config.max_requests_per_window,
            enable_circuit_isolation: true,
        };

        Ok(Self {
            config,
            connection_tracker: HashMap::new(),
            protected_onions: HashMap::new(),
            active_connections: 0,
        })
    }

    /// Initialize the protection system
    pub fn initialize(&mut self) -> TorSecurityResult<()> {
        self.connection_tracker.clear();
        self.active_connections = 0;
        println!("Onion Service Protection initialized");
        Ok(())
    }

    /// Shutdown the protection system
    pub fn shutdown(&mut self) -> TorSecurityResult<()> {
        self.connection_tracker.clear();
        self.protected_onions.clear();
        self.active_connections = 0;
        println!("Onion Service Protection shutdown");
        Ok(())
    }

    /// Register an onion service for protection
    pub fn register_onion_service(&mut self, address: OnionAddress) -> TorSecurityResult<()> {
        self.register_onion_service_with_config(address, OnionServiceConfig::default())
    }

    /// Register an onion service with custom configuration
    pub fn register_onion_service_with_config(
        &mut self,
        address: OnionAddress,
        config: OnionServiceConfig,
    ) -> TorSecurityResult<()> {
        self.protected_onions.insert(address.clone(), config);
        println!("Registered onion service: {}", address.as_str());
        Ok(())
    }

    /// Check if a connection should be allowed
    pub fn should_allow_connection(
        &mut self,
        client_ip: IpAddr,
        onion_address: &OnionAddress,
    ) -> TorSecurityResult<bool> {
        // Check if onion service is registered
        let service_config = self.protected_onions.get(onion_address)
            .unwrap_or(&self.config);

        // Check global connection limit
        if self.active_connections >= service_config.max_concurrent_connections {
            return Ok(false);
        }

        // Check per-IP rate limiting
        let now = Instant::now();
        let connection_info = self.connection_tracker.entry(client_ip).or_insert(ConnectionInfo {
            count: 0,
            last_connection: now,
            first_connection: now,
        });

        // Reset connection window if expired
        if now.duration_since(connection_info.first_connection) > service_config.connection_window {
            connection_info.count = 0;
            connection_info.first_connection = now;
        }

        // Check rate limit
        if connection_info.count >= service_config.max_connections_per_ip {
            return Ok(false);
        }

        // Allow connection and update counters
        connection_info.count += 1;
        connection_info.last_connection = now;
        self.active_connections += 1;

        Ok(true)
    }

    /// Record connection closure
    pub fn connection_closed(&mut self, _client_ip: IpAddr) {
        if self.active_connections > 0 {
            self.active_connections -= 1;
        }
    }

    /// Clean up expired connection tracking data
    pub fn cleanup_expired_connections(&mut self) {
        let now = Instant::now();
        self.connection_tracker.retain(|_, info| {
            now.duration_since(info.last_connection) < self.config.connection_window * 2
        });
    }

    /// Get current connection statistics
    pub fn get_connection_stats(&self) -> ConnectionStats {
        ConnectionStats {
            active_connections: self.active_connections,
            tracked_ips: self.connection_tracker.len(),
            protected_onions: self.protected_onions.len(),
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub active_connections: u32,
    pub tracked_ips: usize,
    pub protected_onions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onion_address_validation() {
        assert!(OnionAddress::new("facebookcorewwwi.onion".to_string()).is_ok());
        assert!(OnionAddress::new("invalid.com".to_string()).is_err());
        assert!(OnionAddress::new("short.onion".to_string()).is_err());
    }

    #[test]
    fn test_connection_limiting() {
        let config = TorSecurityConfig::default();
        let mut protection = OnionServiceProtection::new(&config).unwrap();
        protection.initialize().unwrap();

        let onion = OnionAddress::new("test1234567890123456.onion".to_string()).unwrap();
        protection.register_onion_service(onion.clone()).unwrap();

        let client_ip = "127.0.0.1".parse().unwrap();

        // First connection should be allowed
        assert!(protection.should_allow_connection(client_ip, &onion).unwrap());
    }
}
