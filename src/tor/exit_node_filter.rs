//! Exit Node Filtering
//! 
//! Block known malicious Tor exit nodes and maintain dynamic blocklists.
//! Provides protection against compromised or malicious exit nodes.

use crate::tor::{TorSecurityConfig, TorSecurityResult};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Exit node reputation score
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct ReputationScore(f64);

impl ReputationScore {
    pub fn new(score: f64) -> Self {
        Self(score.clamp(0.0, 1.0))
    }

    pub fn value(&self) -> f64 {
        self.0
    }

    pub fn is_trusted(&self) -> bool {
        self.0 >= 0.7
    }

    pub fn is_suspicious(&self) -> bool {
        self.0 <= 0.3
    }

    pub fn is_malicious(&self) -> bool {
        self.0 <= 0.1
    }
}

impl Default for ReputationScore {
    fn default() -> Self {
        Self(0.5) // Neutral score
    }
}

/// Exit node information
#[derive(Debug, Clone)]
pub struct ExitNodeInfo {
    pub ip_address: IpAddr,
    pub nickname: Option<String>,
    pub fingerprint: Option<String>,
    pub country_code: Option<String>,
    pub reputation: ReputationScore,
    pub last_seen: Instant,
    pub first_seen: Instant,
    pub connection_count: u32,
    pub malicious_activity_count: u32,
    pub is_blocked: bool,
    pub block_reason: Option<String>,
}

/// Blocklist source types
#[derive(Debug, Clone, PartialEq)]
pub enum BlocklistSource {
    Manual,
    ThreatIntelligence,
    BehaviorAnalysis,
    CommunityReports,
    GovernmentNotice,
}

/// Blocklist entry
#[derive(Debug, Clone)]
pub struct BlocklistEntry {
    pub ip_address: IpAddr,
    pub source: BlocklistSource,
    pub reason: String,
    pub added_at: Instant,
    pub expires_at: Option<Instant>,
    pub severity: u8, // 1-10 scale
}

/// Exit node filter configuration
#[derive(Debug, Clone)]
pub struct ExitNodeFilterConfig {
    pub enable_reputation_filtering: bool,
    pub minimum_reputation_score: f64,
    pub blocklist_update_interval: Duration,
    pub reputation_decay_rate: f64,
    pub max_connections_per_node: u32,
    pub enable_country_filtering: bool,
    pub blocked_countries: HashSet<String>,
    pub enable_automatic_blocking: bool,
    pub auto_block_threshold: u32,
}

impl Default for ExitNodeFilterConfig {
    fn default() -> Self {
        Self {
            enable_reputation_filtering: true,
            minimum_reputation_score: 0.3,
            blocklist_update_interval: Duration::from_secs(3600), // 1 hour
            reputation_decay_rate: 0.01, // 1% per day
            max_connections_per_node: 100,
            enable_country_filtering: false,
            blocked_countries: HashSet::new(),
            enable_automatic_blocking: true,
            auto_block_threshold: 10,
        }
    }
}

/// Main exit node filter system
pub struct ExitNodeFilter {
    config: ExitNodeFilterConfig,
    exit_nodes: HashMap<IpAddr, ExitNodeInfo>,
    blocklist: HashMap<IpAddr, BlocklistEntry>,
    trusted_nodes: HashSet<IpAddr>,
    last_update: Instant,
    connection_stats: HashMap<IpAddr, (u32, Instant)>,
}

impl ExitNodeFilter {
    /// Create a new exit node filter instance
    pub fn new(tor_config: &TorSecurityConfig) -> TorSecurityResult<Self> {
        let config = ExitNodeFilterConfig {
            enable_reputation_filtering: true,
            minimum_reputation_score: 0.3,
            blocklist_update_interval: Duration::from_secs(3600),
            reputation_decay_rate: 0.01,
            max_connections_per_node: tor_config.max_connections_per_circuit,
            enable_country_filtering: false,
            blocked_countries: HashSet::new(),
            enable_automatic_blocking: true,
            auto_block_threshold: 10,
        };

        Ok(Self {
            config,
            exit_nodes: HashMap::new(),
            blocklist: HashMap::new(),
            trusted_nodes: HashSet::new(),
            last_update: Instant::now(),
            connection_stats: HashMap::new(),
        })
    }

    /// Initialize the exit node filter system
    pub fn initialize(&mut self) -> TorSecurityResult<()> {
        self.exit_nodes.clear();
        self.blocklist.clear();
        self.trusted_nodes.clear();
        self.connection_stats.clear();
        self.last_update = Instant::now();
        
        // Load default trusted nodes (could be from a config file)
        self.load_default_trusted_nodes()?;
        
        println!("Exit Node Filter initialized");
        Ok(())
    }

    /// Shutdown the exit node filter system
    pub fn shutdown(&mut self) -> TorSecurityResult<()> {
        self.exit_nodes.clear();
        self.blocklist.clear();
        self.trusted_nodes.clear();
        self.connection_stats.clear();
        println!("Exit Node Filter shutdown");
        Ok(())
    }

    /// Check if an exit node should be allowed
    pub fn should_allow_exit_node(&mut self, ip_address: IpAddr) -> TorSecurityResult<bool> {
        let now = Instant::now();

        // Check if explicitly blocked
        if self.is_blocked(ip_address) {
            return Ok(false);
        }

        // Check if explicitly trusted
        if self.trusted_nodes.contains(&ip_address) {
            return Ok(true);
        }

        // Check connection limits
        if !self.check_connection_limits(ip_address, now)? {
            return Ok(false);
        }

        // Check reputation if enabled
        if self.config.enable_reputation_filtering {
            if let Some(node_info) = self.exit_nodes.get(&ip_address) {
                if node_info.reputation.value() < self.config.minimum_reputation_score {
                    return Ok(false);
                }
            }
        }

        // Check country filtering if enabled
        if self.config.enable_country_filtering {
            if let Some(node_info) = self.exit_nodes.get(&ip_address) {
                if let Some(ref country) = node_info.country_code {
                    if self.config.blocked_countries.contains(country) {
                        return Ok(false);
                    }
                }
            }
        }

        // Update connection tracking
        self.record_connection(ip_address, now);

        Ok(true)
    }

    /// Record a connection to an exit node
    pub fn record_connection(&mut self, ip_address: IpAddr, timestamp: Instant) {
        // Update exit node info
        let node_info = self.exit_nodes.entry(ip_address).or_insert_with(|| ExitNodeInfo {
            ip_address,
            nickname: None,
            fingerprint: None,
            country_code: None,
            reputation: ReputationScore::default(),
            last_seen: timestamp,
            first_seen: timestamp,
            connection_count: 0,
            malicious_activity_count: 0,
            is_blocked: false,
            block_reason: None,
        });

        node_info.connection_count += 1;
        node_info.last_seen = timestamp;

        // Update connection stats for rate limiting
        let (count, window_start) = self.connection_stats.entry(ip_address).or_insert((0, timestamp));
        if timestamp.duration_since(*window_start) >= Duration::from_secs(60) {
            *count = 1;
            *window_start = timestamp;
        } else {
            *count += 1;
        }
    }

    /// Report malicious activity from an exit node
    pub fn report_malicious_activity(
        &mut self,
        ip_address: IpAddr,
        reason: String,
    ) -> TorSecurityResult<()> {
        let malicious_count = if let Some(node_info) = self.exit_nodes.get_mut(&ip_address) {
            node_info.malicious_activity_count += 1;
            
            // Decrease reputation
            let current_score = node_info.reputation.value();
            let new_score = (current_score - 0.1).max(0.0);
            node_info.reputation = ReputationScore::new(new_score);

            node_info.malicious_activity_count
        } else {
            0
        };

        // Auto-block if threshold exceeded
        if self.config.enable_automatic_blocking 
            && malicious_count >= self.config.auto_block_threshold {
            self.add_to_blocklist(
                ip_address,
                BlocklistSource::BehaviorAnalysis,
                format!("Automatic block after {} malicious activities: {}", 
                       malicious_count, reason),
                None,
                8,
            )?;
        }
        Ok(())
    }

    /// Add an IP address to the blocklist
    pub fn add_to_blocklist(
        &mut self,
        ip_address: IpAddr,
        source: BlocklistSource,
        reason: String,
        expires_at: Option<Instant>,
        severity: u8,
    ) -> TorSecurityResult<()> {
        let entry = BlocklistEntry {
            ip_address,
            source,
            reason: reason.clone(),
            added_at: Instant::now(),
            expires_at,
            severity: severity.clamp(1, 10),
        };

        self.blocklist.insert(ip_address, entry);

        // Mark the node as blocked if it exists
        if let Some(node_info) = self.exit_nodes.get_mut(&ip_address) {
            node_info.is_blocked = true;
            node_info.block_reason = Some(reason.clone());
        }

        println!("Added {} to blocklist: {}", ip_address, reason);
        Ok(())
    }

    /// Remove an IP address from the blocklist
    pub fn remove_from_blocklist(&mut self, ip_address: IpAddr) -> TorSecurityResult<()> {
        self.blocklist.remove(&ip_address);

        if let Some(node_info) = self.exit_nodes.get_mut(&ip_address) {
            node_info.is_blocked = false;
            node_info.block_reason = None;
        }

        println!("Removed {} from blocklist", ip_address);
        Ok(())
    }

    /// Add an IP address to the trusted nodes list
    pub fn add_trusted_node(&mut self, ip_address: IpAddr) -> TorSecurityResult<()> {
        self.trusted_nodes.insert(ip_address);
        
        // Ensure it's not blocked
        self.remove_from_blocklist(ip_address)?;
        
        // Set high reputation
        if let Some(node_info) = self.exit_nodes.get_mut(&ip_address) {
            node_info.reputation = ReputationScore::new(1.0);
        }

        println!("Added {} to trusted nodes", ip_address);
        Ok(())
    }

    /// Check if an IP address is blocked
    fn is_blocked(&self, ip_address: IpAddr) -> bool {
        if let Some(entry) = self.blocklist.get(&ip_address) {
            // Check if entry has expired
            if let Some(expires_at) = entry.expires_at {
                if Instant::now() > expires_at {
                    return false; // Entry expired
                }
            }
            return true;
        }
        false
    }

    /// Check connection limits for an exit node
    fn check_connection_limits(&self, ip_address: IpAddr, now: Instant) -> TorSecurityResult<bool> {
        if let Some((count, window_start)) = self.connection_stats.get(&ip_address) {
            if now.duration_since(*window_start) < Duration::from_secs(60) {
                if *count >= self.config.max_connections_per_node {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Load default trusted nodes (placeholder implementation)
    fn load_default_trusted_nodes(&mut self) -> TorSecurityResult<()> {
        // In a real implementation, this would load from a configuration file
        // or fetch from a trusted source
        
        // Example trusted nodes (these would be real trusted exit nodes in practice)
        let default_trusted: Vec<&str> = vec![
            // Add some example trusted IPs here if needed
        ];

        for ip_str in default_trusted {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                self.trusted_nodes.insert(ip);
            }
        }

        Ok(())
    }

    /// Update reputation scores (decay over time)
    pub fn update_reputation_scores(&mut self) -> TorSecurityResult<()> {
        let now = Instant::now();
        let decay_amount = self.config.reputation_decay_rate;

        for node_info in self.exit_nodes.values_mut() {
            // Gradually improve reputation over time for nodes with no recent issues
            let days_since_last_seen = now.duration_since(node_info.last_seen).as_secs() as f64 / 86400.0;
            
            if days_since_last_seen < 7.0 && node_info.malicious_activity_count == 0 {
                let current_score = node_info.reputation.value();
                let new_score = (current_score + decay_amount * 0.1).min(1.0);
                node_info.reputation = ReputationScore::new(new_score);
            }
        }

        Ok(())
    }

    /// Clean up expired blocklist entries and old data
    pub fn cleanup_expired_data(&mut self) {
        let now = Instant::now();

        // Remove expired blocklist entries
        self.blocklist.retain(|_, entry| {
            if let Some(expires_at) = entry.expires_at {
                now <= expires_at
            } else {
                true // No expiration
            }
        });

        // Remove old connection stats
        self.connection_stats.retain(|_, (_, window_start)| {
            now.duration_since(*window_start) < Duration::from_secs(3600)
        });

        // Remove very old exit node info
        self.exit_nodes.retain(|_, node_info| {
            now.duration_since(node_info.last_seen) < Duration::from_secs(86400 * 30) // 30 days
        });
    }

    /// Get exit node filter statistics
    pub fn get_filter_stats(&self) -> ExitNodeFilterStats {
        let blocked_count = self.blocklist.len();
        let trusted_count = self.trusted_nodes.len();
        let total_nodes = self.exit_nodes.len();
        let suspicious_nodes = self.exit_nodes.values()
            .filter(|node| node.reputation.is_suspicious())
            .count();

        ExitNodeFilterStats {
            total_nodes,
            blocked_count,
            trusted_count,
            suspicious_nodes,
            total_connections: self.exit_nodes.values().map(|n| n.connection_count).sum(),
        }
    }
}

/// Exit node filter statistics
#[derive(Debug, Clone)]
pub struct ExitNodeFilterStats {
    pub total_nodes: usize,
    pub blocked_count: usize,
    pub trusted_count: usize,
    pub suspicious_nodes: usize,
    pub total_connections: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_node_filter_creation() {
        let config = TorSecurityConfig::default();
        let filter = ExitNodeFilter::new(&config);
        assert!(filter.is_ok());
    }

    #[test]
    fn test_reputation_score() {
        let score = ReputationScore::new(0.8);
        assert!(score.is_trusted());
        assert!(!score.is_suspicious());
        assert!(!score.is_malicious());
    }

    #[test]
    fn test_blocklist_operations() {
        let config = TorSecurityConfig::default();
        let mut filter = ExitNodeFilter::new(&config).unwrap();
        filter.initialize().unwrap();

        let test_ip: IpAddr = "192.168.1.1".parse().unwrap();
        
        // Add to blocklist
        filter.add_to_blocklist(
            test_ip,
            BlocklistSource::Manual,
            "Test block".to_string(),
            None,
            5,
        ).unwrap();

        // Check if blocked
        assert!(!filter.should_allow_exit_node(test_ip).unwrap());

        // Remove from blocklist
        filter.remove_from_blocklist(test_ip).unwrap();
        
        // Should be allowed now
        assert!(filter.should_allow_exit_node(test_ip).unwrap());
    }
}
