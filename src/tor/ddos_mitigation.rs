//! Hidden Service DDoS Mitigation
//! 
//! Specialized protection against Tor-based DDoS attacks targeting hidden services.
//! Implements adaptive rate limiting, traffic pattern analysis, and circuit-based filtering.

use crate::tor::{TorSecurityConfig, TorSecurityResult};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// DDoS attack pattern detection
#[derive(Debug, Clone)]
pub enum AttackPattern {
    HighFrequency,
    LowAndSlow,
    CircuitFlooding,
    RendezvousOverload,
    Unknown,
}

/// Traffic sample for analysis
#[derive(Debug, Clone)]
struct TrafficSample {
    timestamp: Instant,
    source_ip: Option<IpAddr>,
    request_size: u64,
    circuit_id: Option<String>,
}

/// DDoS mitigation configuration
#[derive(Debug, Clone)]
pub struct DDoSConfig {
    pub max_requests_per_second: u32,
    pub circuit_timeout: Duration,
    pub max_circuits_per_ip: u32,
    pub analysis_window: Duration,
    pub mitigation_threshold: f64,
    pub enable_adaptive_limits: bool,
}

impl Default for DDoSConfig {
    fn default() -> Self {
        Self {
            max_requests_per_second: 100,
            circuit_timeout: Duration::from_secs(300),
            max_circuits_per_ip: 5,
            analysis_window: Duration::from_secs(60),
            mitigation_threshold: 0.8,
            enable_adaptive_limits: true,
        }
    }
}

/// Circuit information tracking
#[derive(Debug, Clone)]
struct CircuitInfo {
    circuit_id: String,
    source_ip: Option<IpAddr>,
    created_at: Instant,
    request_count: u32,
    last_activity: Instant,
    suspicious_score: f64,
}

/// DDoS mitigation state
#[derive(Debug, Clone)]
pub enum MitigationState {
    Normal,
    EarlyWarning,
    UnderAttack,
    Emergency,
}

/// Main DDoS mitigation system
pub struct DDoSMitigation {
    config: DDoSConfig,
    traffic_samples: VecDeque<TrafficSample>,
    circuit_tracker: HashMap<String, CircuitInfo>,
    ip_request_counts: HashMap<IpAddr, (u32, Instant)>,
    current_state: MitigationState,
    adaptive_limit: u32,
    last_analysis: Instant,
}

impl DDoSMitigation {
    /// Create a new DDoS mitigation instance
    pub fn new(tor_config: &TorSecurityConfig) -> TorSecurityResult<Self> {
        let config = DDoSConfig {
            max_requests_per_second: tor_config.max_requests_per_window / tor_config.rate_limit_window_seconds as u32,
            circuit_timeout: Duration::from_secs(300),
            max_circuits_per_ip: tor_config.max_connections_per_circuit,
            analysis_window: Duration::from_secs(tor_config.rate_limit_window_seconds),
            mitigation_threshold: 0.8,
            enable_adaptive_limits: true,
        };

        Ok(Self {
            adaptive_limit: config.max_requests_per_second,
            config,
            traffic_samples: VecDeque::new(),
            circuit_tracker: HashMap::new(),
            ip_request_counts: HashMap::new(),
            current_state: MitigationState::Normal,
            last_analysis: Instant::now(),
        })
    }

    /// Initialize the DDoS mitigation system
    pub fn initialize(&mut self) -> TorSecurityResult<()> {
        self.traffic_samples.clear();
        self.circuit_tracker.clear();
        self.ip_request_counts.clear();
        self.current_state = MitigationState::Normal;
        self.last_analysis = Instant::now();
        println!("DDoS Mitigation initialized");
        Ok(())
    }

    /// Shutdown the DDoS mitigation system
    pub fn shutdown(&mut self) -> TorSecurityResult<()> {
        self.traffic_samples.clear();
        self.circuit_tracker.clear();
        self.ip_request_counts.clear();
        println!("DDoS Mitigation shutdown");
        Ok(())
    }

    /// Record a new request for analysis
    pub fn record_request(
        &mut self,
        source_ip: Option<IpAddr>,
        request_size: u64,
        circuit_id: Option<String>,
    ) -> TorSecurityResult<()> {
        let now = Instant::now();

        // Add traffic sample
        let sample = TrafficSample {
            timestamp: now,
            source_ip,
            request_size,
            circuit_id: circuit_id.clone(),
        };
        self.traffic_samples.push_back(sample);

        // Update circuit tracking
        if let Some(cid) = circuit_id {
            self.update_circuit_tracking(cid, source_ip, now)?;
        }

        // Update IP request counts
        if let Some(ip) = source_ip {
            self.update_ip_tracking(ip, now);
        }

        // Perform periodic analysis
        if now.duration_since(self.last_analysis) > Duration::from_secs(10) {
            self.analyze_traffic()?;
            self.last_analysis = now;
        }

        Ok(())
    }

    /// Check if a request should be allowed
    pub fn should_allow_request(
        &mut self,
        source_ip: Option<IpAddr>,
        circuit_id: Option<String>,
    ) -> TorSecurityResult<bool> {
        let now = Instant::now();

        // Check IP rate limiting
        if let Some(ip) = source_ip {
            if let Some((count, window_start)) = self.ip_request_counts.get(&ip) {
                if now.duration_since(*window_start) < Duration::from_secs(1) {
                    if *count >= self.adaptive_limit {
                        return Ok(false);
                    }
                }
            }
        }

        // Check circuit limits
        if let Some(ref cid) = circuit_id {
            if let Some(circuit) = self.circuit_tracker.get(cid) {
                if circuit.suspicious_score > self.config.mitigation_threshold {
                    return Ok(false);
                }
                
                if source_ip.is_some() {
                    let circuits_for_ip = self.circuit_tracker.values()
                        .filter(|c| c.source_ip == source_ip)
                        .count();
                    
                    if circuits_for_ip >= self.config.max_circuits_per_ip as usize {
                        return Ok(false);
                    }
                }
            }
        }

        // Check global state
        match self.current_state {
            MitigationState::Emergency => Ok(false),
            MitigationState::UnderAttack => Ok(source_ip.is_some() && circuit_id.is_some()),
            _ => Ok(true),
        }
    }

    /// Update circuit tracking information
    fn update_circuit_tracking(
        &mut self,
        circuit_id: String,
        source_ip: Option<IpAddr>,
        now: Instant,
    ) -> TorSecurityResult<()> {
        let circuit = self.circuit_tracker.entry(circuit_id.clone()).or_insert(CircuitInfo {
            circuit_id: circuit_id.clone(),
            source_ip,
            created_at: now,
            request_count: 0,
            last_activity: now,
            suspicious_score: 0.0,
        });

        circuit.request_count += 1;
        circuit.last_activity = now;

        // Calculate suspicious score based on request frequency
        let duration = now.duration_since(circuit.created_at).as_secs_f64();
        if duration > 0.0 {
            let request_rate = circuit.request_count as f64 / duration;
            circuit.suspicious_score = (request_rate / self.config.max_requests_per_second as f64).min(1.0);
        }

        Ok(())
    }

    /// Update IP tracking information
    fn update_ip_tracking(&mut self, ip: IpAddr, now: Instant) {
        let (count, window_start) = self.ip_request_counts.entry(ip).or_insert((0, now));
        
        if now.duration_since(*window_start) >= Duration::from_secs(1) {
            *count = 1;
            *window_start = now;
        } else {
            *count += 1;
        }
    }

    /// Analyze traffic patterns and update mitigation state
    fn analyze_traffic(&mut self) -> TorSecurityResult<()> {
        let now = Instant::now();

        // Clean up old data
        self.cleanup_old_data(now);

        // Analyze traffic patterns
        let attack_pattern = self.detect_attack_pattern();
        let traffic_load = self.calculate_traffic_load();

        // Update mitigation state
        self.update_mitigation_state(traffic_load, attack_pattern);

        // Adapt limits if enabled
        if self.config.enable_adaptive_limits {
            self.adapt_rate_limits(traffic_load);
        }

        Ok(())
    }

    /// Detect attack patterns in traffic
    fn detect_attack_pattern(&self) -> AttackPattern {
        let recent_samples: Vec<_> = self.traffic_samples.iter()
            .filter(|s| s.timestamp.elapsed() < self.config.analysis_window)
            .collect();

        if recent_samples.is_empty() {
            return AttackPattern::Unknown;
        }

        let request_rate = recent_samples.len() as f64 / self.config.analysis_window.as_secs_f64();
        
        if request_rate > self.config.max_requests_per_second as f64 * 2.0 {
            AttackPattern::HighFrequency
        } else if self.circuit_tracker.len() > self.config.max_circuits_per_ip as usize * 10 {
            AttackPattern::CircuitFlooding
        } else if request_rate > self.config.max_requests_per_second as f64 * 0.5 {
            AttackPattern::LowAndSlow
        } else {
            AttackPattern::Unknown
        }
    }

    /// Calculate current traffic load
    fn calculate_traffic_load(&self) -> f64 {
        let recent_count = self.traffic_samples.iter()
            .filter(|s| s.timestamp.elapsed() < Duration::from_secs(1))
            .count();
        
        recent_count as f64 / self.config.max_requests_per_second as f64
    }

    /// Update mitigation state based on analysis
    fn update_mitigation_state(&mut self, traffic_load: f64, _attack_pattern: AttackPattern) {
        self.current_state = if traffic_load > 2.0 {
            MitigationState::Emergency
        } else if traffic_load > 1.5 {
            MitigationState::UnderAttack
        } else if traffic_load > 1.0 {
            MitigationState::EarlyWarning
        } else {
            MitigationState::Normal
        };
    }

    /// Adapt rate limits based on current conditions
    fn adapt_rate_limits(&mut self, traffic_load: f64) {
        if traffic_load > 1.2 {
            self.adaptive_limit = (self.adaptive_limit as f64 * 0.8) as u32;
        } else if traffic_load < 0.5 {
            self.adaptive_limit = (self.adaptive_limit as f64 * 1.1) as u32;
        }
        
        self.adaptive_limit = self.adaptive_limit
            .max(self.config.max_requests_per_second / 4)
            .min(self.config.max_requests_per_second * 2);
    }

    /// Clean up old tracking data
    fn cleanup_old_data(&mut self, now: Instant) {
        // Remove old traffic samples
        while let Some(sample) = self.traffic_samples.front() {
            if now.duration_since(sample.timestamp) > self.config.analysis_window * 2 {
                self.traffic_samples.pop_front();
            } else {
                break;
            }
        }

        // Remove expired circuits
        self.circuit_tracker.retain(|_, circuit| {
            now.duration_since(circuit.last_activity) < self.config.circuit_timeout
        });

        // Remove old IP tracking data
        self.ip_request_counts.retain(|_, (_, window_start)| {
            now.duration_since(*window_start) < Duration::from_secs(60)
        });
    }

    /// Get current mitigation statistics
    pub fn get_mitigation_stats(&self) -> MitigationStats {
        MitigationStats {
            current_state: self.current_state.clone(),
            active_circuits: self.circuit_tracker.len(),
            tracked_ips: self.ip_request_counts.len(),
            recent_samples: self.traffic_samples.len(),
            adaptive_limit: self.adaptive_limit,
        }
    }
}

/// DDoS mitigation statistics
#[derive(Debug, Clone)]
pub struct MitigationStats {
    pub current_state: MitigationState,
    pub active_circuits: usize,
    pub tracked_ips: usize,
    pub recent_samples: usize,
    pub adaptive_limit: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ddos_mitigation_creation() {
        let config = TorSecurityConfig::default();
        let mitigation = DDoSMitigation::new(&config);
        assert!(mitigation.is_ok());
    }

    #[test]
    fn test_request_recording() {
        let config = TorSecurityConfig::default();
        let mut mitigation = DDoSMitigation::new(&config).unwrap();
        mitigation.initialize().unwrap();

        let result = mitigation.record_request(
            Some("127.0.0.1".parse().unwrap()),
            1024,
            Some("test_circuit".to_string()),
        );
        assert!(result.is_ok());
    }
}
