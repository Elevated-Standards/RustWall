//! Circuit Analysis
//! 
//! Monitor and analyze Tor circuit patterns for anomalies and security threats.
//! Detects suspicious circuit behavior, timing attacks, and circuit correlation attempts.

use crate::tor::{TorSecurityConfig, TorSecurityResult};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Circuit state tracking
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Building,
    Built,
    Active,
    Closing,
    Closed,
    Failed,
}

/// Circuit anomaly types
#[derive(Debug, Clone)]
pub enum CircuitAnomaly {
    RapidRebuild,
    UnusualTiming,
    SuspiciousPath,
    CorrelationAttempt,
    ExcessiveConnections,
    AbnormalTraffic,
}

/// Circuit path information
#[derive(Debug, Clone)]
pub struct CircuitPath {
    pub guard_node: Option<String>,
    pub middle_node: Option<String>,
    pub exit_node: Option<String>,
    pub path_length: u8,
}

/// Circuit metrics for analysis
#[derive(Debug, Clone)]
pub struct CircuitMetrics {
    pub build_time: Duration,
    pub lifetime: Duration,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub request_count: u32,
    pub average_response_time: Duration,
}

/// Circuit information
#[derive(Debug, Clone)]
pub struct CircuitInfo {
    pub circuit_id: String,
    pub state: CircuitState,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub source_ip: Option<IpAddr>,
    pub path: CircuitPath,
    pub metrics: CircuitMetrics,
    pub anomaly_score: f64,
    pub detected_anomalies: Vec<CircuitAnomaly>,
}

/// Circuit analysis configuration
#[derive(Debug, Clone)]
pub struct CircuitAnalysisConfig {
    pub max_circuit_lifetime: Duration,
    pub max_build_time: Duration,
    pub anomaly_threshold: f64,
    pub correlation_window: Duration,
    pub max_circuits_per_source: u32,
    pub enable_path_analysis: bool,
    pub enable_timing_analysis: bool,
}

impl Default for CircuitAnalysisConfig {
    fn default() -> Self {
        Self {
            max_circuit_lifetime: Duration::from_secs(3600), // 1 hour
            max_build_time: Duration::from_secs(30),
            anomaly_threshold: 0.7,
            correlation_window: Duration::from_secs(300), // 5 minutes
            max_circuits_per_source: 10,
            enable_path_analysis: true,
            enable_timing_analysis: true,
        }
    }
}

/// Main circuit analysis system
pub struct CircuitAnalysis {
    config: CircuitAnalysisConfig,
    circuits: HashMap<String, CircuitInfo>,
    circuit_history: VecDeque<CircuitInfo>,
    timing_patterns: HashMap<IpAddr, Vec<Instant>>,
    path_patterns: HashMap<String, u32>,
    last_analysis: Instant,
}

impl CircuitAnalysis {
    /// Create a new circuit analysis instance
    pub fn new(tor_config: &TorSecurityConfig) -> TorSecurityResult<Self> {
        let config = CircuitAnalysisConfig {
            max_circuit_lifetime: Duration::from_secs(3600),
            max_build_time: Duration::from_secs(30),
            anomaly_threshold: 0.7,
            correlation_window: Duration::from_secs(tor_config.rate_limit_window_seconds),
            max_circuits_per_source: tor_config.max_connections_per_circuit,
            enable_path_analysis: true,
            enable_timing_analysis: true,
        };

        Ok(Self {
            config,
            circuits: HashMap::new(),
            circuit_history: VecDeque::new(),
            timing_patterns: HashMap::new(),
            path_patterns: HashMap::new(),
            last_analysis: Instant::now(),
        })
    }

    /// Initialize the circuit analysis system
    pub fn initialize(&mut self) -> TorSecurityResult<()> {
        self.circuits.clear();
        self.circuit_history.clear();
        self.timing_patterns.clear();
        self.path_patterns.clear();
        self.last_analysis = Instant::now();
        println!("Circuit Analysis initialized");
        Ok(())
    }

    /// Shutdown the circuit analysis system
    pub fn shutdown(&mut self) -> TorSecurityResult<()> {
        self.circuits.clear();
        self.circuit_history.clear();
        self.timing_patterns.clear();
        self.path_patterns.clear();
        println!("Circuit Analysis shutdown");
        Ok(())
    }

    /// Register a new circuit for monitoring
    pub fn register_circuit(
        &mut self,
        circuit_id: String,
        source_ip: Option<IpAddr>,
        path: CircuitPath,
    ) -> TorSecurityResult<()> {
        let now = Instant::now();
        
        let circuit_info = CircuitInfo {
            circuit_id: circuit_id.clone(),
            state: CircuitState::Building,
            created_at: now,
            last_activity: now,
            source_ip,
            path: path.clone(),
            metrics: CircuitMetrics {
                build_time: Duration::default(),
                lifetime: Duration::default(),
                bytes_sent: 0,
                bytes_received: 0,
                request_count: 0,
                average_response_time: Duration::default(),
            },
            anomaly_score: 0.0,
            detected_anomalies: Vec::new(),
        };

        // Track timing patterns
        if let Some(ip) = source_ip {
            self.timing_patterns.entry(ip).or_insert_with(Vec::new).push(now);
        }

        // Track path patterns
        let path_key = format!("{:?}", path);
        *self.path_patterns.entry(path_key).or_insert(0) += 1;

        self.circuits.insert(circuit_id, circuit_info);
        Ok(())
    }

    /// Update circuit state
    pub fn update_circuit_state(
        &mut self,
        circuit_id: &str,
        new_state: CircuitState,
    ) -> TorSecurityResult<()> {
        if let Some(circuit) = self.circuits.get_mut(circuit_id) {
            let now = Instant::now();
            
            // Calculate build time when circuit is built
            if new_state == CircuitState::Built && circuit.state == CircuitState::Building {
                circuit.metrics.build_time = now.duration_since(circuit.created_at);
            }
            
            circuit.state = new_state.clone();
            circuit.last_activity = now;
            
            // Move to history if circuit is closed
            if matches!(new_state, CircuitState::Closed | CircuitState::Failed) {
                circuit.metrics.lifetime = now.duration_since(circuit.created_at);
                if let Some(closed_circuit) = self.circuits.remove(circuit_id) {
                    self.circuit_history.push_back(closed_circuit);
                }
            }
        }
        Ok(())
    }

    /// Record circuit activity
    pub fn record_activity(
        &mut self,
        circuit_id: &str,
        bytes_sent: u64,
        bytes_received: u64,
        response_time: Duration,
    ) -> TorSecurityResult<()> {
        if let Some(circuit) = self.circuits.get_mut(circuit_id) {
            circuit.last_activity = Instant::now();
            circuit.metrics.bytes_sent += bytes_sent;
            circuit.metrics.bytes_received += bytes_received;
            circuit.metrics.request_count += 1;
            
            // Update average response time
            let total_time = circuit.metrics.average_response_time * (circuit.metrics.request_count - 1) + response_time;
            circuit.metrics.average_response_time = total_time / circuit.metrics.request_count;
        }
        Ok(())
    }

    /// Analyze circuits for anomalies
    pub fn analyze_circuits(&mut self) -> TorSecurityResult<Vec<CircuitAnomaly>> {
        let now = Instant::now();
        let mut detected_anomalies = Vec::new();

        // Skip analysis if too recent
        if now.duration_since(self.last_analysis) < Duration::from_secs(10) {
            return Ok(detected_anomalies);
        }

        // Collect circuit data to avoid borrowing issues
        let mut circuit_anomalies: Vec<(String, Vec<CircuitAnomaly>, f64)> = Vec::new();

        for (circuit_id, circuit) in &self.circuits {
            let mut anomalies = Vec::new();
            let mut anomaly_score = 0.0;

            // Check for rapid rebuild patterns
            if let Some(anomaly) = self.check_rapid_rebuild(circuit) {
                anomalies.push(anomaly);
                anomaly_score += 0.3;
            }

            // Check for unusual timing
            if self.config.enable_timing_analysis {
                if let Some(anomaly) = self.check_unusual_timing(circuit) {
                    anomalies.push(anomaly);
                    anomaly_score += 0.2;
                }
            }

            // Check for suspicious paths
            if self.config.enable_path_analysis {
                if let Some(anomaly) = self.check_suspicious_path(circuit) {
                    anomalies.push(anomaly);
                    anomaly_score += 0.25;
                }
            }

            // Check for correlation attempts
            if let Some(anomaly) = self.check_correlation_attempt(circuit) {
                anomalies.push(anomaly);
                anomaly_score += 0.4;
            }

            // Check for excessive connections
            if let Some(anomaly) = self.check_excessive_connections(circuit) {
                anomalies.push(anomaly);
                anomaly_score += 0.3;
            }

            circuit_anomalies.push((circuit_id.clone(), anomalies, anomaly_score));
        }

        // Now update the circuits with the detected anomalies
        for (circuit_id, anomalies, score) in circuit_anomalies {
            if let Some(circuit) = self.circuits.get_mut(&circuit_id) {
                circuit.detected_anomalies = anomalies.clone();
                circuit.anomaly_score = score;
                detected_anomalies.extend(anomalies);
            }
        }

        self.cleanup_old_data(now);
        self.last_analysis = now;
        Ok(detected_anomalies)
    }

    /// Check for rapid circuit rebuild patterns
    fn check_rapid_rebuild(&self, circuit: &CircuitInfo) -> Option<CircuitAnomaly> {
        if let Some(ip) = circuit.source_ip {
            if let Some(timings) = self.timing_patterns.get(&ip) {
                let recent_builds = timings.iter()
                    .filter(|&&t| circuit.created_at.duration_since(t) < Duration::from_secs(60))
                    .count();
                
                if recent_builds > 5 {
                    return Some(CircuitAnomaly::RapidRebuild);
                }
            }
        }
        None
    }

    /// Check for rapid circuit rebuild patterns by circuit ID
    fn check_rapid_rebuild_by_id(&self, circuit_id: &str) -> Option<CircuitAnomaly> {
        if let Some(circuit) = self.circuits.get(circuit_id) {
            self.check_rapid_rebuild(circuit)
        } else {
            None
        }
    }

    /// Check for unusual timing patterns
    fn check_unusual_timing(&self, circuit: &CircuitInfo) -> Option<CircuitAnomaly> {
        if circuit.metrics.build_time > self.config.max_build_time {
            return Some(CircuitAnomaly::UnusualTiming);
        }
        
        if circuit.metrics.average_response_time > Duration::from_millis(10000) {
            return Some(CircuitAnomaly::UnusualTiming);
        }
        
        None
    }

    /// Check for unusual timing patterns by circuit ID
    fn check_unusual_timing_by_id(&self, circuit_id: &str) -> Option<CircuitAnomaly> {
        if let Some(circuit) = self.circuits.get(circuit_id) {
            self.check_unusual_timing(circuit)
        } else {
            None
        }
    }

    /// Check for suspicious circuit paths
    fn check_suspicious_path(&self, circuit: &CircuitInfo) -> Option<CircuitAnomaly> {
        if circuit.path.path_length < 3 {
            return Some(CircuitAnomaly::SuspiciousPath);
        }
        
        // Check for repeated path patterns
        let path_key = format!("{:?}", circuit.path);
        if let Some(&count) = self.path_patterns.get(&path_key) {
            if count > 10 {
                return Some(CircuitAnomaly::SuspiciousPath);
            }
        }
        
        None
    }

    /// Check for suspicious circuit paths by circuit ID
    fn check_suspicious_path_by_id(&self, circuit_id: &str) -> Option<CircuitAnomaly> {
        if let Some(circuit) = self.circuits.get(circuit_id) {
            self.check_suspicious_path(circuit)
        } else {
            None
        }
    }

    /// Check for correlation attempts
    fn check_correlation_attempt(&self, circuit: &CircuitInfo) -> Option<CircuitAnomaly> {
        if let Some(ip) = circuit.source_ip {
            let concurrent_circuits = self.circuits.values()
                .filter(|c| c.source_ip == Some(ip) && c.circuit_id != circuit.circuit_id)
                .count();
            
            if concurrent_circuits > self.config.max_circuits_per_source as usize {
                return Some(CircuitAnomaly::CorrelationAttempt);
            }
        }
        None
    }

    /// Check for correlation attempts by circuit ID
    fn check_correlation_attempt_by_id(&self, circuit_id: &str) -> Option<CircuitAnomaly> {
        if let Some(circuit) = self.circuits.get(circuit_id) {
            self.check_correlation_attempt(circuit)
        } else {
            None
        }
    }

    /// Check for excessive connections
    fn check_excessive_connections(&self, circuit: &CircuitInfo) -> Option<CircuitAnomaly> {
        if circuit.metrics.request_count > 1000 {
            return Some(CircuitAnomaly::ExcessiveConnections);
        }
        
        if circuit.metrics.bytes_sent > 100_000_000 || circuit.metrics.bytes_received > 100_000_000 {
            return Some(CircuitAnomaly::AbnormalTraffic);
        }
        
        None
    }

    /// Check for excessive connections by circuit ID
    fn check_excessive_connections_by_id(&self, circuit_id: &str) -> Option<CircuitAnomaly> {
        if let Some(circuit) = self.circuits.get(circuit_id) {
            self.check_excessive_connections(circuit)
        } else {
            None
        }
    }

    /// Clean up old tracking data
    fn cleanup_old_data(&mut self, now: Instant) {
        // Remove old circuit history
        while let Some(circuit) = self.circuit_history.front() {
            if now.duration_since(circuit.created_at) > Duration::from_secs(3600) {
                self.circuit_history.pop_front();
            } else {
                break;
            }
        }

        // Clean up timing patterns
        for timings in self.timing_patterns.values_mut() {
            timings.retain(|&t| now.duration_since(t) < self.config.correlation_window);
        }
        self.timing_patterns.retain(|_, timings| !timings.is_empty());

        // Clean up expired circuits
        self.circuits.retain(|_, circuit| {
            now.duration_since(circuit.last_activity) < self.config.max_circuit_lifetime
        });
    }

    /// Get circuit analysis statistics
    pub fn get_analysis_stats(&self) -> CircuitAnalysisStats {
        let total_anomalies = self.circuits.values()
            .map(|c| c.detected_anomalies.len())
            .sum();

        let high_risk_circuits = self.circuits.values()
            .filter(|c| c.anomaly_score > self.config.anomaly_threshold)
            .count();

        CircuitAnalysisStats {
            active_circuits: self.circuits.len(),
            historical_circuits: self.circuit_history.len(),
            total_anomalies,
            high_risk_circuits,
            tracked_ips: self.timing_patterns.len(),
        }
    }
}

/// Circuit analysis statistics
#[derive(Debug, Clone)]
pub struct CircuitAnalysisStats {
    pub active_circuits: usize,
    pub historical_circuits: usize,
    pub total_anomalies: usize,
    pub high_risk_circuits: usize,
    pub tracked_ips: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_analysis_creation() {
        let config = TorSecurityConfig::default();
        let analysis = CircuitAnalysis::new(&config);
        assert!(analysis.is_ok());
    }

    #[test]
    fn test_circuit_registration() {
        let config = TorSecurityConfig::default();
        let mut analysis = CircuitAnalysis::new(&config).unwrap();
        analysis.initialize().unwrap();

        let path = CircuitPath {
            guard_node: Some("guard1".to_string()),
            middle_node: Some("middle1".to_string()),
            exit_node: Some("exit1".to_string()),
            path_length: 3,
        };

        let result = analysis.register_circuit(
            "test_circuit".to_string(),
            Some("127.0.0.1".parse().unwrap()),
            path,
        );
        assert!(result.is_ok());
    }
}
