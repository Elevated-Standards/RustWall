//! RustWall - Advanced Firewall and Security System
//! 
//! A comprehensive security solution built in Rust, providing firewall capabilities,
//! DDoS protection, CAPTCHA verification, and specialized Tor network security features.

pub mod ddos;
pub mod tor;

pub use tor::{TorSecurityManager, TorSecurityConfig, TorSecurityError, TorSecurityResult};
