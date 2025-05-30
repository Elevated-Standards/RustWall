# Network Module

## Tor Network Integration

This module provides comprehensive Tor network integration and advanced networking features for enhanced privacy and security.

### Core Features

- **Automatic Tor Configuration** (`tor_config.rs`) - Auto-configure Tor hidden services
- **Multi-Onion Management** (`multi_onion.rs`) - Host multiple .onion addresses with different security levels
- **Tor Bridge Support** (`bridge_support.rs`) - Integrate with Tor bridges for censorship resistance
- **Circuit Control** (`circuit_control.rs`) - Manage Tor circuits and path selection
- **Onion Load Balancing** (`load_balancing.rs`) - Distribute load across multiple hidden service instances

### Advanced Features

- **Decoy Traffic Generation** (`decoy_traffic.rs`) - Generate fake traffic to mask real usage patterns
- **Multi-Hop Proxying** (`multi_hop_proxy.rs`) - Additional proxy layers beyond Tor for extra security
- **Steganographic Channels** (`steganography.rs`) - Hide data in legitimate-looking traffic

### Module Structure

```
src/network/
├── mod.rs                    # Main module with NetworkManager
├── tor_config.rs             # Automatic Tor configuration
├── multi_onion.rs            # Multi-onion address management
├── bridge_support.rs         # Tor bridge integration
├── circuit_control.rs        # Tor circuit management
├── load_balancing.rs         # Onion service load balancing
├── decoy_traffic.rs          # Decoy traffic generation
├── multi_hop_proxy.rs        # Multi-hop proxy chains
├── steganography.rs          # Steganographic communication
└── README.md                # This file
```
