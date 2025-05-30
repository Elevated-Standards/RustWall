
# Content Security Module

## Content & Application Security

This module provides comprehensive content security features to protect against various web-based attacks and privacy violations.

### Features

- **JavaScript Sanitization** (`js_sanitization.rs`) - Strip or modify JS that could compromise anonymity
- **Image Metadata Removal** (`image_metadata.rs`) - Auto-strip EXIF and other identifying data
- **Referrer Policy Enforcement** (`referrer_policy.rs`) - Prevent referrer leaks between sites
- **Font Fingerprinting Protection** (`font_protection.rs`) - Limit font access to prevent browser fingerprinting

### Module Structure

```
src/content-security/
├── mod.rs                    # Main module with ContentSecurityManager
├── js_sanitization.rs        # JavaScript sanitization and filtering
├── image_metadata.rs         # Image metadata removal (EXIF, etc.)
├── referrer_policy.rs        # Referrer policy enforcement
├── font_protection.rs        # Font fingerprinting protection
└── README.md                # This file
```
