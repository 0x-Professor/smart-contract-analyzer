use std::fs;
use std::path::Path;
use chrono::{DateTime, Utc};

/// Helper function to ensure a directory exists
pub fn ensure_directory_exists(path: &Path) -> crate::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

/// Format bytes to human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    
    if bytes == 0 {
        return "0 B".to_string();
    }
    
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    format!("{:.1} {}", size, UNITS[unit_index])
}

/// Format gas amount to human-readable string with units
pub fn format_gas(gas: u64) -> String {
    if gas >= 1_000_000 {
        format!("{:.2}M gas", gas as f64 / 1_000_000.0)
    } else if gas >= 1_000 {
        format!("{:.2}K gas", gas as f64 / 1_000.0)
    } else {
        format!("{} gas", gas)
    }
}

/// Format ethereum value in wei to human-readable string
pub fn format_ether(wei: u64) -> String {
    const WEI_PER_ETHER: f64 = 1_000_000_000_000_000_000.0;
    
    if wei == 0 {
        return "0 ETH".to_string();
    }
    
    let ether = wei as f64 / WEI_PER_ETHER;
    
    if ether >= 1.0 {
        format!("{:.4} ETH", ether)
    } else if ether >= 0.001 {
        format!("{:.6} ETH", ether)
    } else {
        format!("{} wei", wei)
    }
}

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> crate::Result<Vec<u8>> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    hex::decode(hex).map_err(|e| format!("Failed to decode hex: {}", e).into())
}

/// Convert bytes to hex string with 0x prefix
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Generate a unique timestamp-based filename
pub fn generate_timestamped_filename(prefix: &str, extension: &str) -> String {
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    format!("{}_{}.{}", prefix, timestamp, extension)
}

/// Truncate string to specified length with ellipsis
pub fn truncate_string(s: &str, max_length: usize) -> String {
    if s.len() <= max_length {
        s.to_string()
    } else {
        format!("{}...", &s[..max_length.saturating_sub(3)])
    }
}

/// Extract function selector from function signature
pub fn function_selector(signature: &str) -> String {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(signature.as_bytes());
    let hash = hasher.finalize();
    
    format!("0x{}", hex::encode(&hash[..4]))
}

/// Validate Ethereum address format
pub fn is_valid_ethereum_address(address: &str) -> bool {
    let address = address.strip_prefix("0x").unwrap_or(address);
    address.len() == 40 && address.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate private key format
pub fn is_valid_private_key(private_key: &str) -> bool {
    let key = private_key.strip_prefix("0x").unwrap_or(private_key);
    key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit())
}

/// Calculate percentage between two values
pub fn percentage_change(old_value: u64, new_value: u64) -> f64 {
    if old_value == 0 {
        if new_value == 0 {
            0.0
        } else {
            100.0
        }
    } else {
        ((new_value as f64 - old_value as f64) / old_value as f64) * 100.0
    }
}

/// Get severity color for terminal output
pub fn severity_color(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" => "\x1b[31m",  // Red
        "high" => "\x1b[91m",      // Bright Red
        "medium" => "\x1b[33m",    // Yellow
        "low" => "\x1b[32m",       // Green
        "info" => "\x1b[36m",      // Cyan
        _ => "\x1b[0m",            // Reset
    }
}

/// Reset terminal color
pub const COLOR_RESET: &str = "\x1b[0m";

/// Progress bar helper for long-running operations
pub struct ProgressBar {
    total: u64,
    current: u64,
    width: usize,
}

impl ProgressBar {
    pub fn new(total: u64) -> Self {
        Self {
            total,
            current: 0,
            width: 40,
        }
    }
    
    pub fn update(&mut self, current: u64) {
        self.current = current;
        self.display();
    }
    
    pub fn increment(&mut self) {
        self.current += 1;
        self.display();
    }
    
    fn display(&self) {
        let percentage = if self.total == 0 { 0.0 } else { (self.current as f64 / self.total as f64) * 100.0 };
        let filled = ((percentage / 100.0) * self.width as f64) as usize;
        let empty = self.width - filled;
        
        print!("\r[{}{}] {:.1}% ({}/{})", 
               "█".repeat(filled),
               "░".repeat(empty),
               percentage,
               self.current,
               self.total);
        
        use std::io::{self, Write};
        io::stdout().flush().unwrap();
        
        if self.current >= self.total {
            println!(); // New line when complete
        }
    }
}

/// Timer helper for measuring execution time
pub struct Timer {
    start: DateTime<Utc>,
}

impl Timer {
    pub fn new() -> Self {
        Self {
            start: Utc::now(),
        }
    }
    
    pub fn elapsed(&self) -> chrono::Duration {
        Utc::now() - self.start
    }
    
    pub fn elapsed_ms(&self) -> i64 {
        self.elapsed().num_milliseconds()
    }
    
    pub fn elapsed_string(&self) -> String {
        let duration = self.elapsed();
        let total_seconds = duration.num_seconds();
        
        if total_seconds < 60 {
            format!("{:.2}s", duration.num_milliseconds() as f64 / 1000.0)
        } else {
            let minutes = total_seconds / 60;
            let seconds = total_seconds % 60;
            format!("{}m {}s", minutes, seconds)
        }
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

/// File size helper
pub fn get_file_size(path: &Path) -> crate::Result<u64> {
    let metadata = fs::metadata(path)?;
    Ok(metadata.len())
}

/// Check if file is readable
pub fn is_readable_file(path: &Path) -> bool {
    path.exists() && path.is_file() && fs::metadata(path).is_ok()
}

/// Sanitize filename for safe filesystem operations
pub fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512.0 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
    }

    #[test]
    fn test_format_gas() {
        assert_eq!(format_gas(500), "500 gas");
        assert_eq!(format_gas(1500), "1.50K gas");
        assert_eq!(format_gas(2_500_000), "2.50M gas");
    }

    #[test]
    fn test_hex_conversion() {
        let bytes = vec![0x12, 0x34, 0x56];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "0x123456");
        
        let decoded = hex_to_bytes(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_ethereum_address_validation() {
        assert!(is_valid_ethereum_address("0x1234567890123456789012345678901234567890"));
        assert!(is_valid_ethereum_address("1234567890123456789012345678901234567890"));
        assert!(!is_valid_ethereum_address("0x123456789012345678901234567890123456789")); // Too short
        assert!(!is_valid_ethereum_address("0x123456789012345678901234567890123456789G")); // Invalid hex
    }

    #[test]
    fn test_function_selector() {
        let selector = function_selector("transfer(address,uint256)");
        assert_eq!(selector, "0xa9059cbb");
    }

    #[test]
    fn test_percentage_change() {
        assert_eq!(percentage_change(100, 150), 50.0);
        assert_eq!(percentage_change(100, 50), -50.0);
        assert_eq!(percentage_change(0, 100), 100.0);
        assert_eq!(percentage_change(0, 0), 0.0);
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("hello world", 8), "hello...");
        assert_eq!(truncate_string("hi", 8), "hi");
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("valid-name_123.txt"), "valid-name_123.txt");
        assert_eq!(sanitize_filename("invalid/name:with*chars"), "invalid_name_with_chars");
    }
}
