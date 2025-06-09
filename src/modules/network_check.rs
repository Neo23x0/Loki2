use std::process::Command;
use std::collections::HashSet;
use arrayvec::ArrayVec;
use regex::Regex;

use crate::{ScanConfig, GenMatch, C2IOC, C2IOCType};

// Scan network connections for C2 IOCs
pub fn scan_network_connections(c2_iocs: &Vec<C2IOC>, scan_config: &ScanConfig) -> () {
    if c2_iocs.is_empty() {
        log::debug!("No C2 IOCs loaded, skipping network connection scan");
        return;
    }

    log::debug!("Starting network connection scan with {} C2 IOCs", c2_iocs.len());
    
    // Get network connections based on OS
    let connections = get_network_connections();
    
    if connections.is_empty() {
        log::debug!("No network connections found or unable to retrieve connections");
        return;
    }

    log::debug!("Found {} network connections to analyze", connections.len());

    // Check each connection against C2 IOCs
    for connection in connections.iter() {
        let mut connection_matches = ArrayVec::<GenMatch, 100>::new();
        
        for c2_ioc in c2_iocs.iter() {
            let is_match = match c2_ioc.ioc_type {
                C2IOCType::IP => {
                    // Direct string comparison for IP addresses
                    connection.contains(&c2_ioc.pattern)
                },
                C2IOCType::FQDN => {
                    // For FQDNs, check if the connection contains the domain
                    // This handles both exact matches and subdomain matches
                    connection.to_lowercase().contains(&c2_ioc.pattern.to_lowercase())
                }
            };

            if is_match {
                let match_message = format!("C2 IOC match in network connection: {} (IOC: {} - {})", 
                    connection, c2_ioc.pattern, c2_ioc.description);
                
                if !connection_matches.is_full() {
                    connection_matches.insert(
                        connection_matches.len(),
                        GenMatch {
                            message: match_message,
                            score: c2_ioc.score,
                        }
                    );
                }
            }
        }

        // Report matches
        if connection_matches.len() > 0 {
            let mut total_score: i16 = 0;
            for cm in connection_matches.iter() {
                total_score += cm.score;
            }
            
            log::warn!("Suspicious network connection found: {} SCORE: {} REASONS: {:?}", 
                connection, total_score, connection_matches);
        }
    }
}

// Get network connections based on the operating system
fn get_network_connections() -> Vec<String> {
    let mut connections = Vec::new();
    
    // Try different methods based on OS
    if cfg!(target_os = "windows") {
        connections.extend(get_windows_connections());
    } else if cfg!(target_os = "linux") {
        connections.extend(get_linux_connections());
    } else if cfg!(target_os = "macos") {
        connections.extend(get_macos_connections());
    }
    
    // Remove duplicates
    let unique_connections: HashSet<String> = connections.into_iter().collect();
    unique_connections.into_iter().collect()
}

// Get network connections on Windows using netstat
fn get_windows_connections() -> Vec<String> {
    let mut connections = Vec::new();
    
    match Command::new("netstat").args(&["-an"]).output() {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            connections.extend(parse_netstat_output(&output_str));
        },
        Err(e) => {
            log::debug!("Failed to run netstat on Windows: {:?}", e);
        }
    }
    
    connections
}

// Get network connections on Linux using netstat and ss
fn get_linux_connections() -> Vec<String> {
    let mut connections = Vec::new();
    
    // Try netstat first
    match Command::new("netstat").args(&["-tuln"]).output() {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            connections.extend(parse_netstat_output(&output_str));
        },
        Err(_) => {
            log::debug!("netstat not available, trying ss");
        }
    }
    
    // Try ss as fallback
    if connections.is_empty() {
        match Command::new("ss").args(&["-tuln"]).output() {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                connections.extend(parse_ss_output(&output_str));
            },
            Err(e) => {
                log::debug!("Failed to run ss on Linux: {:?}", e);
            }
        }
    }
    
    connections
}

// Get network connections on macOS using netstat
fn get_macos_connections() -> Vec<String> {
    let mut connections = Vec::new();
    
    match Command::new("netstat").args(&["-an"]).output() {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            connections.extend(parse_netstat_output(&output_str));
        },
        Err(e) => {
            log::debug!("Failed to run netstat on macOS: {:?}", e);
        }
    }
    
    connections
}

// Parse netstat output to extract IP addresses and hostnames
fn parse_netstat_output(output: &str) -> Vec<String> {
    let mut connections = Vec::new();
    
    for line in output.lines() {
        // Skip header lines and empty lines
        if line.trim().is_empty() || line.contains("Proto") || line.contains("Active") {
            continue;
        }
        
        // Extract IP addresses from the line
        // This is a simple regex to match IPv4 addresses
        if let Ok(re) = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b") {
            for cap in re.find_iter(line) {
                let ip = cap.as_str();
                // Skip localhost and broadcast addresses
                if !ip.starts_with("127.") && !ip.starts_with("0.") && ip != "255.255.255.255" {
                    connections.push(ip.to_string());
                }
            }
        }
    }
    
    connections
}

// Parse ss output to extract IP addresses
fn parse_ss_output(output: &str) -> Vec<String> {
    let mut connections = Vec::new();
    
    for line in output.lines() {
        // Skip header lines
        if line.contains("Netid") || line.trim().is_empty() {
            continue;
        }
        
        // Extract IP addresses from the line
        if let Ok(re) = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b") {
            for cap in re.find_iter(line) {
                let ip = cap.as_str();
                // Skip localhost and broadcast addresses
                if !ip.starts_with("127.") && !ip.starts_with("0.") && ip != "255.255.255.255" {
                    connections.push(ip.to_string());
                }
            }
        }
    }
    
    connections
}
