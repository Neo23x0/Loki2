use std::process;
use arrayvec::ArrayVec;
use yara::*;
use sysinfo::{System, SystemExt, ProcessExt, PidExt};

use crate::{ScanConfig, GenMatch};

// Scan process memory of all processes
pub fn scan_processes(compiled_rules: &Rules, scan_config: &ScanConfig) ->() {
    // Refresh the process information
    let mut sys = System::new_all();
    sys.refresh_all();
    // Loop over processes
    for (pid_res, process_res) in sys.processes() {
        // Get LOKI's own process
        let own_pid = process::id();
        let pid = pid_res.as_u32();
        let pid_disk_usage = process_res.disk_usage();
        let proc_name = process_res.name();
        let proc_cmd = process_res.cmd();
        // Skip some processes
        if pid == own_pid { continue; }  // skip LOKI's own process
        // Debug output : show every file that gets scanned
        log::debug!("Trying to scan process PID: {} PROC_NAME: {}", pid, proc_name);
        // ------------------------------------------------------------
        // Matches (all types)
        let mut proc_matches = ArrayVec::<GenMatch, 100>::new();
        // ------------------------------------------------------------
        // YARA scanning
        let yara_matches = compiled_rules.scan_process(pid, 30);
        log::trace!("YARA Scan result for PID: {} PROC_NAME: {} RESULT: {:?}", pid, proc_name, yara_matches);
        match &yara_matches {
            Ok(_) => {
                log::info!("Successfully scanned PID: {} PROC_NAME: {}", pid, proc_name);
            },
            Err(e) => {
                if scan_config.show_access_errors { log::error!("Error while scanning process memory PROC_NAME: {} ERROR: {:?}", proc_name, e); }
                else { log::debug!("Error while scanning process memory PROC_NAME: {} ERROR: {:?}", proc_name, e); }
            }
        }
        // Process YARA matches with better error handling
        for ymatch in yara_matches.unwrap_or_default().iter() {
            if !proc_matches.is_full() {
                let match_message: String = format!("YARA match with rule {:?}", ymatch.identifier);
                // Try to extract score from YARA rule metadata
                let score = extract_yara_score_process(&ymatch).unwrap_or(75);
                proc_matches.insert(
                    proc_matches.len(),
                    GenMatch{message: match_message, score: score}
                );
            }
        }

        // Show matches on process
        if proc_matches.len() > 0 {
            log::warn!("Process with matches found PID: {} PROC_NAME: {} REASONS: {:?}", 
            pid, proc_name, proc_matches);
        }
    }
}

// Extract score from YARA rule metadata for process matches
fn extract_yara_score_process(yara_match: &yara::Match) -> Option<i16> {
    // Try to find a "score" metadata field in the YARA rule
    for meta in yara_match.metadatas.iter() {
        if meta.identifier == "score" {
            match &meta.value {
                yara::MetadataValue::Integer(score) => {
                    return Some(*score as i16);
                },
                yara::MetadataValue::String(score_str) => {
                    if let Ok(score) = score_str.parse::<i16>() {
                        return Some(score);
                    }
                },
                _ => continue,
            }
        }
    }

    // Try alternative metadata names
    for meta in yara_match.metadatas.iter() {
        if meta.identifier == "severity" || meta.identifier == "weight" {
            match &meta.value {
                yara::MetadataValue::Integer(score) => {
                    return Some(*score as i16);
                },
                yara::MetadataValue::String(score_str) => {
                    if let Ok(score) = score_str.parse::<i16>() {
                        return Some(score);
                    }
                },
                _ => continue,
            }
        }
    }

    None
}
