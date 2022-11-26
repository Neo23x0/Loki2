use std::process;
use arrayvec::ArrayVec;
use yara::*;

use crate::{ScanConfig, GenMatch};

// Scan process memory of all processes
pub fn scan_processes(compiled_rules: &Rules, scan_config: &ScanConfig) ->() {
    // Refresh the process information
    let proc_result_list = psutil::process::processes();
    // Process list query errors
    if let Err(e) = proc_result_list {
        log::error!("Cannot get process list! ERROR: {:?}", e); 
        return;
    // Otherwise process the list
    } else {
        for proc_result in proc_result_list.unwrap().iter().rev() {
            // Get LOKI's own process
            let own_pid = process::id();
            let pid: u32;
            let mut proc_name: String = "[N/A)]".to_string();
            // Check process result
            match proc_result.as_ref() {
                Ok(r) => {
                    // Get the variables
                    pid = r.pid(); 
                    let proc_name_result = r.name();
                    match proc_name_result {
                        Ok(rn) => { proc_name = rn },
                        Err(_) => {}
                    }
                }, 
                Err(e) => { 
                    if scan_config.show_access_errors { log::error!("Process access error ERROR: {:?}", e); }
                    continue;
                }
            }
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
            // TODO: better scan error handling (debug messages)
            for ymatch in yara_matches.unwrap_or_default().iter() {
                if !proc_matches.is_full() {
                    let match_message: String = format!("YARA match with rule {:?}", ymatch.identifier);
                    //println!("{}", match_message);
                    proc_matches.insert(
                        proc_matches.len(), 
                        // TODO: get score from meta data in a safe way
                        GenMatch{message: match_message, score: 75}
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
}
