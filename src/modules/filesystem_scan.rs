use std::fs::File;
use std::{fs};
use std::time::{UNIX_EPOCH};
use arrayvec::ArrayVec;
use filesize::PathExt;
use file_format::FileFormat;
use chrono::offset::Utc;
use chrono::prelude::*;
use sha2::{Sha256, Digest};
use sha1::*;
use memmap::MmapOptions;
use walkdir::WalkDir;
use yara::*;
use regex::Regex;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use users::{get_user_by_uid};

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;

use crate::{ScanConfig, GenMatch, HashIOC, HashType, ExtVars, YaraMatch, FilenameIOC, FilenameIOCType};

const REL_EXTS: &'static [&'static str] = &[".exe", ".dll", ".bat", ".ps1", ".asp", ".aspx", ".jsp", ".jspx", 
    ".php", ".plist", ".sh", ".vbs", ".js", ".dmp"];
const FILE_TYPES: &'static [&'static str] = &[
    "Debian Binary Package",
    "Executable and Linkable Format",
    "Google Chrome Extension",
    "ISO 9660",
    // "Java Class", // buggy .. many other types get detected as Java Class
    "Microsoft Compiled HTML Help",
    "PCAP Dump",
    "PCAP Next Generation Dump",
    "Windows Executable",
    "Windows Shortcut",
    "ZIP",
];  // see https://docs.rs/file-format/latest/file_format/index.html
const ALL_DRIVE_EXCLUDES: &'static [&'static str] = &[
    "/Library/CloudStorage/",
    "/Volumes/",
    "/mnt/",
    "/media/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/tmp/",
    "\\\\",  // UNC paths on Windows
    "C:\\Windows\\System32\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
];

#[derive(Debug)]
struct SampleInfo {
    md5: String,
    sha1: String,
    sha256: String,
    atime: String,
    mtime: String,
    ctime: String,
}

// Scan a given file system path
pub fn scan_path (
    target_folder: String, 
    compiled_rules: &Rules, 
    scan_config: &ScanConfig, 
    hash_iocs: &Vec<HashIOC>, 
    filename_iocs: &Vec<FilenameIOC>) -> () {

    // Walk the file system
    let mut it = WalkDir::new(target_folder).into_iter();
    loop {
        // Error handling
        let entry = match it.next() {
            None => break,
            Some(Err(err)) => {
                log::debug!("Cannot access file system object ERROR: {:?}", err);
                continue;
            },
            Some(Ok(entry)) => entry,
        };
        
        // Skip certain elements
        // Skip all elements that aren't files
        if !entry.path().is_file() { 
            log::trace!("Skipped element that isn't a file ELEMENT: {} TYPE: {:?}", entry.path().display(), entry.path().symlink_metadata());
            continue;
        };
        // Skip certain drives and folders
        let path_str = entry.path().to_str().unwrap();
        let mut should_skip_dir = false;
        for skip_dir_value in ALL_DRIVE_EXCLUDES.iter() {
            if path_str.contains(skip_dir_value) {
                log::trace!("Skipping directory due to exclusion: {} (pattern: {})",
                    path_str, skip_dir_value);
                should_skip_dir = true;
                break;
            }
        }
        if should_skip_dir {
            it.skip_current_dir();
            continue;
        }

        // Check if this is a network file system
        if is_network_filesystem(entry.path()) {
            log::trace!("Skipping network filesystem: {}", path_str);
            it.skip_current_dir();
            continue;
        }

        // Check custom exclusions
        let file_path = entry.path().to_string_lossy().to_string();
        let mut should_skip = false;
        for exclusion_pattern in scan_config.custom_exclusions.iter() {
            match Regex::new(exclusion_pattern) {
                Ok(re) => {
                    if re.is_match(&file_path) {
                        log::trace!("Skipping file due to custom exclusion: {} (pattern: {})",
                            file_path, exclusion_pattern);
                        should_skip = true;
                        break;
                    }
                },
                Err(e) => {
                    log::debug!("Invalid regex in custom exclusion: {} ERROR: {:?}",
                        exclusion_pattern, e);
                }
            }
        }
        if should_skip {
            continue;
        }
        // Skip big files
        let metadata_result = entry.path().symlink_metadata();
        let metadata = match metadata_result {
            Ok(metadata) => metadata,
            Err(e) => { if scan_config.show_access_errors { log::error!("Cannot access file FILE: {:?} ERROR: {:?}", entry.path(), e) }; continue; }
        };
        let realsize_result = entry.path().size_on_disk_fast(&metadata);
        let realsize = match realsize_result {
            Ok(realsize) => realsize,
            Err(e) => { if scan_config.show_access_errors { log::error!("Cannot access file FILE: {:?} ERROR: {:?}", entry.path(), e) }; continue; }
        };
        if realsize > scan_config.max_file_size as u64 { 
            log::trace!("Skipping file due to size FILE: {} SIZE: {} MAX_FILE_SIZE: {}", 
            entry.path().display(), realsize, scan_config.max_file_size);
            continue; 
        }
        // Skip certain file types
        let extension = entry.path().extension().unwrap_or_default().to_str().unwrap();
        let file_format = FileFormat::from_file(entry.path()).unwrap_or_default();
        let file_format_desc = file_format.to_owned().to_string();
        let file_format_extension = file_format.name();

        if !FILE_TYPES.contains(&file_format_desc.as_str()) &&  // Include certain file types
            !REL_EXTS.contains(&extension) &&  // Include extensions that are in the relevant extensions list 
            !scan_config.scan_all_types  // Scan all types if user enforced it via command line flag
            { 
                log::trace!("Skipping file due to extension or type FILE: {} EXT: {:?} TYPE: {:?}", 
                entry.path().display(), extension, file_format_desc);
                continue; 
            };

        // Debug output : show every file that gets scanned
        log::debug!("Scanning file {} TYPE: {:?}", entry.path().display(), file_format_desc);
        
        // ------------------------------------------------------------
        // VARS
        // Matches (all types)
        let mut sample_matches = ArrayVec::<GenMatch, 100>::new();

        // TIME STAMPS
        let metadata = fs::metadata(entry.path()).unwrap();
        let ts_m_result = &metadata.modified();
        let ts_a_result = &metadata.accessed();
        let ts_c_result = &metadata.created();
        let msecs = match ts_m_result {
            Ok(nsecs) => nsecs.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            Err(_) => 0u64,
        };
        let asecs = match ts_a_result {
            Ok(nsecs) => nsecs.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            Err(_) => 0u64,
        };
        let csecs = match ts_c_result {
            Ok(nsecs) => nsecs.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            Err(_) => 0u64,
        };
        let mtime = Utc.timestamp(msecs as i64, 0);
        let atime = Utc.timestamp(asecs as i64, 0);
        let ctime = Utc.timestamp(csecs as i64, 0);

        // ------------------------------------------------------------
        // READ FILE
        // Read file to data blob
        let result = fs::File::open(&entry.path());
        let file_handle = match &result {
            Ok(data) => data,
            Err(e) => { 
                if scan_config.show_access_errors { log::error!("Cannot access file FILE: {:?} ERROR: {:?}", entry.path(), e); }
                else { log::debug!("Cannot access file FILE: {:?} ERROR: {:?}", entry.path(), e); }
                continue; // skip the rest of the analysis 
            }
        };
        let mmap = unsafe { MmapOptions::new().map(&file_handle).unwrap() };

        // ------------------------------------------------------------
        // IOC Matching

        // Filename Matching
        let filename = entry.path().file_name().unwrap().to_string_lossy().to_string();
        let filepath = entry.path().to_string_lossy().to_string();

        for filename_ioc in filename_iocs.iter() {
            let is_match = match filename_ioc.ioc_type {
                FilenameIOCType::String => {
                    // Simple string matching (case-insensitive)
                    filename.to_lowercase().contains(&filename_ioc.pattern) ||
                    filepath.to_lowercase().contains(&filename_ioc.pattern)
                },
                FilenameIOCType::Regex => {
                    // Regex matching
                    match Regex::new(&filename_ioc.pattern) {
                        Ok(re) => {
                            re.is_match(&filename) || re.is_match(&filepath)
                        },
                        Err(e) => {
                            log::debug!("Invalid regex pattern in filename IOC: {} ERROR: {:?}",
                                filename_ioc.pattern, e);
                            false
                        }
                    }
                }
            };

            if is_match && !sample_matches.is_full() {
                let match_message = format!("FILENAME IOC match: {} (Pattern: {} - {})",
                    filepath, filename_ioc.pattern, filename_ioc.description);
                sample_matches.insert(
                    sample_matches.len(),
                    GenMatch {
                        message: match_message,
                        score: filename_ioc.score,
                    }
                );
            }
        }

        // Hash Matching
        // Generate hashes
        let md5_value = format!("{:x}", md5::compute(&mmap));
        let sha1_hash_array = Sha1::new()
            .chain_update(&mmap)
            .finalize();
        let sha256_hash_array = Sha256::new()
            .chain_update(&mmap)
            .finalize();
        let sha1_value = hex::encode(&sha1_hash_array);
        let sha256_value = hex::encode(&sha256_hash_array);
        //let md5_hash = hex::encode(&md5_hash_array);
        log::trace!("Hashes of FILE: {:?} SHA256: {} SHA1: {} MD5: {}", entry.path(), sha256_value, sha1_value, md5_value);
        // Compare hashes with hash IOCs
        let mut hash_match: bool = false;
        for hash_ioc in hash_iocs.iter() {
            if !sample_matches.is_full() {
                match hash_ioc.hash_type {
                    HashType::Md5 => { if hash_ioc.hash_value == md5_value { hash_match = true; }}, 
                    HashType::Sha1 => { if hash_ioc.hash_value == sha1_value { hash_match = true; }}, 
                    HashType::Sha256 => { if hash_ioc.hash_value == sha256_value { hash_match = true; }}, 
                    _ => {},
                }
            }
            // Hash Match
            if hash_match {
                let match_message: String = format!("HASH match with IOC HASH: {} DESC: {}", hash_ioc.hash_value, hash_ioc.description);
                sample_matches.insert(
                    sample_matches.len(), 
                    GenMatch{message: match_message, score: hash_ioc.score}
                );
            }
        }
        
        // ------------------------------------------------------------
        // SAMPLE INFO 
        let sample_info = SampleInfo {
            md5: md5_value,
            sha1: sha1_value,
            sha256: sha256_value,
            atime: atime.to_rfc3339(),
            mtime: mtime.to_rfc3339(),
            ctime: ctime.to_rfc3339(),
        };

        // ------------------------------------------------------------
        // YARA scanning
        // Preparing the external variables
        let ext_vars = ExtVars{
            filename: entry.path().file_name().unwrap().to_string_lossy().to_string(),
            filepath: entry.path().parent().unwrap().to_string_lossy().to_string(),
            extension: extension.to_string(),
            filetype: file_format_extension.to_ascii_uppercase(),
            owner: get_file_owner(entry.path()),
        };
        log::trace!("Passing external variables to the scan EXT_VARS: {:?}", ext_vars);
        // Actual scanning and result analysis
        let yara_matches = 
            scan_file(&compiled_rules, &file_handle, scan_config, &ext_vars);
        for ymatch in yara_matches.iter() {
            if !sample_matches.is_full() {
                let match_message: String = format!("YARA match with rule {}", ymatch.rulename);
                sample_matches.insert(
                    sample_matches.len(), 
                    GenMatch{message: match_message, score: ymatch.score}
                );
            }
        }
        // Scan Results
        if sample_matches.len() > 0 {
            // Calculate a total score
            let mut total_score: i16 = 0; 
            for sm in sample_matches.iter() {
                total_score += sm.score;
            }
            // Print line
            // Print all matches with detailed information
            log::warn!("File match found FILE: {} {:?} SCORE: {} REASONS: {:?}", 
                entry.path().display(), 
                sample_info, 
                total_score, 
                sample_matches);
        }
    }
}

// scan a file
fn scan_file(rules: &Rules, file_handle: &File, scan_config: &ScanConfig, ext_vars: &ExtVars) -> ArrayVec<YaraMatch, 100> {
    // Preparing the external variables
    // Preparing the scanner
    let mut scanner = rules.scanner().unwrap();
    scanner.set_timeout(10);
    scanner.define_variable("filename", ext_vars.filename.as_str()).unwrap();
    scanner.define_variable("filepath", ext_vars.filepath.as_str()).unwrap();
    scanner.define_variable("extension", ext_vars.extension.as_str()).unwrap();
    scanner.define_variable("filetype", ext_vars.filetype.as_str()).unwrap();
    scanner.define_variable("owner", ext_vars.owner.as_str()).unwrap();
    // Scan file
    let results = scanner.scan_fd(file_handle);
    match &results {
        Ok(_) => {},
        Err(e) => { 
            if scan_config.show_access_errors { log::error!("Cannot access file descriptor ERROR: {:?}", e); }
        }
    }
    //println!("{:?}", results);
    let mut yara_matches = ArrayVec::<YaraMatch, 100>::new();
    for _match in results.iter() {
        if _match.len() > 0 {
            log::debug!("MATCH FOUND: {:?} LEN: {}", _match, _match.len());
            if !yara_matches.is_full() {
                // Try to extract score from YARA rule metadata
                let score = extract_yara_score(&_match[0]).unwrap_or(60);
                yara_matches.insert(
                    yara_matches.len(),
                    YaraMatch{rulename: _match[0].identifier.to_string(), score: score}
                );
            }
        }
    }
    return yara_matches;
}

// Get file owner information
fn get_file_owner(path: &std::path::Path) -> String {
    #[cfg(unix)]
    {
        match fs::metadata(path) {
            Ok(metadata) => {
                let uid = metadata.uid();
                match get_user_by_uid(uid) {
                    Some(user) => user.name().to_string_lossy().to_string(),
                    None => uid.to_string(),
                }
            },
            Err(_) => "unknown".to_string(),
        }
    }

    #[cfg(windows)]
    {
        // On Windows, try to get file owner using Windows API
        get_windows_file_owner(path).unwrap_or_else(|| "unknown".to_string())
    }
}

// Extract score from YARA rule metadata
fn extract_yara_score(yara_match: &yara::Match) -> Option<i16> {
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

// Check if a path is on a network filesystem
fn is_network_filesystem(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        // On Unix systems, check if the filesystem type indicates a network mount
        // This is a simplified check - in practice, you might want to parse /proc/mounts
        let path_str = path.to_string_lossy();

        // Common network filesystem indicators
        if path_str.starts_with("/nfs/") ||
           path_str.starts_with("/cifs/") ||
           path_str.starts_with("/smb/") ||
           path_str.contains("/.gvfs/") ||
           path_str.contains("/.fuse/") {
            return true;
        }

        // Check for common cloud storage paths
        if path_str.contains("Dropbox") ||
           path_str.contains("OneDrive") ||
           path_str.contains("Google Drive") ||
           path_str.contains("iCloud") {
            return true;
        }
    }

    #[cfg(windows)]
    {
        // On Windows, check for UNC paths and mapped network drives
        let path_str = path.to_string_lossy();
        if path_str.starts_with("\\\\") {
            return true;
        }

        // Check for common cloud storage paths on Windows
        if path_str.contains("OneDrive") ||
           path_str.contains("Dropbox") ||
           path_str.contains("Google Drive") ||
           path_str.contains("iCloudDrive") {
            return true;
        }
    }

    false
}

#[cfg(windows)]
fn get_windows_file_owner(path: &std::path::Path) -> Option<String> {
    // Simplified Windows file owner detection
    // In a production environment, you would use the Windows Security API
    // to get the actual owner SID and convert it to a username

    // For now, return a placeholder indicating Windows file owner detection
    // would require more complex Windows API calls
    Some("Windows User".to_string())
}
