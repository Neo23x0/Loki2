mod helpers;
mod modules;

use std::fs;
use rustop::opts;
use flexi_logger::*;
use arrayvec::ArrayVec;
use csv::ReaderBuilder;

use yara::*;

use crate::helpers::helpers::{get_hostname, get_os_type, evaluate_env};
use crate::modules::process_check::scan_processes;
use crate::modules::filesystem_scan::scan_path;
use crate::modules::network_check::scan_network_connections;

// Specific TODOs
// - skipping non-local file systems like network mounts or cloudfs drives

// General TODOs
// - better error handling (partially implemented)
// - putting all modules in an array and looping over that list instead of a fixed sequence (implemented)
// - restructuring project to multiple files (implemented)

const VERSION: &str = "2.0.1-alpha";

const SIGNATURE_SOURCE: &str = "./signatures";
const MODULES: &'static [&'static str] = &["FileScan", "ProcessCheck", "NetworkCheck"];

#[derive(Debug)]
pub struct ModuleConfig {
    pub name: String,
    pub enabled: bool,
    pub description: String,
}

impl ModuleConfig {
    fn new(name: &str, description: &str) -> Self {
        ModuleConfig {
            name: name.to_string(),
            enabled: true,
            description: description.to_string(),
        }
    }
}

#[derive(Debug)]
pub struct GenMatch {
    message: String,
    score: i16,
}

pub struct YaraMatch {
    rulename: String,
    score: i16,
}

pub struct ScanConfig {
    max_file_size: usize,
    show_access_errors: bool,
    scan_all_types: bool,
    custom_exclusions: Vec<String>,
}

#[derive(Debug)]
pub struct ExtVars {
    filename: String,
    filepath: String,
    filetype: String,
    extension: String,
    owner: String,
}

#[derive(Debug)]
pub struct HashIOC {
    hash_type: HashType,
    hash_value: String,
    description: String,
    score: i16,
}

#[derive(Debug)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
    Unknown
}

#[derive(Debug)]
pub struct FilenameIOC {
    pattern: String, 
    ioc_type: FilenameIOCType,
    description: String, 
    score: i16,
}

#[derive(Debug)]
pub enum FilenameIOCType {
    String,
    Regex
}

#[derive(Debug)]
pub struct C2IOC {
    pattern: String,
    ioc_type: C2IOCType,
    description: String,
    score: i16,
}

#[derive(Debug)]
pub enum C2IOCType {
    IP,
    FQDN,
}

// Initialize the hash IOCs
// Using Vec instead of ArrayVec to allow unlimited IOC entries
fn initialize_hash_iocs() -> Vec<HashIOC> {
    // Compose the location of the hash IOC file
    let hash_ioc_file = format!("{}/iocs/hash-iocs.txt", SIGNATURE_SOURCE);
    // Read the hash IOC file
    let hash_iocs_string = match fs::read_to_string(&hash_ioc_file) {
        Ok(content) => content,
        Err(e) => {
            log::error!("Unable to read hash IOC file: {} - Error: {}", hash_ioc_file, e);
            log::info!("Continuing without hash IOCs...");
            return Vec::new();
        }
    };
    // Configure the CSV reader
    let mut reader = ReaderBuilder::new()
        .delimiter(b';')
        .flexible(true)
        .from_reader(hash_iocs_string.as_bytes());
    // Vector that holds the hashes
    let mut hash_iocs:Vec<HashIOC> = Vec::new();
    // Read the lines from the CSV file
    for result in reader.records() {
        let record_result = result;
        let record = match record_result {
            Ok(r) => r,
            Err(e) => { log::debug!("Cannot read line in hash IOCs file (which can be okay) ERROR: {:?}", e); continue;}
        };
        // If more than two elements have been found
        if record.len() > 1 {
            // if it's not a comment line
            if !record[0].starts_with("#") {
                // determining hash type
                let hash_type: HashType = get_hash_type(&record[0]);
                log::trace!("Read hash IOC from from HASH: {} DESC: {} TYPE: {:?}", &record[0], &record[1], hash_type);
                hash_iocs.push(
                    HashIOC { 
                        hash_type: hash_type,
                        hash_value: record[0].to_ascii_lowercase(), 
                        description: record[1].to_string(), 
                        score: 100,  // Default score for hash IOCs
                    });
            }
        }
    }
    log::info!("Successfully initialized {} hash values", hash_iocs.len());
    return hash_iocs;
}

// Get the hash type
fn get_hash_type(hash_value: &str) -> HashType {
    let hash_value_length = hash_value.len();
    match hash_value_length {
        32 => HashType::Md5,
        40 => HashType::Sha1,
        64 => HashType::Sha256,
        _ => HashType::Unknown,
    }
} 

// Initialize filename IOCs / patterns
fn initialize_filename_iocs() -> Vec<FilenameIOC> {
    // Compose the location of the hash IOC file
    let filename_ioc_file = format!("{}/iocs/filename-iocs.txt", SIGNATURE_SOURCE);
    // Read the hash IOC file
    let filename_iocs_string = match fs::read_to_string(&filename_ioc_file) {
        Ok(content) => content,
        Err(e) => {
            log::error!("Unable to read filename IOC file: {} - Error: {}", filename_ioc_file, e);
            log::info!("Continuing without filename IOCs...");
            return Vec::new();
        }
    };
    // Vector that holds the hashes
    let mut filename_iocs:Vec<FilenameIOC> = Vec::new();
    // Configure the CSV reader
    let mut reader = ReaderBuilder::new()
        .delimiter(b';')
        .flexible(true)
        .from_reader(filename_iocs_string.as_bytes());
    
    // Preset description 
    let mut description = "N/A".to_string();
    // Read the lines from the CSV file
    for result in reader.records() {
        let record_result = result;
        let record = match record_result {
            Ok(r) => r,
            Err(e) => { log::debug!("Cannot read line in hash IOCs file (which can be okay) ERROR: {:?}", e); continue;}
        };
        // If line couldn't be split up (no separator)
        if record.len() == 1 {
            // If line starts with # ... this is a description
            if record[0].starts_with("# ") {
                description = record[0].strip_prefix("# ").unwrap().to_string();
            }
            else if record[0].starts_with("#") {
                description = record[0].strip_prefix("#").unwrap().to_string();
            }
        }
        // If more than two elements have been found
        if record.len() > 1 {
            // if it's not a comment line
            if !record[0].starts_with("#") {
                // determining hash type
                let filename_ioc_type = get_filename_ioc_type(&record[0]);
                log::trace!("Read filename IOC from from PATTERN: {} TYPE: {:?} SCORE: {}", &record[0], filename_ioc_type, &record[1]);
                filename_iocs.push(
                    FilenameIOC { 
                        pattern: record[0].to_ascii_lowercase(),
                        ioc_type: filename_ioc_type,
                        description: description.clone(), 
                        score: record[1].parse::<i16>().unwrap_or(50),  // Default to 50 if parsing fails
                    });
            }
        }
    }
    log::info!("Successfully initialized {} filename IOC values", filename_iocs.len());

    // Return file name IOCs
    return filename_iocs;
}

fn get_filename_ioc_type(filename_ioc_value: &str) -> FilenameIOCType {
    // Check if the pattern contains regex metacharacters
    let regex_chars = ['*', '?', '[', ']', '(', ')', '{', '}', '^', '$', '|', '+', '\\', '.'];

    for ch in filename_ioc_value.chars() {
        if regex_chars.contains(&ch) {
            return FilenameIOCType::Regex;
        }
    }

    // If no regex metacharacters found, treat as simple string
    return FilenameIOCType::String;
}

// Initialize C2 IOCs (IP addresses and FQDNs)
fn initialize_c2_iocs() -> Vec<C2IOC> {
    // Compose the location of the C2 IOC file
    let c2_ioc_file = format!("{}/iocs/c2-iocs.txt", SIGNATURE_SOURCE);

    // Try to read the C2 IOC file, return empty vector if file doesn't exist
    let c2_iocs_string = match fs::read_to_string(&c2_ioc_file) {
        Ok(content) => content,
        Err(_) => {
            log::debug!("C2 IOC file not found: {}", c2_ioc_file);
            return Vec::new();
        }
    };

    // Configure the CSV reader
    let mut reader = ReaderBuilder::new()
        .delimiter(b';')
        .flexible(true)
        .from_reader(c2_iocs_string.as_bytes());

    // Vector that holds the C2 IOCs
    let mut c2_iocs: Vec<C2IOC> = Vec::new();

    // Preset description
    let mut description = "N/A".to_string();

    // Read the lines from the CSV file
    for result in reader.records() {
        let record_result = result;
        let record = match record_result {
            Ok(r) => r,
            Err(e) => {
                log::debug!("Cannot read line in C2 IOCs file (which can be okay) ERROR: {:?}", e);
                continue;
            }
        };

        // If line couldn't be split up (no separator)
        if record.len() == 1 {
            // If line starts with # ... this is a description
            if record[0].starts_with("# ") {
                description = record[0].strip_prefix("# ").unwrap().to_string();
            } else if record[0].starts_with("#") {
                description = record[0].strip_prefix("#").unwrap().to_string();
            }
        }

        // If more than two elements have been found
        if record.len() > 1 {
            // if it's not a comment line
            if !record[0].starts_with("#") {
                // determining C2 IOC type
                let c2_ioc_type = get_c2_ioc_type(&record[0]);
                log::trace!("Read C2 IOC PATTERN: {} TYPE: {:?} SCORE: {}", &record[0], c2_ioc_type, &record[1]);
                c2_iocs.push(
                    C2IOC {
                        pattern: record[0].to_ascii_lowercase(),
                        ioc_type: c2_ioc_type,
                        description: description.clone(),
                        score: record[1].parse::<i16>().unwrap_or(75),
                    });
            }
        }
    }

    log::info!("Successfully initialized {} C2 IOC values", c2_iocs.len());
    return c2_iocs;
}

fn get_c2_ioc_type(c2_ioc_value: &str) -> C2IOCType {
    // Simple heuristic: if it contains only digits, dots, and colons, it's likely an IP
    // Otherwise, treat as FQDN
    let ip_chars: Vec<char> = c2_ioc_value.chars().collect();
    let is_ip_like = ip_chars.iter().all(|&c| c.is_ascii_digit() || c == '.' || c == ':');

    if is_ip_like && (c2_ioc_value.contains('.') || c2_ioc_value.contains(':')) {
        C2IOCType::IP
    } else {
        C2IOCType::FQDN
    }
}

// Load custom exclusions from file
fn load_custom_exclusions() -> Vec<String> {
    let exclusions_file = format!("{}/exclusions.txt", SIGNATURE_SOURCE);

    match fs::read_to_string(&exclusions_file) {
        Ok(content) => {
            let exclusions: Vec<String> = content
                .lines()
                .filter(|line| !line.trim().is_empty() && !line.starts_with("#"))
                .map(|line| line.trim().to_string())
                .collect();

            log::info!("Loaded {} custom exclusion patterns", exclusions.len());
            exclusions
        },
        Err(_) => {
            log::debug!("Custom exclusions file not found: {}", exclusions_file);
            Vec::new()
        }
    }
}

// Initialize the rule files
fn initialize_yara_rules() -> Rules {
    // Composed YARA rule set 
    // we're concatenating all rules from all rule files to a single string and 
    // compile them all together into a single big rule set for performance purposes
    let mut all_rules = String::new();
    let mut count = 0u16;
    // Reading the signature folder
    let yara_sigs_folder = format!("{}/yara", SIGNATURE_SOURCE);
    let files = fs::read_dir(yara_sigs_folder).unwrap();
    // Filter 
    let filtered_files = files
        .filter_map(Result::ok)
        .filter(|d| if let Some(e) = d.path().extension() { e == "yar" } else { false })
        .into_iter();
    // Test compile each rule
    for file in filtered_files {
        log::debug!("Reading YARA rule file {} ...", file.path().to_str().unwrap());
        // Read the rule file
        let rules_string = fs::read_to_string(file.path()).expect("Unable to read YARA rule file (use --debug for more information)");
        let compiled_file_result = compile_yara_rules(&rules_string);
        match compiled_file_result {
            Ok(_) => { 
                log::debug!("Successfully compiled rule file {:?} - adding it to the big set", file.path().to_str().unwrap());
                // adding content of that file to the whole rules string
                all_rules += &rules_string;
                count += 1;
            },
            Err(e) => {
                log::error!("Cannot compile rule file {:?}. Ignoring file. ERROR: {:?}", file.path().to_str().unwrap(), e)                
            }
        };
    }
    // Compile the full set and return the compiled rules
    let compiled_all_rules = compile_yara_rules(&all_rules)
        .expect("Error parsing the composed rule set");
    log::info!("Successfully compiled {} rule files into a big set", count);
    return compiled_all_rules;
}

// Compile a rule set string and check for errors
fn compile_yara_rules(rules_string: &str) -> Result<Rules, Error> {
    let mut compiler = Compiler::new().unwrap();
    compiler.define_variable("filename", "")?;
    compiler.define_variable("filepath", "")?;
    compiler.define_variable("extension", "")?;
    compiler.define_variable("filetype", "")?;
    compiler.define_variable("owner", "")?;
    // Parse the rules
    let compiler_result = compiler
        .add_rules_str(rules_string);
    // Handle parse errors
    let compiler = match compiler_result {
        Ok(c) => c,
        Err(e) => return Err(Error::from(e)),
    };
    // Compile the rules
    let compiled_rules_result = compiler.compile_rules();
    // Handle compile errors
    let compiled_rules = match compiled_rules_result {
        Ok(r) => r,
        Err(e) => return Err(Error::from(e)),
    };
    // Return the compiled rule set
    return Ok(compiled_rules);
}

// Log file format for files
fn log_file_format(
    write: &mut dyn std::io::Write,
    now: &mut flexi_logger::DeferredNow,
    record: &log::Record,
 ) -> std::io::Result<()> {
    write!(
        write,
        "[{}] {} {}",
        now.format("%Y-%m-%dT%H:%M:%SZ"),
        record.level(),
        &record.args()
    )
}

// Log file format for command line
fn log_cmdline_format(
    w: &mut dyn std::io::Write,
    _now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    let level = record.level();
    write!(
        w,
        "[{}] {}",
        style(level).paint(level.to_string()),
        record.args().to_string()
    )
}

// Welcome message
fn welcome_message() {
    println!("------------------------------------------------------------------------");
    println!("     __   ____  __ ______  ____                                        ");
    println!("    / /  / __ \\/ //_/  _/ / __/______ ____  ___  ___ ____              ");
    println!("   / /__/ /_/ / ,< _/ /  _\\ \\/ __/ _ `/ _ \\/ _ \\/ -_) __/           ");
    println!("  /____/\\____/_/|_/___/ /___/\\__/\\_,_/_//_/_//_/\\__/_/              ");
    println!("  Simple IOC and YARA Scanner                                           ");
    println!(" ");
    println!("  Version {} (Rust)                                            ", VERSION);
    println!("  Florian Roth 2022                                                     ");
    println!(" ");
    println!("------------------------------------------------------------------------");                      
}

fn main() {

    // Show welcome message
    welcome_message();

    // Parsing command line flags
    let (args, _rest) = opts! {
        synopsis "LOKI YARA and IOC Scanner";
        opt max_file_size:usize=10_000_000, desc:"Maximum file size to scan";
        opt show_access_errors:bool, desc:"Show all file and process access errors";
        opt scan_all_files:bool, desc:"Scan all files regardless of their file type / extension";
        opt scan_all_drives:bool, desc:"Scan all drives (including mounted drives, usb drives, cloud drives)";
        opt debug:bool, desc:"Show debugging information";
        opt trace:bool, desc:"Show very verbose trace output";
        opt noprocs:bool, desc:"Don't scan processes";
        opt nofs:bool, desc:"Don't scan the file system";
        opt nonet:bool, desc:"Don't scan network connections";
        opt folder:Option<String>, desc:"Folder to scan"; // an optional (positional) parameter
    }.parse_or_exit();
    // Load custom exclusions from file if it exists
    let custom_exclusions = load_custom_exclusions();

    // Create a config
    let scan_config = ScanConfig {
        max_file_size: args.max_file_size,
        show_access_errors: args.show_access_errors,
        scan_all_types: args.scan_all_files,
        custom_exclusions: custom_exclusions,
    };

    // Logger
    let mut log_level: String = "info".to_string(); let mut std_out = Duplicate::Info; // default
    if args.debug { log_level = "debug".to_string(); std_out = Duplicate::Debug; }  // set to debug level
    if args.trace { log_level = "trace".to_string(); std_out = Duplicate::Trace; }  // set to trace level
    let log_file_name = format!("loki_{}", get_hostname());
    Logger::try_with_str(log_level).unwrap()
        .log_to_file(
            FileSpec::default()
                .basename(log_file_name)
        )
        .use_utc()
        .format(log_cmdline_format)
        .format_for_files(log_file_format)
        .duplicate_to_stdout(std_out)
        .append()
        .start()
        .unwrap();
    log::info!("LOKI scan started VERSION: {}", VERSION);

    // Print platform & environment information
    evaluate_env();

    // Initialize and configure modules
    let mut module_configs = Vec::new();
    module_configs.push(ModuleConfig::new("FileScan", "File system scanning with YARA and IOC matching"));
    module_configs.push(ModuleConfig::new("ProcessCheck", "Process memory scanning with YARA rules"));
    module_configs.push(ModuleConfig::new("NetworkCheck", "Network connection analysis for C2 IOCs"));

    // Apply command line flags to disable modules
    for module in &mut module_configs {
        if args.noprocs && module.name == "ProcessCheck" { module.enabled = false; }
        if args.nofs && module.name == "FileScan" { module.enabled = false; }
        if args.nonet && module.name == "NetworkCheck" { module.enabled = false; }
    }

    let active_modules: Vec<&ModuleConfig> = module_configs.iter().filter(|m| m.enabled).collect();
    log::info!("Active modules: {:?}", active_modules.iter().map(|m| &m.name).collect::<Vec<_>>());

    // Set some default values
    // default target folder
    let mut target_folder: String = '/'.to_string(); 
    if get_os_type() == "windows" { target_folder = "C:\\".to_string(); }
    // if target folder has ben set via command line flag
    if let Some(args_target_folder) = args.folder {
        target_folder = args_target_folder;
    }
    
    // Initialize IOCs
    log::info!("Initialize hash IOCs ...");
    let hash_iocs = initialize_hash_iocs();
    log::info!("Initialize filename IOCs ...");
    let filename_iocs = initialize_filename_iocs();
    log::info!("Initialize C2 IOCs ...");
    let c2_iocs = initialize_c2_iocs();

    // Initialize the YARA rules
    log::info!("Initializing YARA rules ...");
    let compiled_rules = initialize_yara_rules();

    // Execute active modules
    for module in &active_modules {
        match module.name.as_str() {
            "ProcessCheck" => {
                log::info!("Scanning running processes ... ");
                scan_processes(&compiled_rules, &scan_config);
            },
            "FileScan" => {
                log::info!("Scanning local file system ... ");
                scan_path(target_folder.clone(), &compiled_rules, &scan_config, &hash_iocs, &filename_iocs);
            },
            "NetworkCheck" => {
                log::info!("Scanning network connections ... ");
                scan_network_connections(&c2_iocs, &scan_config);
            },
            _ => {
                log::warn!("Unknown module: {}", module.name);
            }
        }
    }

    // Print scan summary
    print_scan_summary(&active_modules, &hash_iocs, &filename_iocs, &c2_iocs);

    // Finished scan
    log::info!("LOKI scan finished");
}

// Print scan summary
fn print_scan_summary(
    active_modules: &Vec<&ModuleConfig>,
    hash_iocs: &Vec<HashIOC>,
    filename_iocs: &Vec<FilenameIOC>,
    c2_iocs: &Vec<C2IOC>
) {
    println!("------------------------------------------------------------------------");
    println!("SCAN SUMMARY");
    println!("------------------------------------------------------------------------");
    println!("Modules executed: {}", active_modules.len());
    for module in active_modules {
        println!("  - {} ({})", module.name, module.description);
    }
    println!();
    println!("IOCs loaded:");
    println!("  - Hash IOCs: {}", hash_iocs.len());
    println!("  - Filename IOCs: {}", filename_iocs.len());
    println!("  - C2 IOCs: {}", c2_iocs.len());
    println!("------------------------------------------------------------------------");
}