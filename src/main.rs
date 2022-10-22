use std::env;
use std::str;
use std::fs;
use std::{path::Path};
use rustop::opts;
use filesize::PathExt;
use flexi_logger::*;
use file_format::FileFormat;
use sysinfo::CpuExt;
use sysinfo::PidExt;
use sysinfo::{ProcessExt, System, SystemExt, Disk, DiskExt};
use arrayvec::ArrayVec;
use walkdir::WalkDir;
use human_bytes::human_bytes;
use yara::*;

// Specific TODOs
// - skipping non-local file systems like network mounts or cloudfs drives

// General TODOs
// - better error handling
// - putting all modules in an array and looping over that list instead of a fixed sequence
// - restructuring project to multiple files

const VERSION: &str = "2.0.0-alpha";

const REL_EXTS: &'static [&'static str] = &[".exe", ".dll", ".bat", ".ps1", ".asp", ".aspx", ".jsp", ".jspx", 
    ".php", ".plist", ".sh", ".vbs", ".js", ".dmp"];
const MODULES: &'static [&'static str] = &["FileScan", "ProcessCheck"];
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

#[derive(Debug)]
struct GenMatch {
    message: String,
    score: u8,
}

struct YaraMatch {
    rulename: String,
    score: u8,
}

struct ScanConfig {
    max_file_size: usize,
    show_access_errors: bool,
    scan_all_types: bool,
}

#[derive(Debug)]
struct ExtVars {
    filename: String,
    filepath: String,
    filetype: String,
    extension: String,
    owner: String,
}

// Initialize the rule files
fn initialize_rules() -> Rules {
    // Composed YARA rule set 
    // we're concatenating all rules from all rule files to a single string and 
    // compile them all together into a single big rule set for performance purposes
    let mut all_rules = String::new();
    let mut count = 0u16;
    // Reading the signature folder
    let files = fs::read_dir("./signatures/yara").unwrap();
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

// Scan process memory of all processes
fn scan_processes(compiled_rules: &Rules, scan_config: &ScanConfig) ->() {
    // Refresh the process information
    let mut sys = System::new_all();
    sys.refresh_all();
    for (pid, process) in sys.processes() {
        // Debug output : show every file that gets scanned
        log::debug!("Scanning process PID: {} NAME: {}", pid, process.name());
        // ------------------------------------------------------------
        // Matches (all types)
        let mut proc_matches = ArrayVec::<GenMatch, 100>::new();
        // ------------------------------------------------------------
        // YARA scanning
        let yara_matches = 
            compiled_rules.scan_process(pid.as_u32(), 30);
        log::debug!("Scan result: {:?}", yara_matches);
        match &yara_matches {
            Ok(_) => {},
            Err(e) => {
                if scan_config.show_access_errors { log::error!("Error while scanning process memory PROCESS: {} ERROR: {:?}", process.name(), e); }
                else { log::debug!("Error while scanning process memory PROCESS: {} ERROR: {:?}", process.name(), e); }
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

        if proc_matches.len() > 0 {
            log::warn!("Process with matches found PID: {} PROCESS: {} REASONS: {:?}", 
            pid, process.name(), proc_matches);
        }
    }
}

// Scan a given file system path
fn scan_path (target_folder: String, compiled_rules: &Rules, scan_config: &ScanConfig) -> () {
    // Walk the file system
    for entry in WalkDir::new(target_folder).into_iter().filter_map(|e| e.ok()) {
        
        // Skip certain elements
        // Skip all elements that aren't files
        if !entry.path().is_file() { 
            log::trace!("Skipped element that isn't a file ELEMENT: {} TYPE: {:?}", entry.path().display(), entry.path().symlink_metadata());
            continue;
        };
        // Skip big files
        let metadata = entry.path().symlink_metadata().unwrap();
        let realsize = entry.path().size_on_disk_fast(&metadata).unwrap();
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
        // Matches (all types)
        let mut sample_matches = ArrayVec::<GenMatch, 100>::new();
        
        // ------------------------------------------------------------
        // YARA scanning
        // Preparing the external variables
        let ext_vars = ExtVars{
            filename: entry.path().file_name().unwrap().to_string_lossy().to_string(),
            filepath: entry.path().parent().unwrap().to_string_lossy().to_string(),
            extension: extension.to_string(),
            filetype: file_format_extension.to_ascii_uppercase(),
            owner: "".to_string(),  // TODO
        };
        log::trace!("Passing external variables to the scan EXT_VARS: {:?}", ext_vars);
        // Actual scanning and result analysis
        let yara_matches = 
            scan_file(&compiled_rules, entry.path(), scan_config, &ext_vars);
        for ymatch in yara_matches.iter() {
            if !sample_matches.is_full() {
                let match_message: String = format!("YARA match with rule {}", ymatch.rulename);
                sample_matches.insert(
                    sample_matches.len(), 
                    // TODO: get meta data in a safe way from Vec structure
                    GenMatch{message: match_message, score: ymatch.score}
                );
            }
        }
        // Scan Results
        if sample_matches.len() > 0 {
            // Calculate a total score
            let mut total_score: u8 = 0; 
            for sm in sample_matches.iter() {
                total_score += sm.score;
            }
            // Print line
            // TODO: print all matches in a nested form
            log::warn!("File match found FILE: {} SCORE: {} REASONS: {:?}", entry.path().display(), total_score, sample_matches);
        }
    }
}

// scan a file
fn scan_file(rules: &Rules, file: &Path, scan_config: &ScanConfig, ext_vars: &ExtVars) -> ArrayVec<YaraMatch, 100> {
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
    let results = scanner.scan_file(file);
    match &results {
        Ok(_) => {},
        Err(e) => { 
            if scan_config.show_access_errors { log::error!("Cannot access file FILE: {:?} ERROR: {:?}", file, e); }
            else { log::debug!("Cannot access file FILE: {:?} ERROR: {:?}", file, e); }
        }
    }
    //println!("{:?}", results);
    let mut yara_matches = ArrayVec::<YaraMatch, 100>::new();
    for _match in results.iter() {
        if _match.len() > 0 {
            log::debug!("MATCH FOUND: {:?} LEN: {}", _match, _match.len());
            if !yara_matches.is_full() {
                yara_matches.insert(
                    yara_matches.len(), 
                    YaraMatch{rulename: _match[0].identifier.to_string(), score: 60}
                );
            }
        }
    }
    return yara_matches;
}

// Evaluate platform & environment information
fn evaluate_env() {
    let mut sys = System::new_all();
    sys.refresh_all();
    // Command line arguments 
    let args: Vec<String> = env::args().collect();
    log::info!("Command line flags FLAGS: {:?}", args);
    // OS
    log::info!("Operating system information OS: {} ARCH: {}", env::consts::OS, env::consts::ARCH);
    // System Names
    log::info!("System information NAME: {:?} KERNEL: {:?} OS_VER: {:?} HOSTNAME: {:?}",
    sys.name().unwrap(), sys.kernel_version().unwrap(), sys.os_version().unwrap(), sys.host_name().unwrap());
    // CPU
    log::info!("CPU information NUM_CORES: {} FREQUENCY: {:?} VENDOR: {:?}", 
    sys.cpus().len(), sys.cpus()[0].frequency(), sys.cpus()[0].vendor_id());
    // Memory
    log::info!("Memory information TOTAL: {:?} USED: {:?}", 
    human_bytes(sys.total_memory() as f64), human_bytes(sys.used_memory() as f64));
    // Hard disks
    for disk in sys.disks() {
        log::info!(
            "Hard disk NAME: {:?} FS_TYPE: {:?} MOUNT_POINT: {:?} AVAIL: {:?} TOTAL: {:?} REMOVABLE: {:?}", 
            disk.name(), 
            str::from_utf8(disk.file_system()).unwrap(), 
            disk.mount_point(), 
            human_bytes(disk.available_space() as f64),
            human_bytes(disk.total_space() as f64),
            disk.is_removable(),
        );
    }
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
        opt debug:bool, desc:"Show debugging information";
        opt trace:bool, desc:"Show very verbose trace output";
        opt noprocs:bool, desc:"Don't scan processes";
        opt nofs:bool, desc:"Don't scan the file system";
        opt folder:Option<String>, desc:"Folder to scan"; // an optional (positional) parameter
    }.parse_or_exit();
    // Create a config
    let scan_config = ScanConfig {
        max_file_size: args.max_file_size,
        show_access_errors: args.show_access_errors,
        scan_all_types: args.scan_all_files,
    };

    // Logger
    let mut log_level: String = "info".to_string(); let mut std_out = Duplicate::Info; // default
    if args.debug { log_level = "debug".to_string(); std_out = Duplicate::Debug; }  // set to debug level
    if args.trace { log_level = "trace".to_string(); std_out = Duplicate::Trace; }  // set to trace level
    let mut sys = System::new_all();
    sys.refresh_all();
    let log_file_name = format!("loki_{}", sys.host_name().unwrap());
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

    // Evaluate active modules
    let mut active_modules: ArrayVec<String, 20> = ArrayVec::<String, 20>::new();
    for module in MODULES {
        if args.noprocs && module.to_string() == "ProcessCheck" { continue; }
        if args.nofs && module.to_string() == "FileScan" { continue; }
        active_modules.insert(active_modules.len(), module.to_string());
    }
    log::info!("Active modules MODULES: {:?}", active_modules);

    // Set some default values
    // default target folder
    let mut target_folder: String = '/'.to_string(); 
    if env::consts::OS.to_string() == "windows" { target_folder = "C:\\".to_string(); }
    // if target folder has ben set via command line flag
    if let Some(args_target_folder) = args.folder {
        target_folder = args_target_folder;
    }
    
    // Initialize the rules
    log::info!("Initializing YARA rules ...");
    let compiled_rules = initialize_rules();

    // Process scan
    if active_modules.contains(&"ProcessCheck".to_owned()) {
        log::info!("Scanning running processes ... ");
        scan_processes(&compiled_rules, &scan_config);
    }

    // File system scan
    if active_modules.contains(&"FileScan".to_owned()) {
        log::info!("Scanning local file system ... ");
        scan_path(target_folder, &compiled_rules, &scan_config);
    }

    // Finished scan
    log::info!("LOKI scan finished");
}