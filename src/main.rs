use std::env;
use std::str;
use std::fs;
use std::{path::Path};
use log::Level;
use sysinfo::CpuExt;
use sysinfo::PidExt;
use sysinfo::{ProcessExt, System, SystemExt, Disk, DiskExt};
use arrayvec::ArrayVec;
use rustop::opts;
use walkdir::WalkDir;
use human_bytes::human_bytes;
use yara::*;

const VERSION: &str = "2.0.0-alpha";

#[derive(Debug)]
struct GenMatch {
    message: String,
    score: u8,
}

struct YaraMatch {
    rulename: String,
    score: u8,
}

// initialize the rule files
fn initialize_rules() -> Rules {
    // Composed YARA rule set 
    // we're concatenating all rules from all rule files to a single string and 
    // compile them all together into a single big rule set for performance purposes
    let mut all_rules = String::new();
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
        let rules_string = fs::read_to_string(file.path()).expect("Unable to read YARA rule file (use --debug for more information)");
        let compiled_file = compile_yara_rules(&rules_string);
        log::debug!("Successfully compiled rule file {:?} - adding it to the big set", file.path().to_str().unwrap());
        // adding content of that file to the whole rules string
        all_rules += &rules_string;
    }
    // Compile the full set and return the compiled rules
    let compiled_all_rules = compile_yara_rules(&all_rules);
    return compiled_all_rules;
}

// compile a rule file to check for errors
fn compile_yara_rules(rules_string: &str) -> Rules {
    let compiler = Compiler::new().unwrap();
    let compiler = compiler
        .add_rules_str(rules_string)
        .expect("Should have parsed rule");
    let compiled_rules = compiler
        .compile_rules()
        .expect("Should have compiled rules");
    return compiled_rules;
}

// Scan all process memories
fn scan_processes(compiled_rules: &Rules) ->() {
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
fn scan_path (target_folder: String, compiled_rules: &Rules) -> () {
    // Walk the file system
    for entry in WalkDir::new(target_folder).into_iter().filter_map(|e| e.ok()) {
        // Debug output : show every file that gets scanned
        log::debug!("Scanning file {}", entry.path().display());
        // ------------------------------------------------------------
        // Matches (all types)
        let mut sample_matches = ArrayVec::<GenMatch, 100>::new();
        // ------------------------------------------------------------
        // YARA scanning
        let yara_matches = 
            scan_file(&compiled_rules, entry.path());
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
fn scan_file(rules: &Rules, file: &Path) -> ArrayVec<YaraMatch, 100> {
    let results = rules
    .scan_file(file, 10);
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
        opt debug:bool, desc:"Show debugging information";
        opt folder:Option<String>, desc:"Folder to scan"; // an optional (positional) parameter
    }.parse_or_exit();

    // Logger
    let mut log_level: Level = Level::Info;  // default
    if args.debug { log_level = Level::Debug; }  // set to debug level
    simple_logger::init_with_level(log_level).unwrap();
    log::info!("LOKI scan started VERSION: {}", VERSION);

    // Print platform & environment information
    evaluate_env();

    // Default values
    let mut target_folder: String = '.'.to_string(); 
    if let Some(t_folder) = args.folder {
        target_folder = t_folder;
    }
    
    // Initialize the rules
    log::info!("Initializing YARA rules ...");
    let compiled_rules = initialize_rules();

    // Process scan
    log::info!("Scanning running processes ... ");
    scan_processes(&compiled_rules);

    // File system scan
    log::info!("Scanning local file system ... ");
    scan_path(target_folder, &compiled_rules);

}