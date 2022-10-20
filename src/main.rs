use std::{path::Path};
use arrayvec::ArrayVec;
use rustop::opts;
use walkdir::WalkDir;
use simple_logger::SimpleLogger;
use yara::*;

const VERSION: &str = "0.2.0-alpha";

const RULES: &str = r#"
    rule test_rule {
      meta:
        score = 60
      strings:
        $rust = "License" nocase
      condition:
        $rust
    }
"#;

#[derive(Debug)]
struct FileMatch {
    message: String,
    score: u8,
}

struct YaraMatch {
    rulename: String,
    score: u8,
}

// initialize the rule files
fn initialize_rules(rules_string: &str) -> Rules {
    let compiler = Compiler::new().unwrap();
    let compiler = compiler
        .add_rules_str(rules_string)
        .expect("Should have parsed rule");
    let compiled_rules = compiler
        .compile_rules()
        .expect("Should have compiled rules");
    return compiled_rules;
}

// scan a file
fn scan_file(rules: &Rules, file: &Path, debug: bool) -> ArrayVec<YaraMatch, 100> {
    let results = rules
    .scan_file(file, 10);
    //println!("{:?}", results);
    let mut yara_matches = ArrayVec::<YaraMatch, 100>::new();
    for _match in results.iter() {
        if _match.len() > 0 {
            if debug { println!("MATCH FOUND: {:?} LEN: {}", _match, _match.len()); };
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

// Welcome message
fn welcome_message() {
    println!("------------------------------------------------------------------------");
    println!("    __   ____  __ ______  ____                                          ");
    println!("    / /  / __ \\/ //_/  _/ / __/______ ____  ___  ___ ____              ");
    println!("   / /__/ /_/ / ,< _/ /  _\\ \\/ __/ _ `/ _ \\/ _ \\/ -_) __/           ");
    println!("  /____/\\____/_/|_/___/ /___/\\__/\\_,_/_//_/_//_/\\__/_/              ");
    println!("                                                                        ");
    println!("  Version {} (Rust)                                            ", VERSION);
    println!("  by Florian Roth 2022                                                  ");
    println!("------------------------------------------------------------------------");                      
}

fn main() {

    // Show welcome message
    welcome_message();

    // Logger
    
    simple_logger::SimpleLogger::new().env().init().unwrap();
    log::warn!("This is an example message.");

    // Parsing command line flags
    let (args, _rest) = opts! {
        synopsis "LOKI YARA and IOC Scanner";
        opt debug:bool, desc:"Show debugging information";
        opt folder:Option<String>, desc:"Folder to scan"; // an optional (positional) parameter
    }.parse_or_exit();

    // Default values
    let mut target_folder: String = '.'.to_string(); 
    if let Some(t_folder) = args.folder {
        target_folder = t_folder;
    }
    
    // Initialize the rules
    let compiled_rules = initialize_rules(RULES);

    // Walk the file system
    for entry in WalkDir::new(target_folder).into_iter().filter_map(|e| e.ok()) {
        // Debug output : show every file that gets scanned
        if args.debug {
            println!("Scanning file {}", entry.path().display());
        }
        // ------------------------------------------------------------
        // Matches (all types)
        let mut sample_matches = ArrayVec::<FileMatch, 100>::new();
        // ------------------------------------------------------------
        // YARA scanning
        let yara_matches = 
            scan_file(&compiled_rules, entry.path(), args.debug);
        for ymatch in yara_matches.iter() {
            if !sample_matches.is_full() {
                let match_message: String = format!("YARA match with rule {}", ymatch.rulename);
                sample_matches.insert(
                    sample_matches.len(), 
                    FileMatch{message: match_message, score: ymatch.score}
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
            log::warn!("File match found FILE: {} SCORE: {} REASONS: {:?}", entry.path().display(), total_score, sample_matches);
        }
    }
}