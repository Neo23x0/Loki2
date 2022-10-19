use std::path::Path;
use rustop::opts;
use walkdir::WalkDir;
use yara::*;

const RULES: &str = r#"
    rule test_rule {
      strings:
        $rust = "License" nocase
      condition:
        $rust
    }
"#;

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
fn scan_file(rules: &Rules, file: &Path) { //-> Vec<yara::Rule<'_>> {
    let results = rules
    .scan_file(file, 10);
    //println!("{:?}", results);
    for _match in results.iter() {
        if _match.len() > 0 {
            println!("MATCH FOUND: {:?}", _match);
        }
    }
    // return results;
}

// Welcome message
fn welcome_message() {
    println!("------------------------------------------------------------------------");
    println!("    __   ____  __ ______  ____                                          ");
    println!("    / /  / __ \\/ //_/  _/ / __/______ ____  ___  ___ ____              ");
    println!("   / /__/ /_/ / ,< _/ /  _\\ \\/ __/ _ `/ _ \\/ _ \\/ -_) __/           ");
    println!("  /____/\\____/_/|_/___/ /___/\\__/\\_,_/_//_/_//_/\\__/_/              ");
    println!("                                                                        ");
    println!("  Version 2.0.0 alpha (Rust)                                            ");
    println!("  by Florian Roth 2022                                                  ");
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

    // Default values
    let mut target_folder: String = '.'.to_string(); 
    if let Some(t_folder) = args.folder {
        target_folder = t_folder;
    }
    
    // Initialize the rules
    let compiled_rules = initialize_rules(RULES);

    // Walk the file system
    for entry in WalkDir::new(target_folder).into_iter().filter_map(|e| e.ok()) {
        if args.debug {
            println!("Scanning file {}", entry.path().display());
        }
        scan_file(&compiled_rules, entry.path());
    }
}