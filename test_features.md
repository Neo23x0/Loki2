# Testing the New Loki2 Features

## Overview
This document describes how to test the newly implemented features in Loki2.

## New Features Implemented

### 1. Filename IOC Matching
- **Location**: `src/modules/filesystem_scan.rs`
- **Function**: Matches files against filename patterns (both string and regex)
- **Test file**: `signatures-test/iocs/filename-iocs.txt`

### 2. C2 IOC Support
- **Location**: `src/modules/network_check.rs`
- **Function**: Scans network connections for suspicious IPs and domains
- **Test file**: `signatures-test/iocs/c2-iocs.txt`

### 3. Custom Path Exclusions
- **Location**: `src/modules/filesystem_scan.rs`
- **Function**: Excludes files/paths based on regex patterns
- **Test file**: `signatures-test/exclusions.txt`

### 4. Improved Filename IOC Type Detection
- **Location**: `src/main.rs` - `get_filename_ioc_type()`
- **Function**: Automatically detects if a pattern is a simple string or regex

### 5. File Owner Detection
- **Location**: `src/modules/filesystem_scan.rs` - `get_file_owner()`
- **Function**: Detects file owner (Unix/Linux only)

## Command Line Options Added

- `--nonet`: Disable network connection scanning

## File Structure

```
signatures-test/
├── iocs/
│   ├── hash-iocs.txt      # Hash IOCs (existing, with examples)
│   ├── filename-iocs.txt  # Filename IOCs (new)
│   └── c2-iocs.txt        # C2 IOCs (new)
├── exclusions.txt         # Custom exclusions (new)
└── yara/
    ├── test.yar
    └── faulty.yar
```

## Testing Instructions

1. **Build the project**:
   ```bash
   cargo build
   ```

2. **Test with signature files**:
   ```bash
   # Create symlink to test signatures
   ln -s signatures-test signatures
   
   # Run with all features
   ./target/debug/loki --debug --folder /tmp
   
   # Run without network scanning
   ./target/debug/loki --debug --nonet --folder /tmp
   
   # Run with trace output
   ./target/debug/loki --trace --folder /tmp
   ```

3. **Test specific features**:
   
   **Filename IOC matching**:
   - Create a file named `mimikatz.exe` in `/tmp`
   - Run Loki2 - should detect the suspicious filename
   
   **C2 IOC matching**:
   - Ensure network connections exist
   - Check logs for network connection analysis
   
   **Custom exclusions**:
   - Modify `signatures/exclusions.txt` to exclude certain paths
   - Verify those paths are skipped during scanning

## Expected Output

The scanner should now:
1. Load and report the number of each IOC type
2. Match files against filename patterns
3. Scan network connections for C2 indicators
4. Respect custom exclusion patterns
5. Show file owner information in YARA external variables

## Logging

- Use `--debug` for detailed information
- Use `--trace` for very verbose output
- Check the log file `loki_<hostname>.log` for detailed results
