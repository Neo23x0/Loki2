# LOKI2
LOKI - Simple IOC and YARA Scanner

## Status

✅ **FEATURE COMPLETE** - This version now has feature parity with the original Python Loki scanner plus additional enhancements. Ready for testing and production use.

### What's already implemented

- System reconnaissance (system and hardware information for the log)
- Logging and formatting of the different log outputs
- File system walk
- File time evaluation (MAC timestamps)
- Exclusions based on file characteristics
- IOC initialization - hash values
- IOC initialization - filename patterns
- IOC initialization - C2 patterns (FQDN, IP)
- IOC matching on files (hashes)
- IOC matching on files (filename patterns)
- C2 IOC matching (network connections)
- YARA rule initialization, syntax checks, and error handling
- YARA scanning of files
- YARA scanning of process memory
- Custom exclusions (regex on file path)
- File owner detection (Unix/Linux)

### What's still to do (Optional Enhancements)

- Complete Windows file owner detection (Windows API integration)
- Enhanced network connection analysis (DNS resolution, process association)
- Release workflows (automatically build and provide as release)
- GUI interface (optional)
- Real-time monitoring capabilities (optional)

# Setup Build Environment

## Requirements

See the files in the folder .github/workflows for steps to setup a build environment for 

- Linux
- macOS

## Providing Signatures 

```bash
git clone https://github.com/Neo23x0/signature-base ../signature-base/
ln -s ../signature-base/ ./signatures
```

## Build

```bash
cargo build
```

## Test Run

```bash
cargo build && ./target/debug/loki --help
```

## Testing

### Quick Test
```bash
# Run comprehensive functionality test
./test_complete_functionality.sh
```

### Manual Testing
```bash
# Create symlink to test signatures
ln -s signatures-test signatures

# Test with debug output
cargo build && ./target/debug/loki --debug --folder /tmp

# Test specific modules
./target/debug/loki --debug --noprocs --folder /tmp  # No process scanning
./target/debug/loki --debug --nonet --folder /tmp    # No network scanning
```

## Usage

```
Usage: loki [OPTIONS]

LOKI YARA and IOC Scanner

Options:
  -m, --max-file-size         Maximum file size to scan (default: 10000000)
  -s, --show-access-errors    Show all file and process access errors
  -c, --scan-all-files        Scan all files regardless of their file type / extension
  -d, --debug                 Show debugging information
  -t, --trace                 Show very verbose trace output
  -n, --noprocs               Don't scan processes
  -o, --nofs                  Don't scan the file system
      --nonet                 Don't scan network connections
  -f, --folder                Folder to scan
  -h, --help                  Show this help message.
```

# Screenshots

LOKI 2 alpha version

![Screenhot of Alpha Version](/screens/screen-alpha.png)
