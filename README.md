# LOKI2
LOKI - Simple IOC and YARA Scanner

# Status

Work in Progress. This version is not ready for use. There's still some work to do for a first release. 

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
  -f, --folder                Folder to scan
  -h, --help                  Show this help message.
```
