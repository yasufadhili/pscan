# A Boring TCP Port Scanner

This utility, `pscan`, allows you to scan a target for open TCP ports with customisable options.

## Features

- Fast, concurrent port scanning using Go routines
- Customisable port ranges (single ports or ranges)
- Service identification for common ports
- Banner grabbing for open ports
- Adjustable connection timeout
- Control over concurrency with thread limiting
- Verbose mode for detailed scan information
- Options for scanning common ports or all ports

## Installation

- Windows
- Linux

## Usage

```sh 
pscan [flags]
```

**Flags:**
- `-target` or `-t` (required): Specifies the target host to scan (e.g., `example.com`, `192.168.1.1`).
- `-ports` or `-p` (default: `1-1000`): Defines the port range to scan. Use the format `startPort-endPort` (e.g., `20-1024`).
- `-timeout` (default: `2000`): Sets the connection timeout in milliseconds.
- `-threads` (default: `100`): Specifies the number of concurrent threads to use for scanning.
- `-all` or `-a`: Scans all ports from 1 to 65535. This flag overrides the `-ports` flag.
- `-common`: Scans only common ports (currently 1-1024). This flag overrides the `-ports` flag.
- `-verbose` or `-v`: Enables verbose output, showing more details about closed/filtered ports and attempting to grab service banners.

### Examples
1. **Scan a specific host for default ports (1-1000):**

```sh
./pscan -target localhost
```

2. **Scan a specific port range on an IP address:**

```shell
./pscan -t 192.168.1.1 -p 100-500
```

3. **Scan all ports on a target with verbose output:**
``` bash
./pscan -target localhost -all -v
```

4. **Scan common ports with a custom timeout and threads:**
``` bash
./pscan -t localhost -common -timeout 500 -threads 200
```


### Building from source
- Go 1.24 or later

```sh 
go build pscan.go
```
