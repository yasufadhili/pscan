package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanOptions holds the configuration for the port scanner
type ScanOptions struct {
	Target     string
	StartPort  int
	EndPort    int
	Timeout    int
	Threads    int
	AllPorts   bool
	CommonOnly bool
	Verbose    bool
}

// parsePortRange validates and parses the port range
func parsePortRange(rangeStr string) (int, int, error) {
	// Split the range string by hyphen
	ports := strings.Split(rangeStr, "-")

	if len(ports) != 2 {
		return 0, 0, fmt.Errorf("invalid port range format, use: startPort-endPort")
	}

	// Parse start port
	startPort, err := strconv.Atoi(ports[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port: %s", ports[0])
	}

	// Parse end port
	endPort, err := strconv.Atoi(ports[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port: %s", ports[1])
	}

	// Validate port range
	if startPort < 1 {
		return 0, 0, fmt.Errorf("start port must be 1 or greater")
	}

	if endPort <= startPort {
		return 0, 0, fmt.Errorf("end port must be greater than start port")
	}

	if endPort > 65535 {
		return 0, 0, fmt.Errorf("end port must be less than or equal to 65535")
	}

	return startPort, endPort, nil
}

// scanPort attempts to connect to a port to determine if it's open
func scanPort(options ScanOptions, port int, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}

	address := fmt.Sprintf("%s:%d", options.Target, port)

	// Create a custom dialer with the specified timeout
	dialer := net.Dialer{
		Timeout: time.Duration(options.Timeout) * time.Millisecond,
	}

	// Attempt to establish a TCP connection
	conn, err := dialer.Dial("tcp", address)

	if err == nil {
		// Connection successful, port is open
		defer conn.Close()

		// Try to determine service name for the port
		service := getServiceName(port)

		if service != "" {
			fmt.Printf("Port %d/tcp open - %s\n", port, service)
		} else {
			fmt.Printf("Port %d/tcp open\n", port)
		}

		// Perform additional actions for open ports (banner grabbing, etc.) if verbose
		if options.Verbose {
			// Simple banner grabbing attempt
			banner := getBanner(conn, port)
			if banner != "" {
				fmt.Printf("  └─ Banner: %s\n", banner)
			}
		}
	} else if options.Verbose {
		// Report closed/filtered ports only in verbose mode
		if strings.Contains(err.Error(), "timeout") {
			fmt.Printf("Port %d/tcp filtered (timeout)\n", port)
		} else if strings.Contains(err.Error(), "refused") {
			fmt.Printf("Port %d/tcp closed (connection refused)\n", port)
		} else {
			fmt.Printf("Port %d/tcp closed (%s)\n", port, err.Error())
		}
	}
}

// getServiceName returns the standard service name for common ports
func getServiceName(port int) string {
	commonPorts := map[int]string{
		20:   "FTP-data",
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		111:  "RPC",
		135:  "RPC",
		139:  "NetBIOS",
		143:  "IMAP",
		443:  "HTTPS",
		445:  "SMB",
		993:  "IMAPS",
		995:  "POP3S",
		1723: "PPTP",
		3306: "MySQL",
		3389: "RDP",
		5900: "VNC",
		8080: "HTTP-Proxy",
	}

	if service, exists := commonPorts[port]; exists {
		return service
	}
	return ""
}

// getBanner attempts to read the service banner from an open connection
func getBanner(conn net.Conn, port int) string {
	// Set a short read deadline
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	// Read response (if any)
	buffer := make([]byte, 1024)

	// For HTTP ports, send a basic request
	if port == 80 || port == 443 || port == 8080 {
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	}

	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	// Clean the banner and limit its length
	banner := strings.TrimSpace(string(buffer[:n]))
	// Split on newlines and get first line
	lines := strings.Split(banner, "\n")
	if len(lines) > 0 {
		banner = strings.TrimSpace(lines[0])
	}

	// Truncate if too long
	const maxLen = 80
	if len(banner) > maxLen {
		banner = banner[:maxLen] + "..."
	}

	return banner
}

// runPortScan executes the port scan with the given options
func runPortScan(options ScanOptions) {
	fmt.Printf("Starting port scan on %s (ports %d-%d)\n",
		options.Target, options.StartPort, options.EndPort)

	if options.Verbose {
		fmt.Printf("Using %d threads with %dms timeout\n",
			options.Threads, options.Timeout)
	}

	// Concurrent port scanning with goroutines
	var wg sync.WaitGroup

	
	for port := options.StartPort; port <= options.EndPort; port++ {
		wg.Add(1)
		go scanPort(options, port, &wg)

		// Limit concurrent goroutines
		if port%options.Threads == 0 {
			wg.Wait()
		}
	}

	// Wait for remaining goroutines to finish
	wg.Wait()

	fmt.Println("Scan complete!")
}

func main() {
	
	var options ScanOptions
	var portRange string

	// Set up command-line flags
	flag.StringVar(&options.Target, "target", "", "Target host to scan (required)")
	flag.StringVar(&portRange, "ports", "1-1000", "Port range to scan (format: start-end)")
	flag.IntVar(&options.Timeout, "timeout", 2000, "Connection timeout in milliseconds")
	flag.IntVar(&options.Threads, "threads", 100, "Number of concurrent threads")
	flag.BoolVar(&options.AllPorts, "all", false, "Scan all ports (1-65535)")
	flag.BoolVar(&options.CommonOnly, "common", false, "Scan only common ports")
	flag.BoolVar(&options.Verbose, "verbose", false, "Enable verbose output")

	// Alternative short flags
	flag.StringVar(&options.Target, "t", "", "Target host to scan (shorthand)")
	flag.StringVar(&portRange, "p", "1-1000", "Port range to scan (shorthand)")
	flag.BoolVar(&options.AllPorts, "a", false, "Scan all ports (shorthand)")
	flag.BoolVar(&options.Verbose, "v", false, "Enable verbose output (shorthand)")


	flag.Parse()

	
	if len(os.Args) == 1 {
		fmt.Println("Port Scanner - A simple tool for scanning open ports")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Validate target
	if options.Target == "" {
		fmt.Println("Error: Target host is required")
		fmt.Println("Use -target or -t to specify a target host")
		os.Exit(1)
	}

	// Resolve hostname to validate target
	_, err := net.LookupHost(options.Target)
	if err != nil {
		fmt.Printf("Error resolving host %s: %v\n", options.Target, err)
		os.Exit(1)
	}

	// Set port range based on flags
	if options.AllPorts {
		options.StartPort = 1
		options.EndPort = 65535
	} else if options.CommonOnly {
		// For now, use a smaller range for common ports
		options.StartPort = 1
		options.EndPort = 1024
	} else {
		// Parse custom port range
		options.StartPort, options.EndPort, err = parsePortRange(portRange)
		if err != nil {
			fmt.Printf("Error with port range: %v\n", err)
			os.Exit(1)
		}
	}

	
	runPortScan(options)
}
