# Linux Network Scanner MCP Server

A comprehensive Model Context Protocol (MCP) server for network vulnerability scanning using Linux tools.

## Features

- **Network Discovery**: Scan networks for live hosts
- **Port Scanning**: Identify open ports and services
- **Vulnerability Assessment**: Check for common security vulnerabilities
- **Web Security**: Scan web services and applications
- **Device Detection**: Find cameras, routers, and network devices
- **OS Detection**: Identify operating systems
- **Quick Scans**: Comprehensive rapid assessments

## Available Tools

1. `scan_network` - Discover live hosts on a network
2. `port_scan` - Scan for open ports
3. `service_scan` - Identify running services
4. `vulnerability_scan` - Check for security vulnerabilities
5. `web_scan` - Scan web services
6. `camera_scan` - Find IP cameras
7. `router_scan` - Detect network routers
8. `os_detection` - Identify operating systems
9. `quick_scan` - Comprehensive rapid assessment

## Security Notice

This tool is designed for authorized security testing only. Always ensure you have permission to scan the target networks and systems. Unauthorized scanning may violate laws and terms of service.

## Usage Examples

- Scan a local network: `scan_network("192.168.1.0/24")`
- Port scan a host: `port_scan("192.168.1.1", "1-1000")`
- Check for vulnerabilities: `vulnerability_scan("192.168.1.100")`
- Find cameras: `camera_scan("192.168.1.0/24")`
- Quick assessment: `quick_scan("192.168.1.1")`

## Installation

1. Ensure Docker Desktop is installed on your system
2. Navigate to the project directory
3. Run: `docker-compose up --build`
4. The server will be available on port 3000

## Configuration

The server runs in a privileged Docker container to allow network scanning capabilities. All tools use nmap and other Linux security tools for comprehensive network analysis.
