# Network Analyzer

A comprehensive tool for capturing, analyzing, and visualizing network traffic patterns and security issues.

## Features

- **Packet Capture**: Intercept network traffic using packet sniffing libraries
- **Protocol Parsing**: Identify and decode different network protocols (HTTP, TCP, DNS, etc.)
- **Traffic Analysis**: Aggregate data about network usage patterns
- **Anomaly Detection**: Identify unusual patterns that might indicate security issues
- **Data Visualization**: Generate graphs and charts of network activity
- **Security Monitoring**: Detect and alert on potential security threats
- **Report Generation**: Summarize findings in readable formats

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/network-analyzer.git
cd network-analyzer

# Install the package
pip install -e .
```

## Usage

### Basic Usage

```bash
# Start the network analyzer with default settings
network-analyzer

# Capture packets from a specific interface
network-analyzer --interface eth0

# Analyze a pcap file
network-analyzer --file capture.pcap

# Run with verbose output
network-analyzer --verbose
```

### Dashboard Access

Once started, the dashboard will be available at `http://localhost:8050` by default.

## Configuration

Create a `config.yaml` file in your project directory to customize settings:

```yaml
capture:
  interface: eth0
  filter: "not port 22"
  max_packets: 10000

analyzer:
  anomaly_threshold: 0.8
  update_interval: 5  # seconds
  
dashboard:
  port: 8050
  theme: dark
```

## Project Structure

```
network_analyzer/
├── docs/                      # Documentation
├── tests/                     # Test suite
├── network_analyzer/          # Main package
│   ├── capture/               # Packet capture module
│   ├── parser/                # Protocol parsing
│   ├── analyzer/              # Analysis components
│   ├── visualizer/            # Visualization components
│   ├── database/              # Database operations
│   ├── utils/                 # Utility functions
│   └── main.py                # Application entry point
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
