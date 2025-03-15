# Trafnalyzer

A powerful network traffic analyzer built with Python, inspired by Wireshark.

![Trafnalyzer](https://github.com/yourusername/trafnalyzer/raw/main/screenshots/trafnalyzer_main.png)

## Features

- **Live Packet Capture**: Capture network packets in real-time from any available network interface
- **Packet Analysis**: View detailed information about each packet including source/destination IP, protocol, timestamp, etc.
- **Protocol Support**: Analyze TCP, UDP, ICMP, HTTP, HTTPS, DNS, ARP and other protocols
- **Interactive Filtering**: Filter packets based on IP, port, protocol, or custom expressions
- **Packet Inspection**: Examine packet headers, payload, and hex dump
- **PCAP Support**: Save captured packets to .pcap format and load .pcap files for analysis
- **Data Visualization**: View real-time graphs of network traffic including protocol distribution and traffic rates
- **Multi-threaded Design**: Responsive UI with background packet capture
- **Modern UI**: Dark-themed, customized interface for better visibility and reduced eye strain

## Installation

### Prerequisites

- Python 3.6 or higher
- Required Python packages:
  - scapy
  - pyshark (optional, for additional capture capabilities)
  - matplotlib
  - tkinter
  - numpy

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/cybxmonk/trafnalyzer.git
   cd trafnalyzer
   ```

2. Install the required packages:
   ```
   pip install scapy pyshark matplotlib numpy
   ```

3. Run the application:
   ```
   python trafnalyzer.py
   ```

### Running on Windows

For Windows users, we provide several ways to run the application:

1. **Command Prompt or PowerShell**:
   ```
   python trafnalyzer.py
   ```

2. **Using the batch file**:
   - Double-click on `run_trafnalyzer.bat`

3. **With Administrator privileges** (recommended for packet capture):
   - Right-click on `run_trafnalyzer_admin.ps1`
   - Select "Run with PowerShell"
   - Confirm the UAC prompt

**Note**: On Windows, you need to run the application as administrator to capture packets. On Linux, you may need to use `sudo` or configure capabilities for non-root packet capture.

## Usage

### Capturing Packets

1. Select a network interface from the dropdown menu
2. Click "Start Capture" to begin capturing packets
3. The packet list will populate in real-time
4. Click "Stop Capture" when finished

### Filtering Packets

1. Enter a filter expression in the filter field
2. Press Enter or click "Apply" to apply the filter
3. The packet list will update to show only matching packets

#### Filter Examples:

- `tcp` - Show only TCP packets
- `udp` - Show only UDP packets
- `ip.src==192.168.1.1` - Show packets from a specific source IP
- `port==443` - Show packets with source or destination port 443
- `http` - Show only HTTP packets

### Analyzing Packets

1. Click on a packet in the list to view its details
2. The details pane shows:
   - **Details Tab**: Hierarchical view of packet fields and values
   - **Hex Dump Tab**: Raw packet data in hexadecimal format
   - **Visualization Tab**: Real-time traffic graphs and statistics

### Saving and Loading Captures

- Click "Save PCAP" to save the current capture to a .pcap file
- Click "Load PCAP" to load a previously saved .pcap file

## Technical Details

### Architecture

Trafnalyzer is built with a multi-threaded architecture:

1. **Main Thread**: Handles the UI and user interactions
2. **Capture Thread**: Captures packets in the background without blocking the UI
3. **Processing Thread**: Processes and analyzes captured packets

### Components

- **PacketCaptureThread**: Handles packet capture using scapy
- **PacketProcessor**: Extracts and processes information from packets
- **TrafficVisualization**: Creates and updates traffic visualizations
- **TrafnalyzerApp**: Main application class that coordinates all components

### Customization

The application uses a custom theme with the following color scheme:

- Dark background for reduced eye strain
- Color-coded protocols for easy identification
- Customizable visualization options

## Troubleshooting

### Common Issues

1. **No packets captured**:
   - Ensure you're running the application with administrator/root privileges
   - Verify that the selected interface is active and connected to a network
   - Check if any firewall is blocking packet capture

2. **Application crashes**:
   - Check if all required packages are installed
   - Ensure you have the correct Python version

3. **High CPU usage**:
   - Reduce the packet capture rate by applying more specific filters
   - Close the application when not in use

4. **Application won't start**:
   - Make sure Python is in your PATH
   - Try running with the provided batch file or PowerShell script
   - Check for any error messages in the console

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by Wireshark
- Built with Python and Tkinter
- Uses Scapy for packet manipulation
- Visualization powered by Matplotlib 
