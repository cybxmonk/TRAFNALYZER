# Trafnalyzer Quick Start Guide

This guide will help you get started with Trafnalyzer quickly.

## Installation

1. Install Python 3.6 or higher if not already installed
2. Install required packages:
   ```
   pip install scapy matplotlib numpy
   ```
3. Run the application:
   ```
   python trafnalyzer.py
   ```

**Note**: On Windows, run as administrator. On Linux, use `sudo` or configure capabilities.

## Capturing Packets in 3 Steps

1. **Select Interface**: Choose a network interface from the dropdown menu
2. **Start Capture**: Click the "Start Capture" button
3. **View Results**: Watch as packets appear in the list in real-time

## Basic Filtering

- Type `tcp` in the filter box to show only TCP packets
- Type `udp` to show only UDP packets
- Type `http` to show only HTTP packets
- Type `ip.src==192.168.1.1` to filter by source IP
- Press Enter or click "Apply" to apply the filter

## Examining Packets

Click on any packet in the list to view:
- Detailed packet information in the "Details" tab
- Raw packet data in the "Hex Dump" tab
- Traffic statistics in the "Visualization" tab

## Saving Your Work

- Click "Save PCAP" to save captured packets to a file
- Click "Load PCAP" to load previously saved captures

## Keyboard Shortcuts

- **Ctrl+S**: Save capture
- **Ctrl+O**: Open capture
- **Ctrl+F**: Focus on filter field
- **Ctrl+C**: Copy selected packet details
- **Esc**: Clear filter

## Common Issues

- **No packets showing**: Make sure you're running as administrator/root
- **Interface not listed**: Check network connections and permissions
- **Application crashes**: Verify all required packages are installed

## Next Steps

- Explore the visualization tab to see traffic patterns
- Try different filter combinations
- Check the full README.md for detailed documentation 