# Trafnalyzer Technical Documentation

This document provides detailed technical information about the Trafnalyzer application's architecture, classes, and methods.

## Code Structure

The application consists of a single Python file (`trafnalyzer.py`) with several classes:

1. **CustomTkTheme**: Handles UI styling and theming
2. **PacketCaptureThread**: Manages packet capture in a background thread
3. **PacketProcessor**: Processes and analyzes packet data
4. **TrafficVisualization**: Creates and updates traffic visualizations
5. **TrafnalyzerApp**: Main application class

## Class Details

### CustomTkTheme

Responsible for configuring the custom dark theme used throughout the application.

#### Methods:

- **configure_theme(root)**: Applies the custom theme to all UI elements
  - Parameters:
    - `root`: The root Tkinter window
  - Returns:
    - `style`: The configured ttk.Style object

### PacketCaptureThread

A threaded class that captures network packets without blocking the UI.

#### Methods:

- **__init__(packet_queue, interface=None)**: Constructor
  - Parameters:
    - `packet_queue`: Queue to store captured packets
    - `interface`: Network interface to capture from (optional)
- **run()**: Main thread method that captures packets
- **stop()**: Stops the packet capture

### PacketProcessor

Static class that processes and extracts information from network packets.

#### Methods:

- **get_packet_info(packet)**: Extracts key information from a packet
  - Parameters:
    - `packet`: A scapy packet object
  - Returns:
    - Dictionary containing packet details (timestamp, IPs, ports, protocol, etc.)
- **get_tcp_flags(tcp_packet)**: Extracts TCP flags from a TCP packet
  - Parameters:
    - `tcp_packet`: A scapy TCP packet
  - Returns:
    - String representation of the TCP flags
- **get_hex_dump(packet)**: Generates a hexadecimal dump of a packet
  - Parameters:
    - `packet`: A scapy packet object
  - Returns:
    - String containing the hex dump
- **packet_matches_filter(packet_info, filter_text)**: Checks if a packet matches a filter
  - Parameters:
    - `packet_info`: Dictionary of packet information
    - `filter_text`: Filter expression
  - Returns:
    - Boolean indicating if the packet matches the filter

### TrafficVisualization

Handles the visualization of network traffic data using matplotlib.

#### Methods:

- **__init__(parent)**: Constructor
  - Parameters:
    - `parent`: Parent Tkinter widget
- **create_stat_label(parent, label_text, value_text, column)**: Creates a statistics label
  - Parameters:
    - `parent`: Parent widget
    - `label_text`: Label text
    - `value_text`: Initial value
    - `column`: Grid column
  - Returns:
    - The created label widget
- **add_packet(packet_info)**: Adds a packet to the visualization data
  - Parameters:
    - `packet_info`: Dictionary of packet information
- **update_plots()**: Updates all visualization plots and statistics

### TrafnalyzerApp

Main application class that coordinates all components.

#### Methods:

- **__init__(root)**: Constructor
  - Parameters:
    - `root`: Root Tkinter window
- **create_toolbar()**: Creates the application toolbar
- **create_packet_list()**: Creates the packet list view
- **create_packet_details()**: Creates the packet details view
- **create_status_bar()**: Creates the status bar
- **get_interfaces()**: Gets available network interfaces
  - Returns:
    - List of interface names
- **on_interface_selected(event)**: Handles interface selection
- **toggle_capture()**: Toggles packet capture on/off
- **start_capture()**: Starts packet capture
- **stop_capture()**: Stops packet capture
- **clear_packets()**: Clears all captured packets
- **save_pcap()**: Saves captured packets to a PCAP file
- **load_pcap()**: Loads packets from a PCAP file
- **on_packet_selected(event)**: Handles packet selection
- **apply_filter(event=None)**: Applies a filter to the packet list
- **start_ui_update_timer()**: Starts the UI update timer
- **update_ui()**: Updates the UI with new packets
- **on_closing()**: Handles application closing

## Data Flow

1. **Packet Capture**:
   - `PacketCaptureThread` captures packets from the network
   - Captured packets are placed in a queue

2. **Packet Processing**:
   - `update_ui()` method retrieves packets from the queue
   - `PacketProcessor.get_packet_info()` extracts information from each packet
   - Packet information is stored in `all_packets` list

3. **Filtering**:
   - `apply_filter()` applies filters to the packets
   - Filtered packets are stored in `displayed_packets` list

4. **Visualization**:
   - `TrafficVisualization.add_packet()` adds packet data to visualization
   - `TrafficVisualization.update_plots()` updates the visualization

5. **User Interaction**:
   - User selects a packet in the list
   - `on_packet_selected()` displays packet details

## UI Components

1. **Toolbar**:
   - Interface selection dropdown
   - Start/Stop capture button
   - Clear button
   - Save/Load PCAP buttons
   - Filter input field

2. **Packet List**:
   - Displays captured packets in a table
   - Columns: No., Time, Source, Destination, Protocol, Length, Info

3. **Packet Details**:
   - **Details Tab**: Hierarchical view of packet fields
   - **Hex Dump Tab**: Raw packet data in hexadecimal format
   - **Visualization Tab**: Traffic graphs and statistics

4. **Status Bar**:
   - Displays current status and packet count

## Customization Options

The application's appearance can be customized by modifying the color constants at the top of the file:

```python
# Custom theme colors
DARK_BG = "#2E3440"
LIGHT_BG = "#3B4252"
ACCENT_COLOR = "#88C0D0"
TEXT_COLOR = "#ECEFF4"
HIGHLIGHT_COLOR = "#5E81AC"
ALERT_COLOR = "#BF616A"
SUCCESS_COLOR = "#A3BE8C"
WARNING_COLOR = "#EBCB8B"

# Protocol colors for packet list
PROTOCOL_COLORS = {
    "TCP": "#8FBCBB",
    "UDP": "#A3BE8C",
    "ICMP": "#EBCB8B",
    "DNS": "#B48EAD",
    "HTTP": "#5E81AC",
    "HTTPS": "#81A1C1",
    "ARP": "#D08770",
    "OTHER": "#4C566A"
}
```

## Performance Considerations

- The application uses a multi-threaded design to keep the UI responsive
- Packet processing is done in small batches to prevent UI freezing
- Visualization updates are throttled to reduce CPU usage
- Large packet captures may consume significant memory

## Future Enhancements

Potential areas for improvement:

1. **Protocol Analyzers**: Add specialized analyzers for more protocols
2. **Export Options**: Add ability to export data in various formats
3. **Packet Injection**: Add capability to craft and inject packets
4. **Advanced Filtering**: Implement more complex filtering expressions
5. **Plugins**: Create a plugin system for extensibility 