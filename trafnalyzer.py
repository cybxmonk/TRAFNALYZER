# Trafnalyzer - Network Traffic Analyzer
# Python 3.6+ required

import sys
import os
import time
import threading
import queue
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import scapy.all as scapy
from scapy.utils import PcapWriter, PcapReader
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
import binascii

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

class CustomTkTheme:
    @staticmethod
    def configure_theme(root):
        # Configure the main theme
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure(".", 
                        background=DARK_BG, 
                        foreground=TEXT_COLOR, 
                        troughcolor=LIGHT_BG,
                        fieldbackground=LIGHT_BG)
        
        # Configure Treeview
        style.configure("Treeview", 
                        background=LIGHT_BG, 
                        foreground=TEXT_COLOR, 
                        fieldbackground=LIGHT_BG)
        style.configure("Treeview.Heading", 
                        background=DARK_BG, 
                        foreground=ACCENT_COLOR, 
                        relief="flat")
        style.map("Treeview", 
                  background=[('selected', HIGHLIGHT_COLOR)],
                  foreground=[('selected', TEXT_COLOR)])
        
        # Configure Buttons
        style.configure("TButton", 
                        background=ACCENT_COLOR, 
                        foreground=DARK_BG, 
                        padding=6,
                        relief="flat")
        style.map("TButton",
                  background=[('active', HIGHLIGHT_COLOR), ('pressed', LIGHT_BG)],
                  relief=[('pressed', 'sunken')])
        
        # Configure Entry
        style.configure("TEntry", 
                        fieldbackground=LIGHT_BG, 
                        foreground=TEXT_COLOR,
                        insertcolor=TEXT_COLOR,
                        borderwidth=1)
        
        # Configure Combobox
        style.configure("TCombobox", 
                        fieldbackground=LIGHT_BG, 
                        background=DARK_BG,
                        foreground=TEXT_COLOR,
                        arrowcolor=ACCENT_COLOR)
        style.map("TCombobox",
                  fieldbackground=[('readonly', LIGHT_BG)],
                  foreground=[('readonly', TEXT_COLOR)])
        
        # Configure Notebook
        style.configure("TNotebook", 
                        background=DARK_BG, 
                        tabmargins=[2, 5, 2, 0])
        style.configure("TNotebook.Tab", 
                        background=LIGHT_BG, 
                        foreground=TEXT_COLOR,
                        padding=[10, 2],
                        borderwidth=0)
        style.map("TNotebook.Tab",
                background=[('selected', ACCENT_COLOR)],
                foreground=[('selected', DARK_BG)])
        
        # Configure Frame
        style.configure("TFrame", background=DARK_BG)
        style.configure("Card.TFrame", background=LIGHT_BG, relief="flat", borderwidth=0)
        
        # Configure Label
        style.configure("TLabel", background=DARK_BG, foreground=TEXT_COLOR)
        style.configure("Title.TLabel", 
                        font=("Helvetica", 14, "bold"), 
                        foreground=ACCENT_COLOR)
        style.configure("Card.TLabel", background=LIGHT_BG)
        
        # Configure root window
        root.configure(bg=DARK_BG)
        
        return style

class PacketCaptureThread(threading.Thread):
    def __init__(self, packet_queue, interface=None):
        super().__init__()
        self.packet_queue = packet_queue
        self.interface = interface
        self.running = False
        self.daemon = True
    
    def run(self):
        self.running = True
        
        def packet_callback(packet):
            if self.running:
                self.packet_queue.put(packet)
        
        if self.interface:
            scapy.sniff(iface=self.interface, prn=packet_callback, store=False)
        else:
            scapy.sniff(prn=packet_callback, store=False)
    
    def stop(self):
        self.running = False

class PacketProcessor:
    @staticmethod
    def get_packet_info(packet):
        timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        # Initialize default values
        src_ip = dst_ip = "N/A"
        src_port = dst_port = "N/A"
        protocol = "OTHER"
        length = len(packet)
        info = ""
        
        # Extract IP information
        if scapy.IP in packet:
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            
            # TCP
            if scapy.TCP in packet:
                protocol = "TCP"
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                flags = PacketProcessor.get_tcp_flags(packet[scapy.TCP])
                info = f"Flags: {flags}, Seq={packet[scapy.TCP].seq}, Ack={packet[scapy.TCP].ack}"
                
                # HTTP
                if packet.haslayer(scapy.Raw) and (dst_port == 80 or src_port == 80):
                    protocol = "HTTP"
                    payload = packet[scapy.Raw].load.decode('utf-8', 'ignore')
                    if payload.startswith('GET') or payload.startswith('POST') or payload.startswith('HTTP'):
                        info = payload.split('\r\n')[0][:50]
                
                # HTTPS
                if dst_port == 443 or src_port == 443:
                    protocol = "HTTPS"
            
            # UDP
            elif scapy.UDP in packet:
                protocol = "UDP"
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
                info = f"Length: {packet[scapy.UDP].len}"
                
                # DNS
                if scapy.DNSQR in packet:
                    protocol = "DNS"
                    qname = packet[scapy.DNSQR].qname.decode('utf-8')
                    info = f"Query: {qname}"
                elif scapy.DNSRR in packet:
                    protocol = "DNS"
                    if hasattr(packet[scapy.DNSRR], 'rdata'):
                        if isinstance(packet[scapy.DNSRR].rdata, bytes):
                            rdata = packet[scapy.DNSRR].rdata.decode('utf-8', 'ignore')
                        else:
                            rdata = str(packet[scapy.DNSRR].rdata)
                        info = f"Response: {rdata}"
            
            # ICMP
            elif scapy.ICMP in packet:
                protocol = "ICMP"
                icmp_type = packet[scapy.ICMP].type
                icmp_code = packet[scapy.ICMP].code
                info = f"Type: {icmp_type}, Code: {icmp_code}"
        
        # ARP
        elif scapy.ARP in packet:
            protocol = "ARP"
            src_ip = packet[scapy.ARP].psrc
            dst_ip = packet[scapy.ARP].pdst
            info = f"{'Request' if packet[scapy.ARP].op == 1 else 'Reply'} {src_ip} -> {dst_ip}"
        
        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": length,
            "info": info,
            "packet": packet
        }
    
    @staticmethod
    def get_tcp_flags(tcp_packet):
        flags = []
        if tcp_packet.flags.S:
            flags.append("SYN")
        if tcp_packet.flags.A:
            flags.append("ACK")
        if tcp_packet.flags.F:
            flags.append("FIN")
        if tcp_packet.flags.R:
            flags.append("RST")
        if tcp_packet.flags.P:
            flags.append("PSH")
        if tcp_packet.flags.U:
            flags.append("URG")
        return " ".join(flags)
    
    @staticmethod
    def get_hex_dump(packet):
        return scapy.hexdump(packet, dump=True)
    
    @staticmethod
    def packet_matches_filter(packet_info, filter_text):
        if not filter_text:
            return True
        
        filter_text = filter_text.lower()
        
        # Check if filter matches any field
        if (filter_text in str(packet_info["src_ip"]).lower() or
            filter_text in str(packet_info["dst_ip"]).lower() or
            filter_text in str(packet_info["src_port"]).lower() or
            filter_text in str(packet_info["dst_port"]).lower() or
            filter_text in packet_info["protocol"].lower() or
            filter_text in packet_info["info"].lower()):
            return True
        
        # Protocol specific filters
        if filter_text.startswith("tcp") and packet_info["protocol"] == "TCP":
            return True
        if filter_text.startswith("udp") and packet_info["protocol"] == "UDP":
            return True
        if filter_text.startswith("icmp") and packet_info["protocol"] == "ICMP":
            return True
        if filter_text.startswith("dns") and packet_info["protocol"] == "DNS":
            return True
        if filter_text.startswith("http") and packet_info["protocol"] == "HTTP":
            return True
        if filter_text.startswith("arp") and packet_info["protocol"] == "ARP":
            return True
        
        # IP filters
        if filter_text.startswith("ip.src") and filter_text.split("==")[1].strip() in str(packet_info["src_ip"]):
            return True
        if filter_text.startswith("ip.dst") and filter_text.split("==")[1].strip() in str(packet_info["dst_ip"]):
            return True
        
        # Port filters
        if filter_text.startswith("port") and (
            filter_text.split("==")[1].strip() in str(packet_info["src_port"]) or
            filter_text.split("==")[1].strip() in str(packet_info["dst_port"])):
            return True
        
        return False

class TrafficVisualization(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="TFrame")
        
        # Initialize data structures for visualization
        self.protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'DNS': 0, 'HTTP': 0, 'HTTPS': 0, 'ARP': 0, 'OTHER': 0}
        self.packet_times = []
        self.packet_sizes = []
        self.bytes_per_second = []
        self.packets_per_second = []
        self.time_windows = []
        
        # Create matplotlib figure and canvas
        self.figure = Figure(figsize=(10, 8), dpi=100, facecolor=DARK_BG)
        self.figure.subplots_adjust(hspace=0.4)
        
        # Create subplots
        self.protocol_ax = self.figure.add_subplot(211)
        self.protocol_ax.set_facecolor(LIGHT_BG)
        self.protocol_ax.set_title('Protocol Distribution', color=TEXT_COLOR)
        
        self.traffic_ax = self.figure.add_subplot(212)
        self.traffic_ax.set_facecolor(LIGHT_BG)
        self.traffic_ax.set_title('Traffic Rate', color=TEXT_COLOR)
        self.traffic_ax.set_xlabel('Time (seconds)', color=TEXT_COLOR)
        self.traffic_ax.set_ylabel('Bytes per second', color=TEXT_COLOR)
        self.traffic_ax.tick_params(colors=TEXT_COLOR)
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.figure, self)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Stats frame
        self.stats_frame = ttk.Frame(self, style="Card.TFrame")
        self.stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Create stats labels
        self.create_stat_label(self.stats_frame, "Total Packets:", "0", 0)
        self.create_stat_label(self.stats_frame, "Packets/sec:", "0", 1)
        self.create_stat_label(self.stats_frame, "Bytes/sec:", "0", 2)
        self.create_stat_label(self.stats_frame, "Avg Packet Size:", "0", 3)
        
        # Last update time
        self.last_update = time.time()
        self.packet_count_since_update = 0
        self.bytes_since_update = 0
        self.total_packets = 0
    
    def create_stat_label(self, parent, label_text, value_text, column):
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.grid(row=0, column=column, padx=10, pady=10, sticky="nsew")
        
        label = ttk.Label(frame, text=label_text, style="Card.TLabel")
        label.pack(pady=(5, 0))
        
        value = ttk.Label(frame, text=value_text, style="Title.TLabel")
        value.pack(pady=(0, 5))
        
        return value
    
    def add_packet(self, packet_info):
        # Update protocol statistics
        protocol = packet_info["protocol"]
        if protocol in self.protocol_counts:
            self.protocol_counts[protocol] += 1
        else:
            self.protocol_counts["OTHER"] += 1
        
        # Record packet time and size
        current_time = time.time()
        self.packet_times.append(current_time)
        packet_size = packet_info["length"]
        self.packet_sizes.append(packet_size)
        
        # Update counters for stats
        self.total_packets += 1
        self.packet_count_since_update += 1
        self.bytes_since_update += packet_size
        
        # Keep only the last 100 packets for the traffic graph
        if len(self.packet_times) > 100:
            self.packet_times.pop(0)
            self.packet_sizes.pop(0)
    
    def update_plots(self):
        current_time = time.time()
        time_diff = current_time - self.last_update
        
        # Only update if some time has passed
        if time_diff >= 1.0:
            # Calculate rates
            packets_per_sec = self.packet_count_since_update / time_diff
            bytes_per_sec = self.bytes_since_update / time_diff
            
            # Update time windows for x-axis
            self.time_windows.append(current_time)
            self.packets_per_second.append(packets_per_sec)
            self.bytes_per_second.append(bytes_per_sec)
            
            # Keep only the last 30 seconds of data
            if len(self.time_windows) > 30:
                self.time_windows.pop(0)
                self.packets_per_second.pop(0)
                self.bytes_per_second.pop(0)
            
            # Reset counters
            self.last_update = current_time
            self.packet_count_since_update = 0
            self.bytes_since_update = 0
            
            # Update stats display
            avg_packet_size = sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0
            
            # Find and update the stat labels
            for child in self.stats_frame.winfo_children():
                for widget in child.winfo_children():
                    if isinstance(widget, ttk.Label) and widget.cget("style") == "Title.TLabel":
                        if "Total Packets:" in [w.cget("text") for w in child.winfo_children()]:
                            widget.config(text=str(self.total_packets))
                        elif "Packets/sec:" in [w.cget("text") for w in child.winfo_children()]:
                            widget.config(text=f"{packets_per_sec:.2f}")
                        elif "Bytes/sec:" in [w.cget("text") for w in child.winfo_children()]:
                            widget.config(text=f"{bytes_per_sec:.2f}")
                        elif "Avg Packet Size:" in [w.cget("text") for w in child.winfo_children()]:
                            widget.config(text=f"{avg_packet_size:.2f}")
            
            # Clear previous plots
            self.protocol_ax.clear()
            self.traffic_ax.clear()
            
            # Protocol distribution pie chart
            labels = []
            sizes = []
            colors = []
            for protocol, count in self.protocol_counts.items():
                if count > 0:
                    labels.append(f"{protocol} ({count})")
                    sizes.append(count)
                    colors.append(PROTOCOL_COLORS.get(protocol, PROTOCOL_COLORS["OTHER"]))
            
            if sizes:
                self.protocol_ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors)
                self.protocol_ax.set_title('Protocol Distribution', color=TEXT_COLOR)
            
            # Traffic over time
            if len(self.time_windows) > 1:
                # Convert to relative time (seconds ago)
                relative_times = [t - current_time for t in self.time_windows]
                
                # Create twin axis for packets per second
                ax2 = self.traffic_ax.twinx()
                ax2.set_ylabel('Packets per second', color=SUCCESS_COLOR)
                ax2.tick_params(axis='y', colors=SUCCESS_COLOR)
                
                # Plot bytes per second
                self.traffic_ax.plot(relative_times, self.bytes_per_second, color=ACCENT_COLOR, linewidth=2)
                self.traffic_ax.set_title('Traffic Rate', color=TEXT_COLOR)
                self.traffic_ax.set_xlabel('Time (seconds ago)', color=TEXT_COLOR)
                self.traffic_ax.set_ylabel('Bytes per second', color=ACCENT_COLOR)
                self.traffic_ax.tick_params(colors=TEXT_COLOR)
                
                # Plot packets per second on twin axis
                ax2.plot(relative_times, self.packets_per_second, color=SUCCESS_COLOR, linewidth=2)
                ax2.tick_params(colors=TEXT_COLOR)
                
                # Set grid
                self.traffic_ax.grid(True, linestyle='--', alpha=0.7)
                
                # Set y-axis to start at 0
                self.traffic_ax.set_ylim(bottom=0)
                ax2.set_ylim(bottom=0)
            
            # Draw the canvas
            self.canvas.draw()

class TrafnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Trafnalyzer - Network Traffic Analyzer")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Apply custom theme
        self.style = CustomTkTheme.configure_theme(root)
        
        # Initialize variables
        self.packet_queue = queue.Queue()
        self.all_packets = []
        self.displayed_packets = []
        self.capture_thread = None
        self.is_capturing = False
        self.pcap_writer = None
        self.selected_interface = None
        
        # Create main container
        self.main_container = ttk.Frame(root)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create toolbar
        self.create_toolbar()
        
        # Create main content area with paned window
        self.paned_window = ttk.PanedWindow(self.main_container, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create packet list frame
        self.packet_list_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.packet_list_frame, weight=3)
        
        # Create packet details frame
        self.details_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.details_frame, weight=2)
        
        # Create packet list
        self.create_packet_list()
        
        # Create packet details view with notebook
        self.create_packet_details()
        
        # Create status bar
        self.create_status_bar()
        
        # Start UI update timer
        self.update_timer = None
        self.start_ui_update_timer()
        
        # Get available interfaces
        self.interfaces = self.get_interfaces()
        self.interface_combo['values'] = self.interfaces
        if self.interfaces:
            self.interface_combo.current(0)
            self.selected_interface = self.interfaces[0]
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def create_toolbar(self):
        # Toolbar frame
        self.toolbar = ttk.Frame(self.main_container, style="Card.TFrame")
        self.toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        # Interface selection
        ttk.Label(self.toolbar, text="Interface:", style="Card.TLabel").pack(side=tk.LEFT, padx=(10, 5))
        self.interface_combo = ttk.Combobox(self.toolbar, width=20, state="readonly")
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        self.interface_combo.bind("<<ComboboxSelected>>", self.on_interface_selected)
        
        # Start/Stop capture button
        self.capture_button = ttk.Button(self.toolbar, text="Start Capture", command=self.toggle_capture)
        self.capture_button.pack(side=tk.LEFT, padx=10)
        
        # Clear button
        self.clear_button = ttk.Button(self.toolbar, text="Clear", command=self.clear_packets)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Save button
        self.save_button = ttk.Button(self.toolbar, text="Save PCAP", command=self.save_pcap)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        # Load button
        self.load_button = ttk.Button(self.toolbar, text="Load PCAP", command=self.load_pcap)
        self.load_button.pack(side=tk.LEFT, padx=5)
        
        # Filter
        ttk.Label(self.toolbar, text="Filter:", style="Card.TLabel").pack(side=tk.LEFT, padx=(20, 5))
        self.filter_entry = ttk.Entry(self.toolbar, width=30)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        self.filter_entry.bind("<Return>", self.apply_filter)
        
        # Apply filter button
        self.filter_button = ttk.Button(self.toolbar, text="Apply", command=self.apply_filter)
        self.filter_button.pack(side=tk.LEFT, padx=5)
    
    def create_packet_list(self):
        # Create a frame for the packet list with a label
        ttk.Label(self.packet_list_frame, text="Packet List", style="Title.TLabel").pack(anchor=tk.W, padx=10, pady=5)
        
        # Create Treeview for packet list
        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.packet_tree = ttk.Treeview(self.packet_list_frame, columns=columns, show="headings", selectmode="browse")
        
        # Configure columns
        self.packet_tree.heading("No.", text="No.")
        self.packet_tree.heading("Time", text="Time")
        self.packet_tree.heading("Source", text="Source")
        self.packet_tree.heading("Destination", text="Destination")
        self.packet_tree.heading("Protocol", text="Protocol")
        self.packet_tree.heading("Length", text="Length")
        self.packet_tree.heading("Info", text="Info")
        
        self.packet_tree.column("No.", width=50, anchor=tk.CENTER)
        self.packet_tree.column("Time", width=150)
        self.packet_tree.column("Source", width=150)
        self.packet_tree.column("Destination", width=150)
        self.packet_tree.column("Protocol", width=80, anchor=tk.CENTER)
        self.packet_tree.column("Length", width=70, anchor=tk.CENTER)
        self.packet_tree.column("Info", width=300)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.packet_list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Bind selection event
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_selected)
    
    def create_packet_details(self):
        # Create a notebook for packet details
        self.details_notebook = ttk.Notebook(self.details_frame)
        self.details_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.details_tab = ttk.Frame(self.details_notebook, style="TFrame")
        self.hex_tab = ttk.Frame(self.details_notebook, style="TFrame")
        self.visualization_tab = ttk.Frame(self.details_notebook, style="TFrame")
        
        self.details_notebook.add(self.details_tab, text="Details")
        self.details_notebook.add(self.hex_tab, text="Hex Dump")
        self.details_notebook.add(self.visualization_tab, text="Visualization")
        
        # Details tab
        self.details_tree = ttk.Treeview(self.details_tab, show="tree")
        details_scrollbar = ttk.Scrollbar(self.details_tab, orient=tk.VERTICAL, command=self.details_tree.yview)
        self.details_tree.configure(yscrollcommand=details_scrollbar.set)
        
        details_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.details_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Hex dump tab
        self.hex_text = scrolledtext.ScrolledText(self.hex_tab, bg=LIGHT_BG, fg=TEXT_COLOR, font=("Courier", 10))
        self.hex_text.pack(fill=tk.BOTH, expand=True)
        
        # Visualization tab
        self.visualization = TrafficVisualization(self.visualization_tab)
        self.visualization.pack(fill=tk.BOTH, expand=True)
    
    def create_status_bar(self):
        self.status_bar = ttk.Frame(self.main_container, style="Card.TFrame", height=25)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=(0, 10))
        
        self.status_label = ttk.Label(self.status_bar, text="Ready", style="Card.TLabel")
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        self.packet_count_label = ttk.Label(self.status_bar, text="Packets: 0", style="Card.TLabel")
        self.packet_count_label.pack(side=tk.RIGHT, padx=10)
    
    def get_interfaces(self):
        try:
            interfaces = scapy.get_if_list()
            return interfaces
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get network interfaces: {str(e)}")
            return []
    
    def on_interface_selected(self, event):
        self.selected_interface = self.interface_combo.get()
    
    def toggle_capture(self):
        if not self.is_capturing:
            self.start_capture()
        else:
            self.stop_capture()
    
    def start_capture(self):
        print("Starting capture...")  # Debug print
        
        if not self.selected_interface:
            print("No interface selected")  # Debug print
            messagebox.showerror("Error", "Please select a network interface.")
            return
        
        print(f"Selected interface: {self.selected_interface}")  # Debug print
        
        try:
            # Initialize pcap writer for temporary storage
            temp_pcap_file = f"temp_capture_{int(time.time())}.pcap"
            print(f"Creating temporary PCAP file: {temp_pcap_file}")  # Debug print
            self.pcap_writer = PcapWriter(temp_pcap_file, append=True)
            
            # Start capture thread
            print("Creating capture thread")  # Debug print
            self.capture_thread = PacketCaptureThread(self.packet_queue, self.selected_interface)
            self.capture_thread.start()
            print("Capture thread started")  # Debug print
            
            # Update UI
            self.is_capturing = True
            self.capture_button.config(text="Stop Capture")
            self.status_label.config(text=f"Capturing packets on {self.selected_interface}...")
            print(f"Now capturing on {self.selected_interface}")  # Debug print
        except Exception as e:
            print(f"Error starting capture: {e}")  # Debug print
            messagebox.showerror("Error", f"Failed to start capture: {str(e)}")
            if self.capture_thread:
                self.capture_thread.stop()
                print("Capture thread stopped")  # Debug print
            self.is_capturing = False
            self.capture_button.config(text="Start Capture")
            self.status_label.config(text="Capture stopped")
            self.is_capturing = False
            self.capture_button.config(text="Start Capture")
            self.status_label.config(text="Capture stopped")
            print("Capture stopped")  # Debug print
        except Exception as e:
            print(f"Error stopping capture: {e}")  # Debug print
    
    def clear_packets(self):
        self.packet_queue.queue.clear()
        self.all_packets.clear()
        self.displayed_packets.clear()
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.visualization.protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'DNS': 0, 'HTTP': 0, 'HTTPS': 0, 'ARP': 0, 'OTHER': 0}
        self.visualization.packet_times.clear()
        self.visualization.packet_sizes.clear()
        self.visualization.bytes_per_second.clear()
        self.visualization.packets_per_second.clear()
        self.visualization.time_windows.clear()
        self.visualization.update_plots()
    
    def on_closing(self):
        if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            self.stop_capture()
            self.root.destroy()

    def start_ui_update_timer(self):
        if self.update_timer:
            self.root.after_cancel(self.update_timer)
        self.update_timer = self.root.after(100, self.update_ui)
    
    def update_ui(self):
        print("Updating UI...")  # Debug print
        
        # Process packets from the queue
        try:
            packets_processed = 0
            while not self.packet_queue.empty():
                packet = self.packet_queue.get_nowait()
                print(f"Processing packet from queue: {packet.summary()}")  # Debug print
                
                try:
                    packet_info = PacketProcessor.get_packet_info(packet)
                    print(f"Packet info: {packet_info['protocol']} {packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}")  # Debug print
                    
                    self.all_packets.append(packet_info)
                    
                    # Apply current filter
                    current_filter = self.filter_entry.get()
                    if current_filter:
                        print(f"Applying filter: {current_filter}")  # Debug print
                        if PacketProcessor.packet_matches_filter(packet_info, current_filter):
                            print("Packet matches filter")  # Debug print
                            self.displayed_packets.append(packet_info)
                            self.packet_tree.insert("", "end", values=(
                                len(self.all_packets),
                                packet_info["timestamp"],
                                f"{packet_info['src_ip']}:{packet_info['src_port']}",
                                f"{packet_info['dst_ip']}:{packet_info['dst_port']}",
                                packet_info["protocol"],
                                packet_info["length"],
                                packet_info["info"]
                            ))
                    else:
                        print("No filter applied, displaying packet")  # Debug print
                        self.displayed_packets.append(packet_info)
                        self.packet_tree.insert("", "end", values=(
                            len(self.all_packets),
                            packet_info["timestamp"],
                            f"{packet_info['src_ip']}:{packet_info['src_port']}",
                            f"{packet_info['dst_ip']}:{packet_info['dst_port']}",
                            packet_info["protocol"],
                            packet_info["length"],
                            packet_info["info"]
                        ))
                    
                    # Update visualization with new packet
                    self.visualization.add_packet(packet_info)
                    
                    # Write to pcap if active
                    if self.pcap_writer:
                        print("Writing packet to PCAP file")  # Debug print
                        self.pcap_writer.write(packet_info["packet"])
                    
                    packets_processed += 1
                except Exception as e:
                    print(f"Error processing individual packet: {e}")  # Debug print
            
            if packets_processed > 0:
                print(f"Processed {packets_processed} packets in this update")  # Debug print
            
        except queue.Empty:
            pass
        except Exception as e:
            print(f"Error in update_ui queue processing: {e}")  # Debug print
        
        # Update UI elements
        try:
            self.packet_count_label.config(text=f"Packets: {len(self.displayed_packets)}")
            self.visualization.update_plots()
        except Exception as e:
            print(f"Error updating UI elements: {e}")  # Debug print
        
        # Schedule next update
        self.start_ui_update_timer()

    def save_pcap(self):
        if not self.pcap_writer:
            messagebox.showerror("Error", "No PCAP writer initialized.")
            return
        
        filename = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP Files", "*.pcap")])
        if filename:
            self.pcap_writer.write(self.all_packets)
            messagebox.showinfo("Success", "PCAP file saved successfully.")
    
    def load_pcap(self):
        filename = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap")])
        if filename:
            self.pcap_writer = PcapWriter(filename)
            self.all_packets = []
            self.displayed_packets = []
            self.packet_tree.delete(*self.packet_tree.get_children())
            self.visualization.protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'DNS': 0, 'HTTP': 0, 'HTTPS': 0, 'ARP': 0, 'OTHER': 0}
            self.visualization.packet_times.clear()
            self.visualization.packet_sizes.clear()
            self.visualization.bytes_per_second.clear()
            self.visualization.packets_per_second.clear()
            self.visualization.time_windows.clear()
            self.visualization.update_plots()
            messagebox.showinfo("Success", "PCAP file loaded successfully.")

    def apply_filter(self, event=None):
        filter_text = self.filter_entry.get()
        self.displayed_packets = [packet for packet in self.all_packets if PacketProcessor.packet_matches_filter(packet, filter_text)]
        self.packet_tree.delete(*self.packet_tree.get_children())
        for i, packet in enumerate(self.displayed_packets):
            self.packet_tree.insert("", "end", values=(
                i+1,
                packet["timestamp"],
                f"{packet['src_ip']}:{packet['src_port']}",
                f"{packet['dst_ip']}:{packet['dst_port']}",
                packet["protocol"],
                packet["length"],
                packet["info"]
            ))

    def on_packet_selected(self, event):
        selected_item = self.packet_tree.selection()
        if selected_item:
            item_id = selected_item[0]
            packet_index = int(self.packet_tree.item(item_id)['values'][0]) - 1
            if 0 <= packet_index < len(self.displayed_packets):
                packet_info = self.displayed_packets[packet_index]
                
                # Update details tree
                self.details_tree.delete(*self.details_tree.get_children())
                
                # Add packet details to tree
                protocol = packet_info["protocol"]
                parent = self.details_tree.insert("", "end", text=f"{protocol} Packet", open=True)
                
                # Add general information
                general = self.details_tree.insert(parent, "end", text="General Information", open=True)
                self.details_tree.insert(general, "end", text=f"Time: {packet_info['timestamp']}")
                self.details_tree.insert(general, "end", text=f"Length: {packet_info['length']} bytes")
                
                # Add source information
                source = self.details_tree.insert(parent, "end", text="Source", open=True)
                self.details_tree.insert(source, "end", text=f"IP: {packet_info['src_ip']}")
                self.details_tree.insert(source, "end", text=f"Port: {packet_info['src_port']}")
                
                # Add destination information
                dest = self.details_tree.insert(parent, "end", text="Destination", open=True)
                self.details_tree.insert(dest, "end", text=f"IP: {packet_info['dst_ip']}")
                self.details_tree.insert(dest, "end", text=f"Port: {packet_info['dst_port']}")
                
                # Add protocol specific information
                proto_info = self.details_tree.insert(parent, "end", text=f"{protocol} Information", open=True)
                self.details_tree.insert(proto_info, "end", text=f"Info: {packet_info['info']}")
                
                # Update hex dump
                if 'packet' in packet_info:
                    hex_dump = PacketProcessor.get_hex_dump(packet_info['packet'])
                    self.hex_text.delete(1.0, tk.END)
                    self.hex_text.insert(tk.END, hex_dump)

if __name__ == "__main__":
    root = tk.Tk()
    app = TrafnalyzerApp(root)
    root.mainloop() 