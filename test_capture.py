#!/usr/bin/env python3
import scapy.all as scapy
import time
import sys

def packet_callback(packet):
    print(f"Captured: {packet.summary()}")

def main():
    print("Available interfaces:")
    for iface in scapy.get_if_list():
        print(f" - {iface}")
    
    # Use the first interface by default or let user specify
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    else:
        interface = scapy.get_if_list()[0]
    
    print(f"\nStarting packet capture on interface: {interface}")
    print("Press Ctrl+C to stop")
    
    try:
        # Try with a timeout to make it more responsive
        while True:
            print("Starting sniff cycle...")
            packets = scapy.sniff(iface=interface, count=5, timeout=2, store=True)
            print(f"Captured {len(packets)} packets in this cycle")
            
            for packet in packets:
                print(f"Packet: {packet.summary()}")
            
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main() 