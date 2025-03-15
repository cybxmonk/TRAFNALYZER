#!/usr/bin/env python3
import socket
import time
import random

def generate_http_traffic():
    """Generate some HTTP traffic by making requests to popular websites"""
    websites = [
        "www.google.com",
        "www.bing.com",
        "www.github.com",
        "www.stackoverflow.com",
        "www.python.org"
    ]
    
    for site in websites:
        try:
            print(f"Connecting to {site}...")
            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            
            # Connect to the server
            s.connect((site, 80))
            
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {site}\r\nUser-Agent: TrafficGenerator/1.0\r\n\r\n"
            s.send(request.encode())
            
            # Receive response
            response = s.recv(4096)
            print(f"Received {len(response)} bytes from {site}")
            
            # Close the socket
            s.close()
            
            # Wait a bit before the next request
            time.sleep(1)
        except Exception as e:
            print(f"Error connecting to {site}: {e}")

def generate_udp_traffic():
    """Generate some UDP traffic"""
    udp_targets = [
        ("8.8.8.8", 53),  # Google DNS
        ("1.1.1.1", 53),   # Cloudflare DNS
    ]
    
    for target, port in udp_targets:
        try:
            print(f"Sending UDP packet to {target}:{port}...")
            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            
            # Send some data
            data = bytes([random.randint(0, 255) for _ in range(64)])
            s.sendto(data, (target, port))
            
            # Try to receive a response
            try:
                response, addr = s.recvfrom(4096)
                print(f"Received {len(response)} bytes from {addr}")
            except socket.timeout:
                print("No response received (timeout)")
            
            # Close the socket
            s.close()
            
            # Wait a bit before the next packet
            time.sleep(1)
        except Exception as e:
            print(f"Error sending UDP packet to {target}:{port}: {e}")

if __name__ == "__main__":
    print("Generating network traffic for testing...")
    
    # Generate HTTP traffic
    print("\nGenerating HTTP traffic:")
    generate_http_traffic()
    
    # Generate UDP traffic
    print("\nGenerating UDP traffic:")
    generate_udp_traffic()
    
    print("\nTraffic generation complete!") 