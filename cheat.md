# Trafnalyzer Filter Cheat Sheet

## Basic Filters

| Filter | Description | Example |
|--------|-------------|---------|
| `tcp` | Show only TCP packets | `tcp` |
| `udp` | Show only UDP packets | `udp` |
| `icmp` | Show only ICMP packets | `icmp` |
| `dns` | Show only DNS packets | `dns` |
| `http` | Show only HTTP packets | `http` |
| `https` | Show only HTTPS packets | `https` |
| `arp` | Show only ARP packets | `arp` |

## IP Address Filters

| Filter | Description | Example |
|--------|-------------|---------|
| `ip.src==x.x.x.x` | Filter by source IP address | `ip.src==192.168.1.100` |
| `ip.dst==x.x.x.x` | Filter by destination IP address | `ip.dst==8.8.8.8` |
| `x.x.x.x` | Filter by any IP address (source or destination) | `192.168.1.1` |

## Port Filters

| Filter | Description | Example |
|--------|-------------|---------|
| `port==n` | Filter by port number (source or destination) | `port==80` |
| `port==http` | Filter by service name | `port==http` |

## Common Service Port Numbers

| Service | Port | Filter Example |
|---------|------|---------------|
| HTTP | 80 | `port==80` or `port==http` |
| HTTPS | 443 | `port==443` or `port==https` |
| DNS | 53 | `port==53` or `port==domain` |
| SSH | 22 | `port==22` or `port==ssh` |
| FTP | 21 | `port==21` or `port==ftp` |
| SMTP | 25 | `port==25` or `port==smtp` |
| POP3 | 110 | `port==110` or `port==pop3` |
| IMAP | 143 | `port==143` or `port==imap` |
| SNMP | 161 | `port==161` or `port==snmp` |
| RDP | 3389 | `port==3389` |

## Content Filters

| Filter | Description | Example |
|--------|-------------|---------|
| Any text | Filter by any text in packet info | `GET` (finds HTTP GET requests) |
| `SYN` | Find TCP SYN packets | `SYN` |
| `ACK` | Find TCP ACK packets | `ACK` |
| `FIN` | Find TCP FIN packets | `FIN` |
| `RST` | Find TCP RST packets | `RST` |

## Combining Filters

You can combine filters by typing multiple terms. Trafnalyzer will show packets that match ANY of the terms.

Examples:
- `http GET` - Shows HTTP packets containing GET requests
- `dns google` - Shows DNS packets related to Google domains
- `port==443 192.168.1.100` - Shows HTTPS traffic to/from 192.168.1.100

## Tips

1. Filters are case-insensitive (`HTTP` and `http` work the same)
2. Clear the filter field and press Enter to show all packets
3. Press Enter or click "Apply" after typing a filter to apply it
4. The filter applies to all currently captured packets
5. You can filter by any text that appears in the packet details

## Examples of Common Tasks

| Task | Filter |
|------|--------|
| Find web browsing traffic | `http` or `https` |
| Find DNS queries | `dns` |
| Find TCP connection establishments | `SYN` |
| Find TCP connection terminations | `FIN` |
| Find traffic to Google DNS | `8.8.8.8` |
| Find SSH connections | `port==22` |
| Find all traffic from a specific host | `ip.src==192.168.1.100` |
| Find all traffic to a specific host | `ip.dst==192.168.1.100` | 