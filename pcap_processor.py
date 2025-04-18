import logging
import math
import socket
import time
import numpy as np
import os
import gc
import subprocess
import json
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, Ether, ARP
from scapy.error import Scapy_Exception
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLS
from scapy.utils import PcapReader

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('pcap_processor')

def process_pcap_file(filepath):
    """
    Process a PCAP file and extract features for analysis
    
    Args:
        filepath: Path to the PCAP file
        
    Returns:
        List of dictionaries containing extracted features
    """
    try:
        start_time = time.time()
        logger.info(f"Reading PCAP file: {filepath}")
        
        # Check file size for memory management
        file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
        logger.info(f"PCAP file size: {file_size_mb:.2f} MB")
        
        # Adjust chunk size based on file size
        if file_size_mb > 500:
            chunk_size = 500
        elif file_size_mb > 100:
            chunk_size = 1000
        else:
            chunk_size = 2000
            
        # Process packets in chunks to avoid loading the entire file into memory
        packet_features = []
        total_packets = 0
        processed_packets = 0
        skipped_packets = 0
        errors = 0
        
        with PcapReader(filepath) as pcap_reader:
            current_chunk = []
            packet_timestamps = {}  # Store packet timestamps for analysis
            
            for packet_idx, packet in enumerate(pcap_reader):
                total_packets += 1
                
                try:
                    # Extract features for this packet
                    features = extract_packet_features(packet)
                    
                    # Store timestamp if available
                    if hasattr(packet, 'time'):
                        packet_timestamps[packet_idx] = packet.time
                    
                    if features:
                        # Add packet index and timestamp
                        features['packet_idx'] = packet_idx
                        if hasattr(packet, 'time'):
                            features['timestamp'] = packet.time
                            
                        # Ensure IP addresses are extracted
                        if 'src_ip' not in features and IP in packet:
                            features['src_ip'] = packet[IP].src
                        if 'dst_ip' not in features and IP in packet:
                            features['dst_ip'] = packet[IP].dst
                        
                        current_chunk.append(features)
                        processed_packets += 1
                    else:
                        skipped_packets += 1
                except Exception as e:
                    errors += 1
                    if errors <= 10:  # Limit error logging to prevent overwhelming logs
                        logger.error(f"Error processing packet {packet_idx}: {str(e)}")
                    
                # Process in chunks to manage memory
                if len(current_chunk) >= chunk_size:
                    packet_features.extend(current_chunk)
                    logger.info(f"Processed {processed_packets} packets, skipped {skipped_packets}, errors {errors}")
                    current_chunk = []
                    
                    gc.collect()
                    
            # Add any remaining packets in the last chunk
            if current_chunk:
                packet_features.extend(current_chunk)
        
        # Calculate relative timestamps if real timestamps unavailable
        if not any('timestamp' in p for p in packet_features) and packet_features:
            logger.info("No timestamps found, using sequential packet numbering")
            base_time = time.time()  # Use current time as base
            for i, features in enumerate(packet_features):
                features['timestamp'] = base_time + (i * 0.001)  # Add milliseconds
        
        # Enrich with traffic flow information
        enrich_with_flow_data(packet_features)
                
        elapsed = time.time() - start_time
        logger.info(f"Completed processing: extracted features from {processed_packets} out of {total_packets} packets in {elapsed:.2f} seconds")
        logger.info(f"Skipped packets: {skipped_packets}, Errors: {errors}")
        
        # Final validation to ensure we have IP addresses
        ip_count = len(set(p.get('src_ip') for p in packet_features if p.get('src_ip')) | 
                      set(p.get('dst_ip') for p in packet_features if p.get('dst_ip')))
        logger.info(f"Extracted {ip_count} unique IP addresses from PCAP")
        
        # Print a sample of the extracted IPs for debugging
        if packet_features:
            ip_samples = set()
            for p in packet_features[:20]:  # Check first 20 packets
                if p.get('src_ip'):
                    ip_samples.add(p.get('src_ip'))
                if p.get('dst_ip'):
                    ip_samples.add(p.get('dst_ip'))
            
            logger.info(f"Sample IPs extracted: {list(ip_samples)[:10]}")
        
        return packet_features
    
    except Exception as e:
        logger.error(f"Error in process_pcap_file: {e}")
        return []

def try_alternative_pcap_method(filepath):
    """
    Try alternative method for reading PCAP files if Scapy fails
    
    Args:
        filepath: Path to the PCAP file
        
    Returns:
        List of dictionaries containing extracted features (simplified)
    """
    logger.info("Trying alternative PCAP reading method")
    packet_features = []
    
    try:
        # Check if tshark is available
        try:
            subprocess.run(['tshark', '--version'], stdout=subprocess.PIPE, check=True)
            logger.info("Using tshark for PCAP processing")
            
            # Extract basic packet info using tshark JSON output with more fields
            cmd = [
                'tshark', '-r', filepath, '-T', 'json', 
                '-e', 'ip.src', '-e', 'ip.dst', '-e', 'ipv6.src', '-e', 'ipv6.dst',
                '-e', 'tcp.srcport', '-e', 'tcp.dstport',
                '-e', 'udp.srcport', '-e', 'udp.dstport',
                '-e', 'frame.protocols', '-e', 'frame.time_epoch',
                '-e', 'frame.len', '-e', 'ip.proto', '-e', 'arp.src.proto_ipv4', 
                '-e', 'arp.dst.proto_ipv4', '-e', 'eth.src', '-e', 'eth.dst'
            ]
            
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                logger.error(f"Tshark error: {result.stderr.decode()}")
                return []
                
            data = json.loads(result.stdout.decode())
            
            for packet in data:
                if '_source' not in packet or 'layers' not in packet['_source']:
                    continue
                    
                layers = packet['_source']['layers']
                
                features = {}
                features['packet_size'] = int(layers.get('frame.len', [0])[0])
                
                # Process IPv4
                if 'ip.src' in layers and 'ip.dst' in layers:
                    features['src_ip'] = layers['ip.src'][0]
                    features['dst_ip'] = layers['ip.dst'][0]
                    
                    # Determine protocol
                    if 'tcp.srcport' in layers and 'tcp.dstport' in layers:
                        features['src_port'] = int(layers['tcp.srcport'][0])
                        features['dst_port'] = int(layers['tcp.dstport'][0])
                        features['protocol_name'] = 'TCP'
                    elif 'udp.srcport' in layers and 'udp.dstport' in layers:
                        features['src_port'] = int(layers['udp.srcport'][0])
                        features['dst_port'] = int(layers['udp.dstport'][0])
                        features['protocol_name'] = 'UDP'
                    else:
                        features['src_port'] = 0
                        features['dst_port'] = 0
                        if 'ip.proto' in layers:
                            proto = int(layers['ip.proto'][0])
                            if proto == 1:
                                features['protocol_name'] = 'ICMP'
                            else:
                                features['protocol_name'] = f'IP-{proto}'
                        else:
                            features['protocol_name'] = 'IP-OTHER'
                
                # Process IPv6
                elif 'ipv6.src' in layers and 'ipv6.dst' in layers:
                    features['src_ip'] = layers['ipv6.src'][0]
                    features['dst_ip'] = layers['ipv6.dst'][0]
                    
                    # Get ports if available
                    if 'tcp.srcport' in layers and 'tcp.dstport' in layers:
                        features['src_port'] = int(layers['tcp.srcport'][0])
                        features['dst_port'] = int(layers['tcp.dstport'][0])
                        features['protocol_name'] = 'TCP'
                    elif 'udp.srcport' in layers and 'udp.dstport' in layers:
                        features['src_port'] = int(layers['udp.srcport'][0])
                        features['dst_port'] = int(layers['udp.dstport'][0])
                        features['protocol_name'] = 'UDP'
                    else:
                        features['src_port'] = 0
                        features['dst_port'] = 0
                        features['protocol_name'] = 'IPv6-OTHER'
                
                # Process ARP
                elif 'arp.src.proto_ipv4' in layers and 'arp.dst.proto_ipv4' in layers:
                    features['src_ip'] = layers['arp.src.proto_ipv4'][0]
                    features['dst_ip'] = layers['arp.dst.proto_ipv4'][0]
                    features['src_port'] = 0
                    features['dst_port'] = 0
                    features['protocol_name'] = 'ARP'
                
                # Fall back to MAC addresses if no IPs found
                elif 'eth.src' in layers and 'eth.dst' in layers:
                    features['eth_src'] = layers['eth.src'][0]
                    features['eth_dst'] = layers['eth.dst'][0]
                    features['protocol_name'] = 'ETH-OTHER'
                    
                    # Create fake IPs from MACs for visualization
                    mac_to_ip = lambda mac: '192.168.' + '.'.join([str(int(octet, 16)) for octet in mac.split(':')[-2:]])
                    features['src_ip'] = mac_to_ip(layers['eth.src'][0])
                    features['dst_ip'] = mac_to_ip(layers['eth.dst'][0])
                    features['src_port'] = 0
                    features['dst_port'] = 0
                
                # Add timestamp if available
                if 'frame.time_epoch' in layers:
                    features['timestamp'] = float(layers['frame.time_epoch'][0])
                
                # Only add packets that have at least IP information
                if 'src_ip' in features and 'dst_ip' in features:
                    packet_features.append(features)
            
            logger.info(f"Extracted {len(packet_features)} packets using tshark")
            return packet_features
            
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.warning("Tshark not available, trying another method")
            
            # Try direct raw packet analysis
            try:
                from scapy.all import PcapReader
                
                alt_packets = []
                with PcapReader(filepath) as reader:
                    for packet in reader:
                        feature = {}
                        
                        # Try to extract IP information
                        if IP in packet:
                            feature['src_ip'] = packet[IP].src
                            feature['dst_ip'] = packet[IP].dst
                            feature['protocol'] = packet[IP].proto
                            feature['packet_size'] = len(packet)
                            
                            # Get protocol and port information
                            if TCP in packet:
                                feature['protocol_name'] = 'TCP'
                                feature['src_port'] = packet[TCP].sport
                                feature['dst_port'] = packet[TCP].dport
                            elif UDP in packet:
                                feature['protocol_name'] = 'UDP'
                                feature['src_port'] = packet[UDP].sport
                                feature['dst_port'] = packet[UDP].dport
                            elif ICMP in packet:
                                feature['protocol_name'] = 'ICMP'
                                feature['src_port'] = 0
                                feature['dst_port'] = 0
                            else:
                                feature['protocol_name'] = f"IP-{packet[IP].proto}"
                                feature['src_port'] = 0
                                feature['dst_port'] = 0
                                
                            alt_packets.append(feature)
                
                if alt_packets:
                    logger.info(f"Extracted {len(alt_packets)} packets using direct Scapy reading")
                    return alt_packets
            except Exception as scapy_e:
                logger.error(f"Direct Scapy reading failed: {scapy_e}")
    
    except Exception as e:
        logger.error(f"Alternative method failed: {e}")
    
    # If all else fails, return empty list
    logger.error("All PCAP processing methods failed")
    return []

def get_ip_communication_data(packet_features, threat_name=None):
    """
    Analyze packet features to extract IP communication data for visualization
    
    Args:
        packet_features: List of dictionaries containing packet features
        threat_name: Optional threat name for filtering
        
    Returns:
        Dictionary with involved_ips, traffic_flows, graph_nodes, and graph_links
    """
    if not packet_features:
        logger.warning("No packet features provided for IP communication analysis")
        return {
            'involved_ips': [],
            'traffic_flows': [],
            'graph_nodes': [],
            'graph_links': []
        }
    
    logger.info(f"Analyzing IP communication data from {len(packet_features)} packets")
    
    # Track IP details
    ip_details = {}
    
    # Track flow information
    flows = {}
    
    # Process all packets
    for packet in packet_features:
        if not isinstance(packet, dict):
            continue
            
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        
        if not src_ip or not dst_ip:
            continue
            
        # Update IP tracking
        for ip, role in [(src_ip, 'source'), (dst_ip, 'destination')]:
            if ip not in ip_details:
                ip_details[ip] = {
                    'address': ip,
                    'packets_sent': 0,
                    'packets_received': 0,
                    'data_sent': 0,
                    'data_received': 0,
                    'targets': set(),
                    'sources': set(),
                    'is_internal': is_likely_internal_ip(ip),
                    'first_seen': packet.get('timestamp', 0),
                    'last_seen': packet.get('timestamp', 0)
                }
                
            details = ip_details[ip]
            
            # Update timestamp information
            if packet.get('timestamp'):
                if not details['first_seen'] or packet['timestamp'] < details['first_seen']:
                    details['first_seen'] = packet['timestamp']
                if not details['last_seen'] or packet['timestamp'] > details['last_seen']:
                    details['last_seen'] = packet['timestamp']
                    
            # Update traffic statistics
            if role == 'source':
                details['packets_sent'] += 1
                details['data_sent'] += packet.get('packet_size', 0)
                if dst_ip:
                    details['targets'].add(dst_ip)
            else:
                details['packets_received'] += 1
                details['data_received'] += packet.get('packet_size', 0)
                if src_ip:
                    details['sources'].add(src_ip)
        
        # Update flow tracking
        src_port = packet.get('src_port', 0)
        dst_port = packet.get('dst_port', 0)
        protocol = packet.get('protocol_name', 'UNKNOWN')
        
        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}-{protocol}"
        
        if flow_key not in flows:
            flows[flow_key] = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'packet_count': 0,
                'data_volume': 0,
                'first_packet': packet.get('timestamp', 0),
                'last_packet': packet.get('timestamp', 0)
            }
            
        # Update flow statistics
        flow = flows[flow_key]
        flow['packet_count'] += 1
        flow['data_volume'] += packet.get('packet_size', 0)
        
        # Update timestamps
        if packet.get('timestamp'):
            if not flow['first_packet'] or packet['timestamp'] < flow['first_packet']:
                flow['first_packet'] = packet['timestamp']
            if not flow['last_packet'] or packet['timestamp'] > flow['last_packet']:
                flow['last_packet'] = packet['timestamp']
    
    # Prepare involved_ips list - filter by threat if provided
    involved_ips = []
    
    # Determine which IPs are relevant to the threat
    threat_relevant_ips = set()
    if threat_name:
        threat_lower = threat_name.lower()
        
        # Port scanning threats - focus on IPs with many outgoing connections
        if any(term in threat_lower for term in ['scan', 'reconn', 'probe']):
            for ip, details in ip_details.items():
                if len(details['targets']) > 10:  # Many targets = potential scanner
                    threat_relevant_ips.add(ip)
                    # Also include its targets
                    threat_relevant_ips.update(details['targets'])
        
        # DoS threats - focus on IPs with high traffic
        elif any(term in threat_lower for term in ['denial', 'dos', 'ddos', 'flood']):
            # Find average traffic
            avg_packets = sum(d['packets_sent'] + d['packets_received'] for d in ip_details.values()) / max(1, len(ip_details))
            
            # IPs with traffic well above average
            for ip, details in ip_details.items():
                total_packets = details['packets_sent'] + details['packets_received']
                if total_packets > avg_packets * 2:
                    threat_relevant_ips.add(ip)
                    # Also include its communication partners
                    threat_relevant_ips.update(details['targets'])
                    threat_relevant_ips.update(details['sources'])
        
        # Malware/C2 threats - focus on IPs with beaconing or exfiltration
        elif any(term in threat_lower for term in ['malware', 'c2', 'command', 'exfil']):
            for ip, details in ip_details.items():
                # Look for IPs with unusual connection ratios
                outgoing = len(details['targets'])
                incoming = len(details['sources'])
                
                if (outgoing > 3 and outgoing > incoming * 2) or (incoming > 3 and incoming > outgoing * 2):
                    threat_relevant_ips.add(ip)
                    # Also add its communication partners
                    threat_relevant_ips.update(details['targets'])
                    threat_relevant_ips.update(details['sources'])
        
        # If no IPs found with heuristics, include top traffic IPs
        if not threat_relevant_ips:
            sorted_ips = sorted(ip_details.keys(), 
                              key=lambda ip: ip_details[ip]['packets_sent'] + ip_details[ip]['packets_received'], 
                              reverse=True)
            # Take top 25% of IPs by traffic volume
            threat_relevant_ips = set(sorted_ips[:max(2, len(sorted_ips) // 4)])
    
    # If no threat specified, include all IPs
    if not threat_name:
        threat_relevant_ips = set(ip_details.keys())
    
    # Generate involved_ips list
    for ip, details in ip_details.items():
        # Skip if not related to this threat
        if threat_name and ip not in threat_relevant_ips:
            continue
            
        # Determine primary role based on traffic
        total_sent = details['packets_sent']
        total_received = details['packets_received']
        
        if total_sent > total_received * 2:
            role = "Source"
        elif total_received > total_sent * 2:
            role = "Destination"
        else:
            role = "Both"
        
        # Determine risk level based on traffic patterns
        if threat_name:
            # For scanning threats
            if any(term in threat_name.lower() for term in ['scan', 'reconn', 'probe']):
                if len(details['targets']) > 20:
                    risk_level = "High"
                elif len(details['targets']) > 10:
                    risk_level = "Medium"
                else:
                    risk_level = "Low"
            # For DoS threats
            elif any(term in threat_name.lower() for term in ['denial', 'dos', 'ddos', 'flood']):
                total_packets = total_sent + total_received
                if total_packets > 100:
                    risk_level = "High"
                elif total_packets > 50:
                    risk_level = "Medium"
                else:
                    risk_level = "Low"
            # For Malware/C2 threats
            elif any(term in threat_name.lower() for term in ['malware', 'c2', 'command', 'exfil']):
                outgoing = len(details['targets'])
                incoming = len(details['sources'])
                
                if outgoing > 3 and outgoing > incoming * 2:
                    risk_level = "High"  # Potential C2 client
                elif incoming > outgoing * 3:
                    risk_level = "High"  # Potential C2 server
                else:
                    risk_level = "Medium"
            else:
                risk_level = "Medium"
        else:
            # General risk assessment without threat context
            total_connections = len(details['targets']) + len(details['sources'])
            if total_connections > 20:
                risk_level = "Medium"
            else:
                risk_level = "Low"
        
        # Calculate traffic percentage
        total_all_packets = sum(d['packets_sent'] + d['packets_received'] for d in ip_details.values())
        ip_total_packets = total_sent + total_received
        traffic_percentage = round((ip_total_packets / total_all_packets) * 100, 1) if total_all_packets > 0 else 0
        
        # Format data sizes for display
        data_sent = f"{details['data_sent'] / 1024:.2f} KB"
        data_received = f"{details['data_received'] / 1024:.2f} KB"
        
        # Add IP to involved_ips list
        involved_ips.append({
            'address': ip,
            'role': role,
            'traffic_percentage': traffic_percentage,
            'risk_level': risk_level,
            'packets_sent': total_sent,
            'packets_received': total_received,
            'data_sent': data_sent,
            'data_received': data_received,
            'is_internal': details['is_internal'],
            'location': 'Internal Network' if details['is_internal'] else 'External Network'
        })
    
    # Sort by risk level and traffic percentage
    involved_ips.sort(key=lambda ip: (
        {'High': 3, 'Medium': 2, 'Low': 1}.get(ip['risk_level'], 0),
        ip['traffic_percentage']
    ), reverse=True)
    
    # Prepare traffic_flows list
    traffic_flows = []
    # Convert to list format
    for flow_key, flow in flows.items():
        # Calculate duration if timestamps available
        duration = "N/A"
        if flow['first_packet'] and flow['last_packet'] and flow['last_packet'] > flow['first_packet']:
            time_diff = flow['last_packet'] - flow['first_packet']
            if time_diff > 60:
                minutes = int(time_diff / 60)
                seconds = int(time_diff % 60)
                duration = f"{minutes}m {seconds}s"
            else:
                duration = f"{int(time_diff)}s"
        
        # Format timestamps to readable format
        first_packet = format_timestamp(flow['first_packet'])
        last_packet = format_timestamp(flow['last_packet'])
        
        # Format data volume
        data_volume = f"{flow['data_volume'] / 1024:.2f} KB"
        
        # Check if flow involves any threatened IPs
        is_malicious = False
        if threat_name:
            if flow['src_ip'] in threat_relevant_ips or flow['dst_ip'] in threat_relevant_ips:
                is_malicious = True
        
        # Add to traffic flows list
        traffic_flows.append({
            'src_ip': flow['src_ip'],
            'dst_ip': flow['dst_ip'],
            'protocol': flow['protocol'],
            'src_port': flow['src_port'],
            'dst_port': flow['dst_port'],
            'packet_count': flow['packet_count'],
            'data_volume': data_volume,
            'first_packet': first_packet,
            'last_packet': last_packet,
            'duration': duration,
            'is_malicious': is_malicious
        })
    
    # Sort flows by packet count (descending)
    traffic_flows.sort(key=lambda f: f['packet_count'], reverse=True)
    
    # Limit to top 100 flows for performance
    traffic_flows = traffic_flows[:100]
    
    # Prepare graph nodes
    graph_nodes = []
    for ip, details in ip_details.items():
        node = {
            'id': ip,
            'group': 'internal' if details['is_internal'] else 'external',
            'suspicious': ip in threat_relevant_ips if threat_name else False
        }
        graph_nodes.append(node)
    
    # Prepare graph links
    graph_links = []
    # Create a map of unique connections
    connections = {}
    for flow in flows.values():
        src_ip = flow['src_ip']
        dst_ip = flow['dst_ip']
        
        # Create a connection key
        connection_key = f"{src_ip}->{dst_ip}"
        
        if connection_key not in connections:
            connections[connection_key] = {
                'source': src_ip,
                'target': dst_ip,
                'count': 0,
                'size': 0
            }
        
        # Update connection stats
        connections[connection_key]['count'] += flow['packet_count']
        connections[connection_key]['size'] += flow['data_volume']
    
    # Convert to links format for visualization
    for conn in connections.values():
        # Scale value based on packet count (1-5 range)
        value = min(5, max(1, int(conn['count'] / 10))) if conn['count'] >= 10 else 1
        
        # Check if connection involves any threatened IPs
        suspicious = False
        if threat_name:
            if conn['source'] in threat_relevant_ips or conn['target'] in threat_relevant_ips:
                suspicious = True
        
        link = {
            'source': conn['source'],
            'target': conn['target'],
            'value': value,
            'suspicious': suspicious
        }
        graph_links.append(link)
    
    return {
        'involved_ips': involved_ips,
        'traffic_flows': traffic_flows,
        'graph_nodes': graph_nodes,
        'graph_links': graph_links
    }

def extract_packet_features(packet):
    """
    Extract relevant features from a packet for machine learning analysis
    
    Args:
        packet: Scapy packet object
        
    Returns:
        Dictionary of features or None if packet doesn't contain relevant information
    """
    features = {}
    
    # Extract frame time if available
    if hasattr(packet, 'time'):
        features['timestamp'] = float(packet.time)
    
    # Check for Ethernet layer
    if Ether in packet:
        eth = packet[Ether]
        features['eth_src'] = eth.src
        features['eth_dst'] = eth.dst
        features['eth_type'] = eth.type
    
    # Check for ARP
    if ARP in packet:
        arp = packet[ARP]
        features['protocol_name'] = 'ARP'
        features['src_ip'] = arp.psrc
        features['dst_ip'] = arp.pdst
        features['src_port'] = 0
        features['dst_port'] = 0
        features['arp_op'] = arp.op
        features['packet_size'] = len(packet)
        return features
    
    # Handle IP layer packets
    if IP in packet:
        ip = packet[IP]
        features['src_ip'] = ip.src
        features['dst_ip'] = ip.dst
        features['ttl'] = ip.ttl
        features['protocol'] = ip.proto
        features['packet_size'] = len(packet)
        features['header_length'] = ip.ihl * 4
        features['ip_id'] = ip.id
        features['ip_flags'] = ip.flags
        features['ip_frag'] = ip.frag
        
        # Check for payload
        if hasattr(ip, 'payload') and len(ip.payload) > 0:
            features['has_payload'] = True
            features['payload_length'] = len(ip.payload)
            
            # Calculate payload entropy
            try:
                features['payload_entropy'] = calculate_entropy(bytes(ip.payload))
            except Exception:
                features['payload_entropy'] = 0
        else:
            features['has_payload'] = False
            features['payload_length'] = 0
            features['payload_entropy'] = 0
        
        # Protocol-specific features
        if TCP in packet:
            tcp = packet[TCP]
            features['protocol_name'] = 'TCP'
            features['src_port'] = tcp.sport
            features['dst_port'] = tcp.dport
            features['tcp_flags'] = tcp.flags
            features['tcp_flags_str'] = flags_to_str(tcp.flags)
            features['seq_number'] = tcp.seq
            features['ack_number'] = tcp.ack
            features['window_size'] = tcp.window
            features['tcp_options'] = extract_tcp_options(tcp)
            
            # Check for established connection flags
            if tcp.flags & 0x10:  # ACK flag
                features['is_established'] = True
            else:
                features['is_established'] = False
                
            # Check for SYN, FIN, RST
            features['is_syn'] = bool(tcp.flags & 0x02)
            features['is_fin'] = bool(tcp.flags & 0x01)
            features['is_rst'] = bool(tcp.flags & 0x04)
            features['is_push'] = bool(tcp.flags & 0x08)
            
        elif UDP in packet:
            udp = packet[UDP]
            features['protocol_name'] = 'UDP'
            features['src_port'] = udp.sport
            features['dst_port'] = udp.dport
            features['udp_length'] = udp.len
            
        elif ICMP in packet:
            icmp = packet[ICMP]
            features['protocol_name'] = 'ICMP'
            features['icmp_type'] = icmp.type
            features['icmp_code'] = icmp.code
            features['src_port'] = 0
            features['dst_port'] = 0
            
            # ICMP type descriptions
            icmp_types = {
                0: 'Echo Reply',
                3: 'Destination Unreachable',
                5: 'Redirect',
                8: 'Echo Request',
                11: 'Time Exceeded'
            }
            features['icmp_type_desc'] = icmp_types.get(icmp.type, 'Other')
            
        else:
            features['protocol_name'] = 'OTHER'
            features['src_port'] = 0
            features['dst_port'] = 0
        
        # DNS features
        if DNS in packet:
            features['has_dns'] = True
            dns = packet[DNS]
            
            try:
                if dns.qr == 0:  # Query
                    features['dns_type'] = 'query'
                    
                    # Extract query information
                    if dns.qd and dns.qd.qname:
                        features['dns_query'] = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                else:  # Response
                    features['dns_type'] = 'response'
                    features['dns_answers_count'] = dns.ancount
            except Exception as e:
                logger.debug(f"Error parsing DNS: {e}")
        else:
            features['has_dns'] = False
        
        # HTTP features
        if HTTPRequest in packet:
            features['has_http'] = True
            features['http_type'] = 'request'
            http = packet[HTTPRequest]
            
            try:
                features['http_method'] = http.Method.decode('utf-8', errors='ignore')
                features['http_uri'] = http.Path.decode('utf-8', errors='ignore')
                
                if hasattr(http, 'Host'):
                    features['http_host'] = http.Host.decode('utf-8', errors='ignore')
                    
                if hasattr(http, 'User_Agent'):
                    features['http_user_agent'] = http.User_Agent.decode('utf-8', errors='ignore')
            except Exception as e:
                logger.debug(f"Error parsing HTTP request: {e}")
        
        elif HTTPResponse in packet:
            features['has_http'] = True
            features['http_type'] = 'response'
            http = packet[HTTPResponse]
            
            try:
                if hasattr(http, 'Status_Code'):
                    features['http_status'] = int(http.Status_Code)
                    
                if hasattr(http, 'Content_Type'):
                    features['http_content_type'] = http.Content_Type.decode('utf-8', errors='ignore')
            except Exception as e:
                logger.debug(f"Error parsing HTTP response: {e}")
        else:
            features['has_http'] = False
        
        # TLS features
        if TLS in packet:
            features['has_tls'] = True
            tls = packet[TLS]
            
            try:
                features['tls_type'] = tls.type
                if hasattr(tls, 'version') and tls.version:
                    features['tls_version'] = tls.version
            except Exception as e:
                logger.debug(f"Error parsing TLS: {e}")
        else:
            features['has_tls'] = False
        
        # Detect common services based on port numbers
        features['service'] = detect_service(features.get('src_port', 0), features.get('dst_port', 0))
        
        return features
    
    # Handle IPv6 packets if they exist
    elif IPv6 in packet:
        ipv6 = packet[IPv6]
        features['src_ip'] = ipv6.src
        features['dst_ip'] = ipv6.dst
        features['protocol'] = ipv6.nh  # next header
        features['packet_size'] = len(packet)
        features['ipv6_flow'] = ipv6.fl
        features['ipv6_hlim'] = ipv6.hlim
        
        # Add protocol information
        if TCP in packet:
            tcp = packet[TCP]
            features['protocol_name'] = 'TCP'
            features['src_port'] = tcp.sport
            features['dst_port'] = tcp.dport
        elif UDP in packet:
            udp = packet[UDP]
            features['protocol_name'] = 'UDP'
            features['src_port'] = udp.sport
            features['dst_port'] = udp.dport
        else:
            features['protocol_name'] = 'IPv6-OTHER'
            features['src_port'] = 0
            features['dst_port'] = 0
            
        return features
    
    # Try to extract any IP-like strings from the packet
    try:
        raw_packet_bytes = bytes(packet)
        import re
        
        # IPv4 regex pattern
        ipv4_pattern = re.compile(b'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
        ipv4_matches = ipv4_pattern.findall(raw_packet_bytes)
        
        if len(ipv4_matches) >= 2:
            features['src_ip'] = ipv4_matches[0].decode('utf-8', errors='ignore')
            features['dst_ip'] = ipv4_matches[1].decode('utf-8', errors='ignore')
            features['protocol_name'] = 'UNKNOWN'
            features['packet_size'] = len(packet)
            features['src_port'] = 0
            features['dst_port'] = 0
            return features
    except Exception:
        pass
    
    # If we reach here, the packet doesn't have useful information
    return None

def extract_tcp_options(tcp):
    """Extract TCP options as a list of dictionaries"""
    if not hasattr(tcp, 'options') or not tcp.options:
        return []
        
    result = []
    for opt_kind, opt_value in tcp.options:
        if opt_kind == 'MSS':
            result.append({'kind': 'MSS', 'value': opt_value})
        elif opt_kind == 'WScale':
            result.append({'kind': 'WScale', 'value': opt_value})
        elif opt_kind == 'Timestamp':
            if isinstance(opt_value, tuple) and len(opt_value) == 2:
                result.append({'kind': 'Timestamp', 'value': f"{opt_value[0]},{opt_value[1]}"})
        else:
            result.append({'kind': str(opt_kind)})
            
    return result

def flags_to_str(flags):
    """Convert TCP flags to a readable string"""
    flags_str = ''
    if flags & 0x01: flags_str += 'F'  # FIN
    if flags & 0x02: flags_str += 'S'  # SYN
    if flags & 0x04: flags_str += 'R'  # RST
    if flags & 0x08: flags_str += 'P'  # PSH
    if flags & 0x10: flags_str += 'A'  # ACK
    if flags & 0x20: flags_str += 'U'  # URG
    if flags & 0x40: flags_str += 'E'  # ECE
    if flags & 0x80: flags_str += 'C'  # CWR
    return flags_str if flags_str else '.'

def detect_service(src_port, dst_port):
    """Detect common services based on port numbers"""
    ports = [src_port, dst_port]
    services = {
        20: 'FTP-data',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        67: 'DHCP',
        68: 'DHCP',
        69: 'TFTP',
        80: 'HTTP',
        110: 'POP3',
        119: 'NNTP',
        123: 'NTP',
        137: 'NetBIOS',
        139: 'NetBIOS',
        143: 'IMAP',
        161: 'SNMP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        1434: 'MSSQL',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        8080: 'HTTP-ALT',
        8443: 'HTTPS-ALT'
    }
    
    for port in ports:
        if port in services:
            return services[port]
    
    # Check for well-known ephemeral port ranges
    if (src_port > 1024 and dst_port < 1024):
        return services.get(dst_port, 'Unknown')
    elif (dst_port > 1024 and src_port < 1024):
        return services.get(src_port, 'Unknown')
    
    return 'Unknown'

def calculate_entropy(data):
    """
    Calculate Shannon entropy of a byte string
    
    Args:
        data: Bytes to calculate entropy for
        
    Returns:
        Entropy value (float)
    """
    if not data:
        return 0
    
    # Count occurrences of each byte
    counter = Counter(data)
    length = len(data)
    
    # Calculate entropy
    entropy = 0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy

def enrich_with_flow_data(packet_features):
    """
    Enrich packet features with flow information
    
    Args:
        packet_features: List of dictionaries containing packet features
    """
    if not packet_features:
        return
    
    # Group packets by flow
    flows = {}
    
    for packet in packet_features:
        # Create flow keys in both directions
        forward_key = f"{packet.get('src_ip')}:{packet.get('src_port')}->{packet.get('dst_ip')}:{packet.get('dst_port')}"
        reverse_key = f"{packet.get('dst_ip')}:{packet.get('dst_port')}->{packet.get('src_ip')}:{packet.get('src_port')}"
        
        # Use bi-directional flow
        flow_key = forward_key
        
        if flow_key not in flows and reverse_key not in flows:
            # New flow
            flows[flow_key] = {
                'packets': [packet],
                'start_time': packet.get('timestamp', 0),
                'end_time': packet.get('timestamp', 0),
                'src_to_dst_bytes': packet.get('packet_size', 0),
                'dst_to_src_bytes': 0,
                'src_to_dst_packets': 1,
                'dst_to_src_packets': 0
            }
        elif flow_key in flows:
            # Existing forward flow
            flow = flows[flow_key]
            flow['packets'].append(packet)
            flow['end_time'] = max(flow['end_time'], packet.get('timestamp', 0))
            flow['src_to_dst_bytes'] += packet.get('packet_size', 0)
            flow['src_to_dst_packets'] += 1
        elif reverse_key in flows:
            # Existing reverse flow
            flow = flows[reverse_key]
            flow['packets'].append(packet)
            flow['end_time'] = max(flow['end_time'], packet.get('timestamp', 0))
            flow['dst_to_src_bytes'] += packet.get('packet_size', 0)
            flow['dst_to_src_packets'] += 1
    
    # Annotate packets with flow information
    for flow_key, flow in flows.items():
        # Calculate flow metrics
        if flow['end_time'] > flow['start_time']:
            flow['duration'] = flow['end_time'] - flow['start_time']
        else:
            flow['duration'] = 0
            
        flow['total_bytes'] = flow['src_to_dst_bytes'] + flow['dst_to_src_bytes']
        flow['total_packets'] = flow['src_to_dst_packets'] + flow['dst_to_src_packets']
        
        if flow['total_packets'] > 0:
            flow['avg_bytes_per_packet'] = flow['total_bytes'] / flow['total_packets']
        else:
            flow['avg_bytes_per_packet'] = 0
        
        # Add flow ID to each packet
        for packet in flow['packets']:
            packet['flow_id'] = flow_key
            packet['flow_duration'] = flow['duration']
            packet['flow_total_bytes'] = flow['total_bytes']
            packet['flow_total_packets'] = flow['total_packets']
            
            # Calculate packet's position in flow
            if 'timestamp' in packet and flow['start_time'] > 0:
                packet['flow_position'] = packet['timestamp'] - flow['start_time']
            else:
                packet['flow_position'] = 0

def extract_statistical_features(packet_features):
    """
    Extract statistical features from a list of packet features
    
    Args:
        packet_features: List of dictionaries containing packet features
        
    Returns:
        Dictionary of statistical features
    """
    if not packet_features:
        return {}
    
    stats = {}
    
    # Count protocols
    protocols = [p.get('protocol_name', 'UNKNOWN') for p in packet_features]
    protocol_counter = {}
    for protocol in protocols:
        if protocol in protocol_counter:
            protocol_counter[protocol] += 1
        else:
            protocol_counter[protocol] = 1
    stats['protocol_counts'] = protocol_counter
    
    # Extract packet sizes
    packet_sizes = [p.get('packet_size', 0) for p in packet_features]
    if packet_sizes:
        # Chuyển đổi kết quả numpy về Python types
        stats['avg_packet_size'] = float(np.mean(packet_sizes)) if packet_sizes else 0
        stats['min_packet_size'] = int(np.min(packet_sizes)) if packet_sizes else 0
        stats['max_packet_size'] = int(np.max(packet_sizes)) if packet_sizes else 0
        stats['std_packet_size'] = float(np.std(packet_sizes)) if packet_sizes else 0
    else:
        stats['avg_packet_size'] = 0
        stats['min_packet_size'] = 0
        stats['max_packet_size'] = 0
        stats['std_packet_size'] = 0
    
    # Count unique IPs
    src_ips = set(p.get('src_ip', '') for p in packet_features if p.get('src_ip'))
    dst_ips = set(p.get('dst_ip', '') for p in packet_features if p.get('dst_ip'))
    stats['unique_src_ips'] = len(src_ips)
    stats['unique_dst_ips'] = len(dst_ips)
    
    # Count unique ports
    src_ports = set(p.get('src_port', 0) for p in packet_features if p.get('src_port') is not None)
    dst_ports = set(p.get('dst_port', 0) for p in packet_features if p.get('dst_port') is not None)
    stats['unique_src_ports'] = len(src_ports)
    stats['unique_dst_ports'] = len(dst_ports)
    
    # Check for common port scanning patterns
    common_scan_ports = {20, 21, 22, 23, 25, 53, 80, 110, 137, 138, 139, 143, 161, 443, 445, 1433, 3306, 3389, 8080}
    stats['potential_scan_ports'] = len(common_scan_ports.intersection(dst_ports))
    
    # Check for potential port scanning activity
    if len(dst_ports) > 10 and len(dst_ips) < 5:
        stats['potential_port_scan'] = True
    else:
        stats['potential_port_scan'] = False
    
    # Check for potential DoS pattern
    if len(src_ips) < 5 and len(dst_ips) < 5 and len(packet_features) > 100:
        stats['potential_dos'] = True
    else:
        stats['potential_dos'] = False
    
    return stats

def is_likely_internal_ip(ip):
    """Check if an IP is likely an internal IP address"""
    try:
        # Check RFC 1918 private ranges
        octets = ip.split('.')
        if len(octets) != 4:
            return False
            
        # 10.0.0.0/8
        if octets[0] == '10':
            return True
            
        # 172.16.0.0/12
        if octets[0] == '172' and 16 <= int(octets[1]) <= 31:
            return True
            
        # 192.168.0.0/16
        if octets[0] == '192' and octets[1] == '168':
            return True
            
        # Check for other common internal patterns
        if ip.startswith('169.254.'):  # Link-local
            return True
            
        if ip == '127.0.0.1':  # Localhost
            return True
            
        return False
    except Exception:
        return False

def debug_pcap_data(analysis):
    """
    Function to debug PCAP data extraction issues
    
    Args:
        analysis: Analysis object that should contain PCAP data
    """
    logger.info("=============== DEBUG PCAP DATA ===============")
    
    # 1. Check analysis object structure
    logger.info(f"Analysis object type: {type(analysis)}")
    logger.info(f"Analysis attributes: {dir(analysis)}")
    
    # 2. Check traffic_summary
    if hasattr(analysis, 'traffic_summary'):
        logger.info(f"traffic_summary exists and is type: {type(analysis.traffic_summary)}")
        if isinstance(analysis.traffic_summary, dict):
            logger.info(f"traffic_summary keys: {list(analysis.traffic_summary.keys())}")
            
            if 'packet_data' in analysis.traffic_summary:
                pd = analysis.traffic_summary['packet_data']
                logger.info(f"packet_data exists and is type: {type(pd)}")
                logger.info(f"packet_data length: {len(pd) if hasattr(pd, '__len__') else 'N/A'}")
                
                if isinstance(pd, list) and len(pd) > 0:
                    logger.info(f"First packet: {pd[0]}")
                    
                    # Check for IP addresses in packets
                    ips = set()
                    for p in pd[:10]:  # Check first 10 packets
                        if isinstance(p, dict):
                            if 'src_ip' in p:
                                ips.add(p['src_ip'])
                            if 'dst_ip' in p:
                                ips.add(p['dst_ip'])
                    
                    logger.info(f"Found IPs in first 10 packets: {ips}")
    else:
        logger.info("No traffic_summary found")
    
    # 3. Check result_summary
    if hasattr(analysis, 'result_summary'):
        logger.info(f"result_summary exists and is type: {type(analysis.result_summary)}")
        if isinstance(analysis.result_summary, dict):
            logger.info(f"result_summary keys: {list(analysis.result_summary.keys())}")
    else:
        logger.info("No result_summary found")
    
    # 4. Check raw_pcap_data
    if hasattr(analysis, 'raw_pcap_data'):
        logger.info(f"raw_pcap_data exists and is type: {type(analysis.raw_pcap_data)}")
        if isinstance(analysis.raw_pcap_data, list):
            logger.info(f"raw_pcap_data length: {len(analysis.raw_pcap_data)}")
            
            if len(analysis.raw_pcap_data) > 0:
                logger.info(f"First raw packet type: {type(analysis.raw_pcap_data[0])}")
        elif isinstance(analysis.raw_pcap_data, bytes):
            logger.info(f"raw_pcap_data is bytes with length: {len(analysis.raw_pcap_data)}")
    else:
        logger.info("No raw_pcap_data found")
    
    # 5. Check detected_threats
    if hasattr(analysis, 'detected_threats'):
        logger.info(f"detected_threats exists and is type: {type(analysis.detected_threats)}")
        if isinstance(analysis.detected_threats, list):
            logger.info(f"detected_threats length: {len(analysis.detected_threats)}")
            
            # Check for IPs in threats
            for i, threat in enumerate(analysis.detected_threats):
                if not isinstance(threat, dict):
                    continue
                
                logger.info(f"Threat {i} name: {threat.get('name')}")
                
                if 'involved_ips' in threat:
                    logger.info(f"  involved_ips exists: {threat['involved_ips']}")
                
                if 'src_ip' in threat:
                    logger.info(f"  src_ip exists: {threat['src_ip']}")
                
                if 'dst_ip' in threat:
                    logger.info(f"  dst_ip exists: {threat['dst_ip']}")
    else:
        logger.info("No detected_threats found")
    
    logger.info("=============== END DEBUG ===============")