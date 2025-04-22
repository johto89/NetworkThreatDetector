import numpy as np
import logging
from collections import defaultdict, Counter
import time
from scipy.stats import entropy
import statistics
from models import ThreatCategoryEnum
from iputils import is_whitelisted_ip, filter_whitelisted_ips

def detect_zero_day_apt_threats(packet_features, feature_vector=None):
    """
    Detect potential zero-day threats and APTs based on anomaly detection
    without requiring a pre-trained model
    
    Args:
        packet_features: Raw packet feature dictionaries
        feature_vector: Optional extracted feature vector for the traffic
        
    Returns:
        List of detected zero-day or APT threats
    """
    threats = []
    
    if not packet_features:
        return threats
    
    # Use a timeout to prevent excessive processing
    timeout = 30  # seconds
    start_time = time.time()
    
    # Detect using multiple methods for higher confidence
    apt_results = detect_apt_patterns(packet_features)
    if apt_results['apt_detected']:
        threats.append({
            'name': ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
            'confidence': apt_results['confidence'],
            'description': 'Potential Advanced Persistent Threat (APT) activity detected',
            'indicators': apt_results['indicators']
        })
    
    if time.time() - start_time > timeout:
        return threats
    
    # Detect statistical anomalies
    statistical_anomalies = detect_statistical_anomalies(packet_features)
    if len(statistical_anomalies) >= 3:
        # If multiple significant anomalies are detected, flag as zero-day
        threats.append({
            'name': ThreatCategoryEnum.UNKNOWN,
            'confidence': min(0.85, 0.65 + (len(statistical_anomalies) * 0.05)),
            'description': 'Potential zero-day exploit or unknown attack pattern detected',
            'indicators': [
                f'{len(statistical_anomalies)} significant statistical anomalies detected',
                'Unusual traffic patterns not matching known threat signatures',
                f'Anomaly types: {", ".join([a["type"] for a in statistical_anomalies[:3]])}'
            ]
        })
    
    if time.time() - start_time > timeout:
        return threats
    
    # Detect protocol anomalies
    protocol_anomalies = detect_protocol_anomalies(packet_features)
    if len(protocol_anomalies) >= 2:
        # If multiple protocol anomalies are detected, flag as zero-day
        threats.append({
            'name': ThreatCategoryEnum.UNKNOWN,
            'confidence': min(0.85, 0.65 + (len(protocol_anomalies) * 0.05)),
            'description': 'Potential protocol manipulation indicating zero-day exploit',
            'indicators': [
                f'{len(protocol_anomalies)} protocol anomalies detected',
                'Unusual protocol behavior potentially exploiting vulnerabilities',
                f'Anomaly types: {", ".join([a["type"] for a in protocol_anomalies[:3]])}'
            ]
        })
    
    if time.time() - start_time > timeout:
        return threats
    
    # Detect behavior anomalies
    behavior_anomalies = detect_behavior_anomalies(packet_features)
    if len(behavior_anomalies) >= 2:
        # If multiple behavior anomalies are detected, flag as zero-day
        threats.append({
            'name': ThreatCategoryEnum.UNKNOWN,
            'confidence': min(0.80, 0.65 + (len(behavior_anomalies) * 0.05)),
            'description': 'Potential covert channel or evasion technique detected',
            'indicators': [
                f'{len(behavior_anomalies)} behavioral anomalies detected',
                'Unusual communication patterns potentially indicating zero-day',
                f'Anomaly types: {", ".join([a["type"] for a in behavior_anomalies[:3]])}'
            ]
        })
    
    # Deduplicate threats (if there are multiple zero-day threats, keep the highest confidence one)
    unique_threats = {}
    for threat in threats:
        name = threat['name']
        if name not in unique_threats or threat['confidence'] > unique_threats[name]['confidence']:
            unique_threats[name] = threat
    
    return list(unique_threats.values())

def detect_statistical_anomalies(packet_features):
    """Detect statistical anomalies in network traffic without using pre-trained models"""
    anomalies = []
    
    if not packet_features:
        return anomalies
    
    # Extract basic statistics
    packet_sizes = [p.get('packet_size', 0) for p in packet_features]
    payload_lengths = [p.get('payload_length', 0) for p in packet_features if p.get('payload_length', 0) > 0]
    payload_entropies = [p.get('payload_entropy', 0) for p in packet_features if p.get('payload_entropy', 0) > 0]
    
    # Destination IP and port cardinality
    dst_ips = [p.get('dst_ip', '') for p in packet_features if p.get('dst_ip')]
    dst_ports = [p.get('dst_port', 0) for p in packet_features if p.get('dst_port')]
    unique_dst_ips = len(set(dst_ips))
    unique_dst_ports = len(set(dst_ports))
    
    # Protocol distribution
    protocols = [p.get('protocol_name', 'UNKNOWN') for p in packet_features]
    protocol_counts = Counter(protocols)
    
    # Check for unusual packet size distribution
    if packet_sizes:
        avg_packet_size = sum(packet_sizes) / len(packet_sizes)
        std_packet_size = statistics.stdev(packet_sizes) if len(packet_sizes) > 1 else 0
        max_packet_size = max(packet_sizes)
        min_packet_size = min(packet_sizes)
        
        # Detect jumbo frames or unusually large packets
        if max_packet_size > 9000:
            anomalies.append({
                'type': 'LARGE_PACKET_SIZE',
                'description': 'Unusually large packets detected',
                'details': f'Max packet size: {max_packet_size} bytes'
            })
        
        # Detect high variance in packet sizes
        if std_packet_size > avg_packet_size * 2:
            anomalies.append({
                'type': 'PACKET_SIZE_VARIANCE',
                'description': 'Highly variable packet sizes',
                'details': f'StdDev: {std_packet_size:.2f}, Mean: {avg_packet_size:.2f}'
            })
    
    # Check for unusual payload entropy (potential encryption or obfuscation)
    if payload_entropies:
        avg_entropy = sum(payload_entropies) / len(payload_entropies)
        high_entropy_count = sum(1 for e in payload_entropies if e > 7.0)
        
        if avg_entropy > 6.5:
            anomalies.append({
                'type': 'HIGH_ENTROPY',
                'description': 'Unusually high payload entropy detected',
                'details': f'Average entropy: {avg_entropy:.2f}, {high_entropy_count} packets with entropy > 7.0'
            })
    
    # Check for unusual IP/port cardinality
    total_packets = len(packet_features)
    
    if total_packets > 50:
        # High number of destination IPs relative to packet count
        if unique_dst_ips > min(50, total_packets / 3):
            anomalies.append({
                'type': 'HIGH_IP_CARDINALITY',
                'description': 'Unusually high number of destination IPs',
                'details': f'{unique_dst_ips} unique IPs in {total_packets} packets'
            })
        
        # High number of destination ports relative to packet count
        if unique_dst_ports > min(50, total_packets / 3):
            anomalies.append({
                'type': 'HIGH_PORT_CARDINALITY',
                'description': 'Unusually high number of destination ports',
                'details': f'{unique_dst_ports} unique ports in {total_packets} packets'
            })
    
    # Check for unusual protocol distribution
    for protocol, count in protocol_counts.items():
        protocol_ratio = count / total_packets
        
        # Unusual protocol prevalence
        if protocol not in ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS'] and protocol_ratio > 0.3:
            anomalies.append({
                'type': 'UNUSUAL_PROTOCOL_DISTRIBUTION',
                'description': f'Unusual prevalence of {protocol} protocol',
                'details': f'{protocol} makes up {protocol_ratio:.1%} of traffic'
            })
    
    # Detect unusual data flow directions
    upload_volume = sum(p.get('payload_length', 0) for p in packet_features if p.get('src_port', 0) > 1024)
    download_volume = sum(p.get('payload_length', 0) for p in packet_features if p.get('dst_port', 0) > 1024)
    
    # Typically download volume is larger, so high upload/download ratio is suspicious
    if upload_volume > download_volume * 3 and upload_volume > 100000:
        anomalies.append({
            'type': 'UNUSUAL_DATA_FLOW',
            'description': 'Abnormally high upload to download ratio',
            'details': f'Upload: {upload_volume} bytes, Download: {download_volume} bytes'
        })
    
    return anomalies

def detect_protocol_anomalies(packet_features):
    """Detect anomalies in protocol usage and structure"""
    anomalies = []
    
    if not packet_features:
        return anomalies
    
    # Count packets by protocol
    protocol_counts = Counter([p.get('protocol_name', 'UNKNOWN') for p in packet_features])
    
    # Malformed packet detection
    malformed_packets = 0
    malformed_details = []
    
    # Protocol violation detection
    protocol_violations = 0
    violation_details = []
    
    # Encrypted protocol detection
    encrypted_unusual = 0
    encrypted_details = []
    
    # Analyze protocol structures
    for packet in packet_features:
        protocol = packet.get('protocol_name', 'UNKNOWN')
        
        # Check for malformed packets
        if packet.get('is_malformed', False) or packet.get('packet_error', False):
            malformed_packets += 1
            malformed_details.append(f"{protocol} (reason: {packet.get('packet_error_reason', 'unknown')})")
        
        # TCP protocol violations
        if protocol == 'TCP':
            # Invalid flag combinations
            tcp_flags = packet.get('tcp_flags', {})
            if hasattr(tcp_flags, '__contains__'):
                # Check for invalid flag combinations
                syn = 'SYN' in tcp_flags and tcp_flags['SYN']
                fin = 'FIN' in tcp_flags and tcp_flags['FIN']
                rst = 'RST' in tcp_flags and tcp_flags['RST']
                
                if (syn and fin) or (syn and rst) or (fin and rst):
                    protocol_violations += 1
                    violation_details.append('Invalid TCP flag combination')
            
            # Zero window with data
            if packet.get('tcp_window_size', 1) == 0 and packet.get('payload_length', 0) > 0:
                protocol_violations += 1
                violation_details.append('TCP zero window with data')
        
        # DNS protocol anomalies
        elif protocol == 'DNS':
            # Unusually long DNS names
            dns_query = packet.get('dns_query', '')
            if dns_query and len(dns_query) > 255:
                protocol_violations += 1
                violation_details.append(f'Excessive DNS query length: {len(dns_query)}')
            
            # DNS over non-standard ports
            dst_port = packet.get('dst_port', 0)
            if dst_port != 53 and dst_port != 5353:  # Standard DNS and mDNS ports
                protocol_violations += 1
                violation_details.append(f'DNS over non-standard port: {dst_port}')
        
        # HTTP protocol anomalies
        elif protocol == 'HTTP' or packet.get('dst_port') in [80, 443, 8080, 8443]:
            payload = packet.get('payload_str', '')
            
            # Unusual HTTP methods
            if payload.startswith(('PROPFIND', 'CONNECT', 'TRACE', 'TRACK', 'DEBUG')):
                protocol_violations += 1
                violation_details.append(f'Unusual HTTP method: {payload.split()[0] if " " in payload else payload[:10]}')
            
            # Excessive header length
            if 'HTTP/' in payload and '\r\n\r\n' in payload:
                headers = payload.split('\r\n\r\n')[0]
                if len(headers) > 4096:
                    protocol_violations += 1
                    violation_details.append(f'Excessive HTTP header length: {len(headers)}')
        
        # Detect encrypted traffic on unusual ports
        payload_length = packet.get('payload_length', 0)
        payload_entropy = packet.get('payload_entropy', 0)
        dst_port = packet.get('dst_port', 0)
        
        common_encrypted_ports = [443, 993, 995, 465, 8443, 22, 853, 5223]
        
        if payload_length > 100 and payload_entropy > 7.0 and dst_port not in common_encrypted_ports:
            encrypted_unusual += 1
            encrypted_details.append(f'Port {dst_port} (entropy: {payload_entropy:.2f})')
    
    # Add detected anomalies
    if malformed_packets > 5:
        anomalies.append({
            'type': 'MALFORMED_PACKETS',
            'description': 'Multiple malformed packets detected',
            'details': f'{malformed_packets} malformed packets: {", ".join(malformed_details[:5])}'
        })
    
    if protocol_violations > 5:
        anomalies.append({
            'type': 'PROTOCOL_VIOLATIONS',
            'description': 'Multiple protocol violations detected',
            'details': f'{protocol_violations} violations: {", ".join(violation_details[:5])}'
        })
    
    if encrypted_unusual > 5:
        anomalies.append({
            'type': 'ENCRYPTED_UNUSUAL_PORTS',
            'description': 'Encrypted traffic on unusual ports',
            'details': f'{encrypted_unusual} instances: {", ".join(encrypted_details[:5])}'
        })
    
    # Check for protocol tunneling
    if detect_protocol_tunneling(packet_features):
        anomalies.append({
            'type': 'PROTOCOL_TUNNELING',
            'description': 'Potential protocol tunneling detected',
            'details': 'Protocol encapsulation that may be used to bypass security controls'
        })
    
    return anomalies

def detect_protocol_tunneling(packet_features):
    """Detect potential protocol tunneling (e.g., DNS tunneling, HTTP tunneling)"""
    if not packet_features:
        return False
    
    # DNS tunneling detection
    dns_packets = [p for p in packet_features if p.get('dst_port') == 53 or p.get('src_port') == 53]
    if len(dns_packets) > 10:
        # Check for unusually long DNS queries
        dns_queries = [p.get('dns_query', '') for p in dns_packets if p.get('dns_query')]
        if dns_queries:
            avg_query_length = sum(len(q) for q in dns_queries) / len(dns_queries)
            if avg_query_length > 50:  # Normal DNS queries are typically shorter
                return True
        
        # Check for high entropy in DNS payloads
        dns_entropy = [p.get('payload_entropy', 0) for p in dns_packets if p.get('payload_entropy')]
        if dns_entropy and sum(dns_entropy) / len(dns_entropy) > 5.5:
            return True
    
    # HTTP tunneling detection
    http_packets = [p for p in packet_features if p.get('dst_port') in [80, 443, 8080, 8443]]
    if len(http_packets) > 10:
        # Check for unusual HTTP patterns
        http_entropy = [p.get('payload_entropy', 0) for p in http_packets if p.get('payload_entropy')]
        if http_entropy and sum(http_entropy) / len(http_entropy) > 6.5:
            # Check for regular timing patterns
            http_timestamps = sorted([p.get('timestamp', 0) for p in http_packets if p.get('timestamp')])
            if len(http_timestamps) > 5:
                intervals = [http_timestamps[i] - http_timestamps[i-1] for i in range(1, len(http_timestamps))]
                if intervals:
                    mean_interval = sum(intervals) / len(intervals)
                    variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                    std_dev = variance ** 0.5
                    cv = std_dev / mean_interval if mean_interval else float('inf')
                    
                    # Regular intervals suggest tunneling
                    if cv < 0.3 and mean_interval > 2:
                        return True
    
    # ICMP tunneling detection
    icmp_packets = [p for p in packet_features if p.get('protocol_name') == 'ICMP']
    if len(icmp_packets) > 10:
        # Check for unusual ICMP payload sizes
        icmp_sizes = [p.get('payload_length', 0) for p in icmp_packets]
        if icmp_sizes and sum(icmp_sizes) / len(icmp_sizes) > 100:
            return True
        
        # Check for high entropy in ICMP payloads
        icmp_entropy = [p.get('payload_entropy', 0) for p in icmp_packets if p.get('payload_entropy')]
        if icmp_entropy and sum(icmp_entropy) / len(icmp_entropy) > 6.0:
            return True
    
    return False

def detect_behavior_anomalies(packet_features):
    """Detect anomalies in network behavior patterns"""
    anomalies = []
    
    if not packet_features:
        return anomalies
    
    # Detect periodic beaconing
    timestamps_by_dest = {}
    for packet in packet_features:
        dst_ip = packet.get('dst_ip', '')
        timestamp = packet.get('timestamp', 0)
        if dst_ip and timestamp:
            if dst_ip not in timestamps_by_dest:
                timestamps_by_dest[dst_ip] = []
            timestamps_by_dest[dst_ip].append(timestamp)
    
    beaconing_ips = []
    for ip, times in timestamps_by_dest.items():
        if len(times) > 4:  # Need at least 5 data points
            times.sort()
            intervals = [times[i] - times[i-1] for i in range(1, len(times))]
            
            # Calculate coefficient of variation (low = regular timing)
            if intervals:
                mean_interval = sum(intervals) / len(intervals)
                variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = variance ** 0.5
                cv = std_dev / mean_interval if mean_interval else float('inf')
                
                # Regular beaconing has low coefficient of variation
                if cv < 0.25 and mean_interval > 5:
                    beaconing_ips.append((ip, mean_interval, cv))
    
    if beaconing_ips:
        beaconing_details = [f"{ip} (interval: {interval:.1f}s, cv: {cv:.2f})" for ip, interval, cv in beaconing_ips[:3]]
        anomalies.append({
            'type': 'BEACONING_BEHAVIOR',
            'description': 'Regular communication patterns indicative of command & control',
            'details': f'{len(beaconing_ips)} beaconing endpoints: {", ".join(beaconing_details)}'
        })
    
    # Detect unusual port usage
    common_ports = {80, 443, 53, 123, 22, 25, 21, 23, 3389, 8080}
    uncommon_ports = set()
    
    for packet in packet_features:
        port = packet.get('dst_port', 0)
        if port > 1024 and port not in common_ports:
            uncommon_ports.add(port)
    
    if len(uncommon_ports) > 10:
        anomalies.append({
            'type': 'UNCOMMON_PORTS',
            'description': 'Communications over multiple uncommon ports',
            'details': f'{len(uncommon_ports)} uncommon ports: {", ".join(map(str, list(uncommon_ports)[:5]))}'
        })
    
    # Look for signs of data staging before exfiltration
    large_payload_conns = {}
    for packet in packet_features:
        payload_len = packet.get('payload_length', 0)
        if payload_len > 1000:  # Significant payload size
            dst = f"{packet.get('dst_ip', '')}:{packet.get('dst_port', '')}"
            large_payload_conns[dst] = large_payload_conns.get(dst, 0) + payload_len
    
    # Identify endpoints with large data transfers
    staging_endpoints = [(dst, size) for dst, size in large_payload_conns.items() if size > 50000]
    
    if staging_endpoints:
        endpoints_details = [f"{dst} ({size/1024:.1f} KB)" for dst, size in staging_endpoints[:3]]
        anomalies.append({
            'type': 'DATA_STAGING',
            'description': 'Large data transfers potentially indicating data staging',
            'details': f'{len(staging_endpoints)} endpoints with large transfers: {", ".join(endpoints_details)}'
        })
    
    return anomalies

def detect_apt_patterns(packet_features):
    """
    Detect patterns associated with Advanced Persistent Threats (APTs)
    using behavioral analysis
    
    Args:
        packet_features: List of packet feature dictionaries
        
    Returns:
        Dictionary containing APT detection results
    """
    if not packet_features:
        return {'apt_detected': False, 'apt_indicators': [], 'indicators': [], 'confidence': 0.0}
    
    # Initialize APT patterns tracking
    apt_patterns = {
        'lateral_movement': {
            'indicators': 0,
            'unique_targets': set(),
            'techniques': set()
        },
        'data_staging': {
            'indicators': 0,
            'volume': 0,
            'unusual_protocols': set()
        },
        'command_and_control': {
            'indicators': 0,
            'beaconing': {},
            'encrypted_channels': 0,
            'domains': set()
        },
        'persistence': {
            'indicators': 0,
            'techniques': set()
        },
        'evasion': {
            'indicators': 0,
            'techniques': set()
        }
    }
    
    # Analyze lateral movement patterns
    lateral_movement_ports = {
        5985: 'winrm',    # WinRM
        5986: 'winrm',    # WinRM SSL
        3389: 'rdp',      # RDP
        445: 'smb_admin', # SMB
        139: 'smb_admin', # NetBIOS
        135: 'wmi',       # WMI/DCOM
        1433: 'database', # MSSQL
        22: 'ssh'         # SSH
    }
    
    lateral_targets = set()
    lateral_techniques = set()
    
    for packet in packet_features:
        dst_ip = packet.get('dst_ip', '')
        dst_port = packet.get('dst_port', 0)
        payload = packet.get('payload_str', '').lower()
        
        # Check for known lateral movement port usage
        if dst_port in lateral_movement_ports:
            lateral_targets.add(dst_ip)
            technique = lateral_movement_ports[dst_port]
            lateral_techniques.add(technique)
        
        # Check for PsExec usage patterns
        if 'psexec' in payload or 'svcctl' in payload or 'service_control' in payload:
            lateral_techniques.add('psexec')
        
        # Check for admin share access patterns
        admin_share_patterns = ['\\\\C$', '\\\\ADMIN$', '\\\\IPC$', 'net use', 'net view']
        if any(pattern in payload for pattern in admin_share_patterns):
            lateral_techniques.add('admin_share')
    
    # Calculate lateral movement score
    lateral_score = len(lateral_techniques) * 0.5
    
    # Adjust score based on number of unique targets
    if len(lateral_targets) > 1:
        lateral_score += len(lateral_targets) * 0.2
    
    apt_patterns['lateral_movement']['indicators'] = min(5, lateral_score)
    apt_patterns['lateral_movement']['unique_targets'] = lateral_targets
    apt_patterns['lateral_movement']['techniques'] = lateral_techniques
    
    # Analyze C2 patterns
    beaconing_channels = {}
    encrypted_channels = 0
    suspicious_domains = set()
    
    # Analyze timing patterns by destination
    timestamps_by_dest = {}
    for packet in packet_features:
        dst_ip = packet.get('dst_ip', '')
        timestamp = packet.get('timestamp', 0)
        dst_port = packet.get('dst_port', 0)
        payload_entropy = packet.get('payload_entropy', 0)
        
        if dst_ip and timestamp:
            key = f"{dst_ip}:{dst_port}"
            if key not in timestamps_by_dest:
                timestamps_by_dest[key] = []
            timestamps_by_dest[key].append(timestamp)
        
        # Track high-entropy communications
        if payload_entropy > 7.0:
            encrypted_channels += 1
    
    # Analyze beaconing patterns (regular intervals)
    for dest, times in timestamps_by_dest.items():
        if len(times) > 5:  # Need enough data points
            times.sort()
            intervals = [times[i] - times[i-1] for i in range(1, len(times))]
            
            # Calculate coefficient of variation (low = regular timing)
            if intervals:
                mean_interval = sum(intervals) / len(intervals)
                variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = variance ** 0.5
                cv = std_dev / mean_interval if mean_interval else float('inf')
                
                # Regular beaconing has low coefficient of variation
                if cv < 0.3 and mean_interval > 5:
                    beaconing_channels[dest] = (mean_interval, cv)
    
    # Look for suspicious domain patterns in DNS queries
    dns_packets = [p for p in packet_features if p.get('dst_port') == 53]
    for packet in dns_packets:
        query = packet.get('dns_query', '')
        if query:
            # Check for algorithmically generated domain names (DGA)
            if is_potential_dga(query):
                suspicious_domains.add(query)
    
    # Calculate C2 score
    c2_score = 0
    
    # Score based on beaconing channels
    if beaconing_channels:
        c2_score += min(3, len(beaconing_channels) * 0.5)
    
    # Score based on encrypted communications
    if encrypted_channels > 10:
        c2_score += min(2, encrypted_channels / 20)
    
    # Score based on suspicious domains
    if suspicious_domains:
        c2_score += min(2, len(suspicious_domains) * 0.5)
    
    apt_patterns['command_and_control']['indicators'] = min(5, c2_score)
    apt_patterns['command_and_control']['beaconing'] = beaconing_channels
    apt_patterns['command_and_control']['encrypted_channels'] = encrypted_channels
    apt_patterns['command_and_control']['domains'] = suspicious_domains
    
    # Analyze data staging patterns
    staging_volume = 0
    unusual_protocols = set()
    
    # Track internal-to-internal large transfers
    for packet in packet_features:
        src_ip = packet.get('src_ip', '')
        dst_ip = packet.get('dst_ip', '')
        payload_length = packet.get('payload_length', 0)
        protocol = packet.get('protocol_name', '')
        dst_port = packet.get('dst_port', 0)
        
        # Check for internal data transfers (potential staging)
        if is_internal_ip(src_ip) and is_internal_ip(dst_ip):
            if payload_length > 1000:  # Significant payload size
                staging_volume += payload_length
        
        # Look for data transfers over unusual protocols/ports
        if payload_length > 1000:
            if dst_port not in [80, 443, 8080, 8443, 21, 22, 445, 139]:  # Common legitimate transfer ports
                unusual_protocols.add(f"{protocol}:{dst_port}")
    
    # Calculate data staging score
    staging_score = 0
    
    # Score based on internal transfer volume
    if staging_volume > 100000:  # >100KB is significant
        staging_score += min(2, staging_volume / 100000)
    
    # Score based on number of unusual protocols
    if unusual_protocols:
        staging_score += len(unusual_protocols) * 0.5
    
    apt_patterns['data_staging']['indicators'] = min(5, staging_score)
    apt_patterns['data_staging']['volume'] = staging_volume
    apt_patterns['data_staging']['unusual_protocols'] = unusual_protocols
    
    # Calculate APT score
    apt_score = (
        apt_patterns['lateral_movement']['indicators'] * 0.25 +
        apt_patterns['data_staging']['indicators'] * 0.20 +
        apt_patterns['command_and_control']['indicators'] * 0.25
    )
    
    # Determine if APT is detected
    apt_detected = apt_score >= 1.0
    
    # Calculate confidence based on APT score
    confidence = min(0.95, 0.65 + (apt_score / 10))
    
    # Gather indicators for each tactic
    apt_indicators = []
    indicators = []
    
    # Lateral Movement indicators
    if apt_patterns['lateral_movement']['indicators'] > 0:
        lateral_details = []
        if apt_patterns['lateral_movement']['unique_targets']:
            lateral_details.append(f"{len(apt_patterns['lateral_movement']['unique_targets'])} unique targets")
        if apt_patterns['lateral_movement']['techniques']:
            lateral_details.append(f"Techniques: {', '.join(apt_patterns['lateral_movement']['techniques'])}")
        
        apt_indicators.append({
            'tactic': 'Lateral Movement',
            'score': apt_patterns['lateral_movement']['indicators'],
            'details': lateral_details
        })
        
        indicators.append(f"Lateral Movement: {apt_patterns['lateral_movement']['indicators']} indicators")
    
    # Data Staging indicators
    if apt_patterns['data_staging']['indicators'] > 0:
        staging_details = []
        if apt_patterns['data_staging']['volume'] > 0:
            staging_details.append(f"Volume: {apt_patterns['data_staging']['volume']/1024:.1f} KB")
        if apt_patterns['data_staging']['unusual_protocols']:
            staging_details.append(f"Using: {', '.join(apt_patterns['data_staging']['unusual_protocols'])}")
        
        apt_indicators.append({
            'tactic': 'Data Staging',
            'score': apt_patterns['data_staging']['indicators'],
            'details': staging_details
        })
        
        indicators.append(f"Data Staging: {apt_patterns['data_staging']['indicators']} indicators")
    
    # Command and Control indicators
    if apt_patterns['command_and_control']['indicators'] > 0:
        c2_details = []
        if apt_patterns['command_and_control']['beaconing']:
            c2_details.append(f"{len(apt_patterns['command_and_control']['beaconing'])} beaconing channels")
        if apt_patterns['command_and_control']['encrypted_channels'] > 0:
            c2_details.append(f"{apt_patterns['command_and_control']['encrypted_channels']} encrypted channels")
        if apt_patterns['command_and_control']['domains']:
            c2_details.append(f"{len(apt_patterns['command_and_control']['domains'])} suspicious domains")
        
        apt_indicators.append({
            'tactic': 'Command & Control',
            'score': apt_patterns['command_and_control']['indicators'],
            'details': c2_details
        })
        
        indicators.append(f"Command & Control: {apt_patterns['command_and_control']['indicators']} indicators")
    
    # Add overall APT score
    indicators.append(f"APT correlation score: {apt_score:.2f}")
    
    return {
        'apt_detected': apt_detected,
        'apt_indicators': apt_indicators,
        'indicators': indicators,
        'confidence': confidence
    }

def is_internal_ip(ip):
    """Check if an IP address is in private (RFC 1918) address space"""
    if not ip:
        return False
        
    # Common private IP ranges
    if ip.startswith('10.') or ip.startswith('192.168.'):
        return True
        
    # 172.16.0.0/12 range
    if ip.startswith('172.'):
        try:
            second_octet = int(ip.split('.')[1])
            if 16 <= second_octet <= 31:
                return True
        except (IndexError, ValueError):
            pass
            
    return False

def is_potential_dga(domain):
    """Check if a domain might be algorithmically generated (DGA)"""
    if not domain:
        return False
        
    # Remove TLD for analysis
    parts = domain.split('.')
    if len(parts) < 2:
        return False
        
    # Analyze main domain part (before TLD)
    main_part = parts[-2]
    
    # Very short or very long domains are suspicious
    if len(main_part) < 4 or len(main_part) > 20:
        return True
        
    # Calculate entropy (randomness) of the domain
    # High entropy often indicates algorithmic generation
    char_freqs = Counter(main_part)
    domain_entropy = entropy([float(freq) / len(main_part) for freq in char_freqs.values()], base=2)
    
    # High entropy is suspicious
    if domain_entropy > 3.5:
        return True
        
    # Calculate consonant-to-vowel ratio
    vowels = sum(1 for c in main_part if c.lower() in 'aeiou')
    consonants = len(main_part) - vowels
    
    # Domains with very few vowels or unusual consonant ratio are suspicious
    if vowels == 0 or (consonants / max(1, vowels)) > 10:
        return True
        
    # Check for uncommon letter patterns
    uncommon_patterns = ['xz', 'qj', 'vq', 'zx', 'jq', 'wx', 'qx']
    if any(pattern in main_part.lower() for pattern in uncommon_patterns):
        return True
        
    # Check for repeating patterns (common in DGAs)
    for pattern_len in range(2, min(4, len(main_part))):
        pattern_count = {}
        for i in range(len(main_part) - pattern_len + 1):
            pattern = main_part[i:i+pattern_len]
            pattern_count[pattern] = pattern_count.get(pattern, 0) + 1
            
        # Unusual repetition is suspicious
        if any(count > 2 for count in pattern_count.values()):
            return True
            
    return False

# Inside the SYN flood detection block:
syn_flood_ips = set()
for p in packet_features:
    if p.get('protocol_name') == 'TCP':
        # Get source and destination IPs
        src_ip = p.get('src_ip', '')
        dst_ip = p.get('dst_ip', '')
        
        # Skip if either IP is whitelisted
        if is_whitelisted_ip(src_ip) or is_whitelisted_ip(dst_ip):
            continue
            

def add_zero_day_apt_detection(rule_based_threats, packet_features):
    """
    Integrate zero-day and APT detection with rule-based detection
    
    Args:
        rule_based_threats: List of threats from rule-based detection
        packet_features: List of packet feature dictionaries
        
    Returns:
        Enhanced list of threats including potential zero-day and APT threats
    """
    try:
        # First filter out whitelisted IPs from packet_features
        filtered_packets = []
        for packet in packet_features:
            src_ip = packet.get('src_ip', '')
            dst_ip = packet.get('dst_ip', '')
            
            # Skip packets with whitelisted IPs
            if is_whitelisted_ip(src_ip) or is_whitelisted_ip(dst_ip):
                continue
                
            filtered_packets.append(packet)
        
        # Skip if we've filtered out too many packets
        if len(filtered_packets) < len(packet_features) * 0.5:
            logging.info(f"Skipping advanced detection after filtering {len(packet_features) - len(filtered_packets)} packets with whitelisted IPs")
            return rule_based_threats
                
        # Check if we already have zero-day or APT detections from rule-based
        has_unknown = any(threat.get('name', '') == ThreatCategoryEnum.UNKNOWN for threat in rule_based_threats)
        has_malicious_behavior = any(threat.get('name', '') == ThreatCategoryEnum.MALICIOUS_BEHAVIOR for threat in rule_based_threats)
        
        # Only proceed with advanced detection if we don't already have these detections
        if not (has_unknown and has_malicious_behavior):
            # Detect zero-day and APT threats using filtered packets
            zero_day_threats = detect_zero_day_apt_threats(filtered_packets)
            
            # Apply additional whitelist filtering to the threats
            zero_day_threats = filter_whitelisted_ips(zero_day_threats)
            
            # Combine threats without duplicating categories
            combined_threats = rule_based_threats.copy()
            rule_based_names = {threat.get('name', '') for threat in rule_based_threats}
            
            for threat in zero_day_threats:
                if threat.get('name', '') not in rule_based_names:
                    combined_threats.append(threat)
            
            return combined_threats
            
        return rule_based_threats
    except Exception as e:
        logging.error(f"Error in zero-day/APT detection integration: {e}")
        return rule_based_threats