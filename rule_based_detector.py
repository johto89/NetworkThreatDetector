import logging
import numpy as np
from models import ThreatCategoryEnum
from iputils import is_whitelisted_ip
from web_phishing_detector import detect_web_phishing

def check_tcp_flag(tcp_flags, flag_name):
    """
    Safely check TCP flags regardless of how they're represented (dictionary, object attributes, etc.)
    
    Args:
        tcp_flags: TCP flags object/dictionary from packet features
        flag_name: Name of the flag to check (e.g., 'SYN', 'ACK', 'FIN')
        
    Returns:
        Boolean indicating if the flag is set
    """
    try:
        # Dictionary-like access
        if hasattr(tcp_flags, '__contains__'):
            if flag_name in tcp_flags:
                flag_value = tcp_flags[flag_name]
                return bool(flag_value) if hasattr(flag_value, '__bool__') else bool(flag_value)
        
        # Object with attributes
        if hasattr(tcp_flags, flag_name):
            return bool(getattr(tcp_flags, flag_name, False))
        
        # String representation fallback
        if isinstance(tcp_flags, str):
            return flag_name.upper() in tcp_flags.upper()
        
        return False
    except Exception:
        return False

def rule_based_detection(packet_features, stats):
    """
    Main entry point for rule-based threat detection.
    Orchestrates various detection methods and combines results.
    
    Args:
        packet_features: List of packet feature dictionaries
        stats: Statistical features extracted from packets
        
    Returns:
        List of detected threats
    """
    threats = []
    
    # Skip analysis if no packet data
    if not packet_features:
        threats.append(create_threat(
            ThreatCategoryEnum.NORMAL,
            0.95,
            "No packet data to analyze.",
            ["Empty packet data"]
        ))
        return threats
    
    # 1. Check for known indicators of compromise or threat signatures
    # This would normally involve checking against threat intelligence feeds
    # and signature databases, but we're using rule-based logic here
    signature_threats = detect_known_signatures(packet_features)
    threats.extend(signature_threats)
    
    # 2. Check for reconnaissance activities
    recon_threats = detect_reconnaissance(packet_features, stats)
    threats.extend(recon_threats)
    
    # 3. Check for DoS/DDoS attacks
    dos_threats = detect_dos_ddos(packet_features, stats)
    threats.extend(dos_threats)
    
    # 4. Check for network protocol attacks
    protocol_threats = detect_protocol_attacks(packet_features, stats)
    threats.extend(protocol_threats)
    
    # 5. Check for web-based attacks
    web_threats = detect_web_attacks(packet_features, stats)
    threats.extend(web_threats)
    
    # 6. Check for web phishing (using external detector)
    try:
        phishing_threats = detect_phishing(packet_features)
        threats.extend(phishing_threats)
    except Exception as e:
        logging.error(f"Error in phishing detection: {e}")
    
    # 7. Check for server attacks
    server_threats = detect_server_attacks(packet_features, stats)
    threats.extend(server_threats)
    
    # 8. Check for network device attacks
    device_threats = detect_network_device_attacks(packet_features, stats)
    threats.extend(device_threats)
    
    # 9. Check for general malicious behavior
    malicious_threats = detect_malicious_behavior(packet_features, stats)
    threats.extend(malicious_threats)
    
    # 10. Check for behavioral anomalies
    anomaly_threats = detect_behavioral_anomalies(packet_features, stats)
    threats.extend(anomaly_threats)
    
    # Deduplicate threats based on name and description
    deduplicated_threats = []
    threat_signatures = set()
    
    for threat in threats:
        # Create a signature for each threat based on name and primary indicator
        signature = f"{threat['name']}:{threat['indicators'][0] if threat['indicators'] else ''}"
        if signature not in threat_signatures:
            threat_signatures.add(signature)
            deduplicated_threats.append(threat)
    
    # If no threats were found, mark as normal traffic
    if not deduplicated_threats:
        deduplicated_threats.append(create_threat(
            ThreatCategoryEnum.NORMAL,
            0.95,
            "No suspicious patterns detected in the network traffic.",
            ["Normal packet distribution", "No unusual port activity"]
        ))
    
    # Sort threats by confidence level (descending)
    deduplicated_threats.sort(key=lambda x: x['confidence'], reverse=True)
    
    return deduplicated_threats

def create_threat(name, confidence, description, indicators):
    """
    Helper function to create a standardized threat dictionary.
    
    Args:
        name: Name/category of the threat
        confidence: Confidence score (0.0-1.0)
        description: Description of the threat
        indicators: List of indicators that triggered this detection
        
    Returns:
        Threat dictionary
    """
    return {
        'name': name,
        'confidence': confidence,
        'description': description,
        'indicators': indicators
    }

def detect_reconnaissance(packet_features, stats):
    """
    Advanced reconnaissance detection with comprehensive analysis of network scanning and information gathering techniques.
    
    Args:
        packet_features: List of packet feature dictionaries
        stats: Statistical features extracted from packets
        
    Returns:
        List of detected reconnaissance threats
    """
    threats = []
    
    # Comprehensive service port groups for targeted analysis
    service_port_groups = {
        'remote_access': {22, 23, 3389, 5900, 5901, 5902, 5800, 5985, 5986},
        'file_transfer': {21, 20, 69, 115, 989, 990, 2049, 445, 873},
        'databases': {1433, 1434, 3306, 5432, 1521, 1830, 27017, 27018, 27019, 6379, 5984, 9200, 9300, 7000, 7001, 9042},
        'network_services': {53, 67, 68, 123, 161, 162, 514, 520, 546, 547, 1900, 5353},
        'mail_services': {25, 110, 143, 465, 587, 993, 995},
        'windows_services': {135, 137, 138, 139, 389, 636, 3268, 3269, 88, 464},
        'web_services': {80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 4000, 8081, 8181, 10000, 9090},
        'middleware': {1099, 8009, 7001, 9001, 8005, 8140, 2375, 2376, 4243, 6000, 6001, 7199, 8091, 9999, 61616},
        'voice_video': {5060, 5061, 1720, 3478, 5349, 16384, 32767},
        'critical_infrastructure': {102, 502, 20000, 44818, 47808, 1911, 9100, 11112, 50000, 3389},
        'containerization': {2379, 2380, 6443, 10250, 10255, 10256, 30000, 32767}
    }
    
    # Mapping port groups to service types
    def map_port_to_category(port):
        for category, ports in service_port_groups.items():
            if port in ports:
                return category
        return 'other'
    
    # 1. Advanced Port Scanning Detection
    if stats.get('potential_port_scan', False) or stats.get('unique_dst_ports', 0) > 15:
        # Collect and analyze port details
        ports_set = sorted([p.get('dst_port', 0) for p in packet_features])
        
        # Detect scanning patterns
        pattern_types = {
            'consecutive': 0,  # Sequential ports
            'arithmetic': 0,   # Ports with consistent increment
            'prime_ports': 0,  # Scanning prime-numbered ports
            'high_ports': 0,   # High ports (> 1024)
            'targeted_categories': {}  # Targeted service categories
        }
        
        # Pattern detection
        for i in range(1, len(ports_set)):
            # Consecutive port detection
            if ports_set[i] - ports_set[i-1] == 1:
                pattern_types['consecutive'] += 1
            
            # Arithmetic progression detection
            if i > 1:
                diff1 = ports_set[i] - ports_set[i-1]
                diff2 = ports_set[i-1] - ports_set[i-2]
                if diff1 == diff2 and diff1 > 1:
                    pattern_types['arithmetic'] += 1
            
            # High port detection
            if ports_set[i] > 1024:
                pattern_types['high_ports'] += 1
        
        # Prime port detection
        def is_prime(n):
            if n < 2:
                return False
            for i in range(2, int(n**0.5) + 1):
                if n % i == 0:
                    return False
            return True
        
        pattern_types['prime_ports'] = sum(1 for port in ports_set if is_prime(port))
        
        # Service category targeting
        for port in ports_set:
            category = map_port_to_category(port)
            pattern_types['targeted_categories'][category] = pattern_types['targeted_categories'].get(category, 0) + 1
        
        # Calculate scan timeframe
        timestamps = sorted([p.get('timestamp', 0) for p in packet_features if p.get('timestamp')])
        scan_timeframe = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
        scan_rate = len(ports_set) / max(1, scan_timeframe) if scan_timeframe else 0
        
        # Generate list of scanning techniques
        scanning_techniques = []
        for tech, count in pattern_types.items():
            if tech != 'targeted_categories':
                if isinstance(count, int) and count > 0:
                    scanning_techniques.append(f"{tech.replace('_', ' ').title()}: {count}")
        
        # Generate list of targeted categories
        targeted_categories = [f"{cat}: {count}" for cat, count in pattern_types['targeted_categories'].items()]
        
        # Generate threat with comprehensive details
        threats.append(create_threat(
            ThreatCategoryEnum.RECONNAISSANCE,
            0.85,
            "Advanced port scanning activity detected.",
            [
                f"Unique ports scanned: {len(ports_set)}",
                f"Scanning techniques: {scanning_techniques}",
                f"Targeted service categories: {targeted_categories}",
                f"Scan rate: {scan_rate:.2f} ports/second"
            ]
        ))
    
    # 2. Network Mapping and Host Discovery
    # Detect host discovery techniques
    discovery_techniques = {
        'icmp_echo': sum(1 for p in packet_features if p.get('protocol_name') == 'ICMP' and p.get('icmp_type') == 8),
        'tcp_host_discovery': sum(1 for p in packet_features if
                                p.get('protocol_name') == 'TCP' and
                                p.get('payload_length', 0) == 0 and
                                p.get('dst_port') in [7, 9, 13, 19, 21, 22, 23, 25, 80, 139, 443, 445, 3389]),
        'udp_host_discovery': sum(1 for p in packet_features if
                                p.get('protocol_name') == 'UDP' and
                                p.get('payload_length', 0) < 10 and
                                p.get('dst_port') in [53, 67, 68, 69, 123, 161, 162, 1900, 5353]),
        'arp_scanning': sum(1 for p in packet_features if p.get('protocol') == 'ARP' and p.get('arp_opcode') == 1),
        'sctp_discovery': sum(1 for p in packet_features if p.get('protocol_name') == 'SCTP')
    }
    
    # Check if any significant host discovery is happening
    if any(count > 10 for count in discovery_techniques.values()):
        # Analyze IP and subnet patterns
        dst_ips = [p.get('dst_ip', '') for p in packet_features if p.get('dst_ip')]
        subnet_patterns = {'/24': {}, '/16': {}}
        
        for ip in dst_ips:
            parts = ip.split('.')
            if len(parts) == 4:
                # Track /24 subnet
                prefix24 = '.'.join(parts[:3])
                subnet_patterns['/24'][prefix24] = subnet_patterns['/24'].get(prefix24, 0) + 1
                
                # Track /16 subnet
                prefix16 = '.'.join(parts[:2])
                subnet_patterns['/16'][prefix16] = subnet_patterns['/16'].get(prefix16, 0) + 1
        
        # Find most scanned subnets
        most_scanned_24 = max(subnet_patterns['/24'].items(), key=lambda x: x[1]) if subnet_patterns['/24'] else None
        most_scanned_16 = max(subnet_patterns['/16'].items(), key=lambda x: x[1]) if subnet_patterns['/16'] else None
        
        threats.append(create_threat(
            ThreatCategoryEnum.RECONNAISSANCE,
            0.80,
            "Comprehensive network mapping and host discovery detected.",
            [
                f"Discovery techniques: {[tech for tech, count in discovery_techniques.items() if count > 10]}",
                f"Most scanned /24 subnet: {most_scanned_24[0] if most_scanned_24 else 'N/A'} ({most_scanned_24[1] if most_scanned_24 else 0} hits)",
                f"Most scanned /16 subnet: {most_scanned_16[0] if most_scanned_16 else 'N/A'} ({most_scanned_16[1] if most_scanned_16 else 0} hits)"
            ]
        ))
    
    # 3. DNS Enumeration and Zone Transfer Detection
    dns_packets = [p for p in packet_features if p.get('dst_port') == 53]
    
    if len(dns_packets) > 30:
        # Analyze DNS query details
        unique_domains = set()
        dns_query_types = {}
        dns_records = {}
        
        for packet in dns_packets:
            query = packet.get('dns_query', '')
            query_type = packet.get('dns_query_type', 'UNKNOWN')
            
            if query:
                unique_domains.add(query)
                dns_query_types[query_type] = dns_query_types.get(query_type, 0) + 1
                
                # Base domain analysis
                parts = query.split('.')
                if len(parts) > 2:
                    base_domain = '.'.join(parts[-2:])
                    dns_records[base_domain] = dns_records.get(base_domain, 0) + 1
        
        # Look for zone transfer attempts and subdomain enumeration
        zone_transfer_attempts = dns_query_types.get('AXFR', 0)
        max_queries_per_domain = max(dns_records.values()) if dns_records else 0
        
        if zone_transfer_attempts > 0 or len(unique_domains) > 20 or max_queries_per_domain > 10:
            threats.append(create_threat(
                ThreatCategoryEnum.RECONNAISSANCE,
                0.85,
                "Advanced DNS enumeration and potential zone transfer detected.",
                [
                    f"Unique domains: {len(unique_domains)}",
                    f"Zone transfer attempts: {zone_transfer_attempts}",
                    f"DNS query types: {dns_query_types}",
                    f"Most queried domain: {max(dns_records, key=dns_records.get) if dns_records else 'N/A'}"
                ]
            ))
    
    # 4. Active Directory and LDAP Enumeration
    ad_ports = {389, 636, 3268, 3269, 88, 464, 137, 138, 139, 445}
    ad_recon_packets = [p for p in packet_features if p.get('dst_port') in ad_ports]
    
    if len(ad_recon_packets) > 10:
        # Count by service type
        service_counts = {
            'LDAP': sum(1 for p in ad_recon_packets if p.get('dst_port') in {389, 636, 3268, 3269}),
            'Kerberos': sum(1 for p in ad_recon_packets if p.get('dst_port') in {88, 464}),
            'NetBIOS': sum(1 for p in ad_recon_packets if p.get('dst_port') in {137, 138, 139}),
            'SMB': sum(1 for p in ad_recon_packets if p.get('dst_port') == 445)
        }
        
        # Detect specific AD reconnaissance patterns
        ad_patterns = {
            'user_enum': sum(1 for p in ad_recon_packets if 
                            any(term in p.get('payload_str', '').lower() for term in 
                                ['samr', 'enumdomainusers', 'enumdomains', 'useraccountcontrol'])),
            'group_enum': sum(1 for p in ad_recon_packets if 
                            any(term in p.get('payload_str', '').lower() for term in 
                                ['grouprid', 'enumdomaingroups', 'getdomaingroup'])),
            'ldap_query': sum(1 for p in ad_recon_packets if 
                            any(term in p.get('payload_str', '').lower() for term in 
                                ['objectclass', 'objectcategory', 'distinguishedname', 'cn=', 'ou=']))
        }
        
        threats.append(create_threat(
            ThreatCategoryEnum.RECONNAISSANCE,
            0.85,
            "Active Directory and LDAP reconnaissance detected.",
            [
                f"Service reconnaissance: {service_counts}",
                f"Reconnaissance patterns: {ad_patterns}"
            ]
        ))

    # 5. Scan Tool Detection (actual tool signatures in packet payloads)
    scan_tool_patterns = [
        # Actual scan tool signatures and binary patterns
        'nmap', 'masscan', 'zmap', 'unicornscan', 'scanline',
        'advanced port scanner', 'angry ip scanner', 'nessus',
        'openvas', 'nexpose', 'nikto', 'syn scan', 'fin scan', 
        'null scan', 'xmas scan', 'connect scan', 'ack scan',
        'os fingerprint', 'version detection', 'script scan',
        'traceroute', 'whois', 'dig', 'nslookup', 'port scan'
    ]
    
    scan_pattern_count = 0
    scan_pattern_examples = []
    
    for packet in packet_features:
        payload = packet.get('payload_str', '').lower()
        if not payload:
            continue
            
        for pattern in scan_tool_patterns:
            if pattern in payload:
                scan_pattern_count += 1
                if len(scan_pattern_examples) < 3:
                    scan_pattern_examples.append(pattern)
    
    # Check for SYN-only packets which are common in port scans
    syn_only_count = 0
    for packet in packet_features:
        if packet.get('protocol_name') == 'TCP':
            tcp_flags = packet.get('tcp_flags', {})
            if (check_tcp_flag(tcp_flags, 'SYN') and 
                not check_tcp_flag(tcp_flags, 'ACK') and
                not check_tcp_flag(tcp_flags, 'FIN') and
                not check_tcp_flag(tcp_flags, 'RST')):
                syn_only_count += 1
    
    if scan_pattern_count > 0 or syn_only_count > 15:
        # Combine with existing detection logic
        additional_indicators = []
        if scan_pattern_examples:
            additional_indicators.append(f"Scan tool signatures: {', '.join(scan_pattern_examples)}")
        if syn_only_count > 15:
            additional_indicators.append(f"SYN-only packets: {syn_only_count} (indicative of SYN scanning)")
        
        threats.append(create_threat(
            ThreatCategoryEnum.RECONNAISSANCE,
            min(0.85 + (scan_pattern_count * 0.02), 0.95),
            "Network scanning tools or techniques detected.",
            additional_indicators + ["Explicit scanner signatures or scanning techniques identified in packet data"]
        ))
    
    # 6. Web Application Reconnaissance
    web_recon_patterns = [
        # Web application scanning patterns
        'dirbuster', 'dirb ', 'gobuster', 'wfuzz', 'burpsuite',
        'zap', 'sqlmap', 'nikto', 'acunetix', 'whatweb',
        'wafw00f', 'wpscan', 'joomscan', 'droopescan',
        # Common web recon techniques
        '/.git/', '/wp-admin/', '/wp-content/', '/administrator/',
        '/joomla/', '/backup/', '/config/', '/admin/', '/login/',
        '/test/', '/dev/', '/debug/', '/api/', '/.env',
        '/.htaccess', '/robots.txt', '/sitemap.xml'
    ]
    
    web_recon_count = 0
    web_recon_examples = []
    web_packets = [p for p in packet_features if p.get('dst_port') in [80, 443, 8080, 8443]]
    
    for packet in web_packets:
        payload = packet.get('payload_str', '').lower()
        if not payload:
            continue
            
        for pattern in web_recon_patterns:
            if pattern in payload:
                web_recon_count += 1
                if len(web_recon_examples) < 3:
                    web_recon_examples.append(pattern)
    
    if web_recon_count > 3:
        threats.append(create_threat(
            ThreatCategoryEnum.RECONNAISSANCE,
            min(0.75 + (web_recon_count * 0.02), 0.9),
            "Web application reconnaissance detected.",
            [
                f"Web recon indicators: {web_recon_count}",
                f"Examples: {', '.join(web_recon_examples)}" if web_recon_examples else "",
                "Possible web application mapping or vulnerability scanning"
            ]
        ))
    
    return threats

def detect_dos_ddos(packet_features, stats):
    """
    Comprehensive and advanced Denial of Service (DoS) and Distributed Denial of Service (DDoS) attack detection.
    
    Args:
        packet_features: List of packet feature dictionaries
        stats: Statistical features extracted from packets
        
    Returns:
        List of detected DoS/DDoS threats
    """
    threats = []
    
    # Packet and timeframe analysis
    timestamps = sorted([p.get('timestamp', 0) for p in packet_features if p.get('timestamp')])
    timeframe = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 1
    packet_rate = len(packet_features) / max(1, timeframe)
    
    # IP Reputation and Tracking
    src_ip_reputation = {}
    for p in packet_features:
        src_ip = p.get('src_ip', '')
        if not src_ip or is_whitelisted_ip(src_ip):
            continue
        
        if src_ip not in src_ip_reputation:
            src_ip_reputation[src_ip] = {
                'packet_count': 0,
                'unique_ports': set(),
                'bytes_sent': 0,
                'syn_count': 0,
                'fin_count': 0,
                'rst_count': 0,
                'udp_count': 0,
                'icmp_count': 0,
                'protocol_types': set()
            }
        
        rep = src_ip_reputation[src_ip]
        rep['packet_count'] += 1
        rep['unique_ports'].add(p.get('dst_port', 0))
        rep['bytes_sent'] += p.get('packet_size', 0)
        rep['protocol_types'].add(p.get('protocol_name', 'UNKNOWN'))
        
        # Track protocol-specific flags
        if p.get('protocol_name') == 'TCP':
            tcp_flags = p.get('tcp_flags', {})
            if check_tcp_flag(tcp_flags, 'SYN'):
                rep['syn_count'] += 1
            if check_tcp_flag(tcp_flags, 'FIN'):
                rep['fin_count'] += 1
            if check_tcp_flag(tcp_flags, 'RST'):
                rep['rst_count'] += 1
        elif p.get('protocol_name') == 'UDP':
            rep['udp_count'] += 1
        elif p.get('protocol_name') == 'ICMP':
            rep['icmp_count'] += 1
    
    # Identify suspicious IPs
    suspicious_ips = []
    for ip, rep in src_ip_reputation.items():
        # Conditions for suspicious IP
        if (rep['packet_count'] > len(packet_features) * 0.1 or  # Too many packets
            len(rep['unique_ports']) > 10 or  # Too many unique ports
            rep['syn_count'] > 10 and rep['syn_count'] / max(1, rep['packet_count']) > 0.8):  # SYN flood
            suspicious_ips.append(ip)
    
    # TCP SYN Flood Detection
    syn_packets = [p for p in packet_features 
                   if (p.get('protocol_name') == 'TCP' and 
                       check_tcp_flag(p.get('tcp_flags', {}), 'SYN') and 
                       not check_tcp_flag(p.get('tcp_flags', {}), 'ACK'))]
    
    if len(syn_packets) > 20 and len(syn_packets) / len(packet_features) > 0.5:
        threats.append(create_threat(
            ThreatCategoryEnum.DOS_DDOS,
            0.9,
            "TCP SYN Flood attack detected.",
            [
                f"SYN packets: {len(syn_packets)}/{len(packet_features)}",
                f"Suspicious IPs: {suspicious_ips}",
                "Potential connection resource exhaustion"
            ]
        ))
    
    # UDP Flood Detection
    udp_packets = [p for p in packet_features if p.get('protocol_name') == 'UDP']
    
    if len(udp_packets) > 30 and len(udp_packets) / len(packet_features) > 0.6:
        # Analyze UDP port distribution
        udp_ports = {}
        for p in udp_packets:
            dst_port = p.get('dst_port', 0)
            udp_ports[dst_port] = udp_ports.get(dst_port, 0) + 1
        
        threats.append(create_threat(
            ThreatCategoryEnum.DOS_DDOS,
            0.85,
            "UDP Flood attack detected.",
            [
                f"UDP packets: {len(udp_packets)}/{len(packet_features)}",
                f"Targeted UDP ports: {len(udp_ports)}",
                f"Most targeted port: {max(udp_ports, key=udp_ports.get)}",
                "Potential network bandwidth exhaustion"
            ]
        ))
    
    # ICMP Flood Detection
    icmp_packets = [p for p in packet_features if p.get('protocol_name') == 'ICMP']
    
    if len(icmp_packets) > 20 and len(icmp_packets) / len(packet_features) > 0.4:
        # Distinguish ICMP types
        icmp_types = {}
        for p in icmp_packets:
            icmp_type = p.get('icmp_type', 'UNKNOWN')
            icmp_types[icmp_type] = icmp_types.get(icmp_type, 0) + 1
        
        threats.append(create_threat(
            ThreatCategoryEnum.DOS_DDOS,
            0.85,
            "ICMP Flood attack detected.",
            [
                f"ICMP packets: {len(icmp_packets)}/{len(packet_features)}",
                f"ICMP types: {icmp_types}",
                "Potential network ping flood or smurf attack"
            ]
        ))
    
    # Amplification Attack Detection
    amplification_ports = {
        'DNS': (53, 2),     # DNS port, min amplification factor
        'NTP': (123, 10),   # NTP port, min amplification factor
        'SSDP': (1900, 5),  # SSDP port, min amplification factor
        'SNMP': (161, 6),   # SNMP port, min amplification factor
        'Memcached': (11211, 10)  # Memcached port, min amplification factor
    }
    
    for attack_name, (port, min_factor) in amplification_ports.items():
        query_packets = [p for p in packet_features if p.get('dst_port') == port]
        response_packets = [p for p in packet_features if p.get('src_port') == port]
        
        if (len(response_packets) > 10 and 
            len(response_packets) > len(query_packets) * 2):
            
            query_size = sum(p.get('packet_size', 0) for p in query_packets)
            response_size = sum(p.get('packet_size', 0) for p in response_packets)
            
            amp_factor = response_size / max(1, query_size)
            
            if amp_factor > min_factor:
                threats.append(create_threat(
                    ThreatCategoryEnum.DOS_DDOS,
                    0.85,
                    f"{attack_name} Amplification attack detected.",
                    [
                        f"{attack_name} query count: {len(query_packets)}",
                        f"{attack_name} response count: {len(response_packets)}",
                        f"Amplification factor: {amp_factor:.2f}x",
                        f"Query size: {query_size} bytes",
                        f"Response size: {response_size} bytes"
                    ]
                ))
    
    # Application Layer DoS Detection
    http_packets = [p for p in packet_features if p.get('dst_port') in [80, 443, 8080, 8443]]
    
    if len(http_packets) > 50:
        # Slow HTTP attack detection
        incomplete_requests = sum(1 for p in http_packets if 
                                  p.get('payload_length', 0) < 200 and 
                                  'POST' in p.get('payload_str', ''))
        
        unique_uris = len(set(p.get('http_uri', '') for p in http_packets if p.get('http_uri')))
        
        # Analyze request methods and status codes
        request_methods = {}
        status_codes = {}
        for p in http_packets:
            method = p.get('http_method', '')
            status = p.get('http_status', '')
            
            if method:
                request_methods[method] = request_methods.get(method, 0) + 1
            if status:
                status_codes[status] = status_codes.get(status, 0) + 1
        
        if incomplete_requests > 10 or unique_uris < len(http_packets) * 0.1:
            threats.append(create_threat(
                ThreatCategoryEnum.DOS_DDOS,
                0.85,
                "Application Layer DoS attack detected.",
                [
                    f"HTTP/HTTPS requests: {len(http_packets)}",
                    f"Incomplete requests: {incomplete_requests}",
                    f"Unique URIs: {unique_uris}",
                    f"Request methods: {request_methods}",
                    f"Status codes: {status_codes}",
                    "Potential slow HTTP or resource exhaustion attack"
                ]
            ))
    
    # Connection Flood Detection
    connection_attempts = {}
    for p in packet_features:
        if p.get('protocol_name') == 'TCP':
            dst_key = f"{p.get('dst_ip')}:{p.get('dst_port')}"
            connection_attempts[dst_key] = connection_attempts.get(dst_key, 0) + 1
    
    excessive_connections = [
        (dst, count) for dst, count in connection_attempts.items() if count > 15
    ]
    
    if excessive_connections:
        top_targets = sorted(excessive_connections, key=lambda x: x[1], reverse=True)[:3]
        
        threats.append(create_threat(
            ThreatCategoryEnum.DOS_DDOS,
            0.85,
            "TCP Connection Flood attack detected.",
            [
                f"Excessive connection attempts to {len(excessive_connections)} services",
                f"Top targeted: {', '.join([f'{t[0]} ({t[1]} attempts)' for t in top_targets])}",
                "Potential network resource exhaustion"
            ]
        ))
    
    # Reflection/Spoofing Attack Detection
    reflection_patterns = {
        'SYN-ACK': 0,
        'RST': 0
    }
    
    for p in packet_features:
        if p.get('protocol_name') == 'TCP':
            tcp_flags = p.get('tcp_flags', {})
            
            # SYN-ACK packets without prior connection
            if (check_tcp_flag(tcp_flags, 'SYN') and 
                check_tcp_flag(tcp_flags, 'ACK')):
                reflection_patterns['SYN-ACK'] += 1
            
            # Excessive RST packets
            if check_tcp_flag(tcp_flags, 'RST'):
                reflection_patterns['RST'] += 1
    
    if reflection_patterns['SYN-ACK'] > 20 or reflection_patterns['RST'] > 20:
        threats.append(create_threat(
            ThreatCategoryEnum.DOS_DDOS,
            0.80,
            "TCP Reflection attack detected.",
            [
                f"SYN-ACK reflection packets: {reflection_patterns['SYN-ACK']}",
                f"RST reflection packets: {reflection_patterns['RST']}",
                "Potential TCP-based reflection attack"
            ]
        ))
    
    return threats

def detect_protocol_attacks(packet_features, stats):
    """
    Comprehensive detection of network protocol attacks with advanced techniques.
    
    Args:
        packet_features: List of packet feature dictionaries
        stats: Statistical features extracted from packets
        
    Returns:
        List of detected network protocol attack threats
    """
    threats = []
    
    # 1. IP Spoofing Detection
    private_ip_from_public = False
    src_ip_patterns = {}
    for packet in packet_features:
        src_ip = packet.get('src_ip', '')
        
        # Track IP address patterns
        src_ip_patterns[src_ip] = src_ip_patterns.get(src_ip, 0) + 1
        
        # Check for private IP ranges from external sources
        if (src_ip.startswith('10.') or src_ip.startswith('192.168.') or 
            (src_ip.startswith('172.') and 16 <= int(src_ip.split('.')[1]) <= 31)):
            if packet.get('is_external', False):
                private_ip_from_public = True
                break
    
    if private_ip_from_public:
        threats.append(create_threat(
            ThreatCategoryEnum.NETWORK_PROTOCOL_ATTACKS,
            0.85,
            "Potential IP spoofing detected.",
            [
                "Private IP addresses from external sources",
                "Possible IP address falsification"
            ]
        ))
    
    # 2. Source IP Anomaly Detection
    dominant_ips = [ip for ip, count in src_ip_patterns.items() 
                    if count > len(packet_features) * 0.3]
    
    if dominant_ips:
        threats.append(create_threat(
            ThreatCategoryEnum.NETWORK_PROTOCOL_ATTACKS,
            0.75,
            "Unusual source IP traffic pattern detected.",
            [
                f"Dominant IPs: {dominant_ips}",
                "Possible source IP manipulation"
            ]
        ))
    
    # 3. ICMP Attack Detection (Enhanced)
    icmp_packets = [p for p in packet_features if p.get('protocol_name') == 'ICMP']
    
    if len(icmp_packets) > 20:
        # Analyze ICMP types and patterns
        icmp_types = {}
        icmp_destinations = {}
        for p in icmp_packets:
            icmp_type = p.get('icmp_type', 'UNKNOWN')
            icmp_types[icmp_type] = icmp_types.get(icmp_type, 0) + 1
            
            dst_ip = p.get('dst_ip', '')
            icmp_destinations[dst_ip] = icmp_destinations.get(dst_ip, 0) + 1
        
        # Check for potential ICMP tunneling
        suspicious_destinations = [
            ip for ip, count in icmp_destinations.items() 
            if count > len(icmp_packets) * 0.2
        ]
        
        threats.append(create_threat(
            ThreatCategoryEnum.NETWORK_PROTOCOL_ATTACKS,
            0.75,
            "Potential ICMP-based attack detected.",
            [
                f"ICMP packet count: {len(icmp_packets)}",
                f"ICMP types distribution: {icmp_types}",
                f"Suspicious ICMP destinations: {suspicious_destinations}" if suspicious_destinations else "",
                "Possible ICMP flood, tunneling, or covert channel"
            ]
        ))
    
    # 4. TCP Abnormal Flag Combinations
    tcp_packets = [p for p in packet_features if p.get('protocol_name') == 'TCP']
    
    if len(tcp_packets) > 50:
        unusual_flag_combinations = {
            'SYN-FIN': 0,    # Unusual SYN and FIN flags together
            'SYN-RST': 0,    # Unusual SYN and RST flags together
            'FIN-PSH-URG': 0 # XMAS scan pattern
        }
        
        for p in tcp_packets:
            tcp_flags = p.get('tcp_flags', {})
            
            # Check for unusual flag combinations
            if (check_tcp_flag(tcp_flags, 'SYN') and 
                check_tcp_flag(tcp_flags, 'FIN')):
                unusual_flag_combinations['SYN-FIN'] += 1
            
            if (check_tcp_flag(tcp_flags, 'SYN') and 
                check_tcp_flag(tcp_flags, 'RST')):
                unusual_flag_combinations['SYN-RST'] += 1
            
            if (check_tcp_flag(tcp_flags, 'FIN') and 
                check_tcp_flag(tcp_flags, 'PSH') and 
                check_tcp_flag(tcp_flags, 'URG')):
                unusual_flag_combinations['FIN-PSH-URG'] += 1
        
        # Check if unusual combinations exceed threshold
        suspicious_combinations = [
            f"{combo}: {count}" for combo, count in unusual_flag_combinations.items() 
            if count > 10
        ]
        
        if suspicious_combinations:
            threats.append(create_threat(
                ThreatCategoryEnum.NETWORK_PROTOCOL_ATTACKS,
                0.80,
                "Unusual TCP flag combinations detected.",
                [
                    f"Suspicious TCP flag patterns: {suspicious_combinations}",
                    "Possible network scanning or protocol manipulation"
                ]
            ))
    
    # 5. Port Scanning and Protocol Probing
    unique_dst_ports = set(p.get('dst_port', 0) for p in packet_features)
    
    if len(unique_dst_ports) > 20:
        # Analyze port distribution across protocols
        port_protocol_map = {}
        for p in packet_features:
            protocol = p.get('protocol_name', 'UNKNOWN')
            port = p.get('dst_port', 0)
            
            if port not in port_protocol_map:
                port_protocol_map[port] = {}
            
            port_protocol_map[port][protocol] = port_protocol_map[port].get(protocol, 0) + 1
        
        # Identify ports with multi-protocol traffic
        multi_protocol_ports = [
            port for port, protocols in port_protocol_map.items() 
            if len(protocols) > 2
        ]
        
        if multi_protocol_ports:
            threats.append(create_threat(
                ThreatCategoryEnum.NETWORK_PROTOCOL_ATTACKS,
                0.75,
                "Suspicious multi-protocol port scanning detected.",
                [
                    f"Multi-protocol ports: {multi_protocol_ports}",
                    "Possible network reconnaissance or probing"
                ]
            ))
    
    # 6. SSL/TLS Handshake Anomalies
    ssl_packets = [p for p in packet_features if p.get('dst_port') in [443, 8443]]
    
    if len(ssl_packets) > 30:
        ssl_handshake_patterns = {
            'incomplete_handshakes': 0,
            'multiple_cipher_suites': set(),
            'unusual_extensions': 0
        }
        
        for p in ssl_packets:
            payload = p.get('payload_str', '').lower()
            
            # Check for incomplete SSL/TLS handshakes
            if 'client hello' in payload and 'server hello' not in payload:
                ssl_handshake_patterns['incomplete_handshakes'] += 1
            
            # Track cipher suites
            if 'cipher suite' in payload:
                ssl_handshake_patterns['multiple_cipher_suites'].add(
                    p.get('ssl_cipher_suite', 'UNKNOWN')
                )
            
            # Check for unusual SSL/TLS extensions
            if 'extension' in payload:
                ssl_handshake_patterns['unusual_extensions'] += 1
        
        if (ssl_handshake_patterns['incomplete_handshakes'] > 10 or 
            len(ssl_handshake_patterns['multiple_cipher_suites']) > 5):
            threats.append(create_threat(
                ThreatCategoryEnum.NETWORK_PROTOCOL_ATTACKS,
                0.80,
                "Suspicious SSL/TLS handshake behavior detected.",
                [
                    f"Incomplete handshakes: {ssl_handshake_patterns['incomplete_handshakes']}",
                    f"Unique cipher suites: {len(ssl_handshake_patterns['multiple_cipher_suites'])}",
                    f"Unusual SSL/TLS extensions: {ssl_handshake_patterns['unusual_extensions']}",
                    "Possible SSL/TLS protocol manipulation"
                ]
            ))
    
    # 7. Unusual Network Address Translation (NAT) Traversal
    nat_traversal_indicators = {
        'non_standard_ports': 0,
        'high_port_range': 0
    }
    
    for p in packet_features:
        port = p.get('dst_port', 0)
        
        # Check for non-standard high ports
        if port > 49152:  # Dynamic/Private port range
            nat_traversal_indicators['non_standard_ports'] += 1
        
        # Check for unusual port ranges
        if 1024 < port < 49152:
            nat_traversal_indicators['high_port_range'] += 1
    
    if (nat_traversal_indicators['non_standard_ports'] > 20 or 
        nat_traversal_indicators['high_port_range'] > 50):
        threats.append(create_threat(
            ThreatCategoryEnum.NETWORK_PROTOCOL_ATTACKS,
            0.75,
            "Potential NAT traversal or port forwarding detected.",
            [
                f"Non-standard port usage: {nat_traversal_indicators['non_standard_ports']}",
                f"High port range traffic: {nat_traversal_indicators['high_port_range']}",
                "Possible network boundary probing"
            ]
        ))
    
    return threats

def detect_web_attacks(packet_features, stats):
    """
    Advanced web-based attack detection with comprehensive analysis.
    
    Args:
        packet_features: List of packet feature dictionaries
        stats: Statistical features extracted from packets
        
    Returns:
        List of detected web attack threats
    """
    threats = []
    
    # Extract HTTP/HTTPS packets
    http_packets = [p for p in packet_features if p.get('protocol') in ['HTTP', 'HTTPS']]
    if not http_packets:
        return threats
    
    # Comprehensive attack pattern detection
    attack_patterns = {
        'SQL_INJECTION': {
            'patterns': [
                # Classic SQL Injection
                "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", 
                "1=1", "OR 1=1", "' OR '", "' OR 1=1", "--", "/*", 
                
                # Advanced SQL Injection Techniques
                "SLEEP(", "WAITFOR DELAY", "BENCHMARK(", 
                "CASE WHEN", "SUBSTRING(", "FROM DUAL", 
                "; --", "AND 1=1", "OR 1=1", "OR '1'='1'",
                
                # Blind SQL Injection
                "IF(", "EXTRACTVALUE(", "CONCAT(", "LOAD_FILE(",
                
                # Advanced Payload Techniques
                "CONVERT(", "CHAR(", "CONCAT_WS(", "GROUP_CONCAT(",
                "ASCII(", "HEX(", "UNHEX(", "REVERSE(",
                
                # Stored Procedure Attacks
                "EXEC(", "EXECUTE(", "CALL(", "PROCEDURE",
                
                # Time-based Blind SQL Injection
                "AND SLEEP(", "OR SLEEP(", "BENCHMARK("
            ],
            'category': ThreatCategoryEnum.WEB_ATTACKS,
            'confidence': 0.90,
            'severity': 'CRITICAL',
            'description': "Advanced SQL Injection attack targeting database manipulation"
        },
        'XSS': {
            'patterns': [
                # Stored XSS
                "<SCRIPT>", "JAVASCRIPT:", "ONERROR=", "ONLOAD=", 
                "DOCUMENT.COOKIE", "ALERT(", "WINDOW.LOCATION=",
                
                # Reflected XSS
                "<SVG>", "<IMG SRC=", "ONCLICK=", "ONMOUSEOVER=", 
                "ONFOCUS=", "EXPRESSION(", "PROMPT(",
                
                # DOM-based XSS
                ".innerHTML=", ".outerHTML=", "document.write(",
                
                # Advanced Obfuscation Techniques
                "FROMCHARCODE(", "UNESCAPE(", "ATOB(", 
                "STRING.FROMCHARCODE(", "EVAL(",
                
                # JSON/JavaScript Injection
                "JSON.PARSE(", "CONSTRUCTOR(", 
                
                # Event Handlers and Attribute Injection
                "ONEVENT=", "DATA:TEXT/HTML", "BASE64DECODE(",
                
                # HTML5 Advanced XSS
                "<VIDEO>", "<AUDIO>", "<SOURCE>", 
                "<IFRAME SRCDOC=", "XLINK:HREF="
            ],
            'category': ThreatCategoryEnum.WEB_ATTACKS,
            'confidence': 0.85,
            'severity': 'HIGH',
            'description': "Cross-Site Scripting (XSS) attack targeting client-side script execution"
        },
        'COMMAND_INJECTION': {
            'patterns': [
                # OS Command Injection
                "cmd=", "exec=", "command=", "system(", "shell_exec(", 
                "passthru(", "eval(", ";", "||", "&&", "|",
                
                # Remote Code Execution
                "python -c", "perl -e", "ruby -e", "bash -c", 
                "nc -e", "wget ", "curl ", "powershell",
                
                # Linux/Unix Commands
                ";ls", ";cat", ";rm", ";id", ";pwd", 
                ";whoami", ";uname", ";ifconfig",
                
                # Windows Commands
                "cmd.exe", "powershell.exe", "dir", "type", 
                "netstat", "ipconfig", "net user",
                
                # Advanced Injection Techniques
                "$(", "`", "base64 -d", "echo", 
                "system`", "exec`", "shell_exec`"
            ],
            'category': ThreatCategoryEnum.WEB_ATTACKS,
            'confidence': 0.95,
            'severity': 'CRITICAL',
            'description': "Remote Command Execution attack targeting server-side command processing"
        },
        'FILE_INCLUSION': {
            'patterns': [
                # Local File Inclusion (LFI)
                "../", "..\\", "/..", "\\..", "file://", 
                "/etc/passwd", "C:\\Windows", "%2e%2e%2f", 
                "..\\..", "..%2f", "%252e%252e%252f",
                
                # Remote File Inclusion (RFI)
                "http://", "https://", "ftp://", "php://", 
                "data://", "expect://", "zip://", "phar://",
                
                # Stream Wrappers and Bypass Techniques
                "php://filter", "zip://", "bzip2://", "zlib://",
                "data:text/plain", "data:application/x-php",
                
                # Path Traversal Advanced
                "%00", "..%00", "....//", "%2e%2e%2f%2f",
                
                # Windows Specific
                "system32", "boot.ini", "win.ini"
            ],
            'category': ThreatCategoryEnum.WEB_ATTACKS,
            'confidence': 0.85,
            'severity': 'HIGH',
            'description': "File Inclusion attack targeting unauthorized file access"
        },
        'XXE': {
            'patterns': [
                # XML External Entity Injection
                "<!ENTITY", "<!DOCTYPE", "SYSTEM ", "PUBLIC ", 
                "file://", "php://filter", "data://", 
                "jar:", "netdoc:", "expect:",
                
                # Advanced XXE Techniques
                "LOAD_FILE(", "LOAD DATA", 
                
                # XML Namespace and Schema Attacks
                "xmlns:", "xsi:schemaLocation=", 
                "XML_EXTERNAL_ENTITY", "EXTERNAL_ENTITY",
                
                # Recursive Entity Expansion
                "&xxe;", "&expand;", "&entity;"
            ],
            'category': ThreatCategoryEnum.WEB_ATTACKS,
            'confidence': 0.85,
            'severity': 'HIGH',
            'description': "XML External Entity (XXE) injection targeting XML parser exploitation"
        },
        'SSRF': {
            'patterns': [
                # Server-Side Request Forgery
                "localhost", "127.0.0.1", "::1", 
                "internal-", ".internal.", 
                "169.254.", "192.168.", "10.", "172.",
                
                # Protocol Abuse
                "file://", "dict://", "gopher://", 
                "ldap://", "tftp://", "http://internal",
                
                # AWS Metadata and Cloud Instances
                "169.254.169.254", "ec2-metadata", 
                "metadata.google.internal",
                
                # Local Service Discovery
                "localhost:", "127.0.0.1:", 
                "admin", "dashboard", "internal-api"
            ],
            'category': ThreatCategoryEnum.WEB_ATTACKS,
            'confidence': 0.80,
            'severity': 'HIGH',
            'description': "Server-Side Request Forgery (SSRF) attack targeting internal resource access"
        },
        'DESERIALIZATION': {
            'patterns': [
                # Java Deserialization
                "aced0005", "rO0AB", "\\xac\\xed\\x00\\x05",
                "java.io.serializable", "readObject()",
                
                # PHP Deserialization
                "O:\\d+:\"", "a:\\d+:{", "serialize(",
                
                # Python Pickle Deserialization
                "cos\nystem\n", "cposix\nsystem\n",
                
                # .NET Deserialization
                "AAEAAAD//", 
                
                # Advanced Deserialization Techniques
                "ObjectInputStream", "ObjectOutputStream",
                "json.loads(", "eval(", "pickle.loads(",
                
                # Gadget Chains
                "javax.script", "org.apache.commons", 
                "org.springframework"
            ],
            'category': ThreatCategoryEnum.WEB_ATTACKS,
            'confidence': 0.85,
            'severity': 'CRITICAL',
            'description': "Insecure Deserialization attack targeting serialized object manipulation"
        },
        'PROTOTYPE_POLLUTION': {
            'patterns': [
                # JavaScript Prototype Pollution
                "__proto__", "constructor.prototype", 
                ".prototype.", "Object.prototype",
                
                # Advanced Mutation Techniques
                "Object.defineProperty(", 
                "Object.setPrototypeOf(",
                
                # JSON Injection
                "\"__proto__\":", "\"constructor\":",
                
                # Recursive Prototype Modification
                "this.__proto__", "this.constructor"
            ],
            'category': ThreatCategoryEnum.WEB_ATTACKS,
            'confidence': 0.75,
            'severity': 'MEDIUM',
            'description': "Prototype Pollution attack targeting JavaScript object manipulation"
        }
    }
    
    # Comprehensive attack detection
    attack_tracking = {
        attack_type: {
            'count': 0,
            'sources': set(),
            'targets': set(),
            'details': []
        } for attack_type in attack_patterns.keys()
    }
    
    # Advanced pattern matching and tracking
    for p in http_packets:
        payload = p.get('http_payload', '').upper()
        url = p.get('http_url', '').upper()
        headers = p.get('http_headers', {})
        
        # Analyze each attack type
        for attack_type, attack_info in attack_patterns.items():
            for pattern in attack_info['patterns']:
                # Check for pattern in payload or URL
                if pattern in payload or pattern in url:
                    attack_tracking[attack_type]['count'] += 1
                    attack_tracking[attack_type]['sources'].add(p.get('src_ip', 'Unknown'))
                    attack_tracking[attack_type]['targets'].add(p.get('dst_ip', 'Unknown'))
                    attack_tracking[attack_type]['details'].append({
                        'pattern': pattern,
                        'src_ip': p.get('src_ip', 'Unknown'),
                        'dst_port': p.get('dst_port', 'Unknown'),
                        'timestamp': p.get('timestamp', 'Unknown')
                    })
    
    # Generate threats based on detected attacks
    for attack_type, attack_data in attack_tracking.items():
        if attack_data['count'] > 0:
            attack_info = attack_patterns[attack_type]
            
            # Adjust confidence based on number of detections
            confidence = min(1.0, attack_info['confidence'] + (attack_data['count'] * 0.05))
            
            threats.append(create_threat(
                attack_info['category'],
                confidence,
                attack_info['description'],
                [
                    f"{attack_type} detection count: {attack_data['count']}",
                    f"Attacking sources: {list(attack_data['sources'])[:5]}",
                    f"Targeted destinations: {list(attack_data['targets'])[:5]}",
                    f"Example detection patterns: {[det['pattern'] for det in attack_data['details'][:3]]}"
                ]
            ))
    
    # Additional Web Attack Detection
    # Check for unusual HTTP methods
    unusual_methods = [p.get('http_method', '') for p in http_packets 
                       if p.get('http_method', '').upper() not in ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']]
    
    if len(unusual_methods) > 5:
        threats.append(create_threat(
            ThreatCategoryEnum.WEB_ATTACKS,
            0.70,
            "Unusual HTTP methods detected.",
            [
                f"Unusual methods: {set(unusual_methods)}",
                "Potential web service probing or exploitation attempt"
            ]
        ))
    
    # Check for excessive HTTP errors
    http_errors = [p for p in http_packets if p.get('http_status', 0) >= 400]
    
    if len(http_errors) > 10 and len(http_errors) / len(http_packets) > 0.3:
        error_distribution = {}
        for error in http_errors:
            status = error.get('http_status', 0)
            error_distribution[status] = error_distribution.get(status, 0) + 1
        
        threats.append(create_threat(
            ThreatCategoryEnum.WEB_ATTACKS,
            0.75,
            "High volume of HTTP error responses detected.",
            [
                f"Total HTTP errors: {len(http_errors)}/{len(http_packets)}",
                f"Error distribution: {error_distribution}",
                "Possible web service exploitation or scanning"
            ]
        ))
    
    return threats

def detect_server_attacks(packet_features, stats):
    """
    Detect attacks targeting servers including brute force, privilege escalation, etc.
    
    Args:
        packet_features: List of packet feature dictionaries
        stats: Statistical features extracted from packets
        
    Returns:
        List of detected server attack threats
    """
    threats = []
    
    # Expanded list of credential-protected service ports to monitor
    credential_ports = [
        22, 23, 3389,                  # SSH, Telnet, RDP
        21, 20,                        # FTP control/data
        1433, 3306, 5432, 1521, 27017, # MSSQL, MySQL, PostgreSQL, Oracle, MongoDB
        6379,                          # Redis
        5900, 5901, 5902, 5800,        # VNC
        53, 67, 68,                    # DNS, DHCP
        25, 110, 143, 465, 587, 993,   # Mail (SMTP, POP3, IMAP, SMTPS, Submission, IMAPS)
        445, 135, 139,                 # SMB/CIFS, RPC, NetBIOS (lateral movement)
        161, 162,                      # SNMP
        8080, 8443, 10000              # Web management (Tomcat, Webmin, etc.)
    ]

    # Track port connection attempts
    dst_port_counts = {}
    
    # Common credential port mappings
    common_credential_ports = {
        22: "SSH", 23: "Telnet", 3389: "RDP", 
        21: "FTP", 20: "FTP Data", 1433: "MSSQL", 
        3306: "MySQL", 5432: "PostgreSQL", 
        1521: "Oracle", 27017: "MongoDB", 
        6379: "Redis", 5900: "VNC", 
        53: "DNS", 67: "DHCP Server", 
        25: "SMTP", 110: "POP3", 143: "IMAP", 
        445: "SMB/CIFS", 8080: "HTTP Alternate"
    }

    # Authentication failure patterns (real strings found in packets)
    auth_failure_patterns = [
        'authentication failed', 'login failed', 'failed password',
        'invalid password', 'incorrect password', 'wrong password',
        'access denied', 'permission denied', 'auth failed',
        'failed login', 'login incorrect', '530 login', # FTP error code
        '401 unauthorized', '403 forbidden',  # HTTP error codes
        'authentication error', 'credentials rejected'
    ]

    # Lateral movement commands (actual commands found in packet data)
    lateral_movement_patterns = [
        'psexec', 'psexec.exe', 'wmic.exe', 'wmic process call create',
        'sc \\\\ ', 'sc.exe \\\\ ', 'at \\\\ ', 'schtasks /create /s',
        'net use \\\\ ', 'net.exe use \\\\ ', 'cmd.exe /c', 'powershell -e',
        'invoke-command', 'enter-pssession', 'winrm', 'wsman',
        '\\\\admin$', '\\\\c$', '\\\\ipc$', 'impacket-'
    ]

    # Privilege Escalation Commands (actual commands found in packets)
    priv_escalation_patterns = {
        'basic': [
            'sudo ', 'su -', 'sudo -i', 'chmod 777', 'chmod +s',
            'net user /add', 'net localgroup administrators /add',
            'runas /user:administrator', 'pkexec', 'doas',
            'usermod -G', 'usermod -aG sudo', 'usermod -aG wheel'
        ],
        'advanced': [
            # Unix/Linux commands
            'kernel-exploit', 'dirty_sock', 'overlayfs', 'libseccomp',
            'setcap cap_setuid', 'setcap cap_sys_admin', '/etc/sudoers.d',
            'visudo', '/etc/sudoers', 'polkit', 'dbus-send',
            
            # Windows commands
            'whoami /priv', 'net.exe user', 'reg.exe add hklm\\sam',
            'reg add hkcu\\software\\microsoft\\windows\\currentversion\\run',
            'bcdedit.exe /set', 'fodhelper.exe', 'eventvwr.exe',
            'computerdefaults.exe', 'sdclt.exe', 'sdbinst.exe'
        ],
        'container_escape': [
            '/proc/self/mountinfo', '/proc/self/cgroup', 'docker.sock',
            '/var/run/docker.sock', 'unix:///var/run/docker.sock',
            'privileged=true', 'cap_sys_admin', '/.dockerenv',
            'ctr -n', '/var/run/crio/crio.sock', '/run/containerd/'
        ]
    }
    
    # Windows-specific attack commands/artifacts (actual strings in packets)
    windows_attack_patterns = [
        # Process/service manipulation actual commands
        'sc.exe start', 'sc.exe config', 'sc.exe create',
        'taskkill /f /im', 'tasklist /v', 'regsvr32', 'regsvr32 /s /u',
        
        # Admin shares access
        '\\\\target\\admin$', '\\\\target\\c$', '\\\\target\\ipc$',
        'net view \\\\', 'net use * \\\\', 'copy \\\\ ',
        
        # Registry commands
        'reg query', 'reg add', 'reg delete', 'regedit /s',
        'hklm\\sam', 'hklm\\security', 'hklm\\system\\currentcontrolset',
        'hkcu\\software\\microsoft\\windows\\currentversion\\run',
        
        # Scheduled tasks
        'schtasks /create', 'schtasks /run', 'at \\\\',
        'wmic /node:', 'wmic process call', 'wmic os get',
        
        # Event log manipulation
        'wevtutil cl', 'clear-eventlog', 'wevtutil.exe'
    ]
    
    # Linux-specific attack commands (actual commands in packets)
    linux_attack_patterns = [
        # File access
        'cat /etc/shadow', 'cat /etc/passwd', 'cat /etc/group',
        'cat /var/log/', 'less /var/log/', 'tail -f /var/log/',
        
        # Process manipulation
        'ps -aux', 'ps -ef', 'top -n', 'kill -9', 'pkill -f',
        'nohup ', '& disown', 'exec > /dev/null',
        
        # System commands 
        'echo "" > /var/log/', 'rm -f /var/log/', 'touch -r',
        'chattr +i', 'mount --bind', 'mount -o remount',
        'insmod ', 'modprobe ', 'lsmod | grep',
        'ld_preload', 'ld_library_path', 'strace -p',
        'ptrace ', 'chmod u+s', 'chmod g+s',
        
        # Persistence mechanisms
        '/etc/crontab', '/etc/cron.d', '/var/spool/cron',
        '/etc/init.d/', '/etc/systemd/', 'systemctl enable',
        '.bashrc', '.bash_profile', '.profile'
    ]
    
    # Active Directory attack artifacts (actual strings in packets)
    active_directory_attack_patterns = [
        # Kerberos ticket manipulation 
        'asktgt', 'kerberoast', '.kirbi', 'ticket.bin',
        'rc4-hmac', 'krbtgt/', 'setspn -T', 'setspn -A',
        '-request_id', 'ccache', '.ccache', 
        
        # LDAP queries
        'ldapsearch -x', 'ldapsearch -h', 'ldap://', 'ldaps://',
        'ldapadd ', 'ldapmodify ', '(objectClass=*)',
        'userAccountControl:', 'sAMAccountName', 'objectSid',
        
        # AD enumeration
        'net group "domain admins"', 'net user /domain',
        'dsquery * -limit', 'adfind -f', 'nltest /dclist',
        'net view /domain', 'net view /domain:',
        
        # DCSync/replication
        'lsadump::dcsync', 'drsuapi', 'DsGetNCChanges',
        'ntdsutil', 'ntds.dit', 'vssadmin create shadow',
        'IDirectoryReplication'
    ]

    # Analyze packets
    for packet in packet_features:
        # Track connection attempts to credential ports
        dst_port = packet.get('dst_port')
        if dst_port in credential_ports:
            dst_port_counts[dst_port] = dst_port_counts.get(dst_port, 0) + 1

    # Brute Force Detection
    if any(count > 10 for count in dst_port_counts.values()):
        # Detect and analyze brute force attempts
        targeted_services = []
        auth_failures = 0
        lateral_movement_indicators = 0

        # Identify targeted services
        for port, count in dst_port_counts.items():
            if count > 10:
                targeted_services.append(
                    f"{common_credential_ports.get(port, 'Unknown')} (port {port}): {count} attempts"
                )

        # Check for authentication failures and lateral movement
        for packet in packet_features:
            payload = packet.get('payload_str', '').lower()
            if not payload:
                continue
                
            # Count authentication failures
            if any(term in payload for term in auth_failure_patterns):
                auth_failures += 1
            
            # Detect lateral movement
            if any(pattern in payload for pattern in lateral_movement_patterns):
                lateral_movement_indicators += 1

        # Calculate confidence with nuanced scoring
        base_confidence = 0.75
        base_confidence += min(0.15, auth_failures * 0.01)
        base_confidence += 0.05 if max(dst_port_counts.values()) > 20 else 0
        base_confidence += min(0.15, lateral_movement_indicators * 0.03)
        base_confidence += 0.05 if len(targeted_services) > 2 else 0
        
        confidence = min(0.95, base_confidence)

        # Construct threat indicators
        indicators = [
            'Multiple connection attempts to credential-protected services',
            f"Authentication failure indicators: {auth_failures}" if auth_failures > 0 else "",
            f"Targeted services: {', '.join(targeted_services)}",
            f"Maximum connection attempts: {max(dst_port_counts.values())}"
        ]
        if lateral_movement_indicators > 0:
            indicators.append(f"Lateral movement indicators: {lateral_movement_indicators}")

        threats.append(create_threat(
            ThreatCategoryEnum.SERVER_ATTACKS,
            confidence,
            'Potential brute force attack detected.',
            [ind for ind in indicators if ind]
        ))

    # Privilege Escalation Detection
    priv_basic_count = 0
    priv_advanced_count = 0
    lateral_move_count = 0
    container_escape_count = 0

    for packet in packet_features:
        payload = packet.get('payload_str', '').lower()
        if not payload:
            continue
            
        # Check for privilege escalation patterns
        priv_basic_count += sum(1 for pattern in priv_escalation_patterns['basic'] if pattern in payload)
        priv_advanced_count += sum(1 for pattern in priv_escalation_patterns['advanced'] if pattern in payload)
        lateral_move_count += sum(1 for pattern in lateral_movement_patterns if pattern in payload)
        container_escape_count += sum(1 for pattern in priv_escalation_patterns['container_escape'] if pattern in payload)

    # Calculate privilege escalation score
    priv_score = (
        priv_basic_count + 
        (priv_advanced_count * 2) + 
        (lateral_move_count * 1.5) + 
        (container_escape_count * 3)
    )

    # If privilege escalation score is significant
    if priv_score > 2:
        # Calculate confidence
        base_confidence = 0.70
        base_confidence += min(0.10, priv_advanced_count * 0.025)
        base_confidence += min(0.08, lateral_move_count * 0.02)
        base_confidence += min(0.12, container_escape_count * 0.04)
        base_confidence += min(0.05, priv_basic_count * 0.01)
        
        confidence = min(0.95, base_confidence)

        # Construct indicators
        indicators = [
            f"Basic privilege elevation commands: {priv_basic_count}" if priv_basic_count > 0 else "",
            f"Advanced privilege techniques: {priv_advanced_count}" if priv_advanced_count > 0 else "",
            f"Lateral movement techniques: {lateral_move_count}" if lateral_move_count > 0 else "",
            f"Container escape attempts: {container_escape_count}" if container_escape_count > 0 else "",
            f"Privilege escalation score: {priv_score:.1f}",
            'Possible unauthorized permission elevation'
        ]

        threats.append(create_threat(
            ThreatCategoryEnum.SERVER_ATTACKS,
            confidence,
            'Potential privilege escalation attempt detected.',
            [ind for ind in indicators if ind]
        ))

    # Specific service brute force detection - SSH, FTP, RDP
    ssh_packets = [p for p in packet_features if p.get('dst_port') == 22]
    ftp_packets = [p for p in packet_features if p.get('dst_port') == 21]
    rdp_packets = [p for p in packet_features if p.get('dst_port') == 3389]
    
    # SSH brute force detection (actual packet patterns)
    if len(ssh_packets) > 15:
        ssh_auth_patterns = ['ssh2_msg_userauth_failure', 'no matching cipher', 'invalid user', 
                            'failed password', 'authentication failed', 'connection closed']
        
        ssh_auth_failures = 0
        for packet in ssh_packets:
            payload = packet.get('payload_str', '').lower()
            if payload and any(pattern in payload for pattern in ssh_auth_patterns):
                ssh_auth_failures += 1
                
        if ssh_auth_failures > 5 or len(ssh_packets) > 30:
            threats.append(create_threat(
                ThreatCategoryEnum.SERVER_ATTACKS,
                0.8,
                "Potential SSH brute force attack detected.",
                [f"{ssh_auth_failures} SSH authentication failures detected", 
                 f"{len(ssh_packets)} SSH connection attempts"]
            ))
    
    # FTP brute force detection (actual FTP response codes)
    if len(ftp_packets) > 15:
        ftp_auth_failures = 0
        for packet in ftp_packets:
            payload = packet.get('payload_str', '').lower()
            if payload and ('530 ' in payload or '430 ' in payload or '331 ' in payload or 'login incorrect' in payload):
                ftp_auth_failures += 1
                
        if ftp_auth_failures > 5:
            threats.append(create_threat(
                ThreatCategoryEnum.SERVER_ATTACKS,
                0.75,
                "Potential FTP brute force attack detected.",
                [f"{ftp_auth_failures} FTP authentication failures", 
                 f"{len(ftp_packets)} FTP connection attempts"]
            ))
    
    # RDP brute force detection (looking for high connection volume and small packet sizes)
    if len(rdp_packets) > 20:
        rdp_conn_init = sum(1 for p in rdp_packets if 
                         p.get('payload_str', '') and 
                        ('rdp negotiation' in p.get('payload_str', '').lower() or 
                         'mstshash' in p.get('payload_str', '').lower() or
                         'cookie: mstshash=' in p.get('payload_str', '').lower()))
        
        if rdp_conn_init > 8:
            threats.append(create_threat(
                ThreatCategoryEnum.SERVER_ATTACKS,
                0.7,
                "Potential RDP brute force attack detected.",
                [f"{rdp_conn_init} RDP connection initializations detected", 
                 f"{len(rdp_packets)} RDP packets observed"]
            ))
    
    # Windows-specific Attacks Detection (actual commands in packets)
    windows_attack_count = 0
    windows_attack_examples = []
    
    for packet in packet_features:
        payload = packet.get('payload_str', '').lower()
        if not payload:
            continue
            
        for pattern in windows_attack_patterns:
            if pattern.lower() in payload:
                windows_attack_count += 1
                if len(windows_attack_examples) < 3:  # Collect up to 3 examples
                    windows_attack_examples.append(pattern)
    
    if windows_attack_count > 2:
        confidence = min(0.6 + (windows_attack_count * 0.05), 0.95)
        threats.append(create_threat(
            ThreatCategoryEnum.SERVER_ATTACKS,
            confidence,
            "Potential Windows-specific server attack detected.",
            [f"{windows_attack_count} Windows attack indicators detected", 
             f"Examples: {', '.join(windows_attack_examples)}" if windows_attack_examples else "",
             "Attempts to manipulate Windows system components or services"]
        ))
    
    # Linux-specific attacks (actual commands in packets)
    linux_attack_count = 0
    linux_attack_examples = []
    
    for packet in packet_features:
        payload = packet.get('payload_str', '').lower()
        if not payload:
            continue
            
        for pattern in linux_attack_patterns:
            if pattern.lower() in payload:
                linux_attack_count += 1
                if len(linux_attack_examples) < 3:  # Collect up to 3 examples
                    linux_attack_examples.append(pattern)
    
    if linux_attack_count > 2:
        confidence = min(0.6 + (linux_attack_count * 0.05), 0.95)
        threats.append(create_threat(
            ThreatCategoryEnum.SERVER_ATTACKS,
            confidence,
            "Potential Linux-specific server attack detected.",
            [f"{linux_attack_count} Linux attack indicators detected", 
             f"Examples: {', '.join(linux_attack_examples)}" if linux_attack_examples else "",
             "Attempts to exploit Linux system components or services"]
        ))
    
    # Active Directory Attacks Detection (actual commands/artifacts in packets)
    ad_attack_count = 0
    ad_attack_examples = []
    
    for packet in packet_features:
        payload = packet.get('payload_str', '').lower()
        if not payload:
            continue
            
        for pattern in active_directory_attack_patterns:
            if pattern.lower() in payload:
                ad_attack_count += 1
                if len(ad_attack_examples) < 3:
                    ad_attack_examples.append(pattern)
    
    if ad_attack_count > 1:
        confidence = min(0.65 + (ad_attack_count * 0.05), 0.95)
        threats.append(create_threat(
            ThreatCategoryEnum.SERVER_ATTACKS,
            confidence,
            "Potential Active Directory attack detected.",
            [f"{ad_attack_count} Active Directory attack indicators identified", 
             f"Examples: {', '.join(ad_attack_examples)}" if ad_attack_examples else "",
             "Possible attempt to compromise domain controllers or AD services"]
        ))
    
    # LDAP Injection Detection (actual injection payloads)
    ldap_ports = [389, 636, 3268, 3269]  # Standard LDAP, LDAPS, Global Catalog, Global Catalog over SSL
    ldap_packets = [p for p in packet_features if p.get('dst_port') in ldap_ports]
    
    if ldap_packets:
        ldap_injection_patterns = [
            '*)(*&', '*))%00', '|(objectClass=*)', '&(objectClass=*)', 
            '*()|%26', '*()|&', '*)(uid=*))(|(uid=*', 
            '*))(|(objectclass=*', '*)(uid=*))(|(uid=*',
            '*))(|(password=*', 'cn=*)(|(cn=*', '*)*'
        ]
        
        ldap_injection_count = 0
        ldap_injection_examples = []
        
        for packet in ldap_packets:
            payload = packet.get('payload_str', '').lower()
            if not payload:
                continue
                
            for pattern in ldap_injection_patterns:
                if pattern.lower() in payload:
                    ldap_injection_count += 1
                    if len(ldap_injection_examples) < 3:
                        ldap_injection_examples.append(pattern)
        
        if ldap_injection_count > 2:
            confidence = min(0.6 + (ldap_injection_count * 0.05), 0.9)
            threats.append(create_threat(
                ThreatCategoryEnum.SERVER_ATTACKS,
                confidence,
                "Potential LDAP injection attack detected.",
                [f"{ldap_injection_count} LDAP injection indicators identified", 
                 f"Examples: {', '.join(ldap_injection_examples)}" if ldap_injection_examples else "",
                 "Attempt to manipulate directory services queries"]
            ))
    
    # SMB/CIFS Protocol Attack Detection (actual protocol artifacts)
    smb_packets = [p for p in packet_features if p.get('dst_port') in [445, 139, 137, 138]]
    
    if len(smb_packets) > 10:
        smb_attack_patterns = [
            '\\\\ipc$', '\\\\admin$', '\\\\c$', 
            'srvsvc', 'samr', 'lsarpc', 'netlogon',
            'svcctl', 'spoolss', 'browser',
            'trans2', 'transact', 'negotiate protocol',
            'session setup', 'tree connect', 'net view'
        ]
        
        smb_attack_count = 0
        smb_attack_examples = []
        
        for packet in smb_packets:
            payload = packet.get('payload_str', '').lower()
            if not payload:
                continue
                
            for pattern in smb_attack_patterns:
                if pattern in payload:
                    smb_attack_count += 1
                    if len(smb_attack_examples) < 3:
                        smb_attack_examples.append(pattern)
        
        if smb_attack_count > 5:
            confidence = min(0.65 + (smb_attack_count * 0.03), 0.9)
            threats.append(create_threat(
                ThreatCategoryEnum.SERVER_ATTACKS,
                confidence,
                "Potential SMB/CIFS protocol attack detected.",
                [f"{smb_attack_count} SMB/CIFS attack indicators identified", 
                 f"Examples: {', '.join(smb_attack_examples)}" if smb_attack_examples else "",
                 f"{len(smb_packets)} SMB/CIFS packets analyzed",
                 "Possible attempt to exploit file sharing services"]
            ))
    
    # RPC/DCOM Attack Detection (actual protocol artifacts)
    rpc_packets = [p for p in packet_features if p.get('dst_port') in [135, 593]]
    
    if rpc_packets:
        rpc_attack_patterns = [
            'iactivation', 'iremotescmactivator', 'isystemactivator',
            'dcom_ntlm', 'oxid', 'iremoteactivation',
            'iobject_exporter', 'iwbemservices', 'clsid:',
            'imethodsink', 'oleautomation', 'idispatch',
            'object_uuid:', '{00000000-0000-0000-0000-000000000000}',
            'ncacn_ip_tcp'
        ]
        
        rpc_attack_count = 0
        rpc_attack_examples = []
        
        for packet in rpc_packets:
            payload = packet.get('payload_str', '').lower()
            if not payload:
                continue
                
            for pattern in rpc_attack_patterns:
                if pattern in payload:
                    rpc_attack_count += 1
                    if len(rpc_attack_examples) < 3:
                        rpc_attack_examples.append(pattern)
        
        if rpc_attack_count > 3:
            confidence = min(0.6 + (rpc_attack_count * 0.04), 0.9)
            threats.append(create_threat(
                ThreatCategoryEnum.SERVER_ATTACKS,
                confidence,
                "Potential RPC/DCOM attack detected.",
                [f"{rpc_attack_count} RPC/DCOM attack indicators identified", 
                 f"Examples: {', '.join(rpc_attack_examples)}" if rpc_attack_examples else "", 
                 f"{len(rpc_packets)} RPC/DCOM packets analyzed",
                 "Possible attempt to exploit remote procedure calls"]
            ))
    
    # Memory-based Exploitation Detection (actual signatures found in memory attacks)
    memory_exploit_patterns = [
        # Actual signatures of memory attacks
        '%u9090%u6858%ucbd3', 'shellcode',  # Common shellcode patterns
        '\x90\x90\x90\x90', # NOP sleds
        '\x41\x41\x41\x41', '\x42\x42\x42\x42', # AAAA/BBBB buffer overflow
        'heap spray', 'format string', 'ret2lib', 'ret2libc', 
        'vtable hook', 'free()', 'malloc()', 'double free', 
        'use after free', 'stack overflow', 'rop chain',
        'jmp esp', 'call esp', 'pop pop ret'
    ]
    
    memory_exploit_count = 0
    memory_exploit_examples = []
    
    for packet in packet_features:
        payload = packet.get('payload_str', '').lower()
        if not payload:
            continue
            
        for pattern in memory_exploit_patterns:
            if pattern.lower() in payload:
                memory_exploit_count += 1
                if len(memory_exploit_examples) < 3:
                    memory_exploit_examples.append(pattern)
    
    if memory_exploit_count > 1:
        confidence = min(0.7 + (memory_exploit_count * 0.05), 0.95)
        threats.append(create_threat(
            ThreatCategoryEnum.SERVER_ATTACKS,
            confidence,
            "Potential memory-based exploitation attempt detected.",
            [f"{memory_exploit_count} memory exploitation indicators identified", 
             f"Examples: {', '.join(memory_exploit_examples)}" if memory_exploit_examples else "",
             "Possible attempt to exploit memory management vulnerabilities"]
        ))
    
    # Kerberos Attack Detection (actual Kerberos packet artifacts)
    kerberos_packets = [p for p in packet_features if p.get('dst_port') in [88, 464]]
    
    if kerberos_packets:
        kerberos_attack_patterns = [
            'krb5kdc_err', 'tgt-req', 'tgs-req', 'krbtgt', 'rc4-hmac',
            'checksum field', 'ticket_granting_service', 'kinit',
            'pre-auth', 'preauth', 'apreq', 'authenticator',
            'kerberos spoof', 'asreq', 'AS-REQ', 'TGS-REQ',
            'ticket=', 'ticket.kirbi', 'ticket.ccache',
            'delegation=', 's4u2self', 's4u2proxy'
        ]
        
        kerberos_attack_count = 0
        kerberos_attack_examples = []
        
        for packet in kerberos_packets:
            payload = packet.get('payload_str', '').lower()
            if not payload:
                continue
                
            for pattern in kerberos_attack_patterns:
                if pattern.lower() in payload:
                    kerberos_attack_count += 1
                    if len(kerberos_attack_examples) < 3:
                        kerberos_attack_examples.append(pattern)
        
        # Check for abnormal Kerberos traffic patterns (packets with unusual sizes)
        unusual_sizes = [p for p in kerberos_packets if p.get('packet_size', 0) > 1500]  
        
        if kerberos_attack_count > 2 or len(unusual_sizes) > 3:
            confidence = min(0.65 + (kerberos_attack_count * 0.05) + (len(unusual_sizes) * 0.03), 0.95)
            
            indicators = [
                f"{kerberos_attack_count} Kerberos attack indicators identified" if kerberos_attack_count > 0 else "",
                f"Examples: {', '.join(kerberos_attack_examples)}" if kerberos_attack_examples else "",
                f"{len(unusual_sizes)} unusually large Kerberos packets detected" if len(unusual_sizes) > 0 else "",
                f"{len(kerberos_packets)} Kerberos packets analyzed",
                "Possible Kerberos ticket manipulation or abuse"
            ]
            
            threats.append(create_threat(
                ThreatCategoryEnum.SERVER_ATTACKS,
                confidence,
                "Potential Kerberos-based attack detected.",
                [ind for ind in indicators if ind]
            ))
    
    # DNS-based Attacks (actual DNS query/response artifacts)
    dns_packets = [p for p in packet_features if p.get('dst_port') == 53]
    
    if len(dns_packets) > 20:
        dns_attack_patterns = [
            'zone transfer', 'axfr', 'ixfr', 
            'notify', 'update', 'type any', 
            'type=any', 'dnssec', 'dns query flood',
            'malformed dns', 'dns lookup'
        ]
        
        dns_attack_count = 0
        dns_attack_examples = []
        unique_query_types = set()
        unique_domains = set()
        
        for packet in dns_packets:
            payload = packet.get('payload_str', '').lower()
            if not payload:
                continue
                
            # Check for attack patterns
            for pattern in dns_attack_patterns:
                if pattern in payload:
                    dns_attack_count += 1
                    if len(dns_attack_examples) < 3:
                        dns_attack_examples.append(pattern)
            
            # Extract DNS query types (looking for actual DNS record types in packets)
            for qtype in ['a ', 'aaaa ', 'mx ', 'ns ', 'txt ', 'soa ', 'srv ', 
                           'cname ', 'ptr ', 'any ', 'axfr ', 'ixfr ']:
                if qtype in payload:
                    unique_query_types.add(qtype.strip())
            
            # Extract queried domains (looking for actual domain names in DNS packets)
            if 'query: ' in payload or 'question: ' in payload:
                domains = re.findall(r'[a-zA-Z0-9][-a-zA-Z0-9.]{1,62}\.[a-zA-Z]{2,}', payload)
                for domain in domains:
                    if domain.count('.') > 0:  # Valid domain name
                        unique_domains.add(domain)
        
        # Detect DNS tunneling (many unique subdomains queried)
        tunnel_score = len(unique_domains) / 10 if unique_domains else 0
        
        # Detect zone transfers or enumeration attempts
        enumeration_score = 0
        if 'any' in unique_query_types or 'axfr' in unique_query_types:
            enumeration_score += 10
        enumeration_score += len(unique_query_types) * 2
        
        if dns_attack_count > 2 or tunnel_score > 5 or enumeration_score > 8:
            confidence = min(0.6 + (dns_attack_count * 0.05) + (tunnel_score * 0.02) + (enumeration_score * 0.03), 0.9)
            
            indicators = [
                f"{dns_attack_count} DNS attack indicators identified" if dns_attack_count > 0 else "",
                f"Examples: {', '.join(dns_attack_examples)}" if dns_attack_examples else "",
                f"{len(unique_domains)} unique domains queried" if unique_domains else "",
                f"{len(unique_query_types)} different DNS query types used ({', '.join(unique_query_types)})" if unique_query_types else "",
                f"DNS tunneling score: {tunnel_score:.1f}" if tunnel_score > 0 else "",
                f"DNS enumeration score: {enumeration_score:.1f}" if enumeration_score > 0 else "",
                "Possible DNS reconnaissance, enumeration, or tunneling"
            ]
            
            threats.append(create_threat(
                ThreatCategoryEnum.SERVER_ATTACKS,
                confidence,
                "Potential DNS-based attack detected.",
                [ind for ind in indicators if ind]
            ))
    
    # Service-specific Vulnerabilities Exploitation (actual vulnerability signatures)
    service_vuln_patterns = {
        # Remote services vulnerability signatures (actual exploit snippets/traffic)
        'remote': [
            'ms17-010', 'eternalblue', 'tree connect', 'named pipe',
            'smb signing', 'null session', 'bluekeep', 'ms19-016', 
            'rdesktop', 'rdp connection', 'cve-2019-0708', 
            'ntlm_challenge', 'ntlmssp negotiate', 'ntlmssp challenge',
            'smb2_tree_connect', 'smb2_create', 'smb_transaction', 
            'ntlm_auth', 'kerberos_ticket', 'zerologon',
            'netlogon_negotiate', 'secure channel', 'netlogon_auth',
            'cve-2020-1472', 'HKLM\\software\\microsoft\\exchange',
            'exchange server', '/owa/', '/ecp/'
        ]
    }
    
    vuln_exploit_counts = {category: 0 for category in service_vuln_patterns}
    vuln_exploit_examples = {category: [] for category in service_vuln_patterns}
    
    for packet in packet_features:
        payload = packet.get('payload_str', '').lower()
        if not payload:
            continue
            
        for category, patterns in service_vuln_patterns.items():
            for pattern in patterns:
                if pattern.lower() in payload:
                    vuln_exploit_counts[category] += 1
                    if len(vuln_exploit_examples[category]) < 3:
                        vuln_exploit_examples[category].append(pattern)
    
    # Detect vulnerability exploitation attempts
    for category, count in vuln_exploit_counts.items():
        if count > 1:
            confidence = min(0.7 + (count * 0.04), 0.95)
            
            category_names = {
                'remote': 'Remote service'
            }
            
            threats.append(create_threat(
                ThreatCategoryEnum.SERVER_ATTACKS,
                confidence,
                f"Potential {category_names.get(category, '')} vulnerability exploitation attempt.",
                [f"{count} vulnerability exploitation indicators identified",
                 f"Examples: {', '.join(vuln_exploit_examples[category])}" if vuln_exploit_examples[category] else "", 
                 f"Possible attempt to exploit known {category_names.get(category, '')} vulnerabilities"]
            ))
    
    # Authentication Bypass Attempts (actual authentication bypass payloads)
    auth_bypass_patterns = [
        # Actual authentication bypass payloads
        'basic: ', 'bearer: ', 'jwt: ', 'x-api-key: ',
        'authorization: ', 'x-auth: ', 'cookie: auth=',
        'cookie: session=', 'cookie: token=',
        'alg:none', 'alg:"none"', 'alg:hs256', 'alg:rs256', 
        'eyJhbGciOiJIUzI1', 'eyJhbGciOiJSUzI1',  # JWT headers
        'jwks_uri', 'x.509', '.well-known/jwks.json'
    ]
    
    auth_bypass_count = 0
    auth_bypass_examples = []
    
    for packet in packet_features:
        payload = packet.get('payload_str', '').lower()
        if not payload:
            continue
            
        for pattern in auth_bypass_patterns:
            if pattern.lower() in payload:
                auth_bypass_count += 1
                if len(auth_bypass_examples) < 3:
                    auth_bypass_examples.append(pattern)
    
    if auth_bypass_count > 1:
        confidence = min(0.7 + (auth_bypass_count * 0.05), 0.9)
        threats.append(create_threat(
            ThreatCategoryEnum.SERVER_ATTACKS,
            confidence,
            "Potential authentication bypass attempt detected.",
            [f"{auth_bypass_count} authentication bypass indicators identified", 
             f"Examples: {', '.join(auth_bypass_examples)}" if auth_bypass_examples else "",
             "Possible attempt to circumvent authentication controls"]
        ))
    
    # SSL/TLS Attacks (actual TLS/SSL packet artifacts)
    ssl_tls_packets = [p for p in packet_features if 
                      p.get('dst_port') in [443, 636, 989, 990, 993, 995, 5061] or
                      p.get('proto', '').upper() in ['SSL', 'TLS', 'HTTPS']]
    
    if ssl_tls_packets:
        # Actual TLS/SSL attack signatures (binary/packet signatures)
        ssl_attack_patterns = [
            'heartbeat', '\x18\x03\x01',  # Heartbleed
            'sslv2', 'sslv3', 'tls1.0',   # Outdated protocols
            'fallback_scsv', 'downgrade', # Downgrade attacks
            'compress_certificate', 'compress_context', # Compression attacks
            'rc4_128', 'rc4', 'des_cbc', '3des_cbc', 'null_cipher', # Weak ciphers
            'md5', 'export40', 'export56', 'export1024', # Weak algorithms
            'dhe_export', 'rsa_export', # Export-grade cryptography
            'golden_doodle', 'cve-2014-0160', 'cve-2016-0800' # Vulnerabilities by CVE
        ]
        
        ssl_attack_count = 0
        ssl_attack_examples = []
        
        for packet in ssl_tls_packets:
            payload = packet.get('payload_str', '')
            raw_payload = packet.get('raw_payload', b'')
            
            # Check string payload
            if payload:
                for pattern in ssl_attack_patterns:
                    if pattern in payload.lower():
                        ssl_attack_count += 1
                        if len(ssl_attack_examples) < 3:
                            ssl_attack_examples.append(pattern)
            
            # Check binary payload (for binary signatures)
            if isinstance(raw_payload, bytes):
                for pattern in [b'\x18\x03\x01', b'\x01\x00\x02', b'\x80\x24\x01']:  # Binary signatures
                    if pattern in raw_payload:
                        ssl_attack_count += 1
                        if len(ssl_attack_examples) < 3:
                            ssl_attack_examples.append(pattern.hex())
        
        if ssl_attack_count > 0:
            confidence = min(0.75 + (ssl_attack_count * 0.05), 0.9)
            threats.append(create_threat(
                ThreatCategoryEnum.SERVER_ATTACKS,
                confidence,
                "Potential SSL/TLS vulnerability exploitation attempt.",
                [f"{ssl_attack_count} SSL/TLS attack indicators identified", 
                 f"Examples: {', '.join(ssl_attack_examples)}" if ssl_attack_examples else "",
                 f"{len(ssl_tls_packets)} SSL/TLS packets analyzed",
                 "Possible attempt to exploit encrypted channel vulnerabilities"]
            ))
    
    # Credentials Dumping or Harvesting (actual credential dump signatures)
    credential_dump_patterns = [
        # Windows credential access (actual commands/signatures)
        'mimikatz', 'sekurlsa::logonpasswords', 'sekurlsa::tickets',
        'kerberos::list', 'lsadump::sam', 'lsadump::secrets',
        'procdump -ma lsass.exe', 'comsvcs.dll, MiniDump',
        'reg save hklm\\sam', 'reg save hklm\\system',
        'powershell.exe -command "IEX (New-Object Net.WebClient)',
        
        # Linux credential access (actual commands/signatures)
        'cat /etc/shadow', 'cat /etc/passwd', 'cat /etc/master.passwd',
        'dump_memory', 'memory.dmp', '/proc/kcore', '/etc/sudoers',
        'ssh_config', 'id_rsa', 'id_dsa', 'authorized_keys',
        
        # Database credentials (actual database password access)
        'mysql -u root', 'sqlcmd -U sa', 'psql -U postgres',
        'connection string', 'mongodb://username:password',
        'redis-cli -a', 'postgresql password='
    ]
    
    credential_dump_count = 0
    credential_dump_examples = []
    
    for packet in packet_features:
        payload = packet.get('payload_str', '').lower()
        if not payload:
            continue
            
        for pattern in credential_dump_patterns:
            if pattern.lower() in payload:
                credential_dump_count += 1
                if len(credential_dump_examples) < 3:
                    credential_dump_examples.append(pattern)
    
    if credential_dump_count > 1:
        confidence = min(0.8 + (credential_dump_count * 0.03), 0.95)
        threats.append(create_threat(
            ThreatCategoryEnum.SERVER_ATTACKS,
            confidence,
            "Potential credential harvesting activity detected.",
            [f"{credential_dump_count} credential access indicators identified", 
             f"Examples: {', '.join(credential_dump_examples)}" if credential_dump_examples else "",
             "Possible attempt to extract passwords or authentication tokens"]
        ))
    
    return threats

def detect_known_signatures(packet_features):
    """
    Comprehensive detection of known threat signatures and exploit kits.
    
    Args:
        packet_features: List of packet feature dictionaries
        
    Returns:
        List of detected threats based on known signatures
    """
    threats = []
    
    # Expanded Exploit Kit Detection Patterns
    ek_patterns = {
        'neutrino': ['neutrino_pattern', 'cbsthcfq', 'drd', 'neutrino.js', 'webhook=', 'aot='],
        'rig': ['rig.php', 'rig_landing.php', 'rig_exploit', 'rig/gate.php'],
        'angler': ['angler_ek', 'angler/landing', 'angler/gate', 'angler_exploit'],
        'magnitude': ['mg.php?e=', 'magnitude_landing', 'magnitude/flash', 'magnitude_gate'],
        'nuclear': ['Nuclear/iframe', 'nuclear_ek', 'nuclear_exploit', 'nuclear_landing'],
        'sundown': ['sundown/gate.php', 'sundown_forum', 'sundown_exploit', 'sundown/landing'],
        'cobalt_strike': ['beacon.x64.dll', 'cobaltstrike.beacon', 'CS-beacon', 'cobaltstrike/teamserver'],
        'metasploit': ['meterpreter.bind', 'meterpreter.reverse', 'metasploit/exploit', 'msf_payload'],
        'fallout': ['fallout-kit/gate', 'fallout/landing.php', 'fallout_inject', 'fallout_ek'],
        'underminer': ['underminer_ek', 'underminer/crypto', 'underminer_gate', 'underminer/xmr'],
        'grandsoft': ['grandsoft_ek', 'grandsoft/gate.php', 'grandsoft/inject', 'grandsoft_landing'],
        'obfuscation': [
            'eval(atob(', 'eval(unescape(', 'fromCharCode(unescape',
            'document.write(unescape', 'String.fromCharCode(parseInt',
            'eval(String.fromCharCode', 'eval(function(p,a,c,k,e,d)'
        ]
    }
    
    # Existing malicious patterns
    malicious_patterns = [
        # Malware C2 communication patterns
        b'BOTKILL', b'BOTNET', b'DARKCOMET', b'DUQU2', 
        # Exploits and backdoors
        b'cmd.exe', b'/bin/sh', b'system32\\', b'exec(', 
        # Common shell commands in attacks
        b'wget http', b'curl http', b'nc -e', b'bash -i'
    ]
    
    # Known malicious domains
    malicious_domains = [
        "evil.example.com", "malware.example.net", "backdoor.example.org",
        "botnet-cc.example.com", "ransomware.example.net"
    ]
    
    # Exploit Kit and Signature Detection
    ek_matches = {}
    extended_matches = {}
    
    # Extract URIs from HTTP requests
    http_uris = []
    for p in packet_features:
        if p.get('dst_port') in [80, 443, 8000, 8080]:
            # Try to extract URI from various fields
            uri = p.get('http_uri', '')
            if not uri:
                payload = p.get('payload_str', '')
                if payload and ('GET' in payload or 'POST' in payload):
                    try:
                        uri_start = payload.find('GET ') + 4 if 'GET ' in payload else payload.find('POST ') + 5
                        uri_end = payload.find(' HTTP', uri_start)
                        if uri_start > 4 and uri_end > uri_start:
                            uri = payload[uri_start:uri_end]
                    except:
                        pass
            if uri:
                http_uris.append(uri)
    
    # Expanded pattern matching for Exploit Kits
    for ek_name, patterns in ek_patterns.items():
        # Primary pattern matching
        matches = sum(1 for uri in http_uris if any(pattern in uri.lower() for pattern in patterns))
        
        # Extended matching across payload and URI
        extended_match = sum(1 for p in packet_features 
            if any(pattern in str(p.get('payload_str', '')).lower() or 
                pattern in str(p.get('http_uri', '')).lower() 
                for pattern in patterns))
        
        if matches >= 2 or extended_match >= 3:
            ek_matches[ek_name] = matches
            extended_matches[ek_name] = extended_match
    
    # Suspicious Indicators Collection
    suspicious_indicators = {
        'obfuscated_js': sum(1 for p in packet_features if 
            (p.get('http_content_type', '').lower() == 'application/javascript' or '.js' in p.get('http_uri', '')) and
            (p.get('payload_entropy', 0) > 5.5 or 
            any(obf in str(p.get('payload_str', '')).lower() for obf in ek_patterns['obfuscation']))),
        
        'suspicious_downloads': sum(1 for p in packet_features if 
            any(ext in p.get('http_uri', '').lower() for ext in ['.exe', '.jar', '.swf', '.dll', '.bin', '.ps1', '.msi'])),
        
        'unusual_ports': sum(1 for p in packet_features if 
            p.get('dst_port') in [4433, 4444, 8443, 8081, 8085, 6660, 6661, 6662])  # Known malicious ports
    }
    
    # Payload Signature Detection
    for i, p in enumerate(packet_features):
        payload = p.get('raw_payload', b'')
        if not isinstance(payload, bytes):
            continue
            
        # Check for known malicious patterns
        for pattern in malicious_patterns:
            if pattern in payload:
                threats.append(create_threat(
                    ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
                    0.9,
                    f"Known malicious signature detected in packet payload.",
                    [f"Signature match: {pattern.decode('utf-8', errors='ignore')}", 
                     f"Found in packet #{i+1}"]
                ))
                break
    
    # Domain-based Threat Detection
    for p in packet_features:
        domain = p.get('dns_query', '')
        if domain in malicious_domains:
            threats.append(create_threat(
                ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
                0.95,
                "Communication with known malicious domain.",
                [f"Malicious domain: {domain}", "Matches threat intelligence feed"]
            ))
    
    # Exploit Kit Detection
    # Count HTTP requests in rapid succession (under 1 second)
    rapid_requests = 0
    timestamps = sorted([p.get('timestamp', 0) for p in packet_features 
                    if p.get('dst_port') in [80, 443, 8000, 8080] and p.get('timestamp')])

    if len(timestamps) > 5:
        for i in range(1, len(timestamps)):
            if timestamps[i] - timestamps[i-1] < 1:  # Less than 1 second between requests
                rapid_requests += 1

    # Determine if exploit kit is detected
    if ek_matches or (rapid_requests > 5 and (suspicious_indicators['obfuscated_js'] > 0 or suspicious_indicators['suspicious_downloads'] > 0)):
        # Determine which exploit kit with more sophisticated selection
        detected_ek = max(
            {**ek_matches, **extended_matches}.items(), 
            key=lambda x: x[1]
        )[0] if (ek_matches or extended_matches) else "Unknown"
        
        # Adaptive confidence calculation
        confidence = 0.85
        if suspicious_indicators['suspicious_downloads']:
            confidence += 0.10
        if rapid_requests > 5:
            confidence += 0.05
        if suspicious_indicators['obfuscated_js'] > 0:
            confidence += 0.05
        confidence = min(confidence, 0.95)
        
        # Add Exploit Kit to threats
        threats.append({
            'name': ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
            'confidence': confidence,
            'description': f'Potential {detected_ek.capitalize()} Exploit Kit activity detected.',
            'indicators': [
                f"Detected Exploit Kit: {detected_ek}",
                f"Exploit kit patterns: {', '.join(ek_matches.keys()) if ek_matches else 'Unknown'}",
                f"Rapid HTTP requests: {rapid_requests}",
                f"Suspicious JavaScript: {suspicious_indicators['obfuscated_js']}",
                f"Malicious file downloads: {suspicious_indicators['suspicious_downloads']}",
                f"Unusual ports detected: {suspicious_indicators['unusual_ports']}"
            ]
        })
    
    return threats

def detect_phishing(packet_features):
    """
    Detect web phishing attempts using the web phishing detector.
    
    Args:
        packet_features: List of packet feature dictionaries
        
    Returns:
        List of detected phishing threats
    """
    threats = []
    
    try:
        # Directly use the detect_web_phishing function from the web_phishing_detector module
        web_phishing_threat = detect_web_phishing(packet_features)
        
        # If a web phishing threat is detected, add it to the threats list
        if web_phishing_threat:
            threats.append(web_phishing_threat)
    
    except Exception as e:
        logging.error(f"Error in web phishing detection: {e}")
    
    return threats

def detect_network_device_attacks(packet_features, stats):
    """
    Detect attacks targeting network devices like routers, switches, etc.
    
    Args:
        packet_features: List of packet feature dictionaries
        stats: Statistical features extracted from packets
        
    Returns:
        List of detected network device attack threats
    """
    threats = []
    
    # 1. Layer 2 Attacks: ARP Spoofing Detection
    duplicate_arp_replies = stats.get('duplicate_arp_replies', 0)
    if duplicate_arp_replies > 5:
        threats.append(create_threat(
            ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS,
            0.85,
            'Potential ARP spoofing attack detected.',
            [
                f"Duplicate ARP replies: {duplicate_arp_replies}",
                'Multiple IP-to-MAC mappings detected'
            ]
        ))
    
    # 2. MAC Flooding Detection
    unique_mac_addresses = stats.get('unique_mac_addresses', 0)
    if unique_mac_addresses > 50:
        threats.append(create_threat(
            ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS,
            0.75,
            'Potential MAC flooding attack detected.',
            [
                f"High number of unique MAC addresses: {unique_mac_addresses}",
                'Possible CAM table overflow attempt'
            ]
        ))
    
    # 3. MAC Spoofing Detection
    mac_spoofing_indicators = stats.get('mac_spoofing_indicators', 0)
    mac_address_changes = stats.get('mac_address_changes', 0)
    
    if mac_spoofing_indicators > 3 or mac_address_changes > 5:
        threats.append(create_threat(
            ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS,
            0.80,
            'Potential MAC address spoofing detected.',
            [
                f"MAC spoofing indicators: {mac_spoofing_indicators}" if mac_spoofing_indicators > 0 else "",
                f"Rapid MAC address changes: {mac_address_changes}" if mac_address_changes > 0 else "",
                'Possible identity spoofing at data link layer'
            ]
        ))
    
    # 4. VLAN Attacks: VLAN Hopping Detection
    double_tagged_frames = stats.get('double_tagged_frames', 0)
    switch_spoofing_attempts = stats.get('switch_spoofing_attempts', 0)
    
    if double_tagged_frames > 0 or switch_spoofing_attempts > 0:
        threats.append(create_threat(
            ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS,
            0.80,
            'Potential VLAN hopping attack detected.',
            [
                f"Double-tagged frames: {double_tagged_frames}" if double_tagged_frames > 0 else "",
                f"Switch spoofing attempts: {switch_spoofing_attempts}" if switch_spoofing_attempts > 0 else "",
                'Possible unauthorized VLAN access attempt'
            ]
        ))
    
    # 5. Private VLAN Attack Detection
    private_vlan_bypass = stats.get('private_vlan_bypass', 0)
    if private_vlan_bypass > 0:
        threats.append(create_threat(
            ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS,
            0.85,
            'Potential Private VLAN bypass attempt detected.',
            [
                f"Private VLAN security bypass attempts: {private_vlan_bypass}",
                'Possible unauthorized inter-VLAN communication'
            ]
        ))
    
    # 6. Original Router/Switch Exploitation Detection
    router_admin_ports = [80, 443, 8080, 8443, 22, 23, 161, 162, 2000, 2001, 4786]
    
    # Count packets to router admin interfaces
    admin_packets = [p for p in packet_features if p.get('dst_port') in router_admin_ports]
    
    if len(admin_packets) > 10:
        # Check for patterns indicating router exploitation
        exploit_indicators = [
            "cisco", "juniper", "mikrotik", "huawei", "router", "admin", "setup",
            "password", "config", "default", ".cgi", ".pl", "backdoor"
        ]
        
        exploit_count = 0
        for p in admin_packets:
            payload = p.get('http_payload', '') or ''
            url = p.get('http_url', '') or ''
            
            for indicator in exploit_indicators:
                if (indicator in payload.lower() or indicator in url.lower()):
                    exploit_count += 1
                    break
        
        if exploit_count > 0:
            threats.append(create_threat(
                ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS,
                0.8,
                "Potential network device exploitation attempt detected.",
                [f"{exploit_count} suspicious requests to device admin interfaces",
                 f"Targeting ports: {sorted(set(p.get('dst_port') for p in admin_packets))}"]
            ))
    
    # 7. SNMP-based Attacks
    snmp_packets = [p for p in packet_features if p.get('protocol') == 'SNMP']
    if len(snmp_packets) > 5:
        # Check for SNMP community string brute force
        community_strings = set(p.get('snmp_community', '') for p in snmp_packets if 'snmp_community' in p)
        
        if len(community_strings) > 3:
            threats.append(create_threat(
                ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS,
                0.75,
                "Potential SNMP community string brute force attack.",
                [f"Multiple community strings attempted: {len(community_strings)}",
                 "Targeting network monitoring and management interfaces"]
            ))
        
        # Check for SNMP write operations (potential configuration changes)
        snmp_set_packets = [p for p in snmp_packets if p.get('snmp_operation') == 'set']
        if snmp_set_packets:
            threats.append(create_threat(
                ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS,
                0.85,
                "SNMP write operations detected - potential unauthorized configuration changes.",
                [f"{len(snmp_set_packets)} SNMP SET operations",
                 "Possible unauthorized device configuration modification"]
            ))
    
    # 8. Additional Attack Detection Methods from Second Document
    # Wireless Attacks
    wifi_deauth_packets = stats.get('wifi_deauth_packets', 0)
    wifi_beacon_flood = stats.get('wifi_beacon_flood', 0)
    evil_twin_indicators = stats.get('evil_twin_indicators', 0)
    
    if wifi_deauth_packets > 10:
        threats.append(create_threat(
            ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS,
            0.90,
            'Potential WiFi deauthentication attack detected.',
            [
                f"Deauthentication packets: {wifi_deauth_packets}",
                'Possible wireless denial of service'
            ]
        ))
    
    if wifi_beacon_flood > 30 or evil_twin_indicators > 0:
        threats.append(create_threat(
            ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS,
            0.85,
            'Potential rogue access point attack detected.',
            [
                f"Beacon flood detected: {wifi_beacon_flood}" if wifi_beacon_flood > 30 else "",
                f"Evil twin indicators: {evil_twin_indicators}" if evil_twin_indicators > 0 else "",
                'Possible wireless man-in-the-middle attack'
            ]
        ))
    
    # 9. Firewall Bypass Attempts
    firewall_bypass = {
        'port_hopping': stats.get('port_hopping', 0),
        'packet_fragmentation': stats.get('packet_fragmentation', 0),
        'covert_channels': stats.get('covert_channels', 0),
        'tunnel_detection': stats.get('tunnel_detection', 0)
    }
    
    if any(count > 3 for count in firewall_bypass.values()):
        # Build indicators for firewall bypass techniques
        bypass_indicators = []
        for technique, count in firewall_bypass.items():
            if count > 3:
                technique_name = technique.replace('_', ' ').title()
                bypass_indicators.append(f"{technique_name}: {count} instances")
        
        threats.append(create_threat(
            ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS,
            0.80,
            'Potential firewall bypass attempt detected.',
            bypass_indicators + ['Possible attempt to circumvent network security controls']
        ))
    
    return threats

def detect_behavioral_anomalies(packet_features, stats):
    """
    Detect behavioral anomalies and deviations from normal patterns.
    
    Args:
        packet_features: List of packet feature dictionaries
        stats: Statistical features extracted from packets
        
    Returns:
        List of detected anomaly threats
    """
    threats = []
    
    # Check for unusual protocol distribution
    protocol_counts = stats.get('protocol_counts', {})
    total_packets = len(packet_features)
    
    # Typical enterprise protocol distribution (approximate)
    typical_distribution = {
        'TCP': 0.65,  # 65%
        'UDP': 0.25,  # 25%
        'ICMP': 0.02, # 2%
        'HTTP': 0.30, # 30%
        'HTTPS': 0.35, # 35%
        'DNS': 0.10,  # 10%
        'OTHER': 0.08  # 8%
    }
    
    # Find significant deviations from typical distribution
    deviations = []
    for protocol, typical_ratio in typical_distribution.items():
        actual_count = protocol_counts.get(protocol, 0)
        actual_ratio = actual_count / total_packets if total_packets > 0 else 0
        
        # Check if the actual ratio deviates significantly (more than double or less than half)
        if actual_ratio > 0.05 and (actual_ratio > 2.5 * typical_ratio or actual_ratio < 0.4 * typical_ratio):
            deviation = actual_ratio / typical_ratio if typical_ratio > 0 else float('inf')
            deviations.append(f"{protocol}: {actual_ratio:.2f} (expected ~{typical_ratio:.2f}, {deviation:.1f}x difference)")
    
    if len(deviations) >= 2:  # Multiple protocol anomalies
        threats.append(create_threat(
            ThreatCategoryEnum.UNKNOWN,
            0.65,
            "Unusual network protocol distribution detected.",
            [f"Protocol anomalies: {', '.join(deviations[:3])}", 
             "Potential abnormal network behavior"]
        ))
    
    # Check for unusual packet size distribution
    packet_sizes = [p.get('packet_size', 0) for p in packet_features]
    if packet_sizes:
        # Calculate quartiles for packet size distribution
        q1 = np.percentile(packet_sizes, 25)
        q3 = np.percentile(packet_sizes, 75)
        iqr = q3 - q1
        
        # Look for unusually large packets (potential data exfiltration or tunneling)
        upper_bound = q3 + 1.5 * iqr
        outliers = [size for size in packet_sizes if size > upper_bound]
        
        if len(outliers) > 5 and len(outliers) / len(packet_sizes) > 0.1:
            threats.append(create_threat(
                ThreatCategoryEnum.UNKNOWN,
                0.6,
                "Unusual packet size distribution detected.",
                [f"{len(outliers)} outlier packets ({len(outliers)/len(packet_sizes):.1%} of traffic)",
                 f"Average outlier size: {sum(outliers)/len(outliers):.0f} bytes vs normal {(q1+q3)/2:.0f} bytes"]
            ))
    
    # Zero-Day and APT Detection Integration
    try:
        # Import the anomaly detection module
        from anomaly_detection import add_zero_day_apt_detection
        
        # Add zero-day and APT detection results
        threats = add_zero_day_apt_detection(threats, packet_features)
    except ImportError:
        logging.warning("Anomaly detection module not available. Zero-day and APT detection disabled.")
    except Exception as e:
        logging.error(f"Error in zero-day/APT detection: {e}")
    
    return threats

def detect_malicious_behavior(packet_features, stats):
    """
    Advanced detection of malicious network behaviors with comprehensive analysis.
    
    Args:
        packet_features: List of packet feature dictionaries
        stats: Statistical features extracted from packets
        
    Returns:
        List of detected malicious behavior threats
    """
    threats = []
    
    # 1. Advanced Encrypted Communication Detection
    encrypted_communication_indicators = {
        'high_entropy_packets': sum(1 for p in packet_features if p.get('payload_entropy', 0) > 7.5),
        'encrypted_percentage': sum(1 for p in packet_features if p.get('payload_entropy', 0) > 7.5) / max(1, len(packet_features)),
        'unusual_encryption_sources': set()
    }
    
    for p in packet_features:
        if p.get('payload_entropy', 0) > 7.5:
            encrypted_communication_indicators['unusual_encryption_sources'].add(p.get('src_ip', 'Unknown'))
    
    if (encrypted_communication_indicators['high_entropy_packets'] > 10 and 
        encrypted_communication_indicators['encrypted_percentage'] > 0.3):
        threats.append(create_threat(
            ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
            0.85,
            "Advanced Encrypted Communication Detected",
            [
                f"High entropy packets: {encrypted_communication_indicators['high_entropy_packets']}",
                f"Encrypted traffic percentage: {encrypted_communication_indicators['encrypted_percentage']:.1%}",
                f"Unique encryption sources: {len(encrypted_communication_indicators['unusual_encryption_sources'])}",
                "Potential covert communication channel"
            ]
        ))
    
    # 2. Data Exfiltration Detection
    data_exfiltration_indicators = {
        'large_uploads': sum(1 for p in packet_features 
            if p.get('payload_length', 0) > 10000 and p.get('direction', '') == 'outbound'),
        'unusual_destinations': len(set(p.get('dst_ip', '') for p in packet_features 
            if p.get('payload_length', 0) > 10000 and p.get('direction', '') == 'outbound')),
        'encoded_payloads': sum(1 for p in packet_features 
            if any(pattern in p.get('payload_str', '').lower() for pattern in 
                   ['base64', 'encode', '=', '==']) and p.get('payload_entropy', 0) > 5.0)
    }
    
    if (data_exfiltration_indicators['large_uploads'] > 5 or 
        data_exfiltration_indicators['unusual_destinations'] > 3 or 
        data_exfiltration_indicators['encoded_payloads'] > 2):
        threats.append(create_threat(
            ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
            0.80,
            "Potential Data Exfiltration Attempt Detected",
            [
                f"Large upload count: {data_exfiltration_indicators['large_uploads']}",
                f"Unique exfiltration destinations: {data_exfiltration_indicators['unusual_destinations']}",
                f"Encoded payload indicators: {data_exfiltration_indicators['encoded_payloads']}",
                "Possible sensitive data transfer"
            ]
        ))
    
    # 3. Command and Control (C2) Communication Detection
    c2_communication_indicators = {
        'beaconing_ips': set(),
        'communication_intervals': []
    }
    
    # Analyze communication patterns
    timestamps_by_dest = {}
    for packet in packet_features:
        dst_ip = packet.get('dst_ip', '')
        timestamp = packet.get('timestamp', 0)
        if dst_ip and timestamp:
            if dst_ip not in timestamps_by_dest:
                timestamps_by_dest[dst_ip] = []
            timestamps_by_dest[dst_ip].append(timestamp)
    
    for ip, times in timestamps_by_dest.items():
        if len(times) > 4:  # Need at least 5 data points
            times.sort()
            intervals = [times[i] - times[i-1] for i in range(1, len(times))]
            
            # Calculate coefficient of variation
            if intervals:
                mean_interval = sum(intervals) / len(intervals)
                variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = variance ** 0.5
                cv = std_dev / mean_interval if mean_interval else float('inf')
                
                # Detect regular beaconing
                if cv < 0.3 and mean_interval > 5:
                    c2_communication_indicators['beaconing_ips'].add(ip)
                    c2_communication_indicators['communication_intervals'].append(mean_interval)
    
    if len(c2_communication_indicators['beaconing_ips']) > 2:
        threats.append(create_threat(
            ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
            0.85,
            "Potential Command and Control (C2) Communication Detected",
            [
                f"Beaconing IPs: {len(c2_communication_indicators['beaconing_ips'])}",
                f"Average beacon interval: {sum(c2_communication_indicators['communication_intervals']) / len(c2_communication_indicators['communication_intervals']):.1f} seconds",
                "Consistent communication pattern suggesting C2 infrastructure"
            ]
        ))
    
    # 4. Cryptomining Activity Detection
    cryptomining_indicators = {
        'mining_ports': sum(1 for p in packet_features 
            if p.get('dst_port') in [3333, 3334, 3335, 5555, 7777, 8888, 9999, 14444, 14433]),
        'mining_pool_connections': sum(1 for p in packet_features 
            if any(pool in p.get('payload_str', '').lower() for pool in 
                   ['pool.', 'mine.', 'xmr.', 'monero', 'crypto', 'coin', 'btc', 'eth', '.pool'])),
        'stratum_protocol': sum(1 for p in packet_features 
            if any(pattern in p.get('payload_str', '').lower() for pattern in 
                   ['stratum+tcp', 'submitwork', 'getwork', 'mining.subscribe', 'mining.authorize']))
    }
    
    if (cryptomining_indicators['mining_ports'] > 3 or 
        cryptomining_indicators['mining_pool_connections'] > 0 or 
        cryptomining_indicators['stratum_protocol'] > 0):
        threats.append(create_threat(
            ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
            0.75,
            "Potential Cryptocurrency Mining Activity Detected",
            [
                f"Mining port connections: {cryptomining_indicators['mining_ports']}",
                f"Mining pool connections: {cryptomining_indicators['mining_pool_connections']}",
                f"Stratum protocol indicators: {cryptomining_indicators['stratum_protocol']}",
                "Unauthorized resource consumption for cryptocurrency mining"
            ]
        ))
    
    # 5. Unusual Network Behavior Detection
    network_behavior_indicators = {
        'non_standard_protocols': sum(1 for p in packet_features 
            if p.get('protocol') not in ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS']),
        'fragmented_packets': sum(1 for p in packet_features if p.get('is_fragmented', False)),
        'tunnel_indicators': sum(1 for p in packet_features 
            if any(keyword in p.get('payload_str', '').lower() 
                   for keyword in ['tunnel', 'vpn', 'proxy', 'obfuscate']))
    }
    
    if (network_behavior_indicators['non_standard_protocols'] > 5 or 
        network_behavior_indicators['fragmented_packets'] > 10 or 
        network_behavior_indicators['tunnel_indicators'] > 3):
        threats.append(create_threat(
            ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
            0.70,
            "Unusual Network Behavior Detected",
            [
                f"Non-standard protocols: {network_behavior_indicators['non_standard_protocols']}",
                f"Fragmented packets: {network_behavior_indicators['fragmented_packets']}",
                f"Tunnel/proxy indicators: {network_behavior_indicators['tunnel_indicators']}",
                "Potential use of covert communication channels"
            ]
        ))
    
    # 6. Suspicious External Communication
    external_communication_indicators = {
        'tor_connections': sum(1 for p in packet_features 
            if p.get('dst_port') in [9001, 9030, 9050, 9051]),
        'suspicious_tlds': sum(1 for p in packet_features 
            if any(tld in p.get('dst_domain', '').lower() 
                   for tld in ['.ru', '.cn', '.ir', '.kp', '.xyz', '.top'])),
        'dynamic_dns': sum(1 for p in packet_features 
            if any(ddns in p.get('dst_domain', '').lower() 
                   for ddns in ['no-ip.com', 'dyndns.org', 'dynamicdns.net']))
    }
    
    if (external_communication_indicators['tor_connections'] > 2 or 
        external_communication_indicators['suspicious_tlds'] > 3 or 
        external_communication_indicators['dynamic_dns'] > 2):
        threats.append(create_threat(
            ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
            0.75,
            "Suspicious External Communication Detected",
            [
                f"Tor network connections: {external_communication_indicators['tor_connections']}",
                f"Suspicious TLD connections: {external_communication_indicators['suspicious_tlds']}",
                f"Dynamic DNS usage: {external_communication_indicators['dynamic_dns']}",
                "Potential connection to malicious infrastructure"
            ]
        ))
    
    # 7. Ransomware Detection
    ransomware_indicators = {
        'crypto_extensions': [
            '.crypt', '.locked', '.encrypted', '.enc', '.crypto', 
            '.pay', '.ransom', '.wallet', '.cerber', '.LockyLocker'
        ],
        'ransom_note_patterns': [
            'bitcoin', 'btc', 'ransom', 'decrypt', 'pay', 'wallet', 
            'your files are encrypted', 'contact for decryption',
            'restore files', 'payment deadline'
        ],
        'extension_matches': sum(1 for p in packet_features 
            if any(ext in p.get('payload_str', '').lower() for ext in 
                   ['.crypt', '.locked', '.encrypted', '.enc', '.crypto'])),
        'ransom_note_count': sum(1 for p in packet_features 
            if any(pattern in p.get('payload_str', '').lower() for pattern in 
                   ['bitcoin', 'btc', 'ransom', 'decrypt', 'pay', 'wallet'])),
        'tor_connections': sum(1 for p in packet_features 
            if p.get('dst_port') in [9001, 9030, 9050, 9051]),
        'unusual_file_access': stats.get('high_file_access', False)
    }
    
    if (ransomware_indicators['extension_matches'] > 3 or 
        ransomware_indicators['ransom_note_count'] > 2 or 
        (ransomware_indicators['tor_connections'] > 0 and ransomware_indicators['unusual_file_access'])):
        threats.append(create_threat(
            ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
            0.85,
            "Advanced Ransomware Activity Detected",
            [
                f"Encrypted file extensions detected: {ransomware_indicators['extension_matches']}",
                f"Ransom note indicators: {ransomware_indicators['ransom_note_count']}",
                f"Tor network connections: {ransomware_indicators['tor_connections']}",
                "Potential file encryption and extortion attempt"
            ]
        ))
    
    # 8. Backdoor Detection
    backdoor_indicators = {
        'reverse_shell_patterns': [
            'nc -e', 'nc.exe -e', 'bash -i', '/bin/sh -i', 'cmd.exe /c', 
            'powershell -e', 'powershell -enc', 'meterpreter', 'empire', 
            'cobalt strike', 'beacon_', 'c2_callback', 'remote shell',
            'reverse_shell', 'bind_shell', '/dev/tcp/', 'socket.connect'
        ],
        'remote_access_count': sum(1 for p in packet_features 
            if any(pattern in p.get('payload_str', '').lower() for pattern in 
                ['rdp', 'ssh', 'remote desktop', 'teamviewer', 'anydesk'])),
        'unusual_ports': sum(1 for p in packet_features 
            if p.get('dst_port') > 1024 and p.get('dst_port') not in [3389, 5900, 5800]),
        'persistent_connections': len(set(
            f"{p.get('dst_ip')}:{p.get('dst_port')}" for p in packet_features 
            if p.get('dst_port') > 1024
        )),
        'privilege_escalation_hints': sum(1 for p in packet_features 
            if any(pattern in p.get('payload_str', '').lower() for pattern in 
                ['sudo', 'su -', 'setuid', 'elevation', 'token manipulation']))
    }

    # Enhanced RAT detection - integrate with backdoor detection
    additional_rat_indicators = {
        'windows_specific': [
            'darkcomet', 'remcos', 'njrat', 'revenge-rat', 'poison ivy',
            'ghostrat', 'blackshades', 'luminosity', 'net remote'
        ],
        'unix_linux_specific': [
            'reverse connection', 'python -c', 'perl -e', 'php -r',
            'socat', 'ssh -R', 'bind shell'
        ],
        'macos_specific': [
            'backdoor.macos', 'osascript', 'applescript', 'launchctl',
            'eggshell', 'empyre', 'merlin'
        ],
        'cross_platform': [
            'covenant', 'mythic', 'brute ratel', 'sliver', 'havoc'
        ]
    }

    # Track RAT detection by OS type
    rat_detection = {os_type: 0 for os_type in additional_rat_indicators.keys()}

    # Check for RAT indicators beyond what's already covered
    for packet in packet_features:
        payload = packet.get('payload_str', '').lower() if packet.get('payload_str') else ''
        if not payload:
            continue
            
        # Check for RAT indicators by OS type
        for os_type, indicators in additional_rat_indicators.items():
            if any(indicator in payload for indicator in indicators):
                rat_detection[os_type] += 1

    # Add RAT detection info to backdoor detection
    if any(count > 0 for count in rat_detection.values()):
        backdoor_indicators['platform_specific_rat'] = sum(rat_detection.values())
        backdoor_indicators['primary_target_os'] = max(rat_detection.items(), key=lambda x: x[1])[0]

    # Create the backdoor threat if indicators are found
    if (backdoor_indicators['remote_access_count'] > 3 or 
        backdoor_indicators['unusual_ports'] > 5 or 
        backdoor_indicators['persistent_connections'] > 10 or 
        backdoor_indicators['privilege_escalation_hints'] > 0 or
        backdoor_indicators.get('platform_specific_rat', 0) > 0):
        
        # Build the threat indicators list
        threat_indicators = [
            f"Remote access attempts: {backdoor_indicators['remote_access_count']}",
            f"Unusual port connections: {backdoor_indicators['unusual_ports']}",
            f"Persistent network connections: {backdoor_indicators['persistent_connections']}",
            f"Privilege escalation indicators: {backdoor_indicators['privilege_escalation_hints']}",
        ]
        
        # Add OS-specific RAT indicators if detected
        if backdoor_indicators.get('platform_specific_rat', 0) > 0:
            threat_indicators.append(f"OS-specific RAT indicators: {backdoor_indicators['platform_specific_rat']}")
            threat_indicators.append(f"Primary target OS: {backdoor_indicators['primary_target_os'].replace('_specific', '')}")
        
        # Add final indicator
        threat_indicators.append("Potential unauthorized remote access attempt")
        
        # Calculate confidence based on the number of indicators
        base_confidence = 0.80
        if backdoor_indicators.get('platform_specific_rat', 0) > 0:
            base_confidence += min(0.15, backdoor_indicators['platform_specific_rat'] * 0.01)
        
        threats.append(create_threat(
            ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
            min(0.95, base_confidence),  # Cap at 0.95
            "Advanced Backdoor Communication Detected",
            threat_indicators
        ))

    # 9. Linux Rootkit Detection (completely new, no overlap)
    linux_rootkit_indicators = [
        'insmod', 'modprobe', 'kmod', 'lsmod', 'rmmod',
        'hidden process', '/dev/mem', '/dev/kmem', 'syscall table',
        'interrupt descriptor table', 'rootkit', '/proc/modules',
        '/proc/kallsyms', 'kernel module', 'loadable module',
        'kill -31', 'strace', 'ptrace', 'adore', 'suterusu',
        'diamorphine', 'azazel', 'jynx', 'knark', 'modhide',
        '/dev/.', '/tmp/.', '/lib/.', '/lib64/.', '/boot/.'
    ]

    linux_rootkit_matches = 0
    linux_rootkit_details = []

    for packet in packet_features:
        payload = packet.get('payload_str', '').lower() if packet.get('payload_str') else ''
        if not payload:
            continue
            
        # Check for Linux rootkit indicators
        matched_indicators = [indicator for indicator in linux_rootkit_indicators 
                            if indicator in payload]
        
        if matched_indicators:
            linux_rootkit_matches += len(matched_indicators)
            linux_rootkit_details.extend(matched_indicators[:3])  # Limit to 3 indicators per packet

    if linux_rootkit_matches > 2:
        # Confidence increases with more matches
        confidence = min(0.95, 0.80 + linux_rootkit_matches * 0.01)
        
        threats.append(create_threat(
            ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
            confidence,
            "Linux Rootkit Activity Detected",
            [
                f"Rootkit indicators found: {linux_rootkit_matches}",
                f"Suspicious components: {', '.join(set(linux_rootkit_details)[:5])}",
                "Potential kernel-level compromise of Linux systems"
            ]
        ))

    # 10. Enhanced Script Execution Detection
    script_execution_patterns = {
        'windows': [
            'wscript.exe', 'cscript.exe', 'mshta.exe',
            'certutil -decode', 'certutil -urlcache',
            'bitsadmin /transfer', 'installutil.exe', 'regasm.exe',
            'regsvcs.exe', 'msbuild.exe', 'ieexec.exe'
        ],
        'unix_linux': [
            'eval $(', 'python -c', 'perl -e', 'ruby -e',
            'php -r', 'curl | bash', 'wget | bash', '| sh',
            'base64 -d', 'curl | sh', 'wget | sh'
        ],
        'macos': [
            'osascript -e', 'system("', 'python -c',
            'perl -e', 'ruby -e', 'curl | bash', 'curl | sh'
        ]
    }

    script_execution_count = {os_type: 0 for os_type in script_execution_patterns.keys()}
    script_execution_examples = {os_type: [] for os_type in script_execution_patterns.keys()}

    for packet in packet_features:
        payload = packet.get('payload_str', '').lower() if packet.get('payload_str') else ''
        if not payload:
            continue
            
        # Check for suspicious script execution patterns
        for os_type, patterns in script_execution_patterns.items():
            for pattern in patterns:
                if pattern in payload:
                    script_execution_count[os_type] += 1
                    
                    # Get the full command context when possible
                    start_index = payload.find(pattern)
                    if start_index != -1:
                        end_index = payload.find('\n', start_index)
                        if end_index == -1:
                            end_index = min(start_index + 100, len(payload))
                        
                        command_context = payload[start_index:end_index]
                        if len(script_execution_examples[os_type]) < 3:  # Limit to 3 examples per OS
                            script_execution_examples[os_type].append(command_context)
                    break

    if any(count > 1 for count in script_execution_count.values()):
        total_script_exec = sum(script_execution_count.values())
        
        # Confidence increases with more suspicious patterns
        confidence = min(0.90, 0.70 + total_script_exec * 0.02)
        
        # Build indicators
        script_indicators = []
        for os_type, count in script_execution_count.items():
            if count > 0:
                script_indicators.append(f"{os_type.capitalize()} script execution: {count}")
                
                # Add examples if available
                if script_execution_examples[os_type]:
                    examples = '; '.join(script_execution_examples[os_type])
                    if len(examples) > 100:
                        examples = examples[:97] + '...'
                    script_indicators.append(f"Example patterns: {examples}")
        
        threats.append(create_threat(
            ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
            confidence,
            "Suspicious Script Execution Detected",
            script_indicators + ["Potential malicious code execution attempt"]
        ))

    # 11. Remote Code Execution (RCE) detection
    rce_patterns = [
        # Windows RCE actual command signatures
        'cmd.exe /c', 'cmd /c', 'cmd /k', 'powershell -e', 'powershell -enc',
        'powershell -exec bypass', 'powershell -nop', 'powershell iex',
        'wscript.shell', 'rundll32.exe', 'regsvr32 /s /u /i:',
        'mshta.exe http', 'certutil -urlcache -f', 'bitsadmin /transfer',
        
        # Linux RCE actual command signatures
        'wget http', 'curl http', 'wget -O-|', 'curl -s|', 'bash -i',
        '/dev/tcp/', 'nc -e', 'python -c', 'perl -e', 'ruby -e',
        'bash -c', 'socat', 'wget|bash', 'curl|bash', 'curl|sh',
        
        # Common RCE payloads
        'bash -i >& /dev/tcp/', 'bash -c', 'exec /bin/bash',
        'perl -e \'use socket', 'python -c \'import socket',
        'php -r', 'exec(\\"bash', 'system(', 'shell_exec(',
        'proc_open', 'eval(base64_decode'
    ]

    rce_attempt_count = 0
    rce_examples = []

    for packet in packet_features:
        payload = packet.get('payload_str', '').lower()
        if not payload:
            continue
            
        for pattern in rce_patterns:
            if pattern.lower() in payload:
                rce_attempt_count += 1
                if len(rce_examples) < 3:
                    rce_examples.append(pattern)

    if rce_attempt_count > 1:
        confidence = min(0.75 + (rce_attempt_count * 0.05), 0.95)
        threats.append(create_threat(
            ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
            confidence,
            "Potential remote code execution (RCE) attempt detected.",
            [f"{rce_attempt_count} RCE attempt indicators identified", 
            f"Examples: {', '.join(rce_examples)}" if rce_examples else "",
            "Possible attempt to execute arbitrary code on the server"]
        ))

    return threats
