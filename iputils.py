import logging
from ipaddress import ip_address, ip_network

# Public DNS Servers
PUBLIC_DNS_SERVERS = {
    # Google Public DNS
    '8.8.8.8',      # Primary
    '8.8.4.4',      # Secondary
    
    # Cloudflare DNS
    '1.1.1.1',      # Primary
    '1.0.0.1',      # Secondary
    
    # OpenDNS 
    '208.67.222.222',  # Primary
    '208.67.220.220',  # Secondary
    
    # Quad9 DNS
    '9.9.9.9',      # Primary
    '149.112.112.112', # Secondary
    
    # Level3 DNS
    '4.2.2.1',      # Primary
    '4.2.2.2',      # Secondary
    
    # IBM Quad9
    '9.9.9.9',
    
    # AdGuard DNS
    '94.140.14.14',
    '94.140.15.15',
    
    # Cisco OpenDNS
    '208.67.222.123',
    '208.67.220.123',
    
    # Verisign
    '64.6.64.6',
    '64.6.65.6'
}

# Cloud Provider Infrastructure
CLOUD_PROVIDER_IPS = {
    # AWS
    '52.0.0.0/8',
    '52.192.0.0/11',
    '54.0.0.0/8',
    '18.0.0.0/8',
    '3.0.0.0/8',
    
    # Google Cloud
    '8.8.8.0/24',
    '8.8.4.0/24',
    '34.0.0.0/8',
    '35.0.0.0/8',
    '130.211.0.0/22',
    
    # Azure
    '20.0.0.0/8',
    '40.0.0.0/8',
    '52.224.0.0/11',
    '23.96.0.0/13',
    
    # Cloudflare
    '1.1.1.0/24',
    '104.16.0.0/12',
    
    # Akamai
    '23.0.0.0/8',
    '104.0.0.0/8',
    
    # Oracle Cloud
    '129.144.0.0/10',
    
    # Digital Ocean
    '67.207.0.0/16',
    
    # Linode
    '139.144.0.0/16'
}

# Network Infrastructure
NETWORK_INFRASTRUCTURE_IPS = {
    # IANA Reserved
    '127.0.0.0/8',   # Loopback
    '10.0.0.0/8',    # Private Network
    '172.16.0.0/12', # Private Network
    '192.168.0.0/16', # Private Network
    
    # Multicast
    '224.0.0.0/4',
    
    # Link-local
    '169.254.0.0/16',
    
    # Broadcast
    '255.255.255.255/32',
    
    # Reserved for future use
    '240.0.0.0/4'
}

def is_internal_ip(ip):
    """
    Check if an IP address is in private (RFC 1918) address space
    
    Args:
        ip (str): IP address to check
        
    Returns:
        bool: True if IP is internal/private, False otherwise
    """
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
            
    # Loopback address
    if ip.startswith('127.'):
        return True
        
    # Link-local address
    if ip.startswith('169.254.'):
        return True
            
    return False

def is_whitelisted_ip(ip):
    """
    Check if an IP is whitelisted based on predefined sets
    
    Args:
        ip (str): IP address to check
    
    Returns:
        bool: True if IP is whitelisted, False otherwise
    """
    # Direct IP match
    if ip in PUBLIC_DNS_SERVERS:
        return True
    
    # CIDR range matching for cloud and network infrastructure
    try:
        ip_obj = ip_address(ip)
        
        # Check Cloud Provider IPs
        for network_str in CLOUD_PROVIDER_IPS:
            if ip_obj in ip_network(network_str, strict=False):
                return True
        
        # Check Network Infrastructure IPs
        for network_str in NETWORK_INFRASTRUCTURE_IPS:
            if ip_obj in ip_network(network_str, strict=False):
                return True
    
    except ValueError:
        # Invalid IP address
        logging.warning(f"Invalid IP address format: {ip}")
        return False
    
    return False

def extract_ips_from_string(text):
    """
    Extract IP addresses from a string using regex
    
    Args:
        text (str): Text to extract IPs from
        
    Returns:
        list: List of IP addresses found
    """
    import re
    
    if not text:
        return []
    
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(ip_pattern, text)

def filter_whitelisted_ips(threats):
    """
    Filter out threats involving whitelisted IPs
    
    Args:
        threats (list): List of detected threats
    
    Returns:
        list: Filtered list of threats
    """
    filtered_threats = []
    
    for threat in threats:
        # Check destination and source IPs in threat details
        should_keep_threat = True
        whitelisted_ips_found = []
        
        # Check all indicators for IPs
        for indicator in threat.get('indicators', []):
            # Extract IPs from indicator strings
            ips = extract_ips_from_string(indicator)
            
            for ip in ips:
                if is_whitelisted_ip(ip):
                    should_keep_threat = False
                    whitelisted_ips_found.append(ip)
        
        # Check involved_ips if present (more thorough check)
        if 'involved_ips' in threat:
            for ip_info in threat['involved_ips']:
                if isinstance(ip_info, dict) and ip_info.get('address'):
                    ip = ip_info['address']
                    if is_whitelisted_ip(ip):
                        should_keep_threat = False
                        whitelisted_ips_found.append(ip)
        
        # Additional check for direct IP fields if present
        for field in ['src_ip', 'dst_ip', 'source_ip', 'destination_ip']:
            if field in threat and threat[field]:
                ip = threat[field]
                if is_whitelisted_ip(ip):
                    should_keep_threat = False
                    whitelisted_ips_found.append(ip)
        
        # If no whitelisted IPs found, keep the threat
        if should_keep_threat:
            filtered_threats.append(threat)
        else:
            logging.info(f"Filtering out threat involving whitelisted IPs: {', '.join(whitelisted_ips_found)}")
    
    return filtered_threats

def is_potential_dga(domain):
    """
    Check if a domain might be algorithmically generated (DGA)
    
    Args:
        domain (str): Domain name to check
        
    Returns:
        bool: True if domain exhibits DGA characteristics, False otherwise
    """
    from collections import Counter
    from scipy.stats import entropy
    
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

def categorize_ip(ip):
    """
    Categorize an IP address into its type
    
    Args:
        ip (str): IP address to categorize
        
    Returns:
        str: Category of the IP ('private', 'public_dns', 'cloud', 'infrastructure', 'public')
    """
    if not ip:
        return 'unknown'
    
    if is_internal_ip(ip):
        return 'private'
    
    if ip in PUBLIC_DNS_SERVERS:
        return 'public_dns'
    
    try:
        ip_obj = ip_address(ip)
        
        # Check Cloud Provider IPs
        for network_str in CLOUD_PROVIDER_IPS:
            if ip_obj in ip_network(network_str, strict=False):
                return 'cloud'
        
        # Check Network Infrastructure IPs
        for network_str in NETWORK_INFRASTRUCTURE_IPS:
            if ip_obj in ip_network(network_str, strict=False):
                return 'infrastructure'
    
    except ValueError:
        return 'invalid'
    
    return 'public'

def classify_port(port):
    """
    Classify a port number into its service category
    
    Args:
        port (int): Port number to classify
        
    Returns:
        str: Service category ('well_known', 'registered', 'dynamic', 'unknown')
    """
    if not isinstance(port, int):
        try:
            port = int(port)
        except (ValueError, TypeError):
            return 'unknown'
    
    if 0 <= port <= 1023:
        return 'well_known'
    elif 1024 <= port <= 49151:
        return 'registered'
    elif 49152 <= port <= 65535:
        return 'dynamic'
    else:
        return 'unknown'

def get_ip_subnet(ip):
    """
    Get the subnet of an IP address in CIDR notation
    
    Args:
        ip (str): IP address
        
    Returns:
        str: Subnet in CIDR notation (e.g., "192.168.1.0/24")
    """
    if not ip:
        return None
    
    try:
        # Split IP into octets
        parts = ip.split('.')
        if len(parts) != 4:
            return None
        
        # Create /24 subnet
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return subnet
    except Exception as e:
        logging.error(f"Error getting subnet for IP {ip}: {e}")
        return None

def filter_internal_traffic(packets):
    """
    Filter out internal-only traffic from a list of packet features
    
    Args:
        packets (list): List of packet feature dictionaries
        
    Returns:
        list: Filtered packets with at least one public endpoint
    """
    if not packets:
        return []
    
    filtered_packets = []
    for packet in packets:
        src_ip = packet.get('src_ip', '')
        dst_ip = packet.get('dst_ip', '')
        
        # Keep packet if either src or dst is not internal
        if not is_internal_ip(src_ip) or not is_internal_ip(dst_ip):
            filtered_packets.append(packet)
    
    return filtered_packets