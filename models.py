"""
This file contains the data models for the application.
For this PCAP analysis application, we're using a combination of database models
and non-database classes to represent the application's data structures.
"""
import os
import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

# Initialize SQLAlchemy
db = SQLAlchemy()

class PacketFeatures:
    """
    Represents the features extracted from network packets for ML analysis.
    """
    def __init__(self):
        self.protocol = None
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.packet_size = None
        self.tcp_flags = None
        self.udp_length = None
        self.icmp_type = None
        self.payload_entropy = None
        self.header_length = None
        self.ttl = None
        self.has_payload = None
        self.payload_length = None
        self.timestamp = None
        
    def to_dict(self):
        """Convert features to dictionary for ML processing"""
        return {
            'protocol': self.protocol,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'packet_size': self.packet_size,
            'tcp_flags': self.tcp_flags,
            'udp_length': self.udp_length,
            'icmp_type': self.icmp_type,
            'payload_entropy': self.payload_entropy,
            'header_length': self.header_length,
            'ttl': self.ttl,
            'has_payload': self.has_payload,
            'payload_length': self.payload_length
        }

class ThreatCategoryEnum:
    """
    Defines the categories of network threats (aligned with CICIDS 2017 & CTU-13)
    """

    # Normal Traffic
    NORMAL = "Normal Traffic"
    # Reconnaissance (Scanning & Probing)
    RECONNAISSANCE = "Reconnaissance (Scanning & Probing)"
    DOS_DDOS = "Denial of Service (DoS & DDoS)"
    NETWORK_PROTOCOL_ATTACKS = "Network Protocol Attacks"
    NETWORK_DEVICE_ATTACKS = "Network Device Attacks"
    WEB_ATTACKS = "Web Attacks (SQLi, XSS, CSRF, Web Phishing, SSRF, LFI/RFI, Command Injection, etc.)"
    WEB_PHISHING = "Web Phishing"
    SERVER_ATTACKS = "Server Attacks"
    MALICIOUS_BEHAVIOR = "Malicious Behavior (Malware, C2, Data Exfiltration, Cryptomining)"
    # Other / Unknown
    UNKNOWN = "Unknown Threat"

class ThreatCategory(db.Model):
    """
    Database model for threat categories that the system can detect.
    """
    __tablename__ = 'threat_categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False, default='Medium')  # Low, Medium, High
    indicators = db.Column(db.JSON, nullable=False, default=list)
    recommended_actions = db.Column(db.JSON, nullable=False, default=list)
    is_builtin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship with TrainingData
    training_data = db.relationship('TrainingData', backref='category', lazy=True)
    
    @property
    def is_trained(self):
        """Check if this category has training data"""
        return len(self.training_data) > 0
    
    @property
    def sample_count(self):
        """Get count of training samples for this category"""
        return len(self.training_data)
    
    def to_dict(self):
        """Convert the category to a dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'risk_level': self.risk_level,
            'indicators': self.indicators,
            'recommended_actions': self.recommended_actions,
            'is_builtin': self.is_builtin,
            'is_trained': self.is_trained,
            'sample_count': self.sample_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    @classmethod
    def create_defaults(cls):
        """Create default threat categories if they don't exist"""
        # Kiểm tra model hiện tại có hỗ trợ các trường mới không
        model_supports_category = hasattr(cls, 'category')
        model_supports_osi_layer = hasattr(cls, 'osi_layer')
        model_supports_malware_type = hasattr(cls, 'malware_type')
        
        defaults = [
            # Normal Traffic
            {
                'name': 'Normal Traffic',
                'description': 'Regular network traffic with no malicious intent.',
                'risk_level': 'Low',
                'indicators': [
                    'Expected traffic patterns',
                    'Standard protocol usage',
                    'Legitimate source and destination addresses'
                ],
                'recommended_actions': [
                    'Continue monitoring',
                    'Maintain baseline traffic profiles',
                    'Update security policies as needed'
                ],
                'is_builtin': True
            },
            
            # Reconnaissance
            {
                'name': 'Reconnaissance (Scanning & Probing)',
                'description': 'Activities to gather information about target networks and systems before an attack.',
                'risk_level': 'Medium',
                'indicators': [
                    'Port scanning activity',
                    'Network mapping attempts',
                    'Vulnerability scanning patterns',
                    'DNS zone transfer attempts'
                ],
                'recommended_actions': [
                    'Implement network scanning detection',
                    'Configure firewall rules to limit scan responses',
                    'Hide sensitive information in network service banners',
                    'Deploy honeypots to detect reconnaissance activities'
                ],
                'is_builtin': True
            },
            
            # Denial of Service
            {
                'name': 'Denial of Service (DoS & DDoS)',
                'description': 'Attacks designed to overwhelm networks, services, or resources to make them unavailable to legitimate users.',
                'risk_level': 'High',
                'indicators': [
                    'Abnormal traffic volume from single or multiple sources',
                    'Resource exhaustion on target systems',
                    'Service degradation or unavailability',
                    'Traffic patterns matching known DoS signatures'
                ],
                'recommended_actions': [
                    'Implement rate limiting and traffic filtering',
                    'Deploy DDoS protection services',
                    'Establish redundant systems and failover mechanisms',
                    'Develop and test incident response plans for DoS events'
                ],
                'is_builtin': True
            },
            
            # Network Protocol Attacks
            {
                'name': 'Network Protocol Attacks',
                'description': 'Exploitation of vulnerabilities in network protocols such as TCP/IP, DNS, ICMP, and others.',
                'risk_level': 'High',
                'indicators': [
                    'Unusual protocol behavior or malformed packets',
                    'Spoofed or forged protocol headers',
                    'Exploitation of protocol vulnerabilities',
                    'Abnormal protocol state transitions'
                ],
                'recommended_actions': [
                    'Implement deep packet inspection',
                    'Configure protocol validation on network devices',
                    'Deploy intrusion prevention systems with protocol analysis',
                    'Keep network devices and software updated'
                ],
                'is_builtin': True
            },
            
            # Network Device Attacks
            {
                'name': 'Network Device Attacks',
                'description': 'Attacks targeting network infrastructure hardware such as routers, switches, and firewalls.',
                'risk_level': 'Critical',
                'indicators': [
                    'Unauthorized access attempts to network devices',
                    'Configuration changes without approval',
                    'Unexpected device behavior or performance',
                    'Exploitation of device-specific vulnerabilities'
                ],
                'recommended_actions': [
                    'Implement strong device authentication',
                    'Regularly update firmware and software',
                    'Conduct security audits of device configurations',
                    'Monitor device logs for unauthorized access'
                ],
                'is_builtin': True
            },
            
            # Web Attacks
            {
                'name': 'Web Attacks (SQLi, XSS, CSRF, Web Phishing, SSRF, LFI/RFI, Command Injection, etc.)',
                'description': 'Exploitation of vulnerabilities in web applications and services.',
                'risk_level': 'High',
                'indicators': [
                    'Suspicious input patterns in web requests',
                    'Unexpected database queries or errors',
                    'Cross-site scripting attempts',
                    'File inclusion or path traversal attempts',
                    'Command injection patterns'
                ],
                'recommended_actions': [
                    'Implement web application firewall (WAF)',
                    'Validate and sanitize all user inputs',
                    'Use prepared statements for database queries',
                    'Implement Content Security Policy (CSP)',
                    'Conduct regular security testing of web applications'
                ],
                'is_builtin': True
            },
            
            # Web Phishing
            {
                'name': 'Web Phishing',
                'description': 'Deceptive attempts to steal user data including credentials and financial information.',
                'risk_level': 'High',
                'indicators': [
                    'Suspicious URL patterns or domain names',
                    'Imitation of legitimate websites',
                    'Requests for sensitive information',
                    'Embedded malicious links or redirects'
                ],
                'recommended_actions': [
                    'Implement email and web filtering',
                    'Deploy anti-phishing solutions',
                    'Conduct user awareness training',
                    'Implement DMARC, SPF, and DKIM for email security'
                ],
                'is_builtin': True
            },
            
            # Server Attacks
            {
                'name': 'Server Attacks',
                'description': 'Attacks targeting server systems to exploit vulnerabilities, gain unauthorized access, or compromise data.',
                'risk_level': 'Critical',
                'indicators': [
                    'Unauthorized access attempts to servers',
                    'Privilege escalation activities',
                    'Exploitation of server vulnerabilities',
                    'Unusual file system activity or process execution'
                ],
                'recommended_actions': [
                    'Implement server hardening guidelines',
                    'Keep server software and applications updated',
                    'Use principle of least privilege for accounts',
                    'Deploy host-based intrusion detection systems'
                ],
                'is_builtin': True
            },
            
            # Malicious Behavior
            {
                'name': 'Malicious Behavior (Malware, C2, Data Exfiltration, Cryptomining)',
                'description': 'Activities indicating presence of malware, command and control communications, or unauthorized data extraction.',
                'risk_level': 'Critical',
                'indicators': [
                    'Communication with known malicious domains/IPs',
                    'Unusual data transfer patterns or volumes',
                    'Beaconing or command and control traffic',
                    'Unexpected system behavior or resource usage',
                    'Encryption or obfuscation of network traffic'
                ],
                'recommended_actions': [
                    'Implement endpoint protection solutions',
                    'Block known malicious domains and IPs',
                    'Deploy network traffic analysis tools',
                    'Implement data loss prevention measures',
                    'Conduct regular system scans and audits'
                ],
                'is_builtin': True
            },
            
            # Unknown Threat
            {
                'name': 'Unknown Threat',
                'description': 'Suspicious network activities that cannot be clearly classified but exhibit potential security concerns.',
                'risk_level': 'Medium',
                'indicators': [
                    'Anomalous network behavior',
                    'Unexplained traffic patterns',
                    'Potential zero-day exploits',
                    'Behavior not matching known attack signatures'
                ],
                'recommended_actions': [
                    'Investigate suspicious activities',
                    'Isolate affected systems if necessary',
                    'Implement behavioral analysis tools',
                    'Update security controls based on findings'
                ],
                'is_builtin': True
            }
        ]

        if model_supports_category:
            # Match categories to the 11 default threat categories
            defaults[0]['category'] = 'Normal Traffic'
            defaults[1]['category'] = 'Reconnaissance (Scanning & Probing)'
            defaults[2]['category'] = 'Denial of Service (DoS & DDoS)'
            defaults[3]['category'] = 'Network Protocol Attacks'
            defaults[4]['category'] = 'Network Device Attacks'
            defaults[5]['category'] = 'Web Attacks (SQLi, XSS, CSRF, Web Phishing, SSRF, LFI/RFI, Command Injection, etc.)'
            defaults[6]['category'] = 'Web Phishing'
            defaults[7]['category'] = 'Server Attacks'
            defaults[8]['category'] = 'Malicious Behavior (Malware, C2, Data Exfiltration, Cryptomining)'
            defaults[9]['category'] = 'Unknown Threat'

        if model_supports_osi_layer:
            # Assign OSI layers based on the 11 default categories
            defaults[0]['osi_layer'] = 'Multiple Layers'  # Normal Traffic
            defaults[1]['osi_layer'] = 'Multiple Layers'  # Reconnaissance
            defaults[2]['osi_layer'] = 'Multiple Layers'  # DoS & DDoS
            defaults[3]['osi_layer'] = 'Multiple Layers'  # Network Protocol Attacks
            defaults[4]['osi_layer'] = 'Layer 2-3 - Data Link/Network'  # Network Device Attacks
            defaults[5]['osi_layer'] = 'Layer 7 - Application'  # Web Attacks
            defaults[6]['osi_layer'] = 'Layer 7 - Application'  # Web Phishing
            defaults[7]['osi_layer'] = 'Layer 7 - Application'  # Server Attacks
            defaults[8]['osi_layer'] = 'Multiple Layers'  # Malicious Behavior
            defaults[9]['osi_layer'] = 'Multiple Layers'  # Unknown Threat

        if model_supports_malware_type:
            # Only assign malware types to relevant categories
            defaults[8]['malware_type'] = 'Multiple Types'  # Malicious Behavior
        
        for data in defaults:
            # Chỉ tạo nếu không tồn tại
            if not cls.query.filter_by(name=data['name']).first():
                # Chỉ sử dụng các trường được hỗ trợ
                filtered_data = {k: v for k, v in data.items() if hasattr(cls, k)}
                category = cls(**filtered_data)
                db.session.add(category)
        
        db.session.commit()


class TrainingData(db.Model):
    """
    Database model for keeping track of training data used to train the model.
    """
    __tablename__ = 'training_data'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False, unique=True)
    category_id = db.Column(db.Integer, db.ForeignKey('threat_categories.id'), nullable=False)
    feature_count = db.Column(db.Integer, default=0)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convert the training data to a dictionary"""
        return {
            'id': self.id,
            'filename': self.filename,
            'file_hash': self.file_hash,
            'category_id': self.category_id,
            'category_name': self.category.name if self.category else None,
            'feature_count': self.feature_count,
            'added_at': self.added_at.isoformat() if self.added_at else None
        }


class Analysis(db.Model):
    """
    Database model for storing analysis results
    """
    __tablename__ = 'analyses'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    result_summary = db.Column(db.JSON, nullable=False, default=dict)
    detected_threats = db.Column(db.JSON, nullable=False, default=list)
    traffic_summary = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convert the analysis to a dictionary"""
        return {
            'id': self.id,
            'filename': self.filename,
            'file_hash': self.file_hash,
            'result_summary': self.result_summary,
            'detected_threats': self.detected_threats,
            'traffic_summary': self.traffic_summary,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
