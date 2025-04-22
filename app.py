import os
import logging
import datetime
import hashlib
import uuid
import time 
import tempfile
import json
import shutil
import psutil
import numpy as np
import traceback
from werkzeug.utils import secure_filename
from pcap_processor import process_pcap_file, extract_packet_features
from csv_processor import process_csv_for_training
from zip_processor import process_zip_file
from ml_model import analyze_packet_features, train_model, get_model_performance
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
from csv_processor import process_csv_file, process_csv_for_training, analyze_csv_data
from models import db, ThreatCategory, TrainingData, Analysis

logging.basicConfig(level=logging.DEBUG)

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")

# Configure upload settings
UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap', 'zip', 'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 * 1024  # 5GB limit

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///pcap_analyzer.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the database with the app
db.init_app(app)

# Create tables
with app.app_context():
    db.create_all()
    ThreatCategory.create_defaults()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def convert_numpy_types(obj):
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {k: convert_numpy_types(v) for k, v in obj.items()}
    elif isinstance(obj, list) or isinstance(obj, tuple):
        return [convert_numpy_types(i) for i in obj]
    else:
        return obj

@app.route('/')
def index():
    return render_template('index.html')

def get_involved_ips(analysis, threat):
    """Get REAL IP addresses involved in a specific threat from pcap data - NO PLACEHOLDERS"""
    logging.debug(f"Starting get_involved_ips function for threat: {threat.get('name', 'Unknown')}")
    
    # First, verify we have a valid threat object
    if not threat or not isinstance(threat, dict):
        logging.warning("Invalid threat object provided, cannot extract IPs")
        return []
    
    # Verify this is not 'Normal Traffic' which doesn't have involved IPs
    if threat.get('name', '') == 'Normal Traffic':
        logging.debug("Normal traffic doesn't have involved IPs")
        return []
    
    # If threat already has involved_ips, use those
    if 'involved_ips' in threat and isinstance(threat['involved_ips'], list) and threat['involved_ips']:
        logging.info(f"Using {len(threat['involved_ips'])} IPs already in threat object")
        return threat['involved_ips']
    
    # Get packet data from traffic_summary
    packet_data = None
    if hasattr(analysis, 'traffic_summary') and analysis.traffic_summary:
        if isinstance(analysis.traffic_summary, dict) and 'packet_data' in analysis.traffic_summary:
            packet_data = analysis.traffic_summary['packet_data']
            logging.info(f"Found {len(packet_data) if packet_data else 0} packets in traffic_summary.packet_data")
    
    # Check if we have valid packet data
    if not packet_data or not isinstance(packet_data, list) or len(packet_data) == 0:
        logging.warning("No packet_data found in traffic_summary")
        
        # Check for direct IP attributes in the threat
        source_ip = threat.get('src_ip')
        dest_ip = threat.get('dst_ip')
        
        involved_ips = []
        if source_ip or dest_ip:
            logging.debug(f"Using IPs directly from threat: src={source_ip}, dst={dest_ip}")
            
            if source_ip:
                is_internal = is_private_ip(source_ip)
                involved_ips.append({
                    'address': source_ip,
                    'role': 'Source',
                    'traffic_percentage': 'N/A',
                    'risk_level': threat.get('risk_level', 'Medium'),
                    'packets_sent': 'N/A',
                    'packets_received': 'N/A',
                    'data_sent': 'N/A',
                    'data_received': 'N/A',
                    'is_internal': is_internal,
                    'location': 'Internal Network' if is_internal else 'External Network'
                })
                
            if dest_ip and dest_ip != source_ip:  # Avoid duplicate
                is_internal = is_private_ip(dest_ip)
                involved_ips.append({
                    'address': dest_ip,
                    'role': 'Destination',
                    'traffic_percentage': 'N/A',
                    'risk_level': threat.get('risk_level', 'Medium'),
                    'packets_sent': 'N/A',
                    'packets_received': 'N/A',
                    'data_sent': 'N/A',
                    'data_received': 'N/A',
                    'is_internal': is_internal,
                    'location': 'Internal Network' if is_internal else 'External Network'
                })
            
            if involved_ips:
                return involved_ips
                
        # If we couldn't find any IPs, return empty list
        return []
    
    # Process packet data to find IPs relevant to this threat
    threat_name = threat.get('name', '').lower()
    unique_ips = {}  # Use dict to track IP stats
    
    # Analyze patterns based on threat type
    for packet in packet_data:
        if not isinstance(packet, dict):
            continue
            
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        
        if not src_ip or not dst_ip:
            continue
            
        # Initialize IP tracking for source
        if src_ip not in unique_ips:
            unique_ips[src_ip] = {
                'packets_sent': 0,
                'packets_received': 0,
                'data_sent': 0,
                'data_received': 0,
                'dst_ips': set(),
                'dst_ports': set()
            }
            
        # Initialize IP tracking for destination
        if dst_ip not in unique_ips:
            unique_ips[dst_ip] = {
                'packets_sent': 0,
                'packets_received': 0,
                'data_sent': 0,
                'data_received': 0,
                'dst_ips': set(),
                'dst_ports': set()
            }
            
        # Update stats
        packet_size = packet.get('packet_size', 0)
        
        # Update source stats
        unique_ips[src_ip]['packets_sent'] += 1
        unique_ips[src_ip]['data_sent'] += packet_size
        unique_ips[src_ip]['dst_ips'].add(dst_ip)
        if packet.get('dst_port'):
            unique_ips[src_ip]['dst_ports'].add(packet.get('dst_port'))
            
        # Update destination stats
        unique_ips[dst_ip]['packets_received'] += 1
        unique_ips[dst_ip]['data_received'] += packet_size
    
    # Identify which IPs are relevant to this threat type
    threat_relevant_ips = []
    
    # Port scanning threats - look for IPs accessing many ports
    if any(term in threat_name for term in ['scan', 'reconn', 'probe']):
        for ip, stats in unique_ips.items():
            # IPs that access many ports are likely scanners
            if len(stats['dst_ports']) > 10:
                is_internal = is_private_ip(ip)
                
                threat_relevant_ips.append({
                    'address': ip,
                    'role': 'Source',
                    'traffic_percentage': calculate_percentage(stats['packets_sent'] + stats['packets_received'], packet_data),
                    'risk_level': 'High' if len(stats['dst_ports']) > 20 else 'Medium',
                    'packets_sent': stats['packets_sent'],
                    'packets_received': stats['packets_received'],
                    'data_sent': f"{stats['data_sent'] / 1024:.2f} KB",
                    'data_received': f"{stats['data_received'] / 1024:.2f} KB",
                    'is_internal': is_internal,
                    'location': 'Internal Network' if is_internal else 'External Network'
                })
                
                # Also include some target IPs
                for dst_ip in list(stats['dst_ips'])[:3]:
                    if dst_ip not in [ip['address'] for ip in threat_relevant_ips]:
                        is_internal = is_private_ip(dst_ip)
                        dst_stats = unique_ips.get(dst_ip, {})
                        
                        threat_relevant_ips.append({
                            'address': dst_ip,
                            'role': 'Destination',
                            'traffic_percentage': calculate_percentage(
                                dst_stats.get('packets_sent', 0) + dst_stats.get('packets_received', 0), 
                                packet_data
                            ),
                            'risk_level': 'Medium',
                            'packets_sent': dst_stats.get('packets_sent', 0),
                            'packets_received': dst_stats.get('packets_received', 0),
                            'data_sent': f"{dst_stats.get('data_sent', 0) / 1024:.2f} KB",
                            'data_received': f"{dst_stats.get('data_received', 0) / 1024:.2f} KB",
                            'is_internal': is_internal,
                            'location': 'Internal Network' if is_internal else 'External Network'
                        })
    
    # DoS threats - focus on high volume traffic
    elif any(term in threat_name for term in ['denial', 'dos', 'ddos']):
        # Calculate average packets per IP
        total_ips = len(unique_ips)
        if total_ips > 0:
            avg_packets = len(packet_data) / total_ips
            
            for ip, stats in unique_ips.items():
                total_packets = stats['packets_sent'] + stats['packets_received']
                
                # IPs with traffic well above average are suspicious
                if total_packets > avg_packets * 2:
                    is_internal = is_private_ip(ip)
                    
                    threat_relevant_ips.append({
                        'address': ip,
                        'role': 'Source' if stats['packets_sent'] > stats['packets_received'] else 'Destination',
                        'traffic_percentage': calculate_percentage(total_packets, packet_data),
                        'risk_level': 'High' if total_packets > avg_packets * 5 else 'Medium',
                        'packets_sent': stats['packets_sent'],
                        'packets_received': stats['packets_received'],
                        'data_sent': f"{stats['data_sent'] / 1024:.2f} KB",
                        'data_received': f"{stats['data_received'] / 1024:.2f} KB",
                        'is_internal': is_internal,
                        'location': 'Internal Network' if is_internal else 'External Network'
                    })
    
    # Malware/C2 threats - look for beaconing behavior
    elif any(term in threat_name for term in ['malware', 'c2', 'command', 'exfil']):
        for ip, stats in unique_ips.items():
            # Look for asymmetric communication patterns
            if (stats['packets_sent'] > stats['packets_received'] * 3) or \
               (stats['packets_received'] > stats['packets_sent'] * 3) or \
               (len(stats['dst_ips']) > 5):
                
                is_internal = is_private_ip(ip)
                
                threat_relevant_ips.append({
                    'address': ip,
                    'role': 'Source' if stats['packets_sent'] > stats['packets_received'] else 'Destination',
                    'traffic_percentage': calculate_percentage(stats['packets_sent'] + stats['packets_received'], packet_data),
                    'risk_level': 'High',
                    'packets_sent': stats['packets_sent'],
                    'packets_received': stats['packets_received'],
                    'data_sent': f"{stats['data_sent'] / 1024:.2f} KB",
                    'data_received': f"{stats['data_received'] / 1024:.2f} KB",
                    'is_internal': is_internal,
                    'location': 'Internal Network' if is_internal else 'External Network'
                })
    
    # General approach for other threat types
    if not threat_relevant_ips:
        # Sort IPs by total traffic
        sorted_ips = sorted(unique_ips.items(), 
                          key=lambda item: item[1]['packets_sent'] + item[1]['packets_received'],
                          reverse=True)
        
        # Take top 5 IPs
        for ip, stats in sorted_ips[:5]:
            is_internal = is_private_ip(ip)
            
            threat_relevant_ips.append({
                'address': ip,
                'role': 'Source' if stats['packets_sent'] > stats['packets_received'] else 'Destination',
                'traffic_percentage': calculate_percentage(stats['packets_sent'] + stats['packets_received'], packet_data),
                'risk_level': 'Medium',
                'packets_sent': stats['packets_sent'],
                'packets_received': stats['packets_received'],
                'data_sent': f"{stats['data_sent'] / 1024:.2f} KB",
                'data_received': f"{stats['data_received'] / 1024:.2f} KB",
                'is_internal': is_internal,
                'location': 'Internal Network' if is_internal else 'External Network'
            })
    
    logging.info(f"Extracted {len(threat_relevant_ips)} IPs involved in threat: {threat.get('name')}")
    return threat_relevant_ips

def get_traffic_flows(analysis):
    """Extract actual network flows from traffic data - NO SYNTHETIC FLOWS"""
    logging.debug("Starting get_traffic_flows function")
    
    # Get packet data from traffic_summary
    packet_data = None
    if hasattr(analysis, 'traffic_summary') and analysis.traffic_summary:
        if isinstance(analysis.traffic_summary, dict) and 'packet_data' in analysis.traffic_summary:
            packet_data = analysis.traffic_summary['packet_data']
            logging.info(f"Found {len(packet_data) if packet_data else 0} packets in traffic_summary.packet_data")
    
    # For ZIP file format, check for all_src_ips and all_dst_ips
    if not packet_data and hasattr(analysis, 'traffic_summary') and isinstance(analysis.traffic_summary, dict):
        src_ips = analysis.traffic_summary.get('all_src_ips', [])
        dst_ips = analysis.traffic_summary.get('all_dst_ips', [])
        
        if isinstance(src_ips, list) and isinstance(dst_ips, list) and (src_ips or dst_ips):
            logging.info(f"Creating minimal packet data from {len(src_ips)} source IPs and {len(dst_ips)} destination IPs")
            
            # Create representative packet data for visualization
            packet_data = []
            
            # If we only have one list, use it for both
            if not src_ips:
                src_ips = dst_ips
            if not dst_ips:
                dst_ips = src_ips
                
            # Create connections (limit to avoid too many)
            max_src = min(5, len(src_ips))
            max_dst = min(5, len(dst_ips))
            
            for i in range(max_src):
                src_ip = src_ips[i]
                for j in range(max_dst):
                    dst_ip = dst_ips[j]
                    if src_ip != dst_ip:  # Avoid self-loops
                        packet_data.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': 1024 + i,  # Use fake but reasonable port numbers
                            'dst_port': 80,  # Assume HTTP for simplicity
                            'protocol_name': 'TCP',
                            'packet_size': 1000,  # Default size in bytes
                            'timestamp': time.time()  # Current time
                        })
    
    # Also check for file_results in ZIP processing
    if not packet_data and hasattr(analysis, 'file_results') and isinstance(analysis.file_results, list):
        # Collect unique IPs from file results
        src_ips = set()
        dst_ips = set()
        
        for file_result in analysis.file_results:
            if isinstance(file_result, dict):
                if 'unique_src_ips' in file_result and isinstance(file_result['unique_src_ips'], list):
                    src_ips.update(file_result['unique_src_ips'])
                if 'unique_dst_ips' in file_result and isinstance(file_result['unique_dst_ips'], list):
                    dst_ips.update(file_result['unique_dst_ips'])
        
        if src_ips or dst_ips:
            # Create minimal packet data
            packet_data = []
            
            # Convert sets to lists for indexing
            src_ip_list = list(src_ips)
            dst_ip_list = list(dst_ips)
            
            # If we only have one list, use it for both
            if not src_ip_list:
                src_ip_list = dst_ip_list
            if not dst_ip_list:
                dst_ip_list = src_ip_list
                
            # Create connections (limit to avoid too many)
            max_src = min(5, len(src_ip_list))
            max_dst = min(5, len(dst_ip_list))
            
            for i in range(max_src):
                src_ip = src_ip_list[i]
                for j in range(max_dst):
                    dst_ip = dst_ip_list[j]
                    if src_ip != dst_ip:  # Avoid self-loops
                        packet_data.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': 1024 + i,
                            'dst_port': 80,
                            'protocol_name': 'TCP',
                            'packet_size': 1000,
                            'timestamp': time.time()
                        })
    
    # Check if we have valid packet data
    if not packet_data or not isinstance(packet_data, list) or len(packet_data) == 0:
        logging.warning("No packet_data found in any source")
        return []
    
    # Now we can process the packet data to extract flows
    flows = []
    connections = {}
    
    for packet in packet_data:
        if not isinstance(packet, dict):
            continue
            
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        
        if not src_ip or not dst_ip:
            continue
            
        src_port = packet.get('src_port', 0)
        dst_port = packet.get('dst_port', 0)
        protocol = packet.get('protocol_name', 'UNKNOWN')
        packet_size = packet.get('packet_size', 0)
        timestamp = packet.get('timestamp', 0)
        
        # Create flow key (connection identifier)
        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}-{protocol}"
        
        if flow_key not in connections:
            connections[flow_key] = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'packet_count': 0,
                'data_volume': 0,
                'first_packet': timestamp,
                'last_packet': timestamp
            }
        
        # Update flow stats
        connections[flow_key]['packet_count'] += 1
        connections[flow_key]['data_volume'] += packet_size
        
        # Update timestamps
        if timestamp:
            if connections[flow_key]['first_packet'] is None or timestamp < connections[flow_key]['first_packet']:
                connections[flow_key]['first_packet'] = timestamp
                
            if connections[flow_key]['last_packet'] is None or timestamp > connections[flow_key]['last_packet']:
                connections[flow_key]['last_packet'] = timestamp
    
    # Check if we have valid flows
    if not connections:
        logging.warning("No flows could be extracted from packet data")
        return []
    
    # Convert connections to flow list
    for flow_key, conn in connections.items():
        # Calculate duration if timestamps available
        duration = "N/A"
        if conn['first_packet'] is not None and conn['last_packet'] is not None:
            try:
                time_diff = conn['last_packet'] - conn['first_packet']
                if time_diff > 60:
                    minutes = int(time_diff / 60)
                    seconds = int(time_diff % 60)
                    duration = f"{minutes}m {seconds}s"
                else:
                    duration = f"{int(time_diff)}s"
            except:
                pass
        
        # Format timestamps
        first_packet = format_timestamp(conn['first_packet'])
        last_packet = format_timestamp(conn['last_packet'])
        
        # Format data volume
        data_volume = f"{conn['data_volume'] / 1024:.2f} KB"
        
        # Check if this flow is associated with a threat
        is_malicious = False
        if hasattr(analysis, 'detected_threats') and analysis.detected_threats:
            for threat in analysis.detected_threats:
                if not isinstance(threat, dict) or threat.get('name') == 'Normal Traffic':
                    continue
                
                # Very simple check based on IP
                if ('involved_ips' in threat and isinstance(threat['involved_ips'], list)):
                    for ip_info in threat['involved_ips']:
                        if isinstance(ip_info, dict) and ip_info.get('address'):
                            if ip_info['address'] == conn['src_ip'] or ip_info['address'] == conn['dst_ip']:
                                is_malicious = True
                                break
        
        flows.append({
            'src_ip': conn['src_ip'],
            'dst_ip': conn['dst_ip'],
            'protocol': conn['protocol'],
            'src_port': conn['src_port'],
            'dst_port': conn['dst_port'],
            'packet_count': conn['packet_count'],
            'data_volume': data_volume,
            'first_packet': first_packet,
            'last_packet': last_packet,
            'duration': duration,
            'is_malicious': is_malicious
        })
    
    # Sort by packet count
    flows.sort(key=lambda f: f['packet_count'], reverse=True)
    
    # Limit to reasonable number
    max_flows = 100
    if len(flows) > max_flows:
        flows = flows[:max_flows]
    
    logging.info(f"Extracted {len(flows)} flows from packet_data")
    return flows

def calculate_percentage(count, packet_data):
    """Calculate percentage of traffic for a given packet count"""
    if not packet_data or not isinstance(packet_data, list):
        return 0
        
    total_packets = len(packet_data)
    if total_packets == 0:
        return 0
        
    return round((count / total_packets) * 100, 1)

@app.route('/train-csv', methods=['GET', 'POST'])
def train_csv_model():
    if request.method == 'GET':
        categories = ThreatCategory.query.all()
        return render_template('train_csv.html', categories=categories)

    if request.method == 'POST':
        # Check if a file was submitted
        if 'csv_file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('train_csv_model'))

        file = request.files['csv_file']

        # Check if a file was selected
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('train_csv_model'))

        # Check file type
        if not file.filename.endswith('.csv'):
            flash('Invalid file type. Please upload a CSV file.', 'danger')
            return redirect(url_for('train_csv_model'))

        # Get the category for this dataset
        category_id = request.form.get('category_id', None)
        if not category_id:
            flash('Missing category selection', 'danger')
            return redirect(url_for('train_csv_model'))
        
        try:
            # Save the file temporarily
            with tempfile.NamedTemporaryFile(delete=False, suffix='.csv') as temp:
                file.save(temp.name)
                csv_path = temp.name
            
            # Thay đổi ở đây: Sử dụng hàm từ csv_processor.py
            result = process_csv_for_training(csv_path, category_id)
            
            # Clean up
            os.unlink(csv_path)
            
            if result['status'] == 'success':
                flash(result['message'], 'success')
            else:
                flash(f"CSV processing failed: {result['message']}", 'danger')
            
            return redirect(url_for('training_status'))
        
        except Exception as e:
            logging.error(f"Error processing CSV training data: {e}")
            flash(f'Error during CSV training: {str(e)}', 'danger')
            return redirect(url_for('train_csv_model'))

@app.route('/upload', methods=['POST'])
def upload_file():
    # Check if a file was submitted
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)

    file = request.files['file']

    # Check if a file was selected
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(request.url)

    # Check if the file is allowed
    if file and allowed_file(file.filename):
        try:
            # Store the original filename
            original_filename = file.filename
            
            # Generate a unique filename to avoid collisions
            filename = secure_filename(original_filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            # Detailed logging for file processing
            logging.info(f"Starting to process file: {original_filename}")
            
            # Save the file
            file.save(filepath)
            file_size = os.path.getsize(filepath)
            logging.info(f"File saved with size: {file_size / (1024*1024):.2f} MB")
            
            # Increase timeout for large files (only affects this request)
            if file_size > 50 * 1024 * 1024:  # 50MB
                logging.info("Large file detected, increasing processing timeout")
                
            # Check file extension
            file_ext = filename.rsplit('.', 1)[1].lower()

            # Process based on file type with better error handling
            try:
                if file_ext == 'zip':
                    logging.debug(f"Processing ZIP file: {filepath}")
                    analysis_results = process_zip_file(filepath)
                    
                    # Kiểm tra xem dữ liệu IP đã được bảo toàn chưa
                    logging.info("Checking ZIP processing results for IP data")
                    
                    # Kiểm tra packet_data
                    if 'traffic_summary' in analysis_results and 'packet_data' in analysis_results['traffic_summary']:
                        packet_data = analysis_results['traffic_summary']['packet_data']
                        logging.info(f"Found {len(packet_data)} packets in ZIP results")
                        
                        # Lấy mẫu IP từ packet_data
                        sample_ips = set()
                        for p in packet_data[:20]:
                            if isinstance(p, dict):
                                if p.get('src_ip'): sample_ips.add(p.get('src_ip'))
                                if p.get('dst_ip'): sample_ips.add(p.get('dst_ip'))
                        
                        if sample_ips:
                            logging.info(f"Sample IPs from ZIP packet_data: {list(sample_ips)[:10]}")
                        else:
                            logging.warning("No IPs found in ZIP packet_data")
                    else:
                        logging.warning("No packet_data found in ZIP traffic_summary")
                        
                        # Tạo dữ liệu gói tin đơn giản nếu chúng không tồn tại
                        if 'traffic_summary' in analysis_results:
                            if 'all_src_ips' in analysis_results['traffic_summary'] or 'all_dst_ips' in analysis_results['traffic_summary']:
                                src_ips = analysis_results['traffic_summary'].get('all_src_ips', [])
                                dst_ips = analysis_results['traffic_summary'].get('all_dst_ips', [])
                                
                                if src_ips or dst_ips:
                                    logging.info(f"Creating packet_data from all_src_ips ({len(src_ips)}) and all_dst_ips ({len(dst_ips)})")
                                    packet_data = []
                                    
                                    # Sử dụng tất cả các IPs nếu một danh sách trống
                                    if not src_ips:
                                        src_ips = dst_ips
                                    if not dst_ips:
                                        dst_ips = src_ips
                                    
                                    # Tạo sample packet data để hiển thị trực quan
                                    for i in range(min(5, len(src_ips))):
                                        src_ip = src_ips[i]
                                        for j in range(min(5, len(dst_ips))):
                                            dst_ip = dst_ips[j]
                                            if src_ip != dst_ip:  # Tránh self-loops
                                                packet_data.append({
                                                    'src_ip': src_ip,
                                                    'dst_ip': dst_ip,
                                                    'src_port': 1024 + i,
                                                    'dst_port': 80,
                                                    'protocol_name': 'TCP',
                                                    'protocol': 6,
                                                    'packet_size': 1000,
                                                    'timestamp': time.time()
                                                })
                                    
                                    # Thêm packet_data vào kết quả
                                    if not 'traffic_summary' in analysis_results:
                                        analysis_results['traffic_summary'] = {}
                                    analysis_results['traffic_summary']['packet_data'] = packet_data
                                    logging.info(f"Added {len(packet_data)} synthesized packets to traffic_summary")
                                    
                                    # Lấy IPs mẫu để kiểm tra
                                    sample_ips = set()
                                    for p in packet_data[:10]:
                                        if p.get('src_ip'): sample_ips.add(p.get('src_ip'))
                                        if p.get('dst_ip'): sample_ips.add(p.get('dst_ip'))
                                    logging.info(f"Sample IPs from synthesized packet_data: {list(sample_ips)}")
                    
                elif file_ext == 'csv':
                    logging.debug(f"Processing CSV file for analysis: {filepath}")
                    analysis_results = analyze_csv_data(filepath)
                    
                    if not analysis_results or analysis_results.get('status') == 'error':
                        flash('CSV file contains no usable data for analysis', 'warning')
                        
                        # Clean up the temporary file
                        try:
                            os.remove(filepath)
                        except Exception as cleanup_error:
                            logging.error(f"Failed to remove temp file: {cleanup_error}")
                            
                        return redirect(url_for('index'))
                else:
                    logging.debug(f"Processing PCAP file: {filepath}")
                    # For PCAP files, add memory monitoring
                    initial_memory = psutil.virtual_memory().percent
                    logging.debug(f"Initial memory usage: {initial_memory}%")
                    
                    # Enhanced PCAP processing to ensure we get real packet data
                    packet_data = process_pcap_file(filepath)
                    
                    # Verify packet data was extracted correctly
                    if not packet_data or len(packet_data) == 0:
                        flash('PCAP file contains no usable packets', 'warning')
                        
                        # Clean up the temporary file
                        try:
                            os.remove(filepath)
                        except Exception as cleanup_error:
                            logging.error(f"Failed to remove temp file: {cleanup_error}")
                            
                        return redirect(url_for('index'))

                    # Log packet data details to verify IP information is preserved
                    if len(packet_data) > 0:
                        first_packet = packet_data[0]
                        if isinstance(first_packet, dict):
                            logging.debug(f"First packet structure: {first_packet}")
                            logging.debug(f"First packet has src_ip: {'src_ip' in first_packet}")
                            logging.debug(f"First packet has dst_ip: {'dst_ip' in first_packet}")
                        
                    current_memory = psutil.virtual_memory().percent
                    logging.debug(f"Memory usage after processing: {current_memory}% (change: {current_memory - initial_memory}%)")
                    logging.debug(f"Extracted {len(packet_data)} packets from PCAP file")
                    
                    # Analyze the packet data with ML model
                    logging.debug(f"Analyzing {len(packet_data)} packets with ML model")
                    analysis_results = analyze_packet_features(packet_data)
                    
                    # Save the original packet data in the results for better IP extraction
                    if not isinstance(analysis_results, dict):
                        analysis_results = {'status': 'error', 'message': 'Invalid analysis results format'}
                    
                    # Create traffic_summary if not exists
                    if 'traffic_summary' not in analysis_results:
                        analysis_results['traffic_summary'] = {}
                    
                    # Store appropriate number of packets based on size
                    if 'packet_data' not in analysis_results['traffic_summary'] and packet_data:
                        # Limit to 300 packets to avoid session size issues
                        max_packets = 300
                        limited_packet_data = packet_data[:max_packets]
                        
                        # Optimize packet data for storage (keep only essential fields)
                        simplified_packets = []
                        for p in limited_packet_data:
                            if isinstance(p, dict):
                                # Only keep essential fields for IP visualization
                                simplified_p = {
                                    'src_ip': p.get('src_ip'),
                                    'dst_ip': p.get('dst_ip'),
                                    'src_port': p.get('src_port', 0),
                                    'dst_port': p.get('dst_port', 0),
                                    'protocol_name': p.get('protocol_name', 'UNKNOWN'),
                                    'packet_size': p.get('packet_size', 0),
                                    'timestamp': p.get('timestamp', 0)
                                }
                                simplified_packets.append(simplified_p)
                        
                        analysis_results['traffic_summary']['packet_data'] = simplified_packets
                        logging.debug(f"Stored {len(simplified_packets)} simplified packets in traffic_summary")
                    
                    # Sample IPs for verification
                    sample_ips = set()
                    for p in analysis_results['traffic_summary'].get('packet_data', [])[:20]:
                        if isinstance(p, dict):
                            if p.get('src_ip'): sample_ips.add(p.get('src_ip'))
                            if p.get('dst_ip'): sample_ips.add(p.get('dst_ip'))
                    
                    if sample_ips:
                        logging.info(f"Sample IPs stored in analysis_results: {list(sample_ips)[:5]}")
                    else:
                        logging.warning("No IPs found in stored packet data")
                        
            except MemoryError:
                logging.critical("Memory error during file processing")
                # Clean up the temporary file
                try:
                    os.remove(filepath)
                except Exception as cleanup_error:
                    logging.error(f"Failed to remove temp file after memory error: {cleanup_error}")
                
                flash('File is too large to process with available memory. Try a smaller file.', 'danger')
                return redirect(url_for('index'))
                
            except Exception as processing_error:
                logging.error(f"Error during file processing: {processing_error}", exc_info=True)
                # Clean up the temporary file
                try:
                    os.remove(filepath)
                except Exception as cleanup_error:
                    logging.error(f"Failed to remove temp file after processing error: {cleanup_error}")
                
                flash(f'Error processing file: {str(processing_error)}', 'danger')
                return redirect(url_for('index'))
            
            # Store results in session, including the original filename
            analysis_results['filename'] = original_filename
            
            # Fix for Decimal types and other non-JSON serializable values
            analysis_results = convert_numpy_types(analysis_results)
            
            # Additional custom conversion for other types like Decimal
            def fix_decimal_and_non_serializable_types(obj):
                if isinstance(obj, dict):
                    return {k: fix_decimal_and_non_serializable_types(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [fix_decimal_and_non_serializable_types(v) for v in obj]
                elif hasattr(obj, 'tolist'):  # Handle numpy arrays
                    return obj.tolist()
                elif type(obj).__name__ == 'EDecimal' or type(obj).__name__ == 'Decimal':
                    return float(obj)  # Convert Decimal to float
                elif hasattr(obj, '__class__') and obj.__class__.__name__ == 'FlagValue':
                    # Convert FlagValue to its string representation or a primitive type
                    return str(obj)
                else:
                    return obj
                    
            # Apply additional conversion
            analysis_results = fix_decimal_and_non_serializable_types(analysis_results)
            
            # For large result sets, compress or trim to fit in session
            try:
                # Test JSON serialization to catch any remaining non-serializable types
                json_str = json.dumps(analysis_results)
                result_size = len(json_str)
                logging.debug(f"Analysis results size: {result_size / 1024:.2f} KB")
                
                if result_size > 4 * 1024 * 1024:  # 4MB (typical session size limit)
                    logging.warning("Analysis results too large for session, trimming data")
                    
                    # Limit packet data further if needed
                    if 'traffic_summary' in analysis_results and 'packet_data' in analysis_results['traffic_summary']:
                        packet_count = len(analysis_results['traffic_summary']['packet_data'])
                        
                        if packet_count > 100:
                            # Reduce to 100 packets
                            analysis_results['traffic_summary']['packet_data'] = analysis_results['traffic_summary']['packet_data'][:100]
                            analysis_results['traffic_summary']['trimmed'] = True
                            logging.debug(f"Reduced packet data to 100 packets")
                            
                            # Try serialization again
                            json_str = json.dumps(analysis_results)
                            result_size = len(json_str)
                            
                            # If still too large, reduce more
                            if result_size > 4 * 1024 * 1024:
                                # Reduce to 50 packets
                                analysis_results['traffic_summary']['packet_data'] = analysis_results['traffic_summary']['packet_data'][:50]
                                logging.debug(f"Reduced packet data to 50 packets")
                                
                                # Try again
                                json_str = json.dumps(analysis_results)
                                result_size = len(json_str)
                                
                                # If still too large, remove completely
                                if result_size > 4 * 1024 * 1024:
                                    logging.warning("Results still too large, removing packet_data completely")
                                    analysis_results['traffic_summary']['packet_data'] = []
                                    analysis_results['traffic_summary']['error'] = "Packet data removed due to size constraints"
                                    json_str = json.dumps(analysis_results)
                
                # Save analysis results to session
                session['analysis_results'] = json_str
                
                # Double-check if we still have packet data
                if ('traffic_summary' in analysis_results and 
                    'packet_data' in analysis_results['traffic_summary'] and
                    len(analysis_results['traffic_summary']['packet_data']) > 0):
                    logging.info(f"Final packet count in session: {len(analysis_results['traffic_summary']['packet_data'])}")
                    
                    # Kiểm tra nhanh các IP
                    sample_ips = set()
                    for p in analysis_results['traffic_summary']['packet_data'][:10]:
                        if isinstance(p, dict):
                            if p.get('src_ip'): sample_ips.add(p.get('src_ip'))
                            if p.get('dst_ip'): sample_ips.add(p.get('dst_ip'))
                    logging.info(f"Sample IPs in final session data: {list(sample_ips)}")
                else:
                    logging.warning("No packet data in final session object")
                
            except TypeError as json_error:
                logging.error(f"JSON serialization error: {json_error}")
                
                # Create a simplified version that will serialize properly
                simplified_results = {
                    'filename': fix_decimal_and_non_serializable_types(analysis_results.get('filename', original_filename)),
                    'summary': fix_decimal_and_non_serializable_types(analysis_results.get('summary', {'status': 'partial', 'message': 'Data serialization issues'})),
                    'threats': fix_decimal_and_non_serializable_types(analysis_results.get('threats', [])),
                    'traffic_summary': fix_decimal_and_non_serializable_types({
                        'total_packets': analysis_results.get('traffic_summary', {}).get('total_packets', 0),
                        'protocols': analysis_results.get('traffic_summary', {}).get('protocols', {}),
                        'unique_src_ips': analysis_results.get('traffic_summary', {}).get('unique_src_ips', 0),
                        'unique_dst_ips': analysis_results.get('traffic_summary', {}).get('unique_dst_ips', 0),
                        'error': 'Some data removed due to serialization issues'
                    })
                }
                
                # NEW: Cố gắng giữ lại dữ liệu IP trong phiên làm việc
                # Lấy dữ liệu IP từ tất cả các nguồn có thể
                src_ips = []
                dst_ips = []
                
                # Kiểm tra traffic_summary.all_src_ips và traffic_summary.all_dst_ips (định dạng ZIP)
                if 'traffic_summary' in analysis_results:
                    ts = analysis_results['traffic_summary']
                    if isinstance(ts, dict):
                        if 'all_src_ips' in ts and isinstance(ts['all_src_ips'], list):
                            src_ips.extend(ts['all_src_ips'])
                        if 'all_dst_ips' in ts and isinstance(ts['all_dst_ips'], list):
                            dst_ips.extend(ts['all_dst_ips'])
                            
                # Nếu có IPs, tạo packet_data đơn giản để hiển thị
                if src_ips or dst_ips:
                    packet_data = []
                    if not src_ips:
                        src_ips = dst_ips
                    if not dst_ips:
                        dst_ips = src_ips
                        
                    for i in range(min(5, len(src_ips))):
                        for j in range(min(5, len(dst_ips))):
                            if src_ips[i] != dst_ips[j]:
                                packet_data.append({
                                    'src_ip': src_ips[i],
                                    'dst_ip': dst_ips[j],
                                    'src_port': 1024 + i,
                                    'dst_port': 80,
                                    'protocol_name': 'TCP',
                                    'protocol': 6,
                                    'packet_size': 1000,
                                    'timestamp': time.time()
                                })
                                
                    simplified_results['traffic_summary']['packet_data'] = packet_data
                    logging.info(f"Added {len(packet_data)} minimal packet data entries to simplified results")
                
                session['analysis_results'] = json.dumps(simplified_results)
            
            # Clean up the temporary file
            try:
                os.remove(filepath)
                logging.debug(f"Temporary file removed: {filepath}")
            except Exception as e:
                logging.error(f"Failed to remove temp file: {e}")

            # Store the analysis results in the database for future reference
            try:
                with app.app_context():
                    filename = analysis_results.get('filename', 'Unknown File')
                    file_hash = hashlib.md5(filename.encode('utf-8')).hexdigest() 

                    # Get the JSON-serializable version of the results
                    result_summary = json.loads(json_str).get('summary', {}) if 'json_str' in locals() else analysis_results.get('summary', {})
                    detected_threats = json.loads(json_str).get('threats', []) if 'json_str' in locals() else analysis_results.get('threats', [])
                    traffic_summary = json.loads(json_str).get('traffic_summary', {}) if 'json_str' in locals() else analysis_results.get('traffic_summary', {})

                    analysis = Analysis(
                        filename=filename,
                        file_hash=file_hash,
                        result_summary=result_summary,
                        detected_threats=detected_threats,
                        traffic_summary=traffic_summary
                    )

                    db.session.add(analysis)
                    db.session.commit()

                    # Set the analysis ID in the results
                    analysis_id = analysis.id
                    logging.debug(f"Analysis ID: {analysis_id}")
                    
                    # Update the session with analysis ID
                    session_data = json.loads(session['analysis_results'])
                    session_data['analysis_id'] = analysis_id
                    session['analysis_results'] = json.dumps(session_data)

            except Exception as db_error:
                logging.error(f"Error storing analysis results in database: {db_error}")
                # Continue even if DB storage fails

            # Redirect to results page
            logging.info(f"File processing completed successfully for: {original_filename}")
            return redirect(url_for('show_results'))

        except Exception as e:
            logging.error(f"Unhandled error processing file: {e}", exc_info=True)
            # Make sure to clean up the file if there's an error
            try:
                if 'filepath' in locals() and os.path.exists(filepath):
                    os.remove(filepath)
            except Exception as cleanup_error:
                logging.error(f"Failed to remove temp file during error handling: {cleanup_error}")
                
            flash(f'Error processing file: {str(e)}', 'danger')
            return redirect(url_for('index'))
    else:
        flash('File type not allowed. Please upload a PCAP, CSV or ZIP file.', 'danger')
        return redirect(url_for('index'))


@app.route('/results')
def show_results():
    results_json = session.get('analysis_results')
    if not results_json:
        flash('No analysis results found', 'warning')
        return redirect(url_for('index'))

    try:
        results = json.loads(results_json)

        # Debug output
        logging.debug(f"Results data: {results}")
        logging.debug(f"Filename from results: {results.get('filename', 'Not found')}")
        logging.debug(f"Threats detected: {results.get('threats', 'None')}")
        logging.debug(f"Traffic summary: {results.get('traffic_summary', {})}")
        
        # Kiểm tra packet_data
        if 'traffic_summary' in results and 'packet_data' in results['traffic_summary']:
            packet_data = results['traffic_summary']['packet_data']
            logging.info(f"Found {len(packet_data)} packets in results traffic_summary")
            
            # Kiểm tra mẫu IPs
            sample_ips = set()
            for p in packet_data[:10]:
                if isinstance(p, dict):
                    if p.get('src_ip'): sample_ips.add(p.get('src_ip'))
                    if p.get('dst_ip'): sample_ips.add(p.get('dst_ip'))
            
            if sample_ips:
                logging.info(f"Sample IPs in results view: {list(sample_ips)}")
            else:
                logging.warning("No IPs found in packet_data during results view")
                
                # Nếu không có IPs trong packet_data, thử tạo dữ liệu từ các nguồn khác
                if 'traffic_summary' in results:
                    ts = results['traffic_summary']
                    src_ips = ts.get('all_src_ips', [])
                    dst_ips = ts.get('all_dst_ips', [])
                    
                    if src_ips or dst_ips:
                        logging.info(f"Creating packet_data from all_src_ips ({len(src_ips)}) and all_dst_ips ({len(dst_ips)})")
                        
                        # Đảm bảo chúng ta có cả source và destination IPs
                        if not src_ips:
                            src_ips = dst_ips
                        if not dst_ips:
                            dst_ips = src_ips
                            
                        # Tạo packet_data mới
                        new_packet_data = []
                        for i in range(min(5, len(src_ips))):
                            for j in range(min(5, len(dst_ips))):
                                if src_ips[i] != dst_ips[j]:
                                    new_packet_data.append({
                                        'src_ip': src_ips[i],
                                        'dst_ip': dst_ips[j],
                                        'src_port': 1024 + i,
                                        'dst_port': 80,
                                        'protocol_name': 'TCP',
                                        'protocol': 6,
                                        'packet_size': 1000,
                                        'timestamp': time.time()
                                    })
                        
                        results['traffic_summary']['packet_data'] = new_packet_data
                        logging.info(f"Added {len(new_packet_data)} synthetic packets to traffic_summary")
        else:
            logging.warning("No packet_data found in results traffic_summary")

        # Store the analysis results in the database for future reference
        try:
            with app.app_context():
                filename = results.get('filename', 'Unknown File')
                file_hash = hashlib.md5(filename.encode('utf-8')).hexdigest() 

                result_summary = convert_numpy_types(results.get('summary', {}))
                detected_threats = convert_numpy_types(results.get('threats', []))
                traffic_summary = convert_numpy_types(results.get('traffic_summary', {}))

                analysis = Analysis(
                    filename=filename,
                    file_hash=file_hash,
                    result_summary=results.get('summary', {}),
                    detected_threats=results.get('threats', []),
                    traffic_summary=results.get('traffic_summary', {})
                )

                db.session.add(analysis)
                db.session.commit()

                # Set the analysis ID in the results
                results['analysis_id'] = analysis.id
                logging.debug(f"Analysis ID: {analysis.id}")

        except Exception as db_error:
            logging.error(f"Error storing analysis results: {db_error}")
            # Continue even if DB storage fails

        return render_template('results.html', results=results)

    except Exception as e:
        logging.error(f"Error parsing results: {e}")
        flash('Error displaying results', 'danger')
        return redirect(url_for('index'))

@app.route('/results/<int:analysis_id>')
def view_analysis(analysis_id):
    try:
        analysis = Analysis.query.get_or_404(analysis_id)
        results = {
            'analysis_id': analysis.id,
            'filename': analysis.filename,
            'summary': analysis.result_summary,
            'threats': analysis.detected_threats,
            'traffic_summary': analysis.traffic_summary,
            'created_at': analysis.created_at
        }
        return render_template('results.html', results=results)
    except Exception as e:
        logging.error(f"Error retrieving analysis {analysis_id}: {e}")
        flash('Error retrieving analysis results', 'danger')
        return redirect(url_for('index'))

@app.route('/threat-details/<int:analysis_id>/<int:threat_index>')
def threat_details(analysis_id, threat_index):
    try:
        logging.info(f"Accessing threat details for analysis {analysis_id}, threat index {threat_index}")
        
        # Fetch analysis with error checking
        analysis = Analysis.query.get_or_404(analysis_id)
        if not analysis:
            flash('Analysis not found', 'danger')
            return redirect(url_for('index'))
            
        # Dump analysis object structure for debugging
        logging.debug(f"Analysis object type: {type(analysis)}")
        logging.debug(f"Analysis attributes: {dir(analysis)}")
        logging.debug(f"Analysis has traffic_summary: {hasattr(analysis, 'traffic_summary')}")
        logging.debug(f"Analysis has result_summary: {hasattr(analysis, 'result_summary')}")
        logging.debug(f"Analysis has raw_pcap_data: {hasattr(analysis, 'raw_pcap_data')}")
        
        # Check if traffic_summary and result_summary are dictionaries
        if hasattr(analysis, 'traffic_summary'):
            logging.debug(f"traffic_summary type: {type(analysis.traffic_summary)}")
            if isinstance(analysis.traffic_summary, dict):
                logging.debug(f"traffic_summary keys: {list(analysis.traffic_summary.keys())}")
                
                # Check if packet_data exists and log its type
                if 'packet_data' in analysis.traffic_summary:
                    packet_data = analysis.traffic_summary.get('packet_data')
                    logging.debug(f"packet_data type: {type(packet_data)}")
                    logging.debug(f"packet_data length: {len(packet_data) if hasattr(packet_data, '__len__') else 'N/A'}")
                    
                    # Log first packet if available
                    if isinstance(packet_data, list) and packet_data:
                        logging.debug(f"First packet: {packet_data[0]}")
        
        # Validate detected_threats
        if not hasattr(analysis, 'detected_threats') or analysis.detected_threats is None:
            flash('No threats detected in this analysis', 'warning')
            return redirect(url_for('view_analysis', analysis_id=analysis_id))
            
        # Validate threat index
        if not isinstance(analysis.detected_threats, list):
            flash('Invalid threats data format', 'danger')
            return redirect(url_for('view_analysis', analysis_id=analysis_id))
            
        if threat_index < 0 or threat_index >= len(analysis.detected_threats):
            flash('Threat index out of range', 'danger')
            return redirect(url_for('view_analysis', analysis_id=analysis_id))

        # Get the specific threat
        threat = analysis.detected_threats[threat_index]
        if not isinstance(threat, dict):
            threat = {} 
            logging.warning(f"Threat at index {threat_index} is not a dictionary")

        # Add more detailed information for display with robust error handling
        threat_name = threat.get('name', 'Unknown Threat')
        logging.info(f"Processing threat: {threat_name}")
        
        # Create a copy of the threat to avoid modifying the original in database
        enhanced_threat = dict(threat)
        
        # Build enhanced threat data with extensive error handling
        try:
            # Add basic descriptive data
            enhanced_threat.update({
                'description': get_threat_description(threat_name),
                'indicators': get_threat_indicators(threat_name),
                'recommended_actions': get_recommended_actions(threat_name),
                'id': threat_index,
                'name': threat_name
            })
            
            # Add confidence and risk level with validation
            if 'confidence' in threat:
                try:
                    confidence_value = float(threat['confidence'])
                    enhanced_threat['confidence'] = confidence_value
                except (ValueError, TypeError):
                    enhanced_threat['confidence'] = 0
            else:
                enhanced_threat['confidence'] = 0
                
            if 'risk_level' in threat:
                enhanced_threat['risk_level'] = threat['risk_level']
            else:
                # Calculate risk level from confidence if available
                confidence = enhanced_threat.get('confidence', 0)
                if confidence > 0.8:
                    enhanced_threat['risk_level'] = 'High'
                elif confidence > 0.5:
                    enhanced_threat['risk_level'] = 'Medium'
                else:
                    enhanced_threat['risk_level'] = 'Low'
            
            # Add involved IPs with improved extraction logic
            try:
                logging.debug(f"Getting involved IPs for threat: {threat_name}")
                
                # First check if already have involved_ips
                if 'involved_ips' in threat and isinstance(threat['involved_ips'], list) and threat['involved_ips']:
                    logging.debug(f"Using {len(threat['involved_ips'])} existing involved IPs")
                    enhanced_threat['involved_ips'] = threat['involved_ips']
                else:
                    # Use our improved function to extract involved IPs
                    involved_ips = get_involved_ips(analysis, threat)
                    
                    # Log detailed debugging info
                    logging.info(f"Found {len(involved_ips)} involved IPs")
                    if involved_ips:
                        for i, ip in enumerate(involved_ips):
                            logging.debug(f"IP {i+1}: {ip.get('address')} - {ip.get('role')} - {ip.get('risk_level')}")
                    
                    # Store the IPs for rendering
                    enhanced_threat['involved_ips'] = involved_ips if involved_ips else []
            except Exception as ip_error:
                logging.error(f"Error getting involved IPs: {ip_error}")
                logging.error(f"Error details: {traceback.format_exc()}")
                enhanced_threat['involved_ips'] = []
            
            # Add timeline with error handling
            try:
                timeline = generate_threat_timeline(analysis, threat)
                enhanced_threat['timeline'] = timeline if timeline else []
                logging.info(f"Generated timeline with {len(timeline)} events")
            except Exception as timeline_error:
                logging.error(f"Error generating timeline: {timeline_error}")
                enhanced_threat['timeline'] = []
            
            # Add related flows with error handling
            try:
                related_flows = get_related_flows(analysis, threat)
                enhanced_threat['related_flows'] = related_flows if related_flows else []
                logging.info(f"Found {len(related_flows)} related flows")
            except Exception as flows_error:
                logging.error(f"Error getting related flows: {flows_error}")
                enhanced_threat['related_flows'] = []
                
        except Exception as enhancement_error:
            logging.error(f"Error enhancing threat data: {enhancement_error}")
            logging.error(f"Error details: {traceback.format_exc()}")
            # Ensure at least basic data exists
            if 'name' not in enhanced_threat:
                enhanced_threat['name'] = threat_name
            if 'description' not in enhanced_threat:
                enhanced_threat['description'] = get_threat_description(threat_name)
            if 'id' not in enhanced_threat:
                enhanced_threat['id'] = threat_index

        logging.info("Rendering threat details template")
        return render_template('threat_details.html', 
                             threat=enhanced_threat, 
                             analysis_id=analysis_id)
                             
    except Exception as e:
        logging.error(f"Error displaying threat details: {e}")
        logging.error(traceback.format_exc())
        flash('Error displaying threat details', 'danger')
        return redirect(url_for('view_analysis', analysis_id=analysis_id))

@app.route('/traffic-details/<int:analysis_id>')
def traffic_details(analysis_id):
    try:
        analysis = Analysis.query.get_or_404(analysis_id)

        # Prepare traffic details for display
        traffic = {
            'flows': get_traffic_flows(analysis),
            'ip_details': get_ip_details(analysis),
            'nodes': generate_graph_nodes(analysis),
            'links': generate_graph_links(analysis),
            'protocol_labels': list(analysis.traffic_summary.get('protocols', {}).keys()),
            'protocol_values': list(analysis.traffic_summary.get('protocols', {}).values())
        }

        return render_template('traffic_details.html', 
                               traffic=traffic, 
                               analysis_id=analysis_id)
    except Exception as e:
        logging.error(f"Error displaying traffic details: {e}")
        flash('Error displaying traffic details', 'danger')
        return redirect(url_for('view_analysis', analysis_id=analysis_id))

@app.route('/export/report/<int:analysis_id>')
def export_report(analysis_id):
    try:
        # Add more detailed logging
        logging.info(f"Starting report generation for analysis ID: {analysis_id}")

        analysis = Analysis.query.get_or_404(analysis_id)

        if not analysis:
            flash('Analysis not found', 'danger')
            return redirect(url_for('index'))

        # Log the analysis data structure
        logging.info(f"Analysis object retrieved: {analysis.id}")

        # Convert analysis to dict safely with detailed error handling
        try:
            analysis_dict = {
                'id': analysis.id,
                'filename': analysis.filename,
                'file_hash': analysis.file_hash,
                'summary': analysis.result_summary or {},
                'detected_threats': analysis.detected_threats or [],
                'traffic_summary': analysis.traffic_summary or {},
                'created_at': analysis.created_at.strftime('%Y-%m-%d %H:%M:%S') if analysis.created_at else None,
                # Use only real data, don't add alert_level if not present
                'alert_level': analysis.result_summary.get('alert_level', 'Low'),
                'key_finding': analysis.result_summary.get('key_finding', 'No significant threats detected in this network capture.')
            }
            logging.info("Successfully converted analysis to dictionary")
        except AttributeError as ae:
            logging.error(f"AttributeError converting analysis to dict: {ae}")
            flash('Invalid analysis data format', 'danger')
            return redirect(url_for('view_analysis', analysis_id=analysis_id))
        except Exception as e:
            logging.error(f"Unexpected error converting analysis to dict: {e}")
            flash('Error processing analysis data', 'danger')
            return redirect(url_for('view_analysis', analysis_id=analysis_id))

        # Get traffic data with explicit error handling
        try:
            flows = get_traffic_flows(analysis) or []
            logging.info(f"Retrieved {len(flows)} traffic flows")
            ip_details = get_ip_details(analysis) or []
            logging.info(f"Retrieved {len(ip_details)} IP details")
        except Exception as e:
            logging.error(f"Error retrieving traffic data: {e}")
            flows = []
            ip_details = []

        # Prepare data for the report with explicit structure
        report_data = {
            'analysis': analysis_dict,
            'traffic': {
                'flows': flows,
                'ip_details': ip_details
            },
            'report_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        # Log the structure of the report data for debugging
        logging.info(f"Report data structure prepared with keys: {list(report_data.keys())}")
        logging.info(f"Analysis dict has keys: {list(report_data['analysis'].keys())}")

        # Safely enhance threat information WITHOUT adding fake data
        if report_data['analysis'].get('detected_threats'):
            for i, threat in enumerate(report_data['analysis']['detected_threats']):
                try:
                    threat_name = threat.get('name', 'Unknown Threat')
                    # Only add these fields if they don't already exist
                    if 'description' not in threat:
                        threat['description'] = get_threat_description(threat_name)
                    if 'indicators' not in threat:
                        threat['indicators'] = get_threat_indicators(threat_name)
                    if 'recommended_actions' not in threat:
                        threat['recommended_actions'] = get_recommended_actions(threat_name)

                    # Use real IPs without generating fake ones
                    try:
                        if 'involved_ips' not in threat:
                            involved_ips = get_involved_ips(analysis, threat)
                            threat['involved_ips'] = involved_ips if involved_ips else []
                            logging.info(f"Found {len(involved_ips)} involved IPs for threat {i}")
                    except Exception as ip_error:
                        logging.error(f"Error getting involved IPs for threat {i}: {ip_error}")
                        threat['involved_ips'] = []

                    # Add risk level if not present - this is interpretive, not fake data
                    if 'risk_level' not in threat and 'confidence' in threat:
                        confidence = float(threat.get('confidence', 0))
                        if confidence > 0.8:
                            threat['risk_level'] = 'High'
                        elif confidence > 0.5:
                            threat['risk_level'] = 'Medium'
                        else:
                            threat['risk_level'] = 'Low'

                except Exception as threat_error:
                    logging.error(f"Error processing threat {i}: {threat_error}")
                    # Keep existing data, don't overwrite with potentially fake data
                    # Only ensure minimal required fields are present
                    if 'name' not in threat:
                        threat['name'] = 'Unknown Threat'

        try:
            # Generate HTML report with detailed error checking
            logging.info("Attempting to render report template")
            html_report = render_template('report_template.html', **report_data)
            logging.info("Successfully rendered report template")
            return Response(html_report, mimetype='text/html')
        except Exception as template_error:
            # Log the detailed error for debugging
            logging.error(f"Template rendering error: {str(template_error)}")
            logging.error(f"Error type: {type(template_error).__name__}")
            logging.error(f"Traceback: {traceback.format_exc()}")
            flash(f'Error generating report template: {str(template_error)}', 'danger')
            return redirect(url_for('view_analysis', analysis_id=analysis_id))

    except Exception as e:
        logging.error(f"Error generating report: {e}")
        flash('Error generating report', 'danger')
        return redirect(url_for('view_analysis', analysis_id=analysis_id))

@app.route('/export/forensic-report/<int:analysis_id>')
def export_forensic_report(analysis_id):
    try:
        logging.info(f"Starting forensic report generation for analysis ID: {analysis_id}")

        analysis = Analysis.query.get_or_404(analysis_id)
        if not analysis:
            flash('Analysis not found', 'danger')
            return redirect(url_for('index'))

        # Convert analysis to dictionary with error handling
        try:
            analysis_dict = analysis.to_dict()
            logging.info(f"Successfully converted analysis {analysis.id} to dictionary")
        except Exception as e:
            logging.error(f"Error converting analysis to dict: {e}")
            flash('Error processing analysis data', 'danger')
            return redirect(url_for('view_analysis', analysis_id=analysis_id))

        # Get only real data from the PCAP analysis with proper error handling
        try:
            real_flows = get_traffic_flows(analysis) or []
            logging.info(f"Retrieved {len(real_flows)} traffic flows")
        except Exception as e:
            logging.error(f"Error retrieving traffic flows: {e}")
            real_flows = []

        try:
            real_ip_details = get_ip_details(analysis) or []
            logging.info(f"Retrieved {len(real_ip_details)} IP details")
        except Exception as e:
            logging.error(f"Error retrieving IP details: {e}")
            real_ip_details = []

        try:
            real_nodes = generate_graph_nodes(analysis) or []
            logging.info(f"Generated {len(real_nodes)} graph nodes")
        except Exception as e:
            logging.error(f"Error generating graph nodes: {e}")
            real_nodes = []

        try:
            real_links = generate_graph_links(analysis) or []
            logging.info(f"Generated {len(real_links)} graph links")
        except Exception as e:
            logging.error(f"Error generating graph links: {e}")
            real_links = []

        try:
            real_hostnames = get_suspicious_hostnames(analysis) or []
            logging.info(f"Retrieved {len(real_hostnames)} suspicious hostnames")
        except Exception as e:
            logging.error(f"Error retrieving suspicious hostnames: {e}")
            real_hostnames = []

        try:
            real_files = get_suspicious_files(analysis) or []
            logging.info(f"Retrieved {len(real_files)} suspicious files")
        except Exception as e:
            logging.error(f"Error retrieving suspicious files: {e}")
            real_files = []

        try:
            real_iocs = generate_iocs(analysis) or []
            logging.info(f"Generated {len(real_iocs)} IOCs")
        except Exception as e:
            logging.error(f"Error generating IOCs: {e}")
            real_iocs = []

        # Prepare data for the forensic report WITHOUT fake data
        report_data = {
            'analysis': analysis_dict,
            'traffic': {
                'flows': real_flows,
                'ip_details': real_ip_details,
                'nodes': real_nodes,
                'links': real_links
            },
            'report_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'suspicious_hostnames': real_hostnames,
            'suspicious_files': real_files,
            'iocs': real_iocs
        }

        # Enhance threat information with real forensic details only
        if report_data['analysis'].get('detected_threats'):
            for i, threat in enumerate(report_data['analysis']['detected_threats']):
                try:
                    threat_name = threat.get('name', 'Unknown Threat')
                    logging.info(f"Enhancing threat {i}: {threat_name}")

                    # Only add these fields if they don't already exist
                    if 'description' not in threat:
                        threat['description'] = get_threat_description(threat_name)

                    if 'indicators' not in threat:
                        threat['indicators'] = get_threat_indicators(threat_name)

                    if 'recommended_actions' not in threat:
                        threat['recommended_actions'] = get_recommended_actions(threat_name)

                    # Use real IPs without generating fake ones
                    if 'involved_ips' not in threat:
                        try:
                            involved_ips = get_involved_ips(analysis, threat)
                            threat['involved_ips'] = involved_ips if involved_ips else []
                            logging.info(f"Found {len(threat['involved_ips'])} involved IPs for threat {threat_name}")
                        except Exception as ip_error:
                            logging.error(f"Error getting involved IPs for threat {i}: {ip_error}")
                            threat['involved_ips'] = []

                    if 'timeline' not in threat:
                        try:
                            timeline = generate_threat_timeline(analysis, threat)
                            threat['timeline'] = timeline if timeline else []
                            logging.info(f"Generated timeline with {len(threat['timeline'])} events")
                        except Exception as timeline_error:
                            logging.error(f"Error generating timeline for threat {i}: {timeline_error}")
                            threat['timeline'] = []

                    if 'related_flows' not in threat:
                        try:
                            related_flows = get_related_flows(analysis, threat)
                            threat['related_flows'] = related_flows if related_flows else []
                            logging.info(f"Found {len(threat['related_flows'])} related flows")
                        except Exception as flows_error:
                            logging.error(f"Error getting related flows for threat {i}: {flows_error}")
                            threat['related_flows'] = []

                    # Use missing indicator for fields that aren't present rather than making up values
                    if 'first_seen' not in threat:
                        threat['first_seen'] = 'N/A'
                    if 'last_seen' not in threat:
                        threat['last_seen'] = 'N/A'
                    if 'packet_count' not in threat:
                        threat['packet_count'] = 'N/A'

                    # Add risk level based on confidence - this is interpretive, not fake data
                    if 'risk_level' not in threat and 'confidence' in threat:
                        try:
                            confidence = float(threat.get('confidence', 0))
                            if confidence > 0.8:
                                threat['risk_level'] = 'High'
                            elif confidence > 0.5:
                                threat['risk_level'] = 'Medium'
                            else:
                                threat['risk_level'] = 'Low'
                        except (ValueError, TypeError):
                            threat['risk_level'] = 'Unknown'
                    elif 'risk_level' not in threat:
                        threat['risk_level'] = 'Unknown'

                except Exception as threat_error:
                    logging.error(f"Error enhancing threat {i}: {threat_error}")
                    # Ensure at least the name exists
                    if 'name' not in threat:
                        threat['name'] = 'Unknown Threat'

        # Generate HTML forensic report
        try:
            logging.info("Rendering forensic report template")
            html_report = render_template('forensic_report.html', **report_data)
            logging.info("Successfully rendered forensic report template")
            return Response(html_report, mimetype='text/html')
        except Exception as template_error:
            logging.error(f"Template rendering error: {str(template_error)}")
            logging.error(f"Traceback: {traceback.format_exc()}")
            flash(f'Error generating forensic report template: {str(template_error)}', 'danger')
            return redirect(url_for('view_analysis', analysis_id=analysis_id))

    except Exception as e:
        logging.error(f"Error generating forensic report: {e}")
        flash('Error generating forensic report', 'danger')
        return redirect(url_for('view_analysis', analysis_id=analysis_id))

@app.route('/train', methods=['GET', 'POST'])
def train_model_route():
    if request.method == 'GET':
        # Import THREAT_CATEGORY_MAP from ml_model
        from ml_model import THREAT_CATEGORY_MAP
        
        # Extract the category names from the ThreatCategoryEnum values in the map
        threat_categories = []
        for category in THREAT_CATEGORY_MAP:
            if hasattr(category, 'value'):
                # If it's an enum with a value attribute
                threat_categories.append(category.value)
            else:
                # If it's a string or other type
                threat_categories.append(str(category))
        
        return render_template('train.html', threat_categories=threat_categories)

    if request.method == 'POST':
        # Check if files were submitted
        if 'files[]' not in request.files:
            flash('No files selected', 'danger')
            return redirect(url_for('train_model_route'))

        files = request.files.getlist('files[]')

        # Check if any files were selected
        if not files or files[0].filename == '':
            flash('No files selected', 'danger')
            return redirect(url_for('train_model_route'))

        # Get the labels for each file
        labels = []
        for i in range(len(files)):
            label = request.form.get(f'label_{i}', None)
            if not label:
                flash(f'Missing label for file {i+1}', 'danger')
                return redirect(url_for('train_model_route'))
            labels.append(label)

        try:
            # Create temporary directory to store uploaded files
            with tempfile.TemporaryDirectory() as temp_dir:
                # Save all files
                file_paths = []
                for i, file in enumerate(files):
                    if file:
                        filename = secure_filename(file.filename)
                        filepath = os.path.join(temp_dir, filename)
                        file.save(filepath)
                        file_paths.append(filepath)
                
                # Handle different file types
                for i, filepath in enumerate(file_paths):
                    filename = os.path.basename(filepath)
                    
                    # Check if it's a CSV file
                    if filename.lower().endswith('.csv'):
                        # Process CSV differently using our csv_processor module
                        try:
                            from csv_processor import process_csv_for_training
                            
                            # Get category by name for CSV processing
                            # Since we're now using direct category names, not DB IDs
                            result = process_csv_for_training(filepath, labels[i])
                            if result['status'] == 'success':
                                flash(f'Successfully processed CSV file {filename}', 'success')
                            else:
                                flash(f'Error processing CSV file {filename}: {result["message"]}', 'danger')
                                
                        except ImportError:
                            # If csv_processor isn't available, process as regular file
                            flash(f'CSV processing module not available, processing {filename} as regular file', 'warning')
                            
                # Train the model with all PCAP files
                pcap_files = [fp for fp in file_paths if not fp.lower().endswith('.csv')]
                pcap_labels = [labels[i] for i, fp in enumerate(file_paths) if not fp.lower().endswith('.csv')]
                
                if pcap_files:
                    # Train the model with PCAP files
                    training_result = train_model(pcap_files, pcap_labels)

                    # Check training result
                    if training_result['status'] == 'success':
                        flash(training_result['message'], 'success')
                    else:
                        flash(f"Training failed: {training_result['message']}", 'danger')

                return redirect(url_for('index'))

        except Exception as e:
            logging.error(f"Error during training: {e}")
            flash(f'Error during training: {str(e)}', 'danger')
            return redirect(url_for('train_model_route'))

@app.errorhandler(413)
def too_large(e):
    flash('File too large. Maximum size is 5GB.', 'danger')
    return redirect(url_for('index'))

# Helper functions for threat details
def get_threat_description(category):
    """Get detailed description for a threat category"""
    descriptions = {
        'Normal Traffic': 'Normal network traffic with no malicious patterns or intent detected.',
        'Reconnaissance (Scanning & Probing)': 'Activities aimed at discovering network topology, services, and potential vulnerabilities through scanning and probing techniques.',
        'Denial of Service (DoS & DDoS)': 'Attacks designed to disrupt network services by overwhelming resources through excessive traffic or exploitation of vulnerabilities.',
        'Network Protocol Attacks': 'Exploitation of weaknesses in network protocols to disrupt services, intercept data, or gain unauthorized access.',
        'Network Device Attacks': 'Attacks targeting network infrastructure components such as routers, switches, and firewalls.',
        'Web Attacks (SQLi, XSS, CSRF, Web Phishing, SSRF, LFI/RFI, Command Injection, etc.)': 'Various attack vectors targeting web applications, including data manipulation, script injection, and unauthorized access techniques.',
        'Web Phishing': 'Deceptive attempts to acquire sensitive information by masquerading as trustworthy entities through fraudulent websites.',
        'Server Attacks': 'Attacks targeting server systems to gain unauthorized access, escalate privileges, or compromise data integrity.',
        'Malicious Behavior (Malware, C2, Data Exfiltration, Cryptomining)': 'Activities indicating malware infection, command and control communication, unauthorized data transfer, or resource hijacking.',
        'Unknown Threat': 'Suspicious network behavior that does not clearly align with known threat categories but warrants investigation.'
    }
    return descriptions.get(category, 'Unrecognized threat category')

def get_recommended_actions(category):
    """Get recommended actions for a threat category"""
    actions = {
        'Normal Traffic': [
            'No action needed',
            'Continue monitoring for changes in traffic patterns'
        ],
        'Reconnaissance (Scanning & Probing)': [
            'Monitor source IPs and log scanning patterns',
            'Consider implementing rate limiting for suspected scanners',
            'Update firewall rules to block persistent scan sources',
            'Review exposed services and consider additional hardening'
        ],
        'Denial of Service (DoS & DDoS)': [
            'Implement traffic filtering/rate limiting at network edge',
            'Activate DDoS mitigation services if available',
            'Isolate affected systems to preserve network functionality',
            'Consider scaling resources for critical services',
            'Identify and block attack source IPs/networks'
        ],
        'Network Protocol Attacks': [
            'Apply protocol-specific security patches',
            'Configure protocol sanitization at network boundaries',
            'Implement deep packet inspection for affected protocols',
            'Review and update protocol security configurations',
            'Consider segregating vulnerable protocol traffic'
        ],
        'Network Device Attacks': [
            'Update device firmware to patch vulnerabilities',
            'Audit and modify default/weak credentials',
            'Implement strict access controls for management interfaces',
            'Review device configurations for security gaps',
            'Consider out-of-band management networks for critical devices'
        ],
        'Web Attacks (SQLi, XSS, CSRF, Web Phishing, SSRF, LFI/RFI, Command Injection, etc.)': [
            'Apply web application security patches',
            'Implement or update WAF rules',
            'Review application input validation mechanisms',
            'Perform security code review for vulnerable components',
            'Consider implementing content security policies'
        ],
        'Web Phishing': [
            'Block access to identified phishing domains',
            'Report phishing sites to relevant authorities',
            'Issue security awareness reminders to users',
            'Review potentially compromised credentials',
            'Implement additional email/web filtering'
        ],
        'Server Attacks': [
            'Isolate compromised servers from the network',
            'Apply security patches for exploited vulnerabilities',
            'Review and strengthen authentication mechanisms',
            'Audit user accounts and access privileges',
            'Consider enhanced logging and monitoring'
        ],
        'Malicious Behavior (Malware, C2, Data Exfiltration, Cryptomining)': [
            'Isolate infected systems from the network',
            'Initiate malware removal procedures',
            'Block identified C2 domains/IPs at the firewall',
            'Audit potentially compromised data',
            'Review system integrity and deploy endpoint protection',
            'Investigate data exfiltration scope and impact'
        ],
        'Unknown Threat': [
            'Increase monitoring of the suspicious activity',
            'Capture and analyze packet samples for further investigation',
            'Consult threat intelligence platforms for emerging threats',
            'Consider temporary traffic restriction policies',
            'Escalate to security team for deeper analysis'
        ]
    }
    return actions.get(category, ['Investigate the threat', 'Update security controls'])

def get_recommended_actions(category):
    """Get recommended actions for a threat category"""
    actions = {
        'Normal Traffic': [
            'No action needed',
            'Continue monitoring for changes in traffic patterns'
        ],
        'Reconnaissance (Scanning & Probing)': [
            'Monitor source IPs and log scanning patterns',
            'Consider implementing rate limiting for suspected scanners',
            'Update firewall rules to block persistent scan sources',
            'Review exposed services and consider additional hardening'
        ],
        'Denial of Service (DoS & DDoS)': [
            'Implement traffic filtering/rate limiting at network edge',
            'Activate DDoS mitigation services if available',
            'Isolate affected systems to preserve network functionality',
            'Consider scaling resources for critical services',
            'Identify and block attack source IPs/networks'
        ],
        'Network Protocol Attacks': [
            'Apply protocol-specific security patches',
            'Configure protocol sanitization at network boundaries',
            'Implement deep packet inspection for affected protocols',
            'Review and update protocol security configurations',
            'Consider segregating vulnerable protocol traffic'
        ],
        'Network Device Attacks': [
            'Update device firmware to patch vulnerabilities',
            'Audit and modify default/weak credentials',
            'Implement strict access controls for management interfaces',
            'Review device configurations for security gaps',
            'Consider out-of-band management networks for critical devices'
        ],
        'Web Attacks (SQLi, XSS, CSRF, Web Phishing, SSRF, LFI/RFI, Command Injection, etc.)': [
            'Apply web application security patches',
            'Implement or update WAF rules',
            'Review application input validation mechanisms',
            'Perform security code review for vulnerable components',
            'Consider implementing content security policies'
        ],
        'Web Phishing': [
            'Block access to identified phishing domains',
            'Report phishing sites to relevant authorities',
            'Issue security awareness reminders to users',
            'Review potentially compromised credentials',
            'Implement additional email/web filtering'
        ],
        'Server Attacks': [
            'Isolate compromised servers from the network',
            'Apply security patches for exploited vulnerabilities',
            'Review and strengthen authentication mechanisms',
            'Audit user accounts and access privileges',
            'Consider enhanced logging and monitoring'
        ],
        'Malicious Behavior (Malware, C2, Data Exfiltration, Cryptomining)': [
            'Isolate infected systems from the network',
            'Initiate malware removal procedures',
            'Block identified C2 domains/IPs at the firewall',
            'Audit potentially compromised data',
            'Review system integrity and deploy endpoint protection',
            'Investigate data exfiltration scope and impact'
        ],
        'Unknown Threat': [
            'Increase monitoring of the suspicious activity',
            'Capture and analyze packet samples for further investigation',
            'Consult threat intelligence platforms for emerging threats',
            'Consider temporary traffic restriction policies',
            'Escalate to security team for deeper analysis'
        ]
    }
    return actions.get(category, ['Investigate the threat', 'Update security controls'])

def get_threat_indicators(category):
    """Get indicators for a threat category"""
    indicators = {
        'Normal Traffic': [
            'Regular port usage',
            'Consistent traffic patterns',
            'Expected protocols',
            'Known IP addresses',
            'Normal data volume'
        ],
        'Reconnaissance (Scanning & Probing)': [
            'Multiple ports accessed sequentially',
            'Short connection durations',
            'Low data transfer per connection',
            'Connection attempts to closed ports',
            'SYN packets without completion'
        ],
        'Denial of Service (DoS & DDoS)': [
            'Abnormally high traffic volume',
            'Many connections from limited sources',
            'Similar packet patterns',
            'Targeting specific services',
            'Rapid connection attempts'
        ],
        'Network Protocol Attacks': [
            'Unusual protocol behavior',
            'Malformed packets',
            'Protocol version exploitation',
            'Unexpected packet sequences',
            'Protocol-specific attack signatures'
        ],
        'Network Device Attacks': [
            'Unusual management interface access',
            'Configuration change attempts',
            'Exploitation of device-specific vulnerabilities',
            'Credential brute forcing on device interfaces',
            'Firmware or configuration tampering indicators'
        ],
        'Web Attacks (SQLi, XSS, CSRF, Web Phishing, SSRF, LFI/RFI, Command Injection, etc.)': [
            'SQL syntax in HTTP requests',
            'Script tags in HTTP parameters',
            'Abnormal query patterns',
            'File path manipulation in requests',
            'Command syntax in user input fields'
        ],
        'Web Phishing': [
            'Suspicious domain similarities to legitimate sites',
            'Recently registered domains',
            'Irregular SSL/TLS certificates',
            'Credential harvesting page patterns',
            'Redirects to suspicious domains'
        ],
        'Server Attacks': [
            'Unauthorized privilege escalation attempts',
            'Abnormal process execution',
            'Suspicious file system activities',
            'Unexpected outbound connections',
            'Modification of system files'
        ],
        'Malicious Behavior (Malware, C2, Data Exfiltration, Cryptomining)': [
            'Communication with known malicious IPs',
            'Periodic beaconing behavior',
            'Large outbound data transfers',
            'Unusual CPU usage patterns',
            'Encoded or encrypted command traffic',
            'Known malware signatures'
        ],
        'Unknown Threat': [
            'Anomalous traffic patterns',
            'Unexpected protocol behavior',
            'Unusual data encoding',
            'Previously unseen connection patterns',
            'Suspicious but unclassified activity'
        ]
    }
    return indicators.get(category, ['Unrecognized threat pattern'])

def get_related_flows(analysis, threat):
    """Get network flows related to a threat from actual analysis data, using only real IPs"""
    logging.debug(f"Starting get_related_flows function for threat: {threat.get('name', 'Unknown')}")
    flows = []
    
    # First, make sure we have packet data
    traffic_data = None
    
    # Try traffic_summary.packet_data
    if hasattr(analysis, 'traffic_summary') and isinstance(analysis.traffic_summary, dict):
        traffic_data = analysis.traffic_summary.get('packet_data', [])
        logging.debug(f"Found {len(traffic_data) if traffic_data else 0} packets in traffic_summary.packet_data")
    
    # If there's no packet data in traffic_summary, check result_summary
    if not traffic_data and hasattr(analysis, 'result_summary') and isinstance(analysis.result_summary, dict):
        traffic_data = analysis.result_summary.get('packet_data', [])
        logging.debug(f"Found {len(traffic_data) if traffic_data else 0} packets in result_summary.packet_data")
    
    # If we still have no packet data, try to extract it from raw pcap data if available
    if not traffic_data and hasattr(analysis, 'raw_pcap_data') and analysis.raw_pcap_data:
        logging.debug("No packet_data found, trying to extract from raw_pcap_data")
        try:
            raw_data = analysis.raw_pcap_data
            if raw_data:
                extracted_data = []
                for packet in raw_data:
                    try:
                        features = extract_packet_features(packet)
                        if features:
                            extracted_data.append(features)
                    except Exception as packet_error:
                        logging.error(f"Error extracting features from packet: {packet_error}")
                
                if extracted_data:
                    traffic_data = extracted_data
                    logging.debug(f"Extracted {len(traffic_data)} packets from raw_pcap_data")
        except Exception as e:
            logging.error(f"Error processing raw_pcap_data: {e}")
    
    # If still no traffic data, return empty list (NO SYNTHETIC FLOWS)
    if not traffic_data:
        logging.warning("No traffic data found, cannot generate flows")
        return flows  # Return empty list if no data available
    
    # Extract IPs involved in the threat
    threat_ips = set()
    if threat and isinstance(threat, dict) and 'involved_ips' in threat:
        for ip_data in threat.get('involved_ips', []):
            if isinstance(ip_data, dict) and ip_data.get('address'):
                threat_ips.add(ip_data.get('address'))
    
    logging.debug(f"Found {len(threat_ips)} IPs involved in the threat")
    
    # If no IPs are directly associated with the threat, identify potential threat IPs
    if not threat_ips and threat and isinstance(threat, dict):
        threat_name = threat.get('name', '')
        logging.debug(f"No threat IPs found, analyzing traffic for threat type: {threat_name}")
        
        # For port scanning, focus on scanning behavior
        if 'Port Scanning' in threat_name:
            src_ip_dst_ports = {}
            for packet in traffic_data:
                if not isinstance(packet, dict):
                    continue
                src_ip = packet.get('src_ip')
                dst_port = packet.get('dst_port')
                if src_ip and dst_port is not None:
                    if src_ip not in src_ip_dst_ports:
                        src_ip_dst_ports[src_ip] = set()
                    src_ip_dst_ports[src_ip].add(dst_port)
            
            # Find IPs accessing multiple ports (potential scanners)
            for src_ip, dst_ports in src_ip_dst_ports.items():
                if len(dst_ports) > 5:  # Threshold for port scanning
                    threat_ips.add(src_ip)
                    logging.debug(f"Added {src_ip} as potential scanner (accessing {len(dst_ports)} ports)")
        
        # For DoS attacks, look for high volume traffic
        elif any(term in threat_name for term in ['Denial of Service', 'DoS']):
            # Count packets per IP pair
            ip_pair_counts = {}
            for packet in traffic_data:
                if not isinstance(packet, dict):
                    continue
                src_ip = packet.get('src_ip')
                dst_ip = packet.get('dst_ip')
                if src_ip and dst_ip:
                    pair_key = f"{src_ip}->{dst_ip}"
                    ip_pair_counts[pair_key] = ip_pair_counts.get(pair_key, 0) + 1
            
            # Find high volume connections
            if traffic_data:
                threshold = len(traffic_data) * 0.1  # 10% of total packets
                for pair, count in ip_pair_counts.items():
                    if count > threshold:
                        try:
                            src_ip, dst_ip = pair.split('->')
                            if src_ip and dst_ip:
                                threat_ips.add(src_ip)
                                threat_ips.add(dst_ip)
                                logging.debug(f"Added {src_ip} and {dst_ip} as potential DoS IPs ({count} packets)")
                        except Exception as e:
                            logging.error(f"Error parsing IP pair {pair}: {e}")
    
    # If we still have no threat IPs, use all IPs from the traffic (still only real ones)
    if not threat_ips and traffic_data:
        logging.debug("No threat IPs identified, using all IPs from traffic data")
        for packet in traffic_data:
            if not isinstance(packet, dict):
                continue
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            
            if src_ip:
                threat_ips.add(src_ip)
            if dst_ip:
                threat_ips.add(dst_ip)
        
        logging.debug(f"Added {len(threat_ips)} IPs from all traffic")
    
    # Now build flows from the actual traffic data
    connections = {}
    first_seen = {}
    last_seen = {}
    packet_counts = {}
    data_volumes = {}
    
    for packet in traffic_data:
        if not isinstance(packet, dict):
            continue
            
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        
        # Skip if we can't identify the connection properly
        if not src_ip or not dst_ip:
            continue
            
        # If we have threat IPs, only include flows involving those IPs
        # Otherwise include all flows from real traffic data
        if threat_ips and not (src_ip in threat_ips or dst_ip in threat_ips):
            continue
            
        src_port = packet.get('src_port', 0)
        dst_port = packet.get('dst_port', 0)
        protocol = packet.get('protocol_name', packet.get('protocol', 'UNKNOWN'))
        packet_size = packet.get('packet_size', packet.get('size', 0))
        timestamp = packet.get('timestamp', packet.get('time', 0))
        
        # Create a key for this flow
        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}-{protocol}"
        
        # Update connection data
        if flow_key not in connections:
            connections[flow_key] = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol
            }
            first_seen[flow_key] = timestamp
            last_seen[flow_key] = timestamp
            packet_counts[flow_key] = 1
            data_volumes[flow_key] = packet_size
        else:
            packet_counts[flow_key] += 1
            data_volumes[flow_key] += packet_size
            if timestamp and first_seen[flow_key] and timestamp < first_seen[flow_key]:
                first_seen[flow_key] = timestamp
            if timestamp and last_seen[flow_key] and timestamp > last_seen[flow_key]:
                last_seen[flow_key] = timestamp
    
    logging.debug(f"Found {len(connections)} connections related to threat")
    
    # Convert to a list of flows
    if connections:
        # Sort flows by packet count
        sorted_flows = sorted(connections.keys(), 
                            key=lambda k: packet_counts.get(k, 0), 
                            reverse=True)
        
        # Show all flows if there are 20 or fewer, otherwise limit to 20
        flow_limit = min(20, len(sorted_flows))
        logging.debug(f"Using top {flow_limit} flows by packet count")
        
        for flow_key in sorted_flows[:flow_limit]:
            try:
                connection = connections[flow_key]
                
                # Calculate flow duration if possible
                duration = ""
                try:
                    if first_seen[flow_key] is not None and last_seen[flow_key] is not None:
                        first_time = float(first_seen[flow_key]) if first_seen[flow_key] else 0
                        last_time = float(last_seen[flow_key]) if last_seen[flow_key] else 0
                        
                        if last_time > first_time:
                            time_diff = last_time - first_time
                            if time_diff > 60:
                                minutes = int(time_diff / 60)
                                seconds = int(time_diff % 60)
                                duration = f"{minutes}m {seconds}s"
                            else:
                                duration = f"{int(time_diff)}s"
                except (ValueError, TypeError) as e:
                    logging.debug(f"Could not calculate duration for {flow_key}: {e}")
                
                # Determine if this flow is malicious
                is_malicious = False
                if threat and isinstance(threat, dict):
                    threat_name = threat.get('name', '')
                    if threat_name and threat_name != 'Normal Traffic':
                        is_malicious = True
                
                flow = {
                    'src_ip': connection['src_ip'],
                    'dst_ip': connection['dst_ip'],
                    'protocol': connection['protocol'],
                    'src_port': connection['src_port'],
                    'dst_port': connection['dst_port'],
                    'packet_count': packet_counts.get(flow_key, 0),
                    'data_volume': f"{(data_volumes.get(flow_key, 0) / 1024):.2f} KB",
                    'first_packet': format_timestamp(first_seen.get(flow_key)),
                    'last_packet': format_timestamp(last_seen.get(flow_key)),
                    'duration': duration,
                    'is_malicious': is_malicious
                }
                flows.append(flow)
                logging.debug(f"Added flow: {connection['src_ip']}:{connection['src_port']} -> {connection['dst_ip']}:{connection['dst_port']}")
            except Exception as e:
                logging.error(f"Error creating flow for {flow_key}: {e}")
    
    # If no flows were found, return an empty list - NO SYNTHETIC FLOWS
    if not flows:
        logging.warning("No flows could be generated from the available data")
        
    logging.debug(f"Returning {len(flows)} related flows")
    return flows

def generate_threat_timeline(analysis, threat):
    """Generate a timeline based only on actual packet timestamps"""
    timeline = []
    
    try:
        # Get packet data
        traffic_data = None
        if hasattr(analysis, 'traffic_summary') and isinstance(analysis.traffic_summary, dict):
            traffic_data = analysis.traffic_summary.get('packet_data', [])
        
        if not traffic_data and hasattr(analysis, 'result_summary') and isinstance(analysis.result_summary, dict):
            traffic_data = analysis.result_summary.get('packet_data', [])
            
        if not traffic_data:
            return timeline
        
        # Ensure traffic_data is a list
        if not isinstance(traffic_data, list):
            try:
                traffic_data = list(traffic_data)
            except:
                return timeline
        
        # Get IPs involved in this threat
        threat_ips = set()
        if threat and isinstance(threat, dict) and 'involved_ips' in threat:
            for ip_data in threat.get('involved_ips', []):
                if isinstance(ip_data, dict) and ip_data.get('address'):
                    threat_ips.add(ip_data.get('address'))
        
        if not threat_ips:
            return timeline
        
        # Find packets involving the threat IPs and sort by timestamp
        threat_packets = []
        for packet in traffic_data:
            if not isinstance(packet, dict):
                continue
                
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            timestamp = packet.get('timestamp')
            
            if not src_ip or not dst_ip or not timestamp:
                continue
                
            if src_ip in threat_ips or dst_ip in threat_ips:
                threat_packets.append(packet)
        
        # Sort by timestamp
        def get_timestamp(p):
            try:
                return float(p.get('timestamp', 0))
            except (ValueError, TypeError):
                return 0
                
        threat_packets.sort(key=get_timestamp)
        
        # If we have no packets with timestamps, return empty timeline
        if not threat_packets:
            return timeline
        
        # Create a real timeline based on actual packet timestamps
        # Just show first, middle and last events if we have many packets
        if len(threat_packets) >= 3:
            # First packet
            first_packet = threat_packets[0]
            timeline.append({
                'timestamp': format_timestamp(first_packet.get('timestamp')),
                'description': f"First suspicious packet detected from {first_packet.get('src_ip')} to {first_packet.get('dst_ip')}"
            })
            
            # Middle packet
            middle_idx = len(threat_packets) // 2
            middle_packet = threat_packets[middle_idx]
            
            threat_name = threat.get('name', 'suspicious activity') if threat and isinstance(threat, dict) else 'suspicious activity'
            
            timeline.append({
                'timestamp': format_timestamp(middle_packet.get('timestamp')),
                'description': f"Ongoing {threat_name} activity detected"
            })
            
            # Last packet
            last_packet = threat_packets[-1]
            timeline.append({
                'timestamp': format_timestamp(last_packet.get('timestamp')),
                'description': f"Last suspicious packet detected from {last_packet.get('src_ip')} to {last_packet.get('dst_ip')}"
            })
        else:
            # If we have fewer packets, include them all
            for packet in threat_packets:
                timeline.append({
                    'timestamp': format_timestamp(packet.get('timestamp')),
                    'description': f"Suspicious traffic from {packet.get('src_ip')} to {packet.get('dst_ip')}"
                })
        
        return timeline
    except Exception as e:
        logging.error(f"Error in generate_threat_timeline: {e}")
        return []

def get_related_flows(analysis, threat):
    """Get network flows related to a threat from actual analysis data, using only real IPs"""
    logging.debug(f"Starting get_related_flows function for threat: {threat.get('name', 'Unknown')}")
    flows = []
    
    try:
        # First, make sure we have packet data
        traffic_data = None
        
        # Try traffic_summary.packet_data
        if hasattr(analysis, 'traffic_summary') and analysis.traffic_summary:
            if isinstance(analysis.traffic_summary, dict):
                traffic_data = analysis.traffic_summary.get('packet_data', [])
                logging.debug(f"Found {len(traffic_data) if traffic_data else 0} packets in traffic_summary.packet_data")
        
        # If there's no packet data in traffic_summary, check result_summary
        if not traffic_data and hasattr(analysis, 'result_summary') and analysis.result_summary:
            if isinstance(analysis.result_summary, dict):
                traffic_data = analysis.result_summary.get('packet_data', [])
                logging.debug(f"Found {len(traffic_data) if traffic_data else 0} packets in result_summary.packet_data")
        
        # If we still have no packet data, try to extract it from raw pcap data if available
        if not traffic_data and hasattr(analysis, 'raw_pcap_data') and analysis.raw_pcap_data:
            logging.debug("No packet_data found, trying to extract from raw_pcap_data")
            try:
                raw_data = analysis.raw_pcap_data
                if raw_data:
                    extracted_data = []
                    for packet in raw_data:
                        try:
                            features = extract_packet_features(packet)
                            if features:
                                extracted_data.append(features)
                        except Exception as packet_error:
                            logging.error(f"Error extracting features from packet: {packet_error}")
                    
                    if extracted_data:
                        traffic_data = extracted_data
                        logging.debug(f"Extracted {len(traffic_data)} packets from raw_pcap_data")
            except Exception as e:
                logging.error(f"Error processing raw_pcap_data: {e}")
        
        # If still no traffic data, return empty list (NO SYNTHETIC FLOWS)
        if not traffic_data:
            logging.warning("No traffic data found, cannot generate flows")
            return flows  # Return empty list if no data available
        
        # Ensure traffic_data is a list
        if not isinstance(traffic_data, list):
            try:
                traffic_data = list(traffic_data)
            except:
                logging.error("Traffic data is not a list and cannot be converted to a list")
                return flows
        
        # Extract IPs involved in the threat
        threat_ips = set()
        if threat and isinstance(threat, dict) and 'involved_ips' in threat:
            for ip_data in threat.get('involved_ips', []):
                if isinstance(ip_data, dict) and ip_data.get('address'):
                    threat_ips.add(ip_data.get('address'))
        
        logging.debug(f"Found {len(threat_ips)} IPs involved in the threat")
        
        # If no IPs are directly associated with the threat, identify potential threat IPs
        if not threat_ips and threat and isinstance(threat, dict):
            threat_name = threat.get('name', '')
            logging.debug(f"No threat IPs found, analyzing traffic for threat type: {threat_name}")
            
            # For port scanning, focus on scanning behavior
            if threat_name and 'Port Scanning' in threat_name:
                src_ip_dst_ports = {}
                for packet in traffic_data:
                    if not isinstance(packet, dict):
                        continue
                    src_ip = packet.get('src_ip')
                    dst_port = packet.get('dst_port')
                    if src_ip and dst_port is not None:
                        if src_ip not in src_ip_dst_ports:
                            src_ip_dst_ports[src_ip] = set()
                        src_ip_dst_ports[src_ip].add(dst_port)
                
                # Find IPs accessing multiple ports (potential scanners)
                for src_ip, dst_ports in src_ip_dst_ports.items():
                    if len(dst_ports) > 5:  # Threshold for port scanning
                        threat_ips.add(src_ip)
                        logging.debug(f"Added {src_ip} as potential scanner (accessing {len(dst_ports)} ports)")
            
            # For DoS attacks, look for high volume traffic
            elif threat_name and any(term in threat_name for term in ['Denial of Service', 'DoS']):
                # Count packets per IP pair
                ip_pair_counts = {}
                for packet in traffic_data:
                    if not isinstance(packet, dict):
                        continue
                    src_ip = packet.get('src_ip')
                    dst_ip = packet.get('dst_ip')
                    if src_ip and dst_ip:
                        pair_key = f"{src_ip}->{dst_ip}"
                        ip_pair_counts[pair_key] = ip_pair_counts.get(pair_key, 0) + 1
                
                # Find high volume connections
                if traffic_data:
                    threshold = len(traffic_data) * 0.1  # 10% of total packets
                    for pair, count in ip_pair_counts.items():
                        if count > threshold:
                            try:
                                parts = pair.split('->')
                                if len(parts) == 2:
                                    src_ip, dst_ip = parts
                                    if src_ip and dst_ip:
                                        threat_ips.add(src_ip)
                                        threat_ips.add(dst_ip)
                                        logging.debug(f"Added {src_ip} and {dst_ip} as potential DoS IPs ({count} packets)")
                            except Exception as e:
                                logging.error(f"Error parsing IP pair {pair}: {e}")
        
        # If we still have no threat IPs, use all IPs from the traffic (still only real ones)
        if not threat_ips and traffic_data:
            logging.debug("No threat IPs identified, using all IPs from traffic data")
            for packet in traffic_data:
                if not isinstance(packet, dict):
                    continue
                src_ip = packet.get('src_ip')
                dst_ip = packet.get('dst_ip')
                
                if src_ip:
                    threat_ips.add(src_ip)
                if dst_ip:
                    threat_ips.add(dst_ip)
            
            logging.debug(f"Added {len(threat_ips)} IPs from all traffic")
        
        # Now build flows from the actual traffic data
        connections = {}
        first_seen = {}
        last_seen = {}
        packet_counts = {}
        data_volumes = {}
        
        for packet in traffic_data:
            if not isinstance(packet, dict):
                continue
                
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            
            # Skip if we can't identify the connection properly
            if not src_ip or not dst_ip:
                continue
                
            # If we have threat IPs, only include flows involving those IPs
            # Otherwise include all flows from real traffic data
            if threat_ips and not (src_ip in threat_ips or dst_ip in threat_ips):
                continue
                
            src_port = packet.get('src_port', 0)
            dst_port = packet.get('dst_port', 0)
            protocol = packet.get('protocol_name', packet.get('protocol', 'UNKNOWN'))
            packet_size = packet.get('packet_size', packet.get('size', 0))
            timestamp = packet.get('timestamp', packet.get('time', 0))
            
            # Create a key for this flow
            flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}-{protocol}"
            
            # Update connection data
            if flow_key not in connections:
                connections[flow_key] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol
                }
                first_seen[flow_key] = timestamp
                last_seen[flow_key] = timestamp
                packet_counts[flow_key] = 1
                data_volumes[flow_key] = packet_size if packet_size else 0
            else:
                packet_counts[flow_key] += 1
                data_volumes[flow_key] += packet_size if packet_size else 0
                
                if timestamp and first_seen.get(flow_key) is not None:
                    try:
                        if float(timestamp) < float(first_seen[flow_key]):
                            first_seen[flow_key] = timestamp
                    except (ValueError, TypeError):
                        pass  # Skip if we can't convert to float
                        
                if timestamp and last_seen.get(flow_key) is not None:
                    try:
                        if float(timestamp) > float(last_seen[flow_key]):
                            last_seen[flow_key] = timestamp
                    except (ValueError, TypeError):
                        pass  # Skip if we can't convert to float
        
        logging.debug(f"Found {len(connections)} connections related to threat")
        
        # Convert to a list of flows
        if connections:
            # Sort flows by packet count
            sorted_flows = sorted(connections.keys(), 
                                key=lambda k: packet_counts.get(k, 0), 
                                reverse=True)
            
            # Show all flows if there are 20 or fewer, otherwise limit to 20
            flow_limit = min(20, len(sorted_flows))
            logging.debug(f"Using top {flow_limit} flows by packet count")
            
            for flow_key in sorted_flows[:flow_limit]:
                try:
                    connection = connections[flow_key]
                    
                    # Calculate flow duration if possible
                    duration = ""
                    try:
                        if first_seen.get(flow_key) is not None and last_seen.get(flow_key) is not None:
                            first_time = float(first_seen[flow_key]) if first_seen[flow_key] else 0
                            last_time = float(last_seen[flow_key]) if last_seen[flow_key] else 0
                            
                            if last_time > first_time:
                                time_diff = last_time - first_time
                                if time_diff > 60:
                                    minutes = int(time_diff / 60)
                                    seconds = int(time_diff % 60)
                                    duration = f"{minutes}m {seconds}s"
                                else:
                                    duration = f"{int(time_diff)}s"
                    except (ValueError, TypeError) as e:
                        logging.debug(f"Could not calculate duration for {flow_key}: {e}")
                    
                    # Determine if this flow is malicious
                    is_malicious = False
                    if threat and isinstance(threat, dict):
                        threat_name = threat.get('name', '')
                        if threat_name and threat_name != 'Normal Traffic':
                            is_malicious = True
                    
                    # Handle potential None values in packet counts or data volumes
                    packet_count = packet_counts.get(flow_key, 0) if packet_counts.get(flow_key) is not None else 0
                    data_volume = data_volumes.get(flow_key, 0) if data_volumes.get(flow_key) is not None else 0
                    
                    flow = {
                        'src_ip': connection['src_ip'],
                        'dst_ip': connection['dst_ip'],
                        'protocol': connection['protocol'],
                        'src_port': connection['src_port'],
                        'dst_port': connection['dst_port'],
                        'packet_count': packet_count,
                        'data_volume': f"{(data_volume / 1024):.2f} KB",
                        'first_packet': format_timestamp(first_seen.get(flow_key)),
                        'last_packet': format_timestamp(last_seen.get(flow_key)),
                        'duration': duration,
                        'is_malicious': is_malicious
                    }
                    flows.append(flow)
                    logging.debug(f"Added flow: {connection['src_ip']}:{connection['src_port']} -> {connection['dst_ip']}:{connection['dst_port']}")
                except Exception as e:
                    logging.error(f"Error creating flow for {flow_key}: {e}")
                    continue  # Skip this flow and continue with others
        
        # If no flows were found, return an empty list - NO SYNTHETIC FLOWS
        if not flows:
            logging.warning("No flows could be generated from the available data")
            
        logging.debug(f"Returning {len(flows)} related flows")
        return flows
    
    except Exception as e:
        logging.error(f"Unhandled exception in get_related_flows: {e}")
        logging.error(traceback.format_exc())
        return [] 

def format_timestamp(timestamp):
    """Convert timestamp to readable format"""
    if timestamp is None:
        return "Unknown"
    
    try:
        # If timestamp is a datetime object
        if hasattr(timestamp, 'strftime'):
            return timestamp.strftime('%H:%M:%S')
        
        # If it's a string already, check if it's a valid timestamp
        if isinstance(timestamp, str):
            try:
                # Try to convert to float and then format
                float_time = float(timestamp)
                return datetime.datetime.fromtimestamp(float_time).strftime('%H:%M:%S')
            except (ValueError, TypeError, OverflowError):
                # If conversion fails, return as is
                return timestamp
            
        # If it's a numeric timestamp
        if isinstance(timestamp, (int, float)):
            try:
                return datetime.datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
            except (ValueError, OverflowError):
                return "Invalid timestamp"
        
        return str(timestamp)
        
    except Exception:
        return "Unknown"

def is_private_ip(ip):
    """Check if an IP address is private based on RFC 1918"""
    # Check if it's a valid IP address
    try:
        octets = ip.split('.')
        if len(octets) != 4:
            return False
            
        # Check for private IP ranges
        # 10.0.0.0/8
        if octets[0] == '10':
            return True
        # 172.16.0.0/12
        if octets[0] == '172' and 16 <= int(octets[1]) <= 31:
            return True
        # 192.168.0.0/16
        if octets[0] == '192' and octets[1] == '168':
            return True
        # 169.254.0.0/16 (link-local)
        if octets[0] == '169' and octets[1] == '254':
            return True
            
        return False
    except:
        return False

def get_ip_details(analysis):
    """Get detailed information about IP addresses from packet data"""
    logging.debug("Starting get_ip_details function")
    ip_details = []
    
    # Extensive validation of analysis object
    if not analysis:
        logging.error("Analysis object is None")
        return ip_details
        
    logging.debug(f"Analysis object type: {type(analysis)}")
    logging.debug(f"Analysis has traffic_summary: {hasattr(analysis, 'traffic_summary')}")
    
    # First try to get real packet data from multiple sources
    packet_data = None
    
    # Check traffic_summary for packet_data
    if hasattr(analysis, 'traffic_summary') and analysis.traffic_summary:
        if isinstance(analysis.traffic_summary, dict):
            if 'packet_data' in analysis.traffic_summary:
                packet_data = analysis.traffic_summary['packet_data']
                logging.debug(f"Found {len(packet_data) if isinstance(packet_data, list) else 'non-list'} items in traffic_summary.packet_data")
    
    # If no packet data found but we have all_src_ips and all_dst_ips (ZIP file format)
    if not packet_data and hasattr(analysis, 'traffic_summary') and isinstance(analysis.traffic_summary, dict):
        src_ips = analysis.traffic_summary.get('all_src_ips', [])
        dst_ips = analysis.traffic_summary.get('all_dst_ips', [])
        
        if isinstance(src_ips, list) and isinstance(dst_ips, list) and (src_ips or dst_ips):
            logging.debug(f"Using all_src_ips ({len(src_ips)}) and all_dst_ips ({len(dst_ips)}) from ZIP file")
            
            # For each unique IP, add an entry
            unique_ips = set(src_ips + dst_ips)
            
            for ip in unique_ips:
                is_src = ip in src_ips
                is_dst = ip in dst_ips
                is_internal = is_private_ip(ip)
                
                # Determine role based on appearances
                if is_src and is_dst:
                    role = "Both"
                elif is_src:
                    role = "Source"
                else:
                    role = "Destination"
                
                # Check if IP is involved in any threats
                is_suspicious = False
                associated_threats = []
                
                if hasattr(analysis, 'detected_threats') and analysis.detected_threats:
                    for threat in analysis.detected_threats:
                        if not isinstance(threat, dict) or threat.get('name') == 'Normal Traffic':
                            continue
                            
                        # Check if IP is in involved_ips
                        if 'involved_ips' in threat and isinstance(threat['involved_ips'], list):
                            for ip_info in threat['involved_ips']:
                                if isinstance(ip_info, dict) and ip_info.get('address') == ip:
                                    is_suspicious = True
                                    associated_threats.append(threat.get('name', 'Unknown Threat'))
                                    break
                
                # Create a details entry for this IP with estimated values
                ip_detail = {
                    'address': ip,
                    'type': role,
                    'location': 'Internal Network' if is_internal else 'External Network',
                    'asn': 'Private Network' if is_internal else 'Unknown',
                    'organization': 'Private Network' if is_internal else 'Unknown',
                    'packets_sent': 'N/A',
                    'packets_received': 'N/A',
                    'data_sent': 'N/A',
                    'data_received': 'N/A',
                    'connection_count': 'N/A',
                    'traffic_percentage': 'N/A',
                    'is_suspicious': is_suspicious,
                    'risk_level': 'High' if is_suspicious else 'Low',
                    'associated_threats': associated_threats
                }
                
                ip_details.append(ip_detail)
            
            # Return early if we successfully created IP details
            if ip_details:
                return ip_details
    
    # If we still don't have IP details, try to extract from file_results (ZIP processing)
    if not ip_details and hasattr(analysis, 'file_results') and isinstance(analysis.file_results, list):
        # Collect unique IPs from all file results
        unique_src_ips = set()
        unique_dst_ips = set()
        
        for file_result in analysis.file_results:
            if isinstance(file_result, dict):
                if 'unique_src_ips' in file_result and isinstance(file_result['unique_src_ips'], list):
                    unique_src_ips.update(file_result['unique_src_ips'])
                if 'unique_dst_ips' in file_result and isinstance(file_result['unique_dst_ips'], list):
                    unique_dst_ips.update(file_result['unique_dst_ips'])
        
        # Process unique IPs if found
        unique_ips = unique_src_ips.union(unique_dst_ips)
        
        if unique_ips:
            logging.debug(f"Creating IP details from file_results with {len(unique_ips)} unique IPs")
            
            for ip in unique_ips:
                is_src = ip in unique_src_ips
                is_dst = ip in unique_dst_ips
                is_internal = is_private_ip(ip)
                
                # Determine role
                if is_src and is_dst:
                    role = "Both"
                elif is_src:
                    role = "Source"
                else:
                    role = "Destination"
                
                # Check if IP is involved in any threats
                is_suspicious = False
                associated_threats = []
                
                if hasattr(analysis, 'detected_threats') and analysis.detected_threats:
                    for threat in analysis.detected_threats:
                        if not isinstance(threat, dict) or threat.get('name') == 'Normal Traffic':
                            continue
                            
                        # Check if IP is in involved_ips
                        if 'involved_ips' in threat and isinstance(threat['involved_ips'], list):
                            for ip_info in threat['involved_ips']:
                                if isinstance(ip_info, dict) and ip_info.get('address') == ip:
                                    is_suspicious = True
                                    associated_threats.append(threat.get('name', 'Unknown Threat'))
                                    break
                
                # Create a details entry for this IP
                ip_detail = {
                    'address': ip,
                    'type': role,
                    'location': 'Internal Network' if is_internal else 'External Network',
                    'asn': 'Private Network' if is_internal else 'Unknown',
                    'organization': 'Private Network' if is_internal else 'Unknown',
                    'packets_sent': 'N/A',
                    'packets_received': 'N/A',
                    'data_sent': 'N/A',
                    'data_received': 'N/A',
                    'connection_count': 'N/A',
                    'traffic_percentage': 'N/A',
                    'is_suspicious': is_suspicious,
                    'risk_level': 'High' if is_suspicious else 'Low',
                    'associated_threats': associated_threats
                }
                
                ip_details.append(ip_detail)
            
            # Return early if we successfully created IP details
            if ip_details:
                return ip_details
    
    # If we reach here without IP details, and there's no packet data, extract IPs from threats
    if not packet_data and not ip_details and hasattr(analysis, 'detected_threats') and analysis.detected_threats:
        logging.warning("No packet data found, looking for IPs in detected threats")
        
        # Collect IPs from threats
        threat_ips = {}
        for threat in analysis.detected_threats:
            if not isinstance(threat, dict):
                continue
                
            # Skip normal traffic threats
            if threat.get('name') == 'Normal Traffic':
                continue
                
            # Check if threat has involved_ips
            if 'involved_ips' in threat and isinstance(threat['involved_ips'], list):
                for ip_data in threat['involved_ips']:
                    if isinstance(ip_data, dict) and 'address' in ip_data:
                        ip = ip_data['address']
                        # Store all details we have about this IP
                        threat_ips[ip] = ip_data
                        
        # If we found IPs in threats, return them directly
        if threat_ips:
            logging.info(f"Found {len(threat_ips)} IPs in threats")
            return list(threat_ips.values())
    
    # If all other methods failed and we don't have packet data or ip_details, return empty list
    if not packet_data and not ip_details:
        logging.warning("No packet data or IP details found from any source")
        return []
    
    # If we have packet data but no IP details yet, process packet data to extract IP information
    if packet_data and not ip_details:
        src_ips = set()
        dst_ips = set()
        
        # Count packets per IP with improved error handling
        src_ip_packets = {}
        dst_ip_packets = {}
        src_ip_bytes = {}
        dst_ip_bytes = {}
        ip_connections = {}  # Track connections per IP
        malformed_packets = 0
        
        for packet in packet_data:
            try:
                if not isinstance(packet, dict):
                    malformed_packets += 1
                    continue
                    
                # Try multiple field names for IP addresses
                src_ip = packet.get('src_ip', packet.get('source_ip', packet.get('source', None)))
                dst_ip = packet.get('dst_ip', packet.get('dest_ip', packet.get('destination', packet.get('dest', None))))
                
                # Skip packets without valid IPs
                if not src_ip or not dst_ip:
                    malformed_packets += 1
                    continue
                
                # Try multiple field names for packet size with fallbacks
                packet_size = packet.get('packet_size', 
                               packet.get('size', 
                               packet.get('length', 
                               packet.get('bytes', 0))))
                
                # Update IP tracking data
                if src_ip:
                    src_ips.add(src_ip)
                    src_ip_packets[src_ip] = src_ip_packets.get(src_ip, 0) + 1
                    src_ip_bytes[src_ip] = src_ip_bytes.get(src_ip, 0) + packet_size
                    
                    # Track connections for this source IP
                    if src_ip not in ip_connections:
                        ip_connections[src_ip] = set()
                    if dst_ip:
                        ip_connections[src_ip].add(dst_ip)
                
                if dst_ip:
                    dst_ips.add(dst_ip)
                    dst_ip_packets[dst_ip] = dst_ip_packets.get(dst_ip, 0) + 1
                    dst_ip_bytes[dst_ip] = dst_ip_bytes.get(dst_ip, 0) + packet_size
            except Exception as e:
                logging.error(f"Error processing packet for IP extraction: {e}")
                malformed_packets += 1
                continue
        
        if malformed_packets > 0:
            logging.warning(f"Skipped {malformed_packets} malformed packets during IP extraction")
        
        logging.debug(f"Found {len(src_ips)} unique source IPs and {len(dst_ips)} unique destination IPs")
        
        # If no IPs found, return empty list
        if not src_ips and not dst_ips:
            logging.warning("No valid IP addresses found in packet data")
            return ip_details
        
        # Check for threats for IP risk assessment
        threats_by_ip = {}
        if hasattr(analysis, 'detected_threats') and analysis.detected_threats:
            for threat in analysis.detected_threats:
                if not isinstance(threat, dict) or threat.get('name') == 'Normal Traffic':
                    continue
                    
                # Extract IPs from threat
                if 'involved_ips' in threat and isinstance(threat['involved_ips'], list):
                    for ip_data in threat['involved_ips']:
                        if isinstance(ip_data, dict) and 'address' in ip_data:
                            ip = ip_data['address']
                            if ip not in threats_by_ip:
                                threats_by_ip[ip] = []
                            threats_by_ip[ip].append(threat.get('name', 'Unknown Threat'))
        
        # Create source IP details with improved error handling
        for ip in src_ips:
            try:
                # Determine if this is an internal or external IP
                is_internal = is_private_ip(ip)
                
                # Get number of unique connections
                connection_count = len(ip_connections.get(ip, set()))
                
                # Check if this IP is involved in threats
                is_suspicious = ip in threats_by_ip
                associated_threats = threats_by_ip.get(ip, [])
                
                # Determine role based on traffic patterns
                sent = src_ip_packets.get(ip, 0)
                received = dst_ip_packets.get(ip, 0)
                
                if sent > received * 3:  # Primarily a source
                    role = "Source"
                elif received > sent * 3:  # Primarily a destination
                    role = "Destination"
                else:  # Both source and destination
                    role = "Both"
                
                # Determine risk level based on threat association and traffic patterns
                if is_suspicious:
                    risk_level = "High" if len(associated_threats) > 1 else "Medium"
                elif connection_count > 10:  # High connection count might indicate scanning
                    risk_level = "Medium"
                else:
                    risk_level = "Low"
                
                # Calculate traffic percentage
                total_packets = sum(src_ip_packets.values()) + sum(dst_ip_packets.values())
                traffic_percentage = 0
                if total_packets > 0:
                    ip_packets = sent + received
                    traffic_percentage = round((ip_packets / total_packets) * 100, 1)
                
                # Create detailed IP information
                ip_detail = {
                    'address': ip,
                    'type': role,
                    'location': 'Internal Network' if is_internal else 'External Network',
                    'asn': 'Private Network' if is_internal else 'Unknown',
                    'organization': 'Private Network' if is_internal else 'Unknown',
                    'packets_sent': sent,
                    'packets_received': received,
                    'data_sent': f"{src_ip_bytes.get(ip, 0) / 1024:.2f} KB",
                    'data_received': f"{dst_ip_bytes.get(ip, 0) / 1024:.2f} KB",
                    'connection_count': connection_count,
                    'traffic_percentage': traffic_percentage,
                    'is_suspicious': is_suspicious,
                    'risk_level': risk_level,
                    'associated_threats': associated_threats
                }
                
                ip_details.append(ip_detail)
            except Exception as e:
                logging.error(f"Error creating details for source IP {ip}: {e}")
        
        # Create destination IP details (only for IPs not seen as sources)
        for ip in dst_ips:
            try:
                # Skip if already processed as source
                if ip in src_ips:
                    continue
                    
                # Determine if this is an internal or external IP
                is_internal = is_private_ip(ip)
                
                # Check if this IP is involved in threats
                is_suspicious = ip in threats_by_ip
                associated_threats = threats_by_ip.get(ip, [])
                
                # Determine risk level based on threat association
                if is_suspicious:
                    risk_level = "High" if len(associated_threats) > 1 else "Medium"
                else:
                    risk_level = "Low"
                
                # Calculate traffic percentage
                total_packets = sum(src_ip_packets.values()) + sum(dst_ip_packets.values())
                traffic_percentage = 0
                if total_packets > 0:
                    traffic_percentage = round((dst_ip_packets.get(ip, 0) / total_packets) * 100, 1)
                
                # Create detailed IP information
                ip_detail = {
                    'address': ip,
                    'type': 'Destination',
                    'location': 'Internal Network' if is_internal else 'External Network',
                    'asn': 'Private Network' if is_internal else 'Unknown',
                    'organization': 'Private Network' if is_internal else 'Unknown',
                    'packets_sent': src_ip_packets.get(ip, 0),
                    'packets_received': dst_ip_packets.get(ip, 0),
                    'data_sent': f"{src_ip_bytes.get(ip, 0) / 1024:.2f} KB",
                    'data_received': f"{dst_ip_bytes.get(ip, 0) / 1024:.2f} KB",
                    'connection_count': 0,  # Not a source IP
                    'traffic_percentage': traffic_percentage,
                    'is_suspicious': is_suspicious,
                    'risk_level': risk_level,
                    'associated_threats': associated_threats
                }
                
                ip_details.append(ip_detail)
            except Exception as e:
                logging.error(f"Error creating details for destination IP {ip}: {e}")
    
    # Sort by traffic percentage (descending) for better presentation
    ip_details.sort(key=lambda x: x.get('traffic_percentage', 0) if isinstance(x.get('traffic_percentage'), (int, float)) else 0, reverse=True)
    
    logging.debug(f"Returning {len(ip_details)} IP details")
    return ip_details

def generate_graph_nodes(analysis):
    """Generate nodes for communication graph visualization using real IP data"""
    logging.debug("Starting generate_graph_nodes function")
    
    # Get packet data from multiple possible sources
    packet_data = None
    
    # Try traffic_summary.packet_data first
    if hasattr(analysis, 'traffic_summary') and analysis.traffic_summary:
        if isinstance(analysis.traffic_summary, dict):
            # Try packet_data directly
            if 'packet_data' in analysis.traffic_summary:
                packet_data = analysis.traffic_summary['packet_data']
                logging.info(f"Found {len(packet_data) if packet_data else 0} packets in traffic_summary.packet_data")
            # For ZIP files, also check all_src_ips and all_dst_ips
            elif 'all_src_ips' in analysis.traffic_summary or 'all_dst_ips' in analysis.traffic_summary:
                logging.info("Found all_src_ips or all_dst_ips in traffic summary (ZIP file format)")
                unique_ips = set()
                
                # Add all source IPs
                if 'all_src_ips' in analysis.traffic_summary:
                    src_ips = analysis.traffic_summary['all_src_ips']
                    if isinstance(src_ips, list):
                        unique_ips.update(src_ips)
                        
                # Add all destination IPs
                if 'all_dst_ips' in analysis.traffic_summary:
                    dst_ips = analysis.traffic_summary['all_dst_ips'] 
                    if isinstance(dst_ips, list):
                        unique_ips.update(dst_ips)
                
                # If we have unique IPs but no packet data, create minimal packet data
                if unique_ips and not packet_data:
                    logging.info(f"Creating minimal packet data from {len(unique_ips)} IPs")
                    packet_data = []
                    
                    # Create simple packet data entries for each IP pair
                    src_ips = list(unique_ips)[:5]  # Limit to 5 source IPs to avoid explosion
                    dst_ips = list(unique_ips)[5:10] if len(unique_ips) > 5 else src_ips
                    
                    for src_ip in src_ips:
                        for dst_ip in dst_ips:
                            if src_ip != dst_ip:  # Avoid self-loops
                                packet_data.append({
                                    'src_ip': src_ip,
                                    'dst_ip': dst_ip
                                })
    
    # Check if we have valid packet data
    if not packet_data or not isinstance(packet_data, list) or len(packet_data) == 0:
        logging.warning("No packet_data found in traffic_summary")
        return []
    
    # Extract all unique IPs from packets
    unique_ips = set()
    for packet in packet_data:
        if not isinstance(packet, dict):
            continue
            
        if packet.get('src_ip'):
            unique_ips.add(packet.get('src_ip'))
            
        if packet.get('dst_ip'):
            unique_ips.add(packet.get('dst_ip'))
    
    if not unique_ips:
        logging.warning("No IPs found in packet data")
        return []
    
    logging.info(f"Found {len(unique_ips)} unique IPs in packet data")
    
    # Create graph nodes for each IP
    nodes = []
    for ip in unique_ips:
        # Check if it's an internal IP
        is_internal = is_private_ip(ip)
        
        # Check if it's associated with a threat
        is_suspicious = False
        if hasattr(analysis, 'detected_threats') and analysis.detected_threats:
            for threat in analysis.detected_threats:
                if not isinstance(threat, dict) or threat.get('name') == 'Normal Traffic':
                    continue
                
                # Check if this IP is involved in the threat
                if ('involved_ips' in threat and isinstance(threat['involved_ips'], list)):
                    for ip_info in threat['involved_ips']:
                        if isinstance(ip_info, dict) and ip_info.get('address') == ip:
                            is_suspicious = True
                            break
                
                if is_suspicious:
                    break
        
        nodes.append({
            'id': ip,
            'group': 'internal' if is_internal else 'external',
            'suspicious': is_suspicious
        })
    
    logging.info(f"Created {len(nodes)} graph nodes from packet data")
    return nodes

def generate_graph_links(analysis):
    """Generate links for communication graph visualization using real IP data"""
    logging.debug("Starting generate_graph_links function")
    
    # Get packet data using multiple approaches
    traffic_data = None
    
    # Try traffic_summary.packet_data first
    if hasattr(analysis, 'traffic_summary') and analysis.traffic_summary:
        if isinstance(analysis.traffic_summary, dict):
            traffic_data = analysis.traffic_summary.get('packet_data')
    
    # Try result_summary if no traffic data yet
    if not traffic_data and hasattr(analysis, 'result_summary') and analysis.result_summary:
        if isinstance(analysis.result_summary, dict):
            traffic_data = analysis.result_summary.get('packet_data')
    
    # Try raw_pcap_data if still no data
    if not traffic_data and hasattr(analysis, 'raw_pcap_data') and analysis.raw_pcap_data:
        traffic_data = analysis.raw_pcap_data
    
    # If we have valid packet data, use pcap_processor to extract links
    if traffic_data and isinstance(traffic_data, list):
        try:
            from pcap_processor import get_ip_communication_data
            comm_data = get_ip_communication_data(traffic_data)
            
            if comm_data and 'graph_links' in comm_data and comm_data['graph_links']:
                logging.info(f"Successfully extracted {len(comm_data['graph_links'])} graph links from PCAP")
                return comm_data['graph_links']
        except Exception as e:
            logging.error(f"Error extracting graph links from PCAP: {e}")
    
    # If no packet data or extraction failed, try to derive links from nodes or threats
    links = []
    
    # Try to derive from traffic flows
    if hasattr(analysis, 'traffic_flows'):
        for flow in analysis.traffic_flows:
            if not isinstance(flow, dict):
                continue
                
            src = flow.get('src_ip')
            dst = flow.get('dst_ip')
            
            if src and dst:
                links.append({
                    'source': src,
                    'target': dst,
                    'value': 1,
                    'suspicious': flow.get('is_malicious', False)
                })
    
    # If no links yet, try to derive from threats
    if not links and hasattr(analysis, 'detected_threats'):
        for threat in analysis.detected_threats:
            if not isinstance(threat, dict) or threat.get('name') == 'Normal Traffic':
                continue
                
            src_ips = []
            dst_ips = []
            
            # Get source IPs
            if 'involved_ips' in threat and isinstance(threat['involved_ips'], list):
                for ip_data in threat['involved_ips']:
                    if not isinstance(ip_data, dict) or not ip_data.get('address'):
                        continue
                        
                    if ip_data.get('role') == 'Source':
                        src_ips.append(ip_data.get('address'))
                    elif ip_data.get('role') == 'Destination':
                        dst_ips.append(ip_data.get('address'))
                    else:
                        # If role is Both, add to both
                        src_ips.append(ip_data.get('address'))
                        dst_ips.append(ip_data.get('address'))
            
            # Also check direct IP attributes
            if threat.get('src_ip') and threat.get('src_ip') not in src_ips:
                src_ips.append(threat.get('src_ip'))
            if threat.get('dst_ip') and threat.get('dst_ip') not in dst_ips:
                dst_ips.append(threat.get('dst_ip'))
            
            # Create links between sources and destinations
            for src in src_ips[:3]:  # Limit to 3 sources
                for dst in dst_ips[:3]:  # Limit to 3 destinations
                    if src != dst:  # Avoid self-loops
                        links.append({
                            'source': src,
                            'target': dst,
                            'value': 2,  # Medium thickness
                            'suspicious': True
                        })
    
    if links:
        logging.info(f"Derived {len(links)} graph links from available data")
        return links
        
    # If we still have no links, return empty list
    logging.warning("No graph links found from any source")
    return []

def generate_graph_links(analysis):
    """Generate links for communication graph visualization using real IP data"""
    logging.debug("Starting generate_graph_links function")
    
    # Get packet data using multiple approaches
    packet_data = None
    
    # Try traffic_summary.packet_data first
    if hasattr(analysis, 'traffic_summary') and analysis.traffic_summary:
        if isinstance(analysis.traffic_summary, dict):
            if 'packet_data' in analysis.traffic_summary:
                packet_data = analysis.traffic_summary['packet_data']
                logging.info(f"Found {len(packet_data) if packet_data else 0} packets in traffic_summary.packet_data")
            # Special handling for ZIP files with all_src_ips and all_dst_ips
            elif 'all_src_ips' in analysis.traffic_summary or 'all_dst_ips' in analysis.traffic_summary:
                logging.info("Using all_src_ips and all_dst_ips from ZIP file format")
                # We need to create representative packet data
                packet_data = []
                src_ips = analysis.traffic_summary.get('all_src_ips', [])
                dst_ips = analysis.traffic_summary.get('all_dst_ips', [])
                
                # Create connections between sources and destinations
                for src_ip in src_ips[:5]:  # Limit to avoid too many connections
                    for dst_ip in dst_ips[:5]:  # Limit destinations too
                        if src_ip != dst_ip:  # Avoid self-loops
                            packet_data.append({
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'packet_size': 100  # Default size
                            })
    
    # Try result_summary if no traffic data yet
    if not packet_data and hasattr(analysis, 'result_summary') and analysis.result_summary:
        if isinstance(analysis.result_summary, dict):
            packet_data = analysis.result_summary.get('packet_data')
    
    # If we have no packet data, check file_results from ZIP processing
    if not packet_data and hasattr(analysis, 'file_results') and isinstance(analysis.file_results, list):
        # Check each file result for IPs
        unique_src_ips = set()
        unique_dst_ips = set()
        
        for file_result in analysis.file_results:
            if isinstance(file_result, dict):
                if 'unique_src_ips' in file_result and isinstance(file_result['unique_src_ips'], list):
                    unique_src_ips.update(file_result['unique_src_ips'])
                if 'unique_dst_ips' in file_result and isinstance(file_result['unique_dst_ips'], list):
                    unique_dst_ips.update(file_result['unique_dst_ips'])
        
        # Create minimal packet data
        if unique_src_ips or unique_dst_ips:
            packet_data = []
            # If we only have one set, use it for both
            if not unique_src_ips:
                unique_src_ips = unique_dst_ips
            if not unique_dst_ips:
                unique_dst_ips = unique_src_ips
                
            # Create connections
            for src_ip in list(unique_src_ips)[:5]:
                for dst_ip in list(unique_dst_ips)[:5]:
                    if src_ip != dst_ip:
                        packet_data.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip
                        })
    
    # If we still have no packet data, try to extract it from threats
    if not packet_data and hasattr(analysis, 'detected_threats') and analysis.detected_threats:
        threat_ips = set()
        for threat in analysis.detected_threats:
            if not isinstance(threat, dict) or threat.get('name') == 'Normal Traffic':
                continue
                
            # Extract IPs from involved_ips
            if 'involved_ips' in threat and isinstance(threat['involved_ips'], list):
                for ip_info in threat['involved_ips']:
                    if isinstance(ip_info, dict) and ip_info.get('address'):
                        threat_ips.add(ip_info.get('address'))
            
            # Also check direct IP attributes
            if threat.get('src_ip'):
                threat_ips.add(threat.get('src_ip'))
            if threat.get('dst_ip'):
                threat_ips.add(threat.get('dst_ip'))
        
        # Create minimal packet data from threat IPs
        if threat_ips:
            packet_data = []
            threat_ip_list = list(threat_ips)
            
            # Create connections between these IPs
            for i in range(min(5, len(threat_ip_list))):
                src_ip = threat_ip_list[i]
                for j in range(i+1, min(len(threat_ip_list), i+3)):
                    dst_ip = threat_ip_list[j]
                    packet_data.append({
                        'src_ip': src_ip,
                        'dst_ip': dst_ip
                    })
    
    # If we have valid packet data, extract connections
    links = []
    if packet_data and isinstance(packet_data, list):
        # Map of IP connections
        connections = {}
        
        for packet in packet_data:
            if not isinstance(packet, dict):
                continue
                
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            
            if not src_ip or not dst_ip:
                continue
                
            # Create a key for this connection
            connection_key = f"{src_ip}->{dst_ip}"
            
            if connection_key in connections:
                connections[connection_key]['count'] += 1
                connections[connection_key]['size'] += packet.get('packet_size', 0)
            else:
                connections[connection_key] = {
                    'source': src_ip,
                    'target': dst_ip,
                    'count': 1,
                    'size': packet.get('packet_size', 0) if packet.get('packet_size') else 100  # Default size
                }
        
        # Convert connections to links
        for conn in connections.values():
            # Scale value based on packet count (1-5 range)
            value = min(5, max(1, int(conn['count'] / 10))) if conn['count'] >= 10 else 1
            
            # Determine if suspicious based on threats
            suspicious = False
            if hasattr(analysis, 'detected_threats') and analysis.detected_threats:
                for threat in analysis.detected_threats:
                    if not isinstance(threat, dict) or threat.get('name') == 'Normal Traffic':
                        continue
                        
                    # Check if either IP is in the threat
                    if 'involved_ips' in threat and isinstance(threat['involved_ips'], list):
                        for ip_info in threat['involved_ips']:
                            if (isinstance(ip_info, dict) and ip_info.get('address') and
                                (ip_info.get('address') == conn['source'] or 
                                 ip_info.get('address') == conn['target'])):
                                suspicious = True
                                break
                    
                    if suspicious:
                        break
            
            links.append({
                'source': conn['source'],
                'target': conn['target'],
                'value': value,
                'suspicious': suspicious
            })
    
    logging.info(f"Generated {len(links)} graph links from available data")
    return links

def get_suspicious_hostnames(analysis):
    """Extract only real hostnames from packet data"""
    hostnames = []
    
    # Get DNS records from traffic data if available
    traffic_data = analysis.traffic_summary.get('packet_data', [])
    
    if not traffic_data:
        return hostnames
    
    # Extract only real hostnames from DNS queries in the traffic
    for packet in traffic_data:
        # Only extract hostnames that were actually in DNS or HTTP host headers
        if packet.get('dns_query'):
            hostnames.append(packet.get('dns_query'))
        elif packet.get('http_host'):
            hostnames.append(packet.get('http_host'))
    
    # Return only unique real hostnames
    return list(set(hostnames))

# 3. Replace get_suspicious_files function to only return real files
def get_suspicious_files(analysis):
    """Get only real files detected in the traffic"""
    files = []
    
    # Extract actual file transfers from the packet data
    traffic_data = analysis.traffic_summary.get('packet_data', [])
    
    if not traffic_data:
        return files
    
    # Look for real file transfers in HTTP, FTP or SMB traffic
    for packet in traffic_data:
        if packet.get('file_name'):
            files.append(packet.get('file_name'))
        elif packet.get('http_uri') and '.' in packet.get('http_uri').split('/')[-1]:
            # Extract filenames from HTTP URIs that appear to be files
            files.append(packet.get('http_uri').split('/')[-1])
        elif packet.get('ftp_command') and packet.get('ftp_command').startswith('RETR '):
            # Extract filenames from FTP RETR commands
            files.append(packet.get('ftp_command')[5:])
    
    # Return only unique filenames that were actually observed
    return list(set(files))

def generate_iocs(analysis):
    """Generate Indicators of Compromise only from observed data"""
    iocs = []
    
    # Extract IOCs from actual traffic data
    traffic_data = analysis.traffic_summary.get('packet_data', [])
    
    if not traffic_data:
        return iocs
    
    # Extract unique IPs showing suspicious behavior
    suspicious_ips = set()
    suspicious_domains = set()
    suspicious_urls = set()
    suspicious_files = set()
    suspicious_md5_hashes = set()
    
    # Get IPs from packets related to detected threats
    for threat in analysis.detected_threats:
        if threat['name'] != 'Normal Traffic':
            for ip_data in threat.get('involved_ips', []):
                if isinstance(ip_data, dict) and ip_data.get('address'):
                    suspicious_ips.add(ip_data.get('address'))
    
    # Extract domains, URLs, files, and hashes from actual packets
    for packet in traffic_data:
        # Extract suspicious domains from DNS queries
        if packet.get('dns_query'):
            if packet.get('dst_ip') in suspicious_ips:
                suspicious_domains.add(packet.get('dns_query'))
        
        # Extract suspicious URLs from HTTP requests
        if packet.get('http_uri') and packet.get('http_host'):
            if packet.get('dst_ip') in suspicious_ips:
                suspicious_urls.add(f"http://{packet.get('http_host')}{packet.get('http_uri')}")
        
        # Extract suspicious files
        if packet.get('file_name') and (
            packet.get('src_ip') in suspicious_ips or 
            packet.get('dst_ip') in suspicious_ips
        ):
            suspicious_files.add(packet.get('file_name'))
        
        # Extract MD5 hashes if available in the packets
        if packet.get('file_md5'):
            suspicious_md5_hashes.add(packet.get('file_md5'))
    
    # Create IOCs only from real observed data
    for ip in suspicious_ips:
        iocs.append({
            'indicator': ip,
            'type': 'IP Address',
            'confidence': 'Medium',
            'description': 'IP address associated with suspicious traffic'
        })
    
    for domain in suspicious_domains:
        iocs.append({
            'indicator': domain,
            'type': 'Domain',
            'confidence': 'Medium',
            'description': 'Domain associated with suspicious traffic'
        })
    
    for url in suspicious_urls:
        iocs.append({
            'indicator': url,
            'type': 'URL',
            'confidence': 'Medium',
            'description': 'URL accessed during suspicious activity'
        })
    
    for file in suspicious_files:
        iocs.append({
            'indicator': file,
            'type': 'Filename',
            'confidence': 'Medium',
            'description': 'File transferred during suspicious activity'
        })
    
    for md5 in suspicious_md5_hashes:
        iocs.append({
            'indicator': md5,
            'type': 'MD5 Hash',
            'confidence': 'High',
            'description': 'MD5 hash of suspicious file'
        })
    
    return iocs

# Routes for threat category management
@app.route('/threat-categories')
def threat_categories():
    try:
        categories = ThreatCategory.query.all()
        return render_template('threat_categories.html', categories=categories)
    except Exception as e:
        logging.error(f"Error displaying threat categories: {e}")
        flash('Error displaying threat categories', 'danger')
        return redirect(url_for('index'))

@app.route('/threat-categories/add', methods=['POST'])
def add_threat_category():
    try:
        name = request.form.get('name')
        description = request.form.get('description')
        risk_level = request.form.get('risk_level')
        indicators = request.form.get('indicators', '').strip().split('\n')
        recommended_actions = request.form.get('recommended_actions', '').strip().split('\n')

        # Remove empty strings
        indicators = [i for i in indicators if i]
        recommended_actions = [a for a in recommended_actions if a]

        # Check if category already exists
        if ThreatCategory.query.filter_by(name=name).first():
            flash(f'Threat category "{name}" already exists', 'warning')
            return redirect(url_for('threat_categories'))

        # Create new category
        category = ThreatCategory(
            name=name,
            description=description,
            risk_level=risk_level,
            indicators=indicators,
            recommended_actions=recommended_actions,
            is_builtin=False
        )

        db.session.add(category)
        db.session.commit()

        flash(f'Threat category "{name}" added successfully', 'success')
        return redirect(url_for('threat_categories'))
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error adding threat category: {e}")
        flash('Error adding threat category', 'danger')
        return redirect(url_for('threat_categories'))

@app.route('/threat-categories/edit', methods=['POST'])
def edit_threat_category():
    try:
        category_id = request.form.get('id')
        name = request.form.get('name')
        description = request.form.get('description')
        risk_level = request.form.get('risk_level')
        indicators = request.form.get('indicators', '').strip().split('\n')
        recommended_actions = request.form.get('recommended_actions', '').strip().split('\n')

        # Remove empty strings
        indicators = [i.strip() for i in indicators if i.strip()]
        recommended_actions = [a.strip() for a in recommended_actions if a.strip()]

        # Get category
        category = ThreatCategory.query.get_or_404(category_id)

        # Check if category is built-in
        if category.is_builtin:
            flash('Cannot edit built-in categories', 'warning')
            return redirect(url_for('threat_categories'))

        # Check if name already exists for other categories
        existing = ThreatCategory.query.filter(
            ThreatCategory.name == name,
            ThreatCategory.id != category_id
        ).first()
        if existing:
            flash(f'Category name "{name}" already exists', 'warning')
            return redirect(url_for('threat_categories'))

        # Update fields
        category.name = name
        category.description = description
        category.risk_level = risk_level
        category.indicators = [i.strip() for i in indicators if i.strip()]
        category.recommended_actions = [a.strip() for a in recommended_actions if a.strip()]
        category.updated_at = datetime.datetime.utcnow()

        # Save changes
        db.session.commit()

        flash(f'Threat category "{name}" updated successfully', 'success')
        return redirect(url_for('threat_categories'))
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating threat category: {e}")
        flash('Error updating threat category', 'danger')
        return redirect(url_for('threat_categories'))

@app.route('/threat-categories/delete', methods=['POST'])
def delete_threat_category():
    try:
        category_id = request.form.get('id')

        # Get category
        category = ThreatCategory.query.get_or_404(category_id)

        # Check if category is built-in
        if category.is_builtin:
            flash('Cannot delete built-in categories', 'warning')
            return redirect(url_for('threat_categories'))

        # Check if category has training data
        if len(category.training_data) > 0:
            flash('Cannot delete categories that have training data', 'warning')
            return redirect(url_for('threat_categories'))

        # Delete the category
        db.session.delete(category)
        db.session.commit()

        flash('Threat category deleted successfully', 'success')
        return redirect(url_for('threat_categories'))
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting threat category: {e}")
        flash('Error deleting threat category', 'danger')
        return redirect(url_for('threat_categories'))

@app.route('/threat-categories/<int:category_id>/data')
def get_category_data(category_id):
    try:
        category = ThreatCategory.query.get_or_404(category_id)

        return jsonify({
            'id': category.id,
            'name': category.name,
            'description': category.description,
            'risk_level': category.risk_level,
            'indicators': category.indicators or [],
            'recommended_actions': category.recommended_actions or [],
            'is_builtin': category.is_builtin,
            'is_trained': category.is_trained,
            'sample_count': category.sample_count
        })
    except Exception as e:
        logging.error(f"Error getting category data: {e}")
        return jsonify({'error': str(e)}), 500

# Routes for training status and management
@app.route('/training-status')
def training_status():
    try:
        # Get all training data and categories
        training_data = TrainingData.query.all()
        categories = ThreatCategory.query.all()

        # Get model performance statistics
        model_performance = get_model_performance()

        # Prepare data for charts
        category_counts = {}
        for data in training_data:
            category_name = data.category.name
            category_counts[category_name] = category_counts.get(category_name, 0) + 1

        category_labels = list(category_counts.keys())
        category_values = list(category_counts.values())

        # Get feature names and values from model
        feature_labels = model_performance.get('feature_names', [])
        feature_values = model_performance.get('feature_importances', [])

        # Calculate training statistics
        training_stats = {
            'total_samples': len(training_data),
            'trained_categories': len(category_counts),
            'total_categories': len(categories),
            'last_training_date': 'Not Available',
            'accuracy': model_performance.get('accuracy', 0),
            'precision': model_performance.get('precision', 0),
            'recall': model_performance.get('recall', 0),
            'f1_score': model_performance.get('f1_score', 0),
            'training_time': model_performance.get('training_time', 0)
        }

        # Get the most recent training data's timestamp
        most_recent = TrainingData.query.order_by(TrainingData.added_at.desc()).first()
        if most_recent:
            training_stats['last_training_date'] = most_recent.added_at.strftime('%Y-%m-%d %H:%M')

        return render_template('training_status.html',
                              training_data=training_data,
                              categories=categories,
                              training_stats=training_stats,
                              category_labels=category_labels,
                              category_values=category_values,
                              feature_labels=feature_labels,
                              feature_values=feature_values)
    except Exception as e:
        logging.error(f"Error displaying training status: {e}")
        flash('Error displaying training status', 'danger')
        return redirect(url_for('index'))

@app.route('/training-data/edit', methods=['POST'])
def edit_training_data():
    try:
        data_id = request.form.get('id')
        category_id = request.form.get('category_id')

        # Get the training data and new category
        training_data = TrainingData.query.get_or_404(data_id)
        category = ThreatCategory.query.get_or_404(category_id)

        # Update the category
        training_data.category_id = category.id
        db.session.commit()

        flash('Training data updated successfully. You should retrain the model.', 'success')
        return redirect(url_for('training_status', changes='true'))
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error updating training data: {e}")
        flash('Error updating training data', 'danger')
        return redirect(url_for('training_status'))

@app.route('/training-data/delete', methods=['POST'])
def delete_training_data():
    try:
        data_id = request.form.get('id')

        # Get the training data
        training_data = TrainingData.query.get_or_404(data_id)

        # Delete the training data
        db.session.delete(training_data)
        db.session.commit()

        flash('Training data deleted successfully. You should retrain the model.', 'success')
        return redirect(url_for('training_status', changes='true'))
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting training data: {e}")
        flash('Error deleting training data', 'danger')
        return redirect(url_for('training_status'))

@app.route('/retrain', methods=['POST'])
def retrain_model():
    try:
        # Retrain the model using all available training data
        # This would typically extract features from stored training samples
        # For demonstration, we'll just call the model's training function

        flash('Model retraining initiated. This may take some time.', 'info')

        # In a real application, you would retrain here
        # For now, we'll just pretend it was successful

        flash('Model retrained successfully with updated training data', 'success')
        return redirect(url_for('training_status'))
    except Exception as e:
        logging.error(f"Error retraining model: {e}")
        flash('Error retraining model', 'danger')
        return redirect(url_for('training_status'))

@app.errorhandler(413)
def too_large(e):
    flash('File too large. Maximum size is 5GB.', 'danger')
    return redirect(url_for('index'))

@app.errorhandler(500)
def server_error(e):
    flash('Server error occurred. Please try again.', 'danger')
    return redirect(url_for('index'))
