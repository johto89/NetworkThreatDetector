"""
Module for extracting and processing PCAP files from ZIP archives.
This module handles batch processing of multiple PCAP files contained in a ZIP archive.
"""

import os
import logging
import tempfile
import zipfile
import time 
from werkzeug.utils import secure_filename
from pcap_processor import process_pcap_file
from ml_model import analyze_packet_features, load_model

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('zip_processor')

def combine_traffic_summaries(traffic_summaries):
    """
    Combine multiple traffic summaries into one
    
    Args:
        traffic_summaries: List of traffic summary dictionaries
        
    Returns:
        Combined traffic summary dictionary
    """
    if not traffic_summaries:
        return {}
    
    # Initialize combined summary
    combined = {
        'total_packets': 0,
        'protocols': {},
        'unique_src_ips': 0,
        'unique_dst_ips': 0,
        'unique_src_ports': 0,
        'unique_dst_ports': 0,
        'avg_packet_size': 0,
        'packet_data': []  # Add this to store packet data
    }
    
    # Set for unique IPs and ports across all files
    all_src_ips = set()
    all_dst_ips = set()
    all_src_ports = set()
    all_dst_ports = set()
    
    # Total packet size for calculating average
    total_size = 0
    
    # Combine summaries
    for summary in traffic_summaries:
        if not summary:
            continue
        
        # Add packet count
        combined['total_packets'] += summary.get('total_packets', 0)
        
        # Combine protocol counts
        for protocol, count in summary.get('protocols', {}).items():
            if protocol not in combined['protocols']:
                combined['protocols'][protocol] = 0
            combined['protocols'][protocol] += count
        
        # Accumulate unique IPs and ports
        # Handle potential non-list/non-set inputs
        src_ips = summary.get('unique_src_ips', [])
        dst_ips = summary.get('unique_dst_ips', [])
        src_ports = summary.get('unique_src_ports', [])
        dst_ports = summary.get('unique_dst_ports', [])
        
        all_src_ips.update(src_ips if isinstance(src_ips, (list, set)) else [])
        all_dst_ips.update(dst_ips if isinstance(dst_ips, (list, set)) else [])
        all_src_ports.update(src_ports if isinstance(src_ports, (list, set)) else [])
        all_dst_ports.update(dst_ports if isinstance(dst_ports, (list, set)) else [])
        
        # Add to total size for average calculation
        total_size += summary.get('avg_packet_size', 0) * summary.get('total_packets', 0)
        
        # Add packet data from each file (up to a maximum limit to avoid memory issues)
        # This is the key change to preserve real IP information
        if 'packet_data' in summary and isinstance(summary['packet_data'], list):
            # Limit to 100 packets per file to avoid excessive memory usage
            combined['packet_data'].extend(summary['packet_data'][:100])
    
    # Limit the total number of packets to avoid session size issues
    max_packets = 300
    if len(combined['packet_data']) > max_packets:
        combined['packet_data'] = combined['packet_data'][:max_packets]
    
    # Set final unique counts
    combined['unique_src_ips'] = len(all_src_ips)
    combined['unique_dst_ips'] = len(all_dst_ips)
    combined['unique_src_ports'] = len(all_src_ports)
    combined['unique_dst_ports'] = len(all_dst_ports)
    
    # Calculate average packet size
    if combined['total_packets'] > 0:
        combined['avg_packet_size'] = total_size / combined['total_packets']
    
    return combined

def process_pcap_batch(pcap_files):
    """
    Process a batch of PCAP files and combine the results
    
    Args:
        pcap_files: List of paths to PCAP files
        
    Returns:
        Dictionary containing combined analysis results
    """
    logger.info(f"Processing batch of {len(pcap_files)} PCAP files")
    
    all_packet_features = []
    all_threats = []
    all_traffic_summaries = []
    file_results = []
    combined_packet_data = []  # NEW: Tạo danh sách gộp packet_data
    
    # Track overall unique IPs
    all_src_ips = set()
    all_dst_ips = set()
    
    for pcap_file in pcap_files:
        logger.info(f"Processing PCAP file: {os.path.basename(pcap_file)}")
        
        # Process the PCAP file
        packet_features = process_pcap_file(pcap_file)
        
        if not packet_features:
            logger.warning(f"No features extracted from {os.path.basename(pcap_file)}")
            file_results.append({
                'filename': os.path.basename(pcap_file),
                'status': 'warning',
                'message': 'No features extracted from file',
                'threats': [],
                'packet_count': 0
            })
            continue
        
        # Log a few packet samples to verify IP addresses
        logger.debug(f"Sample packets from {os.path.basename(pcap_file)}:")
        for i, packet in enumerate(packet_features[:3]):
            if isinstance(packet, dict):
                logger.debug(f"  Packet {i}: src_ip={packet.get('src_ip')}, dst_ip={packet.get('dst_ip')}")
        
        # Analyze the packet features (use default analysis)
        results = analyze_packet_features(packet_features)
        
        # Extract IPs for this file
        file_src_ips = set(p.get('src_ip') for p in packet_features if p.get('src_ip'))
        file_dst_ips = set(p.get('dst_ip') for p in packet_features if p.get('dst_ip'))
        all_src_ips.update(file_src_ips)
        all_dst_ips.update(file_dst_ips)
        
        # Make sure traffic_summary has packet_data for IP extraction
        if 'traffic_summary' not in results:
            results['traffic_summary'] = {}
        
        # Store a limited number of packets in the traffic summary
        max_packets = 100  # Limit packets per file
        sample_packets = packet_features[:max_packets]
        results['traffic_summary']['packet_data'] = sample_packets
        
        # NEW: Add packet_data to combined list
        combined_packet_data.extend(sample_packets)
        logger.info(f"Added {len(sample_packets)} packets to combined packet data (total now: {len(combined_packet_data)})")
        
        # Add the current file results
        file_results.append({
            'filename': os.path.basename(pcap_file),
            'status': results.get('status', 'success'),
            'message': results.get('message', 'Processed successfully'),
            'threats': results.get('threats', []),
            'packet_count': len(packet_features),
            'unique_src_ips': list(file_src_ips),
            'unique_dst_ips': list(file_dst_ips)
        })
        
        # Combine all packet features and threats
        all_packet_features.extend(packet_features)
        all_threats.extend(results.get('threats', []))
        all_traffic_summaries.append(results.get('traffic_summary', {}))
    
    # Deduplicate threats by name and take the highest confidence one
    unique_threats = {}
    for threat in all_threats:
        threat_name = threat.get('name', 'Unknown')
        if threat_name not in unique_threats or threat.get('confidence', 0) > unique_threats[threat_name].get('confidence', 0):
            unique_threats[threat_name] = threat
    
    combined_threats = list(unique_threats.values())
    
    # Combine traffic summaries
    combined_traffic_summary = combine_traffic_summaries(all_traffic_summaries)
    
    # NEW: Đảm bảo danh sách packet_data được giữ lại trong traffic_summary
    if 'packet_data' not in combined_traffic_summary or not combined_traffic_summary['packet_data']:
        # Giới hạn số lượng gói tin để tránh tràn bộ nhớ
        max_combined_packets = 300
        combined_traffic_summary['packet_data'] = combined_packet_data[:max_combined_packets]
        logger.info(f"Added {len(combined_traffic_summary['packet_data'])} packets to traffic_summary from combined packet data")
    
    # Add all unique IPs to the traffic summary
    combined_traffic_summary['all_src_ips'] = list(all_src_ips)
    combined_traffic_summary['all_dst_ips'] = list(all_dst_ips)
    
    # Log a summary of what we collected
    logger.info(f"Combined results summary:")
    logger.info(f"- Total unique source IPs: {len(all_src_ips)}")
    logger.info(f"- Total unique destination IPs: {len(all_dst_ips)}")
    logger.info(f"- Total packet data samples: {len(combined_traffic_summary.get('packet_data', []))}")
    
    # Sample IP verification
    if combined_traffic_summary.get('packet_data'):
        sample_ips = set()
        for p in combined_traffic_summary['packet_data'][:10]:
            if isinstance(p, dict):
                if p.get('src_ip'): sample_ips.add(p.get('src_ip'))
                if p.get('dst_ip'): sample_ips.add(p.get('dst_ip'))
        logger.info(f"Sample IPs from combined packet_data: {list(sample_ips)}")
    
    # Determine if any file is malicious
    is_malicious = any(
        any(t.get('name', '') != 'Normal Traffic' for t in file_result.get('threats', []))
        for file_result in file_results
    )
    
    # Create combined results
    combined_results = {
        'status': 'success',
        'message': f'Successfully analyzed {len(pcap_files)} PCAP files',
        'threats': combined_threats,
        'file_results': file_results,
        'summary': {
            'is_malicious': is_malicious,
            'threat_count': len([t for t in combined_threats if t.get('name', '') != 'Normal Traffic']),
            'packet_count': len(all_packet_features),
            'confidence': max([t.get('confidence', 0) for t in combined_threats]) if combined_threats else 0.0,
            'unique_src_ips': list(all_src_ips),
            'unique_dst_ips': list(all_dst_ips)
        },
        'traffic_summary': combined_traffic_summary
    }
    
    return combined_results

def extract_pcap_files(zip_filepath, extract_dir):
    """
    Extract all PCAP files from a ZIP archive
    
    Args:
        zip_filepath: Path to the ZIP file
        extract_dir: Directory to extract files to
        
    Returns:
        Dictionary containing extraction results
    """
    pcap_files = []
    
    try:
        with zipfile.ZipFile(zip_filepath, 'r') as zip_ref:
            # Get list of all files in the ZIP archive
            file_list = zip_ref.namelist()
            
            # Extract only PCAP files
            for file_info in zip_ref.infolist():
                filename = file_info.filename
                
                # Skip directories
                if filename.endswith('/'):
                    continue
                
                # Check if file is a PCAP file
                if filename.lower().endswith(('.pcap', '.pcapng', '.cap')):
                    # Secure the filename to prevent path traversal
                    safe_filename = secure_filename(os.path.basename(filename))
                    
                    # Extract the file
                    extracted_path = os.path.join(extract_dir, safe_filename)
                    with open(extracted_path, 'wb') as f:
                        f.write(zip_ref.read(filename))
                    
                    pcap_files.append(extracted_path)
                    logger.info(f"Extracted PCAP file: {safe_filename}")
            
        return {
            'success': True,
            'pcap_files': pcap_files
        }
    
    except zipfile.BadZipFile:
        logger.error(f"Invalid ZIP file: {zip_filepath}")
        return {
            'success': False,
            'message': 'Invalid ZIP file'
        }
    except Exception as e:
        logger.error(f"Error extracting files from ZIP: {e}")
        return {
            'success': False,
            'message': f'Error extracting files: {str(e)}'
        }

def process_zip_file(zip_filepath):
    """
    Process all PCAP files contained in a ZIP archive
    
    Args:
        zip_filepath: Path to the ZIP file
        
    Returns:
        Dictionary containing combined analysis results
    """
    logger.info(f"Processing ZIP file: {zip_filepath}")
    
    # Create a temporary directory to extract files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Extract all files from the ZIP archive
        extract_results = extract_pcap_files(zip_filepath, temp_dir)
        
        if not extract_results['success']:
            return {
                'status': 'error',
                'message': extract_results['message']
            }
        
        pcap_files = extract_results['pcap_files']
        
        if not pcap_files:
            return {
                'status': 'error',
                'message': 'No PCAP files found in the ZIP archive'
            }
        
        # Process each PCAP file and combine results
        combined_results = process_pcap_batch(pcap_files)
        
        # Add the filenames to the results
        combined_results['files'] = [os.path.basename(f) for f in pcap_files]
        combined_results['file_count'] = len(pcap_files)
        
        # DEBUG: Kiểm tra dữ liệu IP trong kết quả
        logger.info("DEBUG - ZIP processing results:")
        
        # Kiểm tra traffic_summary
        if 'traffic_summary' in combined_results and combined_results['traffic_summary']:
            ts = combined_results['traffic_summary']
            logger.info(f"traffic_summary keys: {list(ts.keys())}")
            
            # Kiểm tra packet_data
            if 'packet_data' in ts:
                logger.info(f"packet_data length: {len(ts['packet_data'])}")
                if ts['packet_data'] and len(ts['packet_data']) > 0:
                    logger.info(f"First packet: {ts['packet_data'][0]}")
                    
                    # Log mẫu IPs từ packet_data
                    sample_ips = set()
                    for p in ts['packet_data'][:10]:
                        if isinstance(p, dict):
                            if p.get('src_ip'): sample_ips.add(p.get('src_ip'))
                            if p.get('dst_ip'): sample_ips.add(p.get('dst_ip'))
                    logger.info(f"Sample IPs from packet_data: {list(sample_ips)}")
            
            # Kiểm tra all_src_ips và all_dst_ips
            if 'all_src_ips' in ts:
                logger.info(f"all_src_ips count: {len(ts['all_src_ips'])}")
                logger.info(f"Sample src IPs: {ts['all_src_ips'][:5]}")
            
            if 'all_dst_ips' in ts:
                logger.info(f"all_dst_ips count: {len(ts['all_dst_ips'])}")
                logger.info(f"Sample dst IPs: {ts['all_dst_ips'][:5]}")
        
        # Kiểm tra file_results
        if 'file_results' in combined_results:
            file_results = combined_results['file_results']
            logger.info(f"file_results count: {len(file_results)}")
            
            for i, fr in enumerate(file_results[:2]):  # Log chi tiết về 2 file đầu tiên
                logger.info(f"File result {i}:")
                logger.info(f"  filename: {fr.get('filename')}")
                logger.info(f"  unique_src_ips count: {len(fr.get('unique_src_ips', []))}")
                logger.info(f"  unique_dst_ips count: {len(fr.get('unique_dst_ips', []))}")
                
                # Log mẫu IP
                if 'unique_src_ips' in fr and fr['unique_src_ips']:
                    logger.info(f"  Sample src IPs: {fr['unique_src_ips'][:5]}")
                if 'unique_dst_ips' in fr and fr['unique_dst_ips']:
                    logger.info(f"  Sample dst IPs: {fr['unique_dst_ips'][:5]}")
        
        # Kiểm tra threats
        if 'threats' in combined_results:
            threats = combined_results['threats']
            logger.info(f"threats count: {len(threats)}")
            
            for i, threat in enumerate(threats[:2]):  # Log chi tiết về 2 threat đầu tiên
                logger.info(f"Threat {i}:")
                logger.info(f"  name: {threat.get('name')}")
                
                # Kiểm tra involved_ips
                if 'involved_ips' in threat and isinstance(threat['involved_ips'], list):
                    logger.info(f"  involved_ips count: {len(threat['involved_ips'])}")
                    
                    # Log mẫu IPs từ involved_ips
                    if threat['involved_ips']:
                        involved_ip_samples = []
                        for ip_info in threat['involved_ips'][:3]:  # Log tối đa 3 IP
                            if isinstance(ip_info, dict) and 'address' in ip_info:
                                involved_ip_samples.append(ip_info['address'])
                        logger.info(f"  Sample involved IPs: {involved_ip_samples}")
        
        return combined_results