"""
CSV Processor module for PCAP Analyzer

This module handles the processing of CSV files containing network traffic data
for model training and analysis. It provides functions to extract features from CSV files,
process them for training the machine learning model, and analyze them for threat detection.
Optimized for real network traffic datasets like CICIDS 2017 and CTU-13.

Functions:
- process_csv_file: Extract packet features from a CSV file
- process_csv_for_training: Process a CSV file for model training
- analyze_csv_data: Analyze CSV data to detect threats
"""

import logging
import pandas as pd
import numpy as np
import os
import hashlib
import json
import tempfile
from datetime import datetime
import traceback
from iputils import is_internal_ip
from pcap_processor import extract_statistical_features
from models import ThreatCategory, TrainingData, db, ThreatCategoryEnum

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Dataset specific column mappings
CICIDS_COLUMNS = {
    'Flow ID': 'flow_id',
    'Source IP': 'src_ip',
    'Source Port': 'src_port',
    'Destination IP': 'dst_ip',
    'Destination Port': 'dst_port',
    'Protocol': 'protocol',
    'Timestamp': 'timestamp',
    'Flow Duration': 'flow_duration',
    'Total Fwd Packets': 'fwd_packets',
    'Total Backward Packets': 'bwd_packets',
    'Total Length of Fwd Packets': 'fwd_bytes',
    'Total Length of Bwd Packets': 'bwd_bytes',
    'Fwd Packet Length Max': 'fwd_packet_max',
    'Fwd Packet Length Min': 'fwd_packet_min',
    'Fwd Packet Length Mean': 'fwd_packet_mean',
    'Bwd Packet Length Max': 'bwd_packet_max',
    'Bwd Packet Length Min': 'bwd_packet_min',
    'Bwd Packet Length Mean': 'bwd_packet_mean',
    'Flow Bytes/s': 'bytes_per_sec',
    'Flow Packets/s': 'packet_rate',
    'Flow IAT Mean': 'flow_iat_mean',
    'Flow IAT Std': 'flow_iat_std',
    'Fwd IAT Total': 'fwd_iat_total',
    'Bwd IAT Total': 'bwd_iat_total',
    'Label': 'classification'
}

CTU_COLUMNS = {
    'StartTime': 'timestamp',
    'Dur': 'flow_duration',
    'Proto': 'protocol',
    'SrcAddr': 'src_ip',
    'Sport': 'src_port',
    'Dir': 'direction', 
    'DstAddr': 'dst_ip',
    'Dport': 'dst_port',
    'State': 'tcp_state',
    'sTos': 'src_tos',
    'dTos': 'dst_tos',
    'TotPkts': 'total_packets',
    'TotBytes': 'total_bytes',
    'SrcBytes': 'src_bytes',
    'Label': 'classification'
}

# Protocol mapping for numeric protocols
PROTOCOL_MAP = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    'tcp': 'TCP',
    'udp': 'UDP',
    'icmp': 'ICMP'
}

def detect_dataset_type(df):
    """
    Detect which dataset format is being used
    
    Args:
        df: Pandas DataFrame containing the CSV data
        
    Returns:
        String indicating dataset type ('CICIDS', 'CTU', or 'UNKNOWN')
    """
    columns = set(df.columns)
    
    # Check for CICIDS specific columns
    cicids_markers = {'Flow ID', 'Source IP', 'Destination IP', 'Flow Duration', 'Total Fwd Packets'}
    if len(columns.intersection(cicids_markers)) >= 3:
        return 'CICIDS'
    
    # Check for CTU specific columns
    ctu_markers = {'StartTime', 'Dur', 'Proto', 'SrcAddr', 'DstAddr', 'Dir', 'State'}
    if len(columns.intersection(ctu_markers)) >= 3:
        return 'CTU'
    
    # Check if it looks like a packet-level capture (Wireshark/tcpdump style)
    packet_level_markers = {'src_ip', 'dst_ip', 'packet_size', 'ttl', 'protocol', 'timestamp'}
    if len(columns.intersection(packet_level_markers)) >= 3:
        return 'PACKET'
    
    return 'UNKNOWN'

def normalize_protocol(protocol):
    """
    Normalize different protocol representations to a standard format
    
    Args:
        protocol: Protocol value from the dataset
        
    Returns:
        Normalized protocol string or number
    """
    if protocol is None:
        return 'UNKNOWN'
    
    # If it's already an integer
    if isinstance(protocol, (int, float)):
        return PROTOCOL_MAP.get(int(protocol), 'OTHER')
    
    # If it's a string that can be converted to integer
    if isinstance(protocol, str) and protocol.isdigit():
        return PROTOCOL_MAP.get(int(protocol), 'OTHER')
    
    # If it's a string protocol name
    if isinstance(protocol, str):
        protocol = protocol.lower()
        if protocol in ['tcp', 'udp', 'icmp']:
            return protocol.upper()
        
    return 'OTHER'

def process_csv_file(csv_path, return_data=True):
    """
    Process a CSV file containing network traffic data and extract packet features.
    Optimized for CICIDS 2017 and CTU-13 datasets, with improved protocol and feature detection.
    
    Args:
        csv_path: Path to the CSV file
        return_data: Whether to return the extracted data or just process it
        
    Returns:
        List of packet feature dictionaries or None based on return_data
    """
    try:
        logger.info(f"Processing CSV file: {os.path.basename(csv_path)}")
        
        # Read the CSV file with multiple attempts for different formats
        df = None
        try:
            # Try different delimiters and encodings
            for delimiter in [',', ';', '\t']:
                for encoding in ['utf-8', 'latin1', 'ISO-8859-1']:
                    try:
                        df = pd.read_csv(csv_path, delimiter=delimiter, encoding=encoding, low_memory=False)
                        if df is not None and not df.empty:
                            logger.info(f"Successfully read CSV with delimiter '{delimiter}' and encoding '{encoding}'")
                            break
                    except Exception as e:
                        continue
                if df is not None and not df.empty:
                    break
        except Exception as e:
            logger.error(f"Error reading CSV file with all attempted options: {e}")
            return None
        
        if df is None or df.empty:
            logger.warning("CSV file is empty or could not be read")
            return None
        
        logger.info(f"CSV has {len(df)} rows and {len(df.columns)} columns")
        logger.info(f"Columns found: {list(df.columns)}")
        
        # Clean column names - strip whitespace, lowercase
        df.columns = [col.strip() for col in df.columns]
        
        # Detect dataset type
        dataset_type = detect_dataset_type(df)
        logger.info(f"Detected dataset type: {dataset_type}")
        
        # Extract features from the CSV data
        packet_features = []
        
        # Process based on dataset type
        if dataset_type == 'CICIDS':
            packet_features = process_cicids_data(df)
        elif dataset_type == 'CTU':
            packet_features = process_ctu_data(df)
        else:
            # Generic processing for unknown format
            packet_features = process_generic_data(df)
        
        # Log the extraction results
        logger.info(f"Extracted {len(packet_features)} packet features from CSV file")
        
        if return_data:
            return packet_features
        else:
            return True
            
    except Exception as e:
        logger.error(f"Error processing CSV file: {e}")
        logger.error(traceback.format_exc())
        return None

def process_cicids_data(df):
    """
    Process CICIDS 2017 dataset format
    
    Args:
        df: Pandas DataFrame containing the CSV data
        
    Returns:
        List of packet feature dictionaries
    """
    logger.info("Processing CICIDS 2017 format data")
    packet_features = []
    
    # Rename columns to standardized names if present
    columns_to_rename = {}
    for original, standardized in CICIDS_COLUMNS.items():
        if original in df.columns:
            columns_to_rename[original] = standardized
    
    if columns_to_rename:
        df = df.rename(columns=columns_to_rename)
    
    # Process each flow as a feature
    for _, row in df.iterrows():
        feature = {}
        
        # Add all available data
        for col in df.columns:
            try:
                # Handle NaN values
                if pd.isna(row[col]):
                    feature[col] = None
                else:
                    feature[col] = row[col]
            except:
                feature[col] = None
        
        # Ensure required fields are present
        if 'src_ip' not in feature and 'Source IP' in df.columns:
            feature['src_ip'] = row['Source IP']
        
        if 'dst_ip' not in feature and 'Destination IP' in df.columns:
            feature['dst_ip'] = row['Destination IP']
        
        # Convert ports to integers if possible
        try:
            if 'src_port' in feature and feature['src_port'] is not None:
                feature['src_port'] = int(float(feature['src_port']))
            if 'dst_port' in feature and feature['dst_port'] is not None:
                feature['dst_port'] = int(float(feature['dst_port']))
        except:
            pass
        
        # Normalize protocol
        if 'protocol' in feature:
            feature['protocol_name'] = normalize_protocol(feature['protocol'])
        
        # Set packet size based on available metrics
        if 'packet_size' not in feature:
            # Use mean packet size if available
            if 'fwd_packet_mean' in feature and feature['fwd_packet_mean'] is not None:
                feature['packet_size'] = float(feature['fwd_packet_mean'])
            elif 'bwd_packet_mean' in feature and feature['bwd_packet_mean'] is not None:
                feature['packet_size'] = float(feature['bwd_packet_mean'])
            else:
                # Default to 0
                feature['packet_size'] = 0
        
        # Calculate entropy if not present
        if 'payload_entropy' not in feature:
            feature['payload_entropy'] = 0
        
        # Handle classification label
        if 'classification' in feature and feature['classification'] is not None:
            label = str(feature['classification']).lower()
            # Convert CICIDS labels to simpler format
            if 'benign' in label:
                feature['classification'] = 'benign'
            elif 'attack' in label or 'bot' in label or 'ddos' in label or 'infiltration' in label or 'portscan' in label:
                # Keep the original label for attack type information
                feature['classification'] = label
        else:
            feature['classification'] = 'unknown'
        
        # Add flag indicating this is flow-based data not packet-based
        feature['is_flow'] = True
        
        packet_features.append(feature)
    
    return packet_features

def process_ctu_data(df):
    """
    Process CTU-13 dataset format
    
    Args:
        df: Pandas DataFrame containing the CSV data
        
    Returns:
        List of packet feature dictionaries
    """
    logger.info("Processing CTU-13 format data")
    packet_features = []
    
    # Rename columns to standardized names if present
    columns_to_rename = {}
    for original, standardized in CTU_COLUMNS.items():
        if original in df.columns:
            columns_to_rename[original] = standardized
    
    if columns_to_rename:
        df = df.rename(columns=columns_to_rename)
    
    # Process each flow as a feature
    for _, row in df.iterrows():
        feature = {}
        
        # Add all available data
        for col in df.columns:
            try:
                # Handle NaN values
                if pd.isna(row[col]):
                    feature[col] = None
                else:
                    feature[col] = row[col]
            except:
                feature[col] = None
        
        # Ensure required fields exist
        if 'src_ip' not in feature and 'SrcAddr' in df.columns:
            feature['src_ip'] = row['SrcAddr']
        
        if 'dst_ip' not in feature and 'DstAddr' in df.columns:
            feature['dst_ip'] = row['DstAddr']
        
        # Convert ports to integers if possible
        try:
            if 'src_port' in feature and feature['src_port'] is not None:
                feature['src_port'] = int(float(feature['src_port']))
            if 'dst_port' in feature and feature['dst_port'] is not None:
                feature['dst_port'] = int(float(feature['dst_port']))
        except:
            pass
        
        # Handle protocol
        if 'protocol' in feature:
            feature['protocol_name'] = normalize_protocol(feature['protocol'])
        
        # Add additional calculated fields
        if 'total_bytes' in feature and 'total_packets' in feature:
            try:
                total_bytes = float(feature['total_bytes'])
                total_packets = float(feature['total_packets'])
                if total_packets > 0:
                    feature['packet_size'] = total_bytes / total_packets
                else:
                    feature['packet_size'] = 0
            except:
                feature['packet_size'] = 0
        else:
            feature['packet_size'] = 0
        
        # Handle CTU-13 specific botnet labels
        if 'Label' in df.columns:
            label = str(row['Label']).lower()
            if 'botnet' in label:
                feature['classification'] = 'botnet'
            elif 'normal' in label or 'background' in label:
                feature['classification'] = 'benign'
            else:
                feature['classification'] = label
        
        # Add flag indicating this is flow-based data not packet-based
        feature['is_flow'] = True
        
        packet_features.append(feature)
    
    return packet_features

def process_generic_data(df):
    """
    Process generic network data format
    
    Args:
        df: Pandas DataFrame containing the CSV data
        
    Returns:
        List of packet feature dictionaries
    """
    logger.info("Processing generic network data format")
    packet_features = []
    
    # First check for required columns
    required_columns_found = True
    required_columns = ['src_ip', 'dst_ip']
    missing_columns = [col for col in required_columns if col not in df.columns]
    
    if missing_columns:
        logger.warning(f"CSV is missing required columns: {', '.join(missing_columns)}")
        # Try alternative column names
        alternative_columns = {
            'src_ip': ['Source', 'Source IP', 'src', 'ip.src', 'SrcAddr', 'srcip', 'src_addr'],
            'dst_ip': ['Destination', 'Destination IP', 'dst', 'ip.dst', 'DstAddr', 'dstip', 'dst_addr']
        }
        
        # Create column mappings
        col_mapping = {}
        for req_col in missing_columns:
            for alt_col in alternative_columns[req_col]:
                if alt_col in df.columns:
                    col_mapping[alt_col] = req_col
                    break
        
        # If we found alternative columns, rename them
        if len(col_mapping) == len(missing_columns):
            logger.info(f"Using alternative column names: {col_mapping}")
            df = df.rename(columns=col_mapping)
        else:
            # Still missing columns, need to add placeholders
            required_columns_found = False
    
    # Process each row
    for _, row in df.iterrows():
        feature = {}
        
        # Handle missing required columns
        if not required_columns_found:
            for col in missing_columns:
                if col == 'src_ip':
                    # Try to find a botnet/attacker IP if available in this row
                    if 'classification' in row and row['classification'] != 'benign':
                        feature[col] = identify_potential_malicious_ip(row)
                    else:
                        feature[col] = '0.0.0.0'  # Add placeholder
                else:
                    feature[col] = '0.0.0.0'  # Add placeholder
        
        # Add all available columns
        for col in df.columns:
            # Handle NaN values
            if pd.isna(row[col]):
                feature[col] = None
            else:
                feature[col] = row[col]
        
        # Ensure numeric fields are properly formatted
        for numeric_field in ['src_port', 'dst_port', 'packet_size', 'ttl', 'payload_length']:
            if numeric_field in feature and feature[numeric_field] is not None:
                try:
                    feature[numeric_field] = float(feature[numeric_field])
                except (ValueError, TypeError):
                    feature[numeric_field] = 0
        
        # Set defaults for fields that are needed but might not be present
        if 'src_port' not in feature or feature['src_port'] is None:
            feature['src_port'] = 0
        if 'dst_port' not in feature or feature['dst_port'] is None:
            feature['dst_port'] = 0
        if 'packet_size' not in feature or feature['packet_size'] is None:
            feature['packet_size'] = 0
        
        # Determine protocol if available
        if 'protocol' in feature:
            feature['protocol_name'] = normalize_protocol(feature['protocol'])
        elif 'proto' in feature:
            feature['protocol_name'] = normalize_protocol(feature['proto'])
        elif 'protocol_name' not in feature:
            if feature['src_port'] == 53 or feature['dst_port'] == 53:
                feature['protocol_name'] = 'DNS'
            elif feature['src_port'] == 80 or feature['dst_port'] == 80:
                feature['protocol_name'] = 'HTTP'
            elif feature['src_port'] == 443 or feature['dst_port'] == 443:
                feature['protocol_name'] = 'HTTPS'
            else:
                feature['protocol_name'] = 'UNKNOWN'
        
        # Add flag indicating this is likely packet-based data
        feature['is_flow'] = False
        
        packet_features.append(feature)
    
    return packet_features

def identify_potential_malicious_ip(row):
    """
    Try to identify a potential malicious IP from the row data
    Used when src_ip column is missing
    
    Args:
        row: DataFrame row
        
    Returns:
        IP address string
    """
    # Check if any column looks like an IP address
    for col, value in row.items():
        if isinstance(value, str) and '.' in value:
            parts = value.split('.')
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                # Found something that looks like an IP
                return value
    
    # Fallback to botnet IP ranges used in CTU-13
    return '147.32.84.165'  # Default CTU-13 botnet IP

def process_csv_for_training(csv_path, category_id):
    """
    Process a CSV file for model training and store the data in the database
    Enhanced for CICIDS 2017 and CTU-13 datasets
    
    Args:
        csv_path: Path to the CSV file
        category_id: ID of the threat category this data represents
        
    Returns:
        Dictionary containing processing results
    """
    try:
        logger.info(f"Processing CSV for training: {os.path.basename(csv_path)}, Category ID: {category_id}")
        
        # Process the CSV file
        packet_features = process_csv_file(csv_path)
        
        if not packet_features:
            return {
                'status': 'error',
                'message': 'Failed to extract features from the CSV file'
            }
        
        # Get the category - support both ID and string name
        category = None
        
        # Try to get by ID first
        try:
            if isinstance(category_id, int) or category_id.isdigit():
                category = ThreatCategory.query.get(int(category_id))
        except (ValueError, AttributeError):
            pass
            
        # If not found by ID, try to find by name
        if not category and isinstance(category_id, str):
            # Clean up the category name
            category_name = category_id.strip()
            category = ThreatCategory.query.filter(ThreatCategory.name.ilike(f"%{category_name}%")).first()
            
        # If still not found, try to create it
        if not category:
            try:
                # Check if we need to create a new category
                if isinstance(category_id, str) and len(category_id) > 0:
                    logger.info(f"Creating new threat category: {category_id}")
                    
                    # Determine the appropriate enum value
                    enum_value = None
                    for enum_item in ThreatCategoryEnum:
                        if category_id.lower() in enum_item.name.lower():
                            enum_value = enum_item
                            break
                    
                    # If no matching enum, use OTHER
                    if enum_value is None:
                        enum_value = ThreatCategoryEnum.OTHER
                    
                    # Create new category
                    new_category = ThreatCategory(
                        name=category_id,
                        description=f"Automatically created category for {category_id}",
                        severity=3,  # Default medium severity
                        category_type=enum_value
                    )
                    
                    db.session.add(new_category)
                    db.session.commit()
                    
                    category = new_category
                    logger.info(f"Created new category with ID: {category.id}")
            except Exception as e:
                logger.error(f"Error creating new category: {e}")
        
        if not category:
            return {
                'status': 'error',
                'message': f'Category ID "{category_id}" not found and could not be created'
            }
        
        # Create file hash for uniqueness checking
        file_hash = hashlib.md5(open(csv_path, 'rb').read()).hexdigest()
        
        # Check if this file has already been processed
        existing = TrainingData.query.filter_by(file_hash=file_hash).first()
        if existing:
            return {
                'status': 'error',
                'message': f'This CSV file has already been processed (ID: {existing.id})'
            }
        
        # Analyze the data to get statistical features
        stats = extract_statistical_features(packet_features)
        
        # Apply classification based on the category
        for feature in packet_features:
            # For training data, override the classification with the category
            feature['classification'] = category.name
        
        # Store the training data reference in the database
        training_data = TrainingData(
            filename=os.path.basename(csv_path),
            file_hash=file_hash,
            category_id=category.id,
            feature_count=len(packet_features),
            added_at=datetime.utcnow()
        )
        
        db.session.add(training_data)
        db.session.commit()
        
        # Initialize default return values
        training_result = {'status': 'error', 'message': 'Model training failed'}
        detected_threats = []
        threat_matches = 0
        
        # Train the model with the new data
        try:
            from ml_model import train_model, rule_based_detection
            
            # Safely apply rule-based detection
            try:
                detected_threats = rule_based_detection(packet_features, stats)
            except Exception as detection_error:
                logger.error(f"Error in rule-based detection: {detection_error}")
                detected_threats = []
            
            # Ensure detected_threats is a list
            if not isinstance(detected_threats, list):
                detected_threats = []
            
            # Create a temporary directory to hold training data
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create a temporary CSV file for training
                temp_csv = os.path.join(temp_dir, 'train_data.csv')
                df = pd.DataFrame(packet_features)
                df.to_csv(temp_csv, index=False)
                
                # Train with just this file
                training_result = train_model([temp_csv], [category.name])
                
                if training_result['status'] == 'success':
                    logger.info(f"Successfully trained model with CSV data: {training_result}")
                else:
                    logger.warning(f"Model training returned warnings: {training_result}")
        except Exception as train_error:
            logger.error(f"Error training model with CSV data: {train_error}")
            # Continue anyway - we've stored the training data
        
        # Get threat match count
        threat_matches = sum(1 for t in detected_threats if t.get('name', '').lower() == category.name.lower())
        
        return {
            'status': 'success',
            'message': f'Successfully processed CSV with {len(packet_features)} records for training category "{category.name}"',
            'samples': len(packet_features),
            'training_id': training_data.id,
            'threat_matches': threat_matches,
            'dataset_stats': stats,
            'training_result': training_result
        }
        
    except Exception as e:
        logger.error(f"Error processing CSV for training: {e}")
        logger.error(traceback.format_exc())
        return {
            'status': 'error',
            'message': f'Error processing CSV file: {str(e)}'
        }

def analyze_csv_data(csv_path):
    """
    Analyze CSV data to detect threats and generate results similar to PCAP analysis
    Enhanced for CICIDS 2017 and CTU-13 datasets
    
    Args:
        csv_path: Path to the CSV file
        
    Returns:
        Dictionary containing analysis results
    """
    try:
        logger.info(f"Analyzing CSV data: {os.path.basename(csv_path)}")
        
        # Process the CSV file and get features
        packet_features = process_csv_file(csv_path)
        
        if not packet_features or len(packet_features) == 0:
            return {
                'status': 'error',
                'message': 'CSV file contains no usable data',
                'threats': [],
                'summary': {
                    'is_malicious': False,
                    'threat_count': 0,
                    'packet_count': 0,
                    'confidence': 0.0
                }
            }
        
        # Determine if dataset has its own classifications
        has_classifications = any('classification' in p and p['classification'] != 'unknown' for p in packet_features)
        
        # Extract dataset type information
        dataset_type = 'Generic'
        if packet_features and 'is_flow' in packet_features[0]:
            if packet_features[0]['is_flow']:
                # Check for CICIDS specific fields
                if any('fwd_packets' in p for p in packet_features):
                    dataset_type = 'CICIDS'
                # Check for CTU specific fields
                elif any('direction' in p for p in packet_features):
                    dataset_type = 'CTU'
                else:
                    dataset_type = 'Flow-based'
            else:
                dataset_type = 'Packet-based'
        
        # Analyze the packet data using the ML model
        from ml_model import analyze_packet_features
        analysis_results = analyze_packet_features(packet_features)
        
        # Add CSV source information to the results
        analysis_results['source_type'] = 'CSV'
        analysis_results['dataset_type'] = dataset_type
        analysis_results['filename'] = os.path.basename(csv_path)
        
        # Add traffic summary information
        stats = extract_statistical_features(packet_features)
        
        if 'traffic_summary' not in analysis_results:
            analysis_results['traffic_summary'] = {}
        
        # Update traffic summary with packet data
        analysis_results['traffic_summary']['packet_data'] = packet_features[:100]  # limit to 100 entries to avoid overload
        
        # If dataset has its own classifications, count them and add to results
        if has_classifications:
            classification_counts = {}
            for p in packet_features:
                if 'classification' in p and p['classification']:
                    c = str(p['classification']).lower()
                    if c in classification_counts:
                        classification_counts[c] += 1
                    else:
                        classification_counts[c] = 1
            
            analysis_results['dataset_classifications'] = classification_counts
            
            # Calculate potential attack percentage
            total = len(packet_features)
            benign_count = classification_counts.get('benign', 0) + classification_counts.get('normal', 0)
            attack_percent = 100 * (total - benign_count) / total if total > 0 else 0
            analysis_results['dataset_attack_percent'] = attack_percent
        
        # Add other stats
        for key, value in stats.items():
            if key not in analysis_results['traffic_summary']:
                analysis_results['traffic_summary'][key] = value
        
        # Add dataset-specific insights
        if dataset_type == 'CICIDS':
            analysis_results['dataset_insights'] = extract_cicids_insights(packet_features)
        elif dataset_type == 'CTU':
            analysis_results['dataset_insights'] = extract_ctu_insights(packet_features)
        
        logger.info(f"Analysis complete: {len(analysis_results.get('threats', []))} threats detected")
        
        return analysis_results
        
    except Exception as e:
        logger.error(f"Error analyzing CSV data: {e}")
        logger.error(traceback.format_exc())
        return {
            'status': 'error',
            'message': f'Error analyzing CSV data: {str(e)}',
            'threats': [],
            'summary': {
                'is_malicious': False,
                'threat_count': 0,
                'packet_count': 0,
                'confidence': 0.0
            }
        }

def extract_cicids_insights(packet_features):
    """
    Extract specific insights from CICIDS dataset
    
    Args:
        packet_features: List of packet feature dictionaries
        
    Returns:
        Dictionary of insights
    """
    insights = {}
    
    # CICIDS contains specific attack types
    attacks = {}
    for p in packet_features:
        if 'classification' in p and p['classification'] and p['classification'] != 'benign':
            attack_type = p['classification']
            if attack_type in attacks:
                attacks[attack_type] += 1
            else:
                attacks[attack_type] = 1
    
    insights['attack_types'] = attacks
    
    # Calculate flow statistics
    flow_durations = [p.get('flow_duration', 0) for p in packet_features if 'flow_duration' in p]
    if flow_durations:
        insights['avg_flow_duration'] = np.mean(flow_durations)
        insights['max_flow_duration'] = np.max(flow_durations)
    
    # Analyze packet rates
    packet_rates = [p.get('packet_rate', 0) for p in packet_features if 'packet_rate' in p]
    if packet_rates:
        insights['avg_packet_rate'] = np.mean(packet_rates)
        insights['max_packet_rate'] = np.max(packet_rates)
    
    # Check for potential DoS attacks
    if insights.get('max_packet_rate', 0) > 1000:
        insights['potential_dos'] = True
    else:
        insights['potential_dos'] = False
    
    return insights

def extract_ctu_insights(packet_features):
    """
    Extract specific insights from CTU-13 dataset
    
    Args:
        packet_features: List of packet feature dictionaries
        
    Returns:
        Dictionary of insights
    """
    insights = {}
    
    # Count botnet and normal traffic
    classifications = {}
    for p in packet_features:
        if 'classification' in p and p['classification']:
            cls = p['classification']
            if cls in classifications:
                classifications[cls] += 1
            else:
                classifications[cls] = 1
    
    insights['traffic_classifications'] = classifications
    
    # Count traffic direction
    directions = {}
    for p in packet_features:
        if 'direction' in p and p['direction']:
            direction = p['direction']
            if direction in directions:
                directions[direction] += 1
            else:
                directions[direction] = 1
    
    insights['traffic_directions'] = directions
    
    # Identify potential C&C communication
    # In CTU-13, botnet C&C often involves repeated small packets to the same destination
    src_dst_pairs = {}
    for p in packet_features:
        if 'src_ip' in p and 'dst_ip' in p:
            pair = f"{p['src_ip']}->{p['dst_ip']}"
            if pair in src_dst_pairs:
                src_dst_pairs[pair] += 1
            else:
                src_dst_pairs[pair] = 1
    
    # Find pairs with suspiciously high counts
    suspicious_pairs = {pair: count for pair, count in src_dst_pairs.items() if count > 100}
    insights['potential_cc_channels'] = len(suspicious_pairs)
    
    # Analyze packet size distribution
    if 'classification' in packet_features[0]:
        normal_sizes = [p.get('packet_size', 0) for p in packet_features if p.get('classification') == 'benign']
        botnet_sizes = [p.get('packet_size', 0) for p in packet_features if p.get('classification') != 'benign']
        
        if normal_sizes:
            insights['avg_normal_packet_size'] = np.mean(normal_sizes)
        if botnet_sizes:
            insights['avg_botnet_packet_size'] = np.mean(botnet_sizes)
    
    # Identify potential port scanning activity
    dst_ports_per_src = {}
    for p in packet_features:
        if 'src_ip' in p and 'dst_port' in p:
            src_ip = p['src_ip']
            dst_port = p['dst_port']
            
            if src_ip not in dst_ports_per_src:
                dst_ports_per_src[src_ip] = set()
            
            dst_ports_per_src[src_ip].add(dst_port)
    
    # Sources accessing many different ports may be conducting port scans
    potential_scanners = {src: len(ports) for src, ports in dst_ports_per_src.items() if len(ports) > 20}
    insights['potential_port_scanners'] = len(potential_scanners)
    
    return insights

def csv_to_pcap_features(csv_path):
    """
    Convert CSV data to a format compatible with PCAP processing
    Enhanced for CICIDS 2017 and CTU-13 datasets
    
    Args:
        csv_path: Path to the CSV file
    
    Returns:
        List of feature dictionaries in PCAP format
    """
    try:
        # Process the CSV file
        packet_features = process_csv_file(csv_path)
        
        if not packet_features:
            logger.error("Failed to extract features from CSV file")
            return None
        
        # Determine if this is flow-based or packet-based data
        is_flow_based = False
        if packet_features and 'is_flow' in packet_features[0]:
            is_flow_based = packet_features[0]['is_flow']
        
        # For flow-based data, we need to convert to packet-based format
        if is_flow_based:
            logger.info("Converting flow-based data to packet-based format")
            pcap_features = []
            
            for flow in packet_features:
                # Estimate number of packets in this flow
                packet_count = 1
                if 'fwd_packets' in flow and 'bwd_packets' in flow:
                    # CICIDS format
                    packet_count = int(float(flow['fwd_packets'] or 0)) + int(float(flow['bwd_packets'] or 0))
                elif 'total_packets' in flow:
                    # CTU format
                    packet_count = int(float(flow['total_packets'] or 1))
                
                # Ensure we have at least one packet
                packet_count = max(1, packet_count)
                
                # Generate representative packets for this flow
                for i in range(min(packet_count, 10)):  # Cap at 10 packets per flow to avoid explosion
                    packet = {}
                    
                    # Copy basic flow information
                    for key in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'protocol_name', 'classification']:
                        if key in flow:
                            packet[key] = flow[key]
                    
                    # Set packet-specific information
                    packet['packet_size'] = flow.get('packet_size', 0)
                    packet['is_flow'] = False
                    
                    # Add TCP flags if this is TCP
                    if flow.get('protocol_name') == 'TCP':
                        # Alternate between common flag combinations
                        if i == 0:
                            packet['tcp_flags_str'] = 'S'  # SYN
                        elif i == packet_count - 1:
                            packet['tcp_flags_str'] = 'FA'  # FIN-ACK
                        else:
                            packet['tcp_flags_str'] = 'PA'  # PUSH-ACK
                    
                    # Add packet timestamp based on flow duration
                    if 'timestamp' in flow and 'flow_duration' in flow:
                        try:
                            base_time = float(flow['timestamp'])
                            duration = float(flow['flow_duration'])
                            # Distribute packets evenly across flow duration
                            packet['timestamp'] = base_time + (i * duration / packet_count)
                        except (ValueError, TypeError):
                            # If conversion fails, use index as relative time
                            packet['timestamp'] = i
                    
                    pcap_features.append(packet)
            
            return pcap_features
        else:
            # Already in packet format
            return packet_features
    
    except Exception as e:
        logger.error(f"Error converting CSV to PCAP features: {e}")
        logger.error(traceback.format_exc())
        return None

def enrich_features_with_geo_info(packet_features):
    """
    Enrich packet features with geographical information for IPs
    
    Args:
        packet_features: List of packet feature dictionaries
        
    Returns:
        Enriched features with geo information
    """
    try:
        # This would normally use a GeoIP database
        # For this example, we'll just identify if IPs are internal or external
        
        for feature in packet_features:
            if 'src_ip' in feature:
                feature['src_ip_internal'] = is_internal_ip(feature['src_ip'])
            
            if 'dst_ip' in feature:
                feature['dst_ip_internal'] = is_internal_ip(feature['dst_ip'])
            
            # Add direction based on internal/external classification
            if 'src_ip_internal' in feature and 'dst_ip_internal' in feature:
                if feature['src_ip_internal'] and not feature['dst_ip_internal']:
                    feature['traffic_direction'] = 'outbound'
                elif not feature['src_ip_internal'] and feature['dst_ip_internal']:
                    feature['traffic_direction'] = 'inbound'
                elif feature['src_ip_internal'] and feature['dst_ip_internal']:
                    feature['traffic_direction'] = 'internal'
                else:
                    feature['traffic_direction'] = 'external'
        
        return packet_features
    
    except Exception as e:
        logger.error(f"Error enriching features with geo info: {e}")
        return packet_features  # Return original features on error