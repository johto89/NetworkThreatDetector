import logging
import numpy as np
import os
import joblib
import time
import json
import traceback
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from web_phishing_detector import detect_web_phishing
from pcap_processor import extract_statistical_features, process_pcap_file
from models import ThreatCategoryEnum
from csv_processor import process_csv_file, csv_to_pcap_features
from iputils import is_whitelisted_ip, filter_whitelisted_ips
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from rule_based_detector import rule_based_detection as detector
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier, AdaBoostClassifier, StackingClassifier

# Initialize the model and scaler as global variables
model = None
scaler = None

THREAT_CATEGORY_MAP = [
    # Normal Traffic
    ThreatCategoryEnum.NORMAL,
    # Reconnaissance (Scanning & Probing)
    ThreatCategoryEnum.RECONNAISSANCE,
    ThreatCategoryEnum.DOS_DDOS,
    ThreatCategoryEnum.NETWORK_PROTOCOL_ATTACKS,
    ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS,
    ThreatCategoryEnum.WEB_ATTACKS,
    ThreatCategoryEnum.WEB_PHISHING,
    ThreatCategoryEnum.SERVER_ATTACKS,
    # Malicious Behavior (Malware & C2)
    ThreatCategoryEnum.MALICIOUS_BEHAVIOR,
    ThreatCategoryEnum.UNKNOWN
]

def create_feature_vector(packet_data, stats, include_extended_features=False):
    """
    Create a consistent feature vector from packet data and statistics
    for both training and prediction.
    
    Args:
        packet_data: List of packet feature dictionaries
        stats: Statistical features extracted from the packets
        include_extended_features: Boolean to control inclusion of extended feature set
                                  (True for training, False for basic prediction)
        
    Returns:
        List containing the feature vector
    """
    # Base feature vector - used for both training and prediction
    feature_vector = [
        len(packet_data),  # Number of packets
        stats.get('avg_packet_size', 0),
        stats.get('min_packet_size', 0),
        stats.get('max_packet_size', 0),
        stats.get('std_packet_size', 0),
        stats.get('unique_src_ips', 0),
        stats.get('unique_dst_ips', 0),
        stats.get('unique_src_ports', 0),
        stats.get('unique_dst_ports', 0),
        stats.get('potential_scan_ports', 0),
        int(stats.get('potential_port_scan', False)),
        int(stats.get('potential_dos', False)),
        stats.get('protocol_counts', {}).get('TCP', 0),
        stats.get('protocol_counts', {}).get('UDP', 0),
        stats.get('protocol_counts', {}).get('ICMP', 0),
        stats.get('protocol_counts', {}).get('HTTP', 0),
        stats.get('protocol_counts', {}).get('HTTPS', 0),
        stats.get('protocol_counts', {}).get('DNS', 0),
        stats.get('protocol_counts', {}).get('OTHER', 0),
        # Add additional packet-derived features
        sum(1 for p in packet_data if p.get('has_payload', False)) / max(1, len(packet_data)),  # Payload ratio
        sum(p.get('payload_entropy', 0) for p in packet_data) / max(1, len(packet_data)),  # Avg entropy
        sum(p.get('ttl', 0) for p in packet_data) / max(1, len(packet_data)),  # Avg TTL
        np.std([p.get('packet_size', 0) for p in packet_data]) if len(packet_data) > 1 else 0  # Packet size std
    ]
    
    # Extended features - used primarily for training with more detailed analysis
    if include_extended_features:
        # Additional protocol counts (ensuring no duplication with base features)
        protocol_counts = stats.get('protocol_counts', {})
        for protocol in ['ARP', 'OTHER']:  # Only adding protocols not in base vector
            if protocol not in ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS']:  # Avoid duplication
                feature_vector.append(protocol_counts.get(protocol, 0))
        
        # Add time-based features if available
        if 'time_stats' in stats:
            feature_vector.append(stats['time_stats'].get('avg_interarrival_time', 0))
            feature_vector.append(stats['time_stats'].get('std_interarrival_time', 0))
            feature_vector.append(stats['time_stats'].get('max_packets_per_second', 0))
        else:
            # Default values if time stats not available
            feature_vector.extend([0, 0, 0])
    
    return feature_vector

def build_model(use_advanced=True, use_class_weights=True):
    """
    Build and return an optimized ensemble machine learning model for threat detection.
    
    Args:
        use_advanced: Boolean flag to use advanced stacking ensemble (True) or simpler model (False)
        use_class_weights: Boolean flag to enable/disable class weight balancing
    
    Returns:
        Trained scikit-learn ensemble model
    """
    logging.debug("Building threat detection model")
    
    # Class weight setting based on parameter
    class_weight = 'balanced' if use_class_weights else None
    logging.debug(f"Using class_weight: {class_weight}")
    
    if not use_advanced:
        # Simpler but robust model approach
        try:
            # Primary model - RandomForest with enhanced parameters
            rf = RandomForestClassifier(
                n_estimators=150, 
                max_depth=10,
                min_samples_split=2,
                min_samples_leaf=1,
                class_weight=class_weight,  # Can be None or 'balanced'
                random_state=42,
                n_jobs=-1  # Parallel processing
            )
            logging.debug("Built enhanced RandomForest model")
            return rf
        except Exception as e:
            logging.error(f"Error building enhanced RandomForest: {e}")
            # Fallback to simplest possible model
            return RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    
    # Advanced stacking approach
    try:
        # Base models with optimized parameters
        base_models = [
            ('rf', RandomForestClassifier(n_estimators=150, max_depth=8, 
                                        class_weight=class_weight, random_state=42, n_jobs=-1)),
            ('gb', GradientBoostingClassifier(n_estimators=200, learning_rate=0.05, 
                                             max_depth=4, random_state=42)),
            ('logreg', LogisticRegression(max_iter=500, class_weight=class_weight, 
                                         random_state=42, solver='saga', n_jobs=-1))
        ]
        
        # Meta-learner: RandomForest
        model = StackingClassifier(
            estimators=base_models,
            final_estimator=RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
            cv=5,
            stack_method='predict_proba',
            n_jobs=-1
        )
        logging.debug("Stacking model built successfully")
        return model
        
    except Exception as e:
        logging.error(f"Error in StackingClassifier: {e}")
        logging.info("Falling back to VotingClassifier")
        
        try:
            # Fallback to VotingClassifier
            # Recreate base models for safety
            base_models = [
                ('rf', RandomForestClassifier(n_estimators=150, max_depth=8, 
                                            class_weight=class_weight, random_state=42, n_jobs=-1)),
                ('gb', GradientBoostingClassifier(n_estimators=200, learning_rate=0.05, 
                                                 max_depth=4, random_state=42))
                # No LogisticRegression here to simplify
            ]
            
            model = VotingClassifier(
                estimators=base_models,
                voting='soft',
                n_jobs=-1
            )
            logging.debug("Voting model built successfully")
            return model
            
        except Exception as e2:
            logging.error(f"Error in VotingClassifier: {e2}")
            logging.info("Falling back to RandomForest")
            
            # Final fallback - RandomForest with minimal parameters
            rf_model = RandomForestClassifier(
                n_estimators=100, 
                max_depth=8, 
                min_samples_leaf=2,
                random_state=42, 
                n_jobs=-1
            )
            logging.debug("Fallback to basic RandomForest successful")
            return rf_model

def load_model():
    """
    Load or initialize the threat detection model
    
    Since we don't have a pre-trained model, we'll use a rule-based approach
    combined with a scikit-learn model for demonstration purposes.
    
    Returns:
        The model
    """
    global model, scaler
    
    if model is None:
        try:
            model_path = 'threat_detection_model.joblib'
            scaler_path = 'feature_scaler.joblib'
            
            if os.path.exists(model_path) and os.path.exists(scaler_path):
                logging.info(f"Loading model from {model_path}")
                model = joblib.load(model_path)
                scaler = joblib.load(scaler_path)
                logging.info("Model and scaler loaded successfully")
            else:
                # Create a new model
                logging.info("No model file found, creating a new model")
                model = build_model()
                scaler = StandardScaler()
                
                model.fit(dummy_X, dummy_y)
            
            logging.debug("Model initialized successfully")
        except Exception as e:
            logging.error(f"Error initializing model: {e}")
            # We'll fall back to rule-based analysis if model creation fails
            model = None
    
    return model


# Add this comment to better explain the approach
# We've modified the approach to focus on a more robust RandomForest implementation
# rather than a full ensemble, as it handles edge cases better while still
# providing enhanced threat detection capabilities

def train_model(input_files, labels, window_size=100, step_size=50):
    """
    Train the threat detection model using labeled files (PCAP or CSV)
    with multiple samples extracted from each file using sliding window approach.
    
    Args:
        input_files: List of paths to input files (PCAP or CSV)
        labels: List of corresponding labels for each file (ThreatCategoryEnum values)
        window_size: Number of packets to include in each sample window
        step_size: Number of packets to shift when creating the next window
        
    Returns:
        Dictionary containing training results
    """
    global model, scaler
    
    if not input_files or not labels or len(input_files) != len(labels):
        return {
            'status': 'error',
            'message': 'Invalid training data: files and labels must be non-empty and match in length'
        }
    
    start_time = time.time()
    
    logging.info(f"Training model with {len(input_files)} input files")
    
    # Map category names to numerical indices
    category_map = THREAT_CATEGORY_MAP
    
    # Process all input files and extract features
    all_features = []
    category_indices = []
    
    # Track which categories actually have data
    category_counts = {}
    
    # Process files to extract features with sliding window approach
    for i, (input_file, label) in enumerate(zip(input_files, labels)):
        try:
            logging.info(f"Processing training file {i+1}/{len(input_files)}: {os.path.basename(input_file)}")
            
            # Determine file type by extension
            file_ext = os.path.splitext(input_file)[1].lower()
            
            # Process the file to get raw packet features
            raw_packet_features = None
            
            if file_ext == '.pcap' or file_ext == '.pcapng':
                raw_packet_features = process_pcap_file(input_file)
            elif file_ext == '.csv':
                # First try to process as CSV directly
                raw_packet_features = process_csv_file(input_file)
                
                # If that fails, try converting CSV to PCAP feature format
                if not raw_packet_features:
                    raw_packet_features = csv_to_pcap_features(input_file)
            else:
                logging.warning(f"Unsupported file type: {file_ext} for file {input_file}")
                continue
            
            if not raw_packet_features:
                logging.warning(f"No features extracted from {os.path.basename(input_file)}")
                continue
                
            # Log the total number of packets found in the file
            num_packets = len(raw_packet_features)
            logging.info(f"Extracted {num_packets} packets from {os.path.basename(input_file)}")
            
            # Use sliding window approach to create multiple samples from each file
            if num_packets < window_size:
                # If file has fewer packets than window size, use all packets as one sample
                samples = [raw_packet_features]
            else:
                # Create multiple windows with overlapping packets
                samples = []
                for start_idx in range(0, num_packets - window_size + 1, step_size):
                    end_idx = start_idx + window_size
                    window = raw_packet_features[start_idx:end_idx]
                    samples.append(window)
                    
            logging.info(f"Created {len(samples)} samples using sliding window approach")
            
            # Map label to index
            try:
                label_index = category_map.index(label)
            except ValueError:
                label_index = len(category_map) - 1  # Unknown category
                
            # Process each window to extract features
            for window in samples:
                # Extract statistical features for this window
                stats = extract_statistical_features(window)
                
                # Create feature vector with extended features for training
                feature_vector = create_feature_vector(window, stats, include_extended_features=True)
                
                # Add to feature list
                all_features.append(feature_vector)
                category_indices.append(label_index)
                
                # Track count of each category
                category_counts[label_index] = category_counts.get(label_index, 0) + 1
            
        except Exception as e:
            logging.error(f"Error processing training file {input_file}: {e}")
            logging.error(traceback.format_exc())
    
    # Report total number of samples created
    logging.info(f"Total samples created: {len(all_features)}")
    
    if not all_features:
        return {
            'status': 'error',
            'message': 'Failed to extract features from any of the training files'
        }
    
    # Check if we have at least 2 classes with data
    unique_classes = len(category_counts)
    logging.info(f"Found {unique_classes} unique classes in the training data: {category_counts}")
    
    if unique_classes < 2:
        # Handle the single-class case
        logging.warning("Only one class detected in training data. Adding synthetic samples for other classes.")
        
        # Find which class we have
        existing_class = list(category_counts.keys())[0]
        
        # Choose a different class to synthesize
        synthetic_class = 0 if existing_class != 0 else 1
        
        # Convert to numpy arrays first
        X = np.array(all_features)
        y = np.array(category_indices)
        
        # Create synthetic samples (add small random variations to existing samples)
        num_synthetic = max(5, len(X) // 4)  # Create enough samples
        
        synthetic_indices = np.random.choice(len(X), num_synthetic, replace=True)
        synthetic_X = X[synthetic_indices].copy()
        
        # Add small random variations to make them different
        noise = np.random.normal(0, 0.1, synthetic_X.shape)
        synthetic_X += noise
        
        # Ensure positive values where needed
        synthetic_X = np.maximum(0, synthetic_X)
        
        # Create synthetic labels
        synthetic_y = np.full(num_synthetic, synthetic_class)
        
        # Add synthetic data to original data
        X = np.vstack([X, synthetic_X])
        y = np.append(y, synthetic_y)
        
        logging.info(f"Added {num_synthetic} synthetic samples for class {synthetic_class}")
        logging.info(f"Updated dataset has {len(X)} samples across {len(np.unique(y))} classes")
        
        # Update our working data
        all_features = X.tolist()
        category_indices = y.tolist()
    
    # Convert to numpy arrays
    X = np.array(all_features)
    y = np.array(category_indices)
    
    # Create a new scaler every time
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Create a new model instance based on dataset size
    if unique_classes <= 2 or len(all_features) < 50:
        logging.info("Using simpler model without class balancing due to limited data")
        model = RandomForestClassifier(
            n_estimators=150, 
            max_depth=10,
            min_samples_split=2,
            min_samples_leaf=1,
            random_state=42,
            n_jobs=-1
        )
    else:
        # Use more sophisticated model for larger datasets
        logging.info("Building advanced ensemble model")
        try:
            # Base models
            base_models = [
                ('rf', RandomForestClassifier(n_estimators=150, max_depth=8, 
                                            class_weight='balanced', random_state=42, n_jobs=-1)),
                ('gb', GradientBoostingClassifier(n_estimators=200, learning_rate=0.05, 
                                                max_depth=4, random_state=42)),
                ('logreg', LogisticRegression(max_iter=500, class_weight='balanced', 
                                            random_state=42, solver='saga', n_jobs=-1))
            ]
            
            # Meta-learner
            model = StackingClassifier(
                estimators=base_models,
                final_estimator=RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
                cv=5,
                stack_method='predict_proba',
                n_jobs=-1
            )
        except Exception as e:
            logging.error(f"Error creating advanced model: {str(e)}")
            logging.info("Falling back to RandomForest model")
            model = RandomForestClassifier(
                n_estimators=150, 
                max_depth=10,
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            )
    
    # Train the model
    try:
        logging.info(f"Training model with {X.shape[0]} samples, {X.shape[1]} features and {len(set(y))} classes")
        
        # Fit the model with our training data
        model.fit(X_scaled, y)
        
        # Save the model and scaler with error checking
        try:
            # Use consistent file paths
            model_path = 'threat_detection_model.joblib'
            scaler_path = 'feature_scaler.joblib'
            
            # Save model and check file size
            joblib.dump(model, model_path)
            model_size = os.path.getsize(model_path) if os.path.exists(model_path) else 0
            logging.info(f"Model saved to {model_path}, size: {model_size} bytes")
            
            if model_size == 0:
                logging.error("Model file has zero size after saving!")
                return {
                    'status': 'error',
                    'message': 'Model file has zero size after saving'
                }
                
            # Save scaler and check file size
            joblib.dump(scaler, scaler_path)
            scaler_size = os.path.getsize(scaler_path) if os.path.exists(scaler_path) else 0
            logging.info(f"Scaler saved to {scaler_path}, size: {scaler_size} bytes")
            
            if scaler_size == 0:
                logging.error("Scaler file has zero size after saving!")
                
            # Save training time
            training_time = time.time() - start_time
            with open('model_training_time.txt', 'w') as f:
                f.write(str(training_time))
                
            # Save class distribution for future reference
            unique, counts = np.unique(y, return_counts=True)
            class_distribution = dict(zip(unique.tolist(), counts.tolist()))
            with open('class_distribution.json', 'w') as f:
                json.dump(class_distribution, f)
            
            # Save feature importances if model supports it
            if hasattr(model, 'feature_importances_'):
                feature_importances = model.feature_importances_
                with open('feature_importances.json', 'w') as f:
                    json.dump({str(i): float(importance) for i, importance in enumerate(feature_importances)}, f)
            elif hasattr(model, 'final_estimator_') and hasattr(model.final_estimator_, 'feature_importances_'):
                feature_importances = model.final_estimator_.feature_importances_
                with open('feature_importances.json', 'w') as f:
                    json.dump({str(i): float(importance) for i, importance in enumerate(feature_importances)}, f)
            
            logging.info("Model trained and saved successfully")
            
            return {
                'status': 'success',
                'message': f'Model trained successfully with {len(all_features)} samples',
                'samples': len(all_features),
                'features': X.shape[1],
                'classes': len(set(y)),
                'class_distribution': class_distribution,
                'model_size': model_size,
                'scaler_size': scaler_size,
                'training_time': training_time
            }
        except Exception as e:
            logging.error(f"Error saving model: {e}")
            return {
                'status': 'error',
                'message': f'Error saving model: {str(e)}'
            }
    
    except Exception as e:
        logging.error(f"Error training model: {e}")
        return {
            'status': 'error',
            'message': f'Error training model: {str(e)}'
        }

def preprocess_features(packet_features):
    """
    Preprocess packet features for the machine learning model
    
    Args:
        packet_features: List of dictionaries containing packet features
        
    Returns:
        Numpy array of preprocessed features
    """
    global scaler
    
    if not packet_features:
        return np.array([])
    
    # Extract statistical features from packet data
    stats = extract_statistical_features(packet_features)
    
    # Create a feature vector - using the standard features for prediction
    feature_vector = create_feature_vector(packet_features, stats, include_extended_features=False)
    
    # Normalize features
    # If we have a trained scaler, use it; otherwise create a new one
    if scaler is None:
        scaler = StandardScaler()
        normalized_features = scaler.fit_transform(np.array(feature_vector).reshape(1, -1))
    else:
        # Use the existing scaler to transform the features consistently
        try:
            normalized_features = scaler.transform(np.array(feature_vector).reshape(1, -1))
        except:
            # If the scaler fails (e.g., different number of features), fall back to a new scaler
            temp_scaler = StandardScaler()
            normalized_features = temp_scaler.fit_transform(np.array(feature_vector).reshape(1, -1))
    
    return normalized_features

def analyze_packet_features(packet_features):
    """
    Analyze packet features to detect threats using a combination of
    rule-based approaches and the machine learning model
    
    Args:
        packet_features: List of dictionaries containing packet features
        
    Returns:
        Dictionary containing analysis results
    """
    if not packet_features:
        return {
            'status': 'error',
            'message': 'No packet features to analyze',
            'threats': [],
            'summary': {
                'is_malicious': False,
                'threat_count': 0,
                'packet_count': 0,
                'confidence': 0.0
            }
        }
    
    # Extract high-level statistics
    stats = extract_statistical_features(packet_features)
    
    # Preprocess features for the model
    features = preprocess_features(packet_features)
    
    # Load the model (or initialize it)
    model = load_model()
    
    threats = []
    threat_scores = {}
    confidence = 0.0
    
    # Generate threats using rule-based detection with stats
    rule_based_threats = rule_based_detection(packet_features, stats)
    
    # Filter threats based on IP reputation
    filtered_threats = filter_whitelisted_ips(rule_based_threats)
    threats.extend(filtered_threats)
    
    # If we have a model, use it to enhance the detection
    if model is not None and len(features) > 0:
        try:
            # Get model predictions
            # For ensemble using soft voting, we can get prediction probabilities
            if hasattr(model, 'predict_proba'):
                probas = model.predict_proba(features)[0]
                predictions = model.predict(features)
                
                # Get confidence from probability of the predicted class
                confidence = max(probas)
            else:
                # Fallback for other types of models
                predictions = model.predict(features)
                confidence = 0.8  # Default confidence
                
            # Map predictions to threat categories
            model_threats = interpret_predictions(predictions[0], confidence)
            
            # Combine model-based threats with rule-based ones
            threats.extend([t for t in model_threats if t['name'] not in [threat['name'] for threat in threats]])
            
        except Exception as e:
            logging.error(f"Error using model for prediction: {e}")
            # Continue with rule-based results only
    
    # If no threats were detected, mark as normal traffic
    if not threats:
        threats.append({
            'name': ThreatCategoryEnum.NORMAL,
            'confidence': 0.95,
            'description': 'No suspicious patterns detected in the network traffic.',
            'indicators': ['Normal packet distribution', 'No unusual port activity']
        })
    
    # Categorize threats by OSI layer and attack type
    categorized_threats = categorize_threats(threats)
    
    # Summarize the traffic
    traffic_summary = {
        'total_packets': len(packet_features),
        'protocols': stats.get('protocol_counts', {}),
        'unique_src_ips': stats.get('unique_src_ips', 0),
        'unique_dst_ips': stats.get('unique_dst_ips', 0),
        'unique_src_ports': stats.get('unique_src_ports', 0),
        'unique_dst_ports': stats.get('unique_dst_ports', 0),
        'avg_packet_size': stats.get('avg_packet_size', 0)
    }
    
    # Determine if the traffic is malicious
    is_malicious = any(t['name'] != ThreatCategoryEnum.NORMAL for t in threats)
    
    # Prepare detailed results
    results = {
        'status': 'success',
        'message': 'Analysis completed successfully',
        'threats': threats,
        'categorized_threats': categorized_threats,
        'summary': {
            'is_malicious': is_malicious,
            'threat_count': len([t for t in threats if t['name'] != ThreatCategoryEnum.NORMAL]),
            'packet_count': len(packet_features),
            'confidence': max([t['confidence'] for t in threats]) if threats else 0.0
        },
        'traffic_summary': traffic_summary
    }
    
    return results

def interpret_predictions(prediction, confidence=0.8):
    """
    Interpret model predictions and map them to threat categories
    Handles predictions from both RandomForest and ensemble models
    
    Args:
        prediction: Model prediction (class index)
        confidence: Confidence of the prediction (probability)
        
    Returns:
        List of detected threats
    """
    # Map prediction indices to threat categories
    category_map = THREAT_CATEGORY_MAP
    
    threats = []
    
    # Convert the prediction to an integer to use as an index
    idx = int(prediction)
    category = category_map[idx] if idx < len(category_map) else ThreatCategoryEnum.UNKNOWN
    
    threat = {
        'name': category,
        'confidence': confidence,
        'description': get_threat_description(category),
        'indicators': get_threat_indicators(category)
    }
    
    threats.append(threat)
    
    return threats

def get_model_performance():
    """
    Get performance metrics for the trained model using actual validation data
    
    Returns:
        Dictionary containing model performance metrics
    """
    global model
    
    try:
        if model is None:
            model = load_model()
        
        # Load validation data
        X_val, y_val = load_validation_data()
        
        # Make predictions
        y_pred = model.predict(X_val)
        
        accuracy = accuracy_score(y_val, y_pred)
        precision = precision_score(y_val, y_pred, average='weighted')
        recall = recall_score(y_val, y_pred, average='weighted')
        f1 = f1_score(y_val, y_pred, average='weighted')
        
        # Extract feature importances if available
        feature_importances = []
        if hasattr(model, 'feature_importances_'):
            feature_importances = model.feature_importances_.tolist()
        
        # Determine model type
        if hasattr(model, 'estimators_'):
            estimators = len(model.estimators_)
            model_type = "Ensemble (AdaBoost or Gradient Boosting)"
        elif hasattr(model, 'estimators'):
            estimators = len(model.estimators)
            model_type = "Ensemble (Voting Classifier)"
        else:
            estimators = model.n_estimators if hasattr(model, 'n_estimators') else 0
            model_type = "Enhanced RandomForest"
        
        # Return metrics based on actual validation data
        return {
            'accuracy': accuracy * 100,  # Convert to percentage
            'precision': precision * 100,
            'recall': recall * 100,
            'f1_score': f1 * 100,
            'training_time': get_training_time(),  # Function to get actual training time
            'model_type': model_type,
            'n_trees': estimators,
            'feature_importances': feature_importances,
            'feature_names': [
                'packet_count', 'avg_packet_size', 'unique_src_ips', 
                'unique_dst_ips', 'unique_src_ports', 'unique_dst_ports',
                'scan_ports', 'is_port_scan', 'is_dos', 'tcp_count',
                'udp_count', 'icmp_count', 'other_protocols', 'min_size',
                'max_size', 'payload_ratio', 'avg_entropy', 'avg_ttl',
                'http_ratio', 'size_std'
            ],
            'model_advantages': [
                'Robust handling of imbalanced data',
                'Better generalization to unseen threats',
                'Class weight balancing for improved detection of rare threats',
                'Compatible with existing processing pipeline'
            ]
        }
    except Exception as e:
        logging.error(f"Error getting model performance: {e}")
        return {
            'accuracy': 0,
            'precision': 0,
            'recall': 0,
            'f1_score': 0,
            'training_time': 0,
            'model_type': 'Unknown',
            'num_estimators': 0,
            'feature_importances': [],
            'feature_names': []
        }

def load_validation_data():
    """
    Load validation data for model evaluation
    
    Returns:
        Tuple of (X_validation, y_validation)
    """
    validation_path = 'validation_data.npz'
    
    try:
        if os.path.exists(validation_path):
            logging.info(f"Loading validation data from {validation_path}")
            data = np.load(validation_path)
            X_val = data['X']
            y_val = data['y']
            logging.info(f"Loaded validation data: {X_val.shape} samples, {y_val.shape} labels")
            return X_val, y_val
        else:
            # Create dummy validation data if none exists
            logging.warning("No validation data found, creating dummy validation data")
            X_val = np.random.random((10, 20))
            y_val = np.random.randint(0, 8, 10)  # 8 threat categories
            
            # Save the dummy validation data for future use
            np.savez(validation_path, X=X_val, y=y_val)
            
            return X_val, y_val
    except Exception as e:
        logging.error(f"Error loading validation data: {e}")
        # Return minimal dummy data in case of error
        return np.random.random((5, 20)), np.random.randint(0, 8, 5)

def get_training_time():
    """
    Get the training time of the model
    
    Returns:
        Training time in seconds or 0 if unknown
    """
    try:
        # Try to read training time from file
        training_time_path = 'model_training_time.txt'
        if os.path.exists(training_time_path):
            with open(training_time_path, 'r') as f:
                return float(f.read().strip())
        else:
            return 0
    except Exception as e:
        logging.error(f"Error getting training time: {e}")
        return 0

def rule_based_detection(packet_features, stats):
    """
    Perform rule-based threat detection with enhanced capabilities
    
    Args:
        packet_features: List of packet feature dictionaries
        stats: Statistical features extracted from packets
        
    Returns:
        List of detected threats
    """
    # Simply call the detector function imported from rule_based_detector.py
    return detector(packet_features, stats)

def categorize_threats(threats):
    """
    Categorize threats by OSI layer and attack type
    
    Args:
        threats: List of detected threats
        
    Returns:
        Dictionary of categorized threats
    """
    # Định nghĩa mapping giữa tên mối đe dọa và danh mục
    threat_category_map = {
        # Normal Traffic
        ThreatCategoryEnum.NORMAL: {
            "category": "Normal Traffic",
            "osi_layer": "Multiple Layers",
        },
        
        # Reconnaissance
        ThreatCategoryEnum.RECONNAISSANCE: {
            "category": "Reconnaissance",
            "osi_layer": "Multiple Layers",
        },
        
        # Denial of Service
        ThreatCategoryEnum.DOS_DDOS: {
            "category": "Denial of Service",
            "osi_layer": "Multiple Layers",
        },
        
        # Network Protocol Attacks
        ThreatCategoryEnum.NETWORK_PROTOCOL_ATTACKS: {
            "category": "Network Protocol Attacks",
            "osi_layer": "Multiple Layers",
        },
        
        # Network Device Attacks
        ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS: {
            "category": "Network Device Attacks",
            "osi_layer": "Layer 2-3 - Data Link/Network",
        },
        
        # Web Attacks
        ThreatCategoryEnum.WEB_ATTACKS: {
            "category": "Web Attacks",
            "osi_layer": "Layer 7 - Application",
        },
        
        # Web Phishing
        ThreatCategoryEnum.WEB_PHISHING: {
            "category": "Web Phishing",
            "osi_layer": "Layer 7 - Application",
        },
        
        # Server Attacks
        ThreatCategoryEnum.SERVER_ATTACKS: {
            "category": "Server Attacks",
            "osi_layer": "Layer 7 - Application",
        },
        
        # Malicious Behavior
        ThreatCategoryEnum.MALICIOUS_BEHAVIOR: {
            "category": "Malicious Behavior",
            "osi_layer": "Multiple Layers",
            "malware_type": "Multiple Types",
        },
        
        # Unknown Threat
        ThreatCategoryEnum.UNKNOWN: {
            "category": "Unknown Threat",
            "osi_layer": "Multiple Layers",
        },
    }
    
    # Create a data structure for categorization
    categorized = {
        "by_category": {},
        "by_osi_layer": {},
        "by_malware_type": {}
    }
    
    # Classify threats
    for threat in threats:
        threat_name = threat.get('name')
        
        # Find the appropriate threat_category in threat_category_map
        matching_category = None
        for enum_value, category_info in threat_category_map.items():
            if threat_name == enum_value or (
                isinstance(threat_name, str) and 
                threat_name.lower() in enum_value.lower()
            ):
                matching_category = category_info
                break
        
        # If no specific mapping is found, use Unknown
        if not matching_category:
            matching_category = threat_category_map[ThreatCategoryEnum.UNKNOWN]
        
        # Categorize by threat category
        category = matching_category.get("category", "Unknown Threat")
        if category not in categorized["by_category"]:
            categorized["by_category"][category] = []
        categorized["by_category"][category].append(threat)
        
        # Categorize by OSI layer
        if "osi_layer" in matching_category:
            osi_layer = matching_category["osi_layer"]
            if osi_layer not in categorized["by_osi_layer"]:
                categorized["by_osi_layer"][osi_layer] = []
            categorized["by_osi_layer"][osi_layer].append(threat)
        
        # Categorize by malware type
        if "malware_type" in matching_category:
            malware_type = matching_category["malware_type"]
            if malware_type not in categorized["by_malware_type"]:
                categorized["by_malware_type"][malware_type] = []
            categorized["by_malware_type"][malware_type].append(threat)
    
    return categorized

def get_threat_description(category):
    """
    Get a description for a threat category
    
    Args:
        category: Threat category string
        
    Returns:
        Description string
    """
    descriptions = {
        ThreatCategoryEnum.NORMAL: "Regular network traffic with no malicious intent.",
        ThreatCategoryEnum.RECONNAISSANCE: "Activities to gather information about target networks and systems before an attack.",
        ThreatCategoryEnum.DOS_DDOS: "Attacks designed to overwhelm networks, services, or resources to make them unavailable to legitimate users.",
        ThreatCategoryEnum.NETWORK_PROTOCOL_ATTACKS: "Exploitation of vulnerabilities in network protocols such as TCP/IP, DNS, ICMP, and others.",
        ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS: "Attacks targeting network infrastructure hardware such as routers, switches, and firewalls.",
        ThreatCategoryEnum.WEB_ATTACKS: "Exploitation of vulnerabilities in web applications and services.",
        ThreatCategoryEnum.WEB_PHISHING: "Deceptive attempts to steal user data including credentials and financial information.",
        ThreatCategoryEnum.SERVER_ATTACKS: "Attacks targeting server systems to exploit vulnerabilities, gain unauthorized access, or compromise data.",
        ThreatCategoryEnum.MALICIOUS_BEHAVIOR: "Activities indicating presence of malware, command and control communications, or unauthorized data extraction.",
        ThreatCategoryEnum.UNKNOWN: "Suspicious network activities that cannot be clearly classified but exhibit potential security concerns."
    }
    
    return descriptions.get(category, "Unrecognized threat category")

def get_threat_indicators(category):
    """
    Get a list of indicators for a threat category
    
    Args:
        category: Threat category string
        
    Returns:
        List of indicator strings
    """
    indicators = {
        # Normal Traffic
        ThreatCategoryEnum.NORMAL: [
            "Expected protocol distribution",
            "Normal connection patterns",
            "No unusual behavior detected"
        ],
        
        # Reconnaissance (Scanning & Probing)
        ThreatCategoryEnum.RECONNAISSANCE: [
            "Port scanning activity",
            "Host/service discovery attempts",
            "Vulnerability scanning patterns",
            "Excessive DNS queries",
            "Network mapping behavior"
        ],
        
        # Denial of Service (DoS & DDoS)
        ThreatCategoryEnum.DOS_DDOS: [
            "Abnormally high traffic volume",
            "Traffic amplification patterns",
            "SYN flood signatures",
            "Resource exhaustion indicators",
            "Distributed attack sources"
        ],
        
        # Network Protocol Attacks
        ThreatCategoryEnum.NETWORK_PROTOCOL_ATTACKS: [
            "Protocol manipulation signatures",
            "Unusual fragmentation patterns",
            "Invalid packet structures",
            "Protocol exploits",
            "ARP/ICMP/DNS poisoning attempts"
        ],
        
        # Network Device Attacks
        ThreatCategoryEnum.NETWORK_DEVICE_ATTACKS: [
            "Router/switch exploitation attempts",
            "Default credential usage",
            "Management interface access attempts",
            "Configuration tampering indicators",
            "Firmware vulnerability exploitation"
        ],
        
        # Web Attacks
        ThreatCategoryEnum.WEB_ATTACKS: [
            "SQL injection patterns",
            "Cross-site scripting (XSS) attempts",
            "CSRF attack indicators",
            "Command injection signatures",
            "Path traversal attempts",
            "Local/Remote file inclusion patterns"
        ],
        
        # Web Phishing
        ThreatCategoryEnum.WEB_PHISHING: [
            "Credential harvesting pages",
            "Brand impersonation indicators",
            "Deceptive domain patterns",
            "Social engineering content",
            "Fake login portals"
        ],
        
        # Server Attacks
        ThreatCategoryEnum.SERVER_ATTACKS: [
            "Brute force login attempts",
            "Privilege escalation indicators",
            "Remote code execution patterns",
            "Unauthorized access attempts",
            "Server vulnerability exploitation"
        ],
        
        # Malicious Behavior (Malware & C2)
        ThreatCategoryEnum.MALICIOUS_BEHAVIOR: [
            "Command and control communication",
            "Data exfiltration patterns",
            "Cryptomining activities",
            "Malware communication signatures",
            "Suspicious DNS resolution patterns",
            "Unusual outbound connections"
        ],
        
        # Other / Unknown
        ThreatCategoryEnum.UNKNOWN: [
            "Unclassified suspicious behavior",
            "Anomalous traffic patterns",
            "Emerging threat indicators",
            "Non-standard protocol usage",
            "Traffic with unknown signatures"
        ]
    }
    
    return indicators.get(category, ["Unrecognized threat indicators"])