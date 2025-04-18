# Network Traffic Threat Analyzer 

A comprehensive network traffic analysis tool that detects and classifies threats in PCAP files using machine learning and rule-based approaches.

## 🔍 Overview

Network Traffic Threat Analyzer is a powerful, web-based tool designed to analyze network packet capture (PCAP) files for security threats and anomalies. It combines machine learning models with rule-based detection to identify various network threats such as port scanning, DoS attacks, malware communication, and more.

## ✨ Features

- **Multi-format Support**: Analyze PCAP, PCAPNG, CAP, ZIP, and CSV files
- **Threat Detection**: Identify 10+ categories of network threats including:
  - Reconnaissance (Port Scanning)
  - Denial of Service (DoS/DDoS)
  - Network Protocol Attacks
  - Web Attacks (SQL Injection, XSS, etc.)
  - Malicious Behavior (Malware, C2, Data Exfiltration)
  - And more...
- **Traffic Visualization**:
  - Network flow graphs
  - Protocol distribution
  - IP communication patterns
- **Detailed Analysis Reports**:
  - Threat indicators
  - Recommended actions
  - Involved IP addresses
  - Traffic flows
- **Batch Processing**: Analyze multiple files within ZIP archives
- **CSV Support**: Process network traffic CSV datasets (e.g., CICIDS 2017, CTU-13)
- **Model Training**: Train the detection model with custom data

## 🖥️ Screenshots

![Ảnh minh họa](./images/tools.PNG)

## 🛠️ Installation

### Prerequisites
- Python 3.9+
- pip
- Virtual environment (recommended)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/pcap-analyzer.git
   cd pcap-analyzer
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python main.py
   ```

5. Access the web interface at http://localhost:5000

### Optional Dependencies

- **tshark**: For enhanced PCAP processing (install Wireshark)
- **PostgreSQL**: For production deployments (update `DATABASE_URL` in environment)

## 📋 Usage Guide

### Analyzing PCAP Files

1. From the main page, click "Upload File" or drag and drop your PCAP file
2. Select the file type if needed (PCAP/PCAPNG/CAP/ZIP/CSV)
3. Click "Analyze" to start processing
4. View the generated analysis report showing:
   - Detected threats
   - Traffic summary
   - IP details and traffic flows

### Viewing Traffic Details

1. From the analysis results page, click "View Traffic Details"
2. Explore the interactive network graph showing:
   - Communication patterns between IPs
   - Internal vs external traffic
   - Suspicious connections

### Exporting Reports

1. From the analysis results page, click "Export Report"
2. Choose the report format (HTML)
3. Download the report for sharing or further analysis

### Training the Model

1. Navigate to the "Training" section
2. Upload labeled PCAP or CSV files with known threats
3. Assign appropriate threat categories to each file
4. Click "Train Model" to enhance detection capabilities
5. View training status and model performance metrics

## 🔄 Model Training

The Network Traffic Threat Analyzer uses machine learning to improve threat detection accuracy over time. The detection model can be trained with your own data:

### Training Data Requirements

- PCAP files containing examples of specific threat categories
- CSV datasets (must follow CICIDS 2017 or CTU-13 format)

### Training Process

1. Prepare labeled data files (one per threat category)
2. Navigate to Training > Upload Training Data
3. Assign appropriate threat categories for each file
4. The system extracts features and updates the model
5. View performance metrics in the Training Dashboard

### Default Model

The system includes a baseline model trained on common threat patterns. However, training with your own network data will significantly improve detection accuracy for your specific environment.

## 🔒 Security Considerations

- The tool is designed for use in controlled environments
- Avoid uploading sensitive or confidential network captures
- Implement access controls when deploying in shared environments
- Use a secure HTTPS connection for production deployments

## 🚀 Deployment

For production deployment:

1. Set secure environment variables:
   ```bash
   export SESSION_SECRET=your_secure_random_string
   export DATABASE_URL=postgresql://user:password@localhost/pcap_analyzer
   ```

2. Use a production WSGI server:
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:8000 wsgi:app
   ```

3. Configure a reverse proxy (Nginx/Apache) with HTTPS

## 🧩 Architecture

The Network Traffic Threat Analyzer consists of several core components:

- **Web Interface**: Flask-based web application
- **PCAP Processor**: Extracts features from network packet captures
- **ML Model**: Identifies threats using ensemble machine learning
- **Rule Engine**: Applies heuristic rules for enhanced detection
- **Database**: Stores analysis results and training data

## ⚠️ Disclaimer

This tool is provided for educational and research purposes only. The developers are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before analyzing network traffic in any environment.

Network Traffic Threat Analyzer should not be used as the sole security measure for network monitoring or threat detection. It is intended to complement existing security practices and tools.

Detection results are based on pattern analysis and may include false positives or miss certain threats. Always verify findings manually when investigating security incidents.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

Made with ❤️ for network security enthusiasts
