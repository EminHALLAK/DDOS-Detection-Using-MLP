# DDoS Detection Using MLP

A real-time DDoS (Distributed Denial of Service) attack detection system using Machine Learning with Multi-Layer Perceptron (MLP).

## Components

- `mlpDdosDetectionModel.py`: MLP classifier implementation for DDoS detection
- `realTimeModelImplementation.py`: Real-time network traffic monitoring and attack detection
- `dataGenerator.py`: Network traffic data generation
- `csvMerger.py`: Dataset merging utility
- `merged_ddos_dataset.csv`: Training dataset

## Features

- Real-time network traffic monitoring
- MLP-based DDoS attack detection
- Advanced feature engineering
- Performance metrics and visualizations
- Live packet capture and analysis

## Working Scenario

### Data Generation

The dataset for this project was generated using a controlled network environment:

1. **Virtual Machine Setup**:
   - 4 Virtual Machines were configured:
     - 3 Kali Linux VMs (attackers)
     - 1 Windows VM (target)

2. **Traffic Generation**:
   - DDoS Attack Traffic: The Kali Linux VMs were used to launch various DDoS attacks against the Windows VM
   - Normal Traffic: Regular network activity was recorded on the Windows VM
   - The `dataGenerator.py` script was run during both attack and non-attack scenarios to capture network packets

3. **Dataset Creation**:
   - Approximately 500,000 network traffic records were collected
   - Attack traffic was labeled as '1' and normal traffic as '0'
   - The `csvMerger.py` script was used to combine multiple CSV files into the final dataset

### Feature Engineering

Several features were engineered to improve detection accuracy:

1. **Time-based Features**:
   - `time_diff`: Time difference between consecutive packets from the same IP
   - `rolling_avg`: Rolling average of time differences (window size of 5)

2. **Flow-based Features**:
   - Flow duration calculations
   - Bytes per second and packets per second metrics
   - Mean packet length

3. **Protocol-specific Features**:
   - TCP flag analysis (FIN, SYN, RST, PSH, ACK, URG)
   - Protocol identification (TCP/UDP)
   - Destination port analysis

### Real-time Monitoring

The system monitors network traffic in real-time using the following approach:

1. **Packet Capture**:
   - `pyshark` library is used to capture live network packets
   - Interface selection based on the network setup (e.g., Wi-Fi)

2. **Feature Extraction**:
   - Each captured packet is processed to extract relevant features
   - The same feature engineering applied during training is used for live packets

3. **Prediction and Alerting**:
   - The trained MLP model analyzes each packet in real-time
   - Alerts are generated for detected DDoS attacks
   - Detailed information about suspicious traffic is displayed

4. **Continuous Monitoring**:
   - The system runs continuously, analyzing network traffic
   - Performance is optimized for minimal impact on network operations

## Requirements

- Python 3.x
- pandas
- numpy
- scikit-learn
- matplotlib
- pyshark

## Usage

1. Train the model:
```bash
python mlpDdosDetectionModel.py
```

2. Start real-time detection:
```bash
python realTimeModelImplementation.py
```

## Author

Emin HALLAK
