# ssh-distributed-detector
# Distributed SSH Brute-Force & IP Rotation Detector

A defensive correlation engine designed to detect coordinated, low-and-slow SSH brute-force attacks that bypass traditional single-IP rate-limiting solutions (such as default Fail2ban rules).

## Detection Mechanics
- **Coordinated Account Targeting**: Flags when a single username is probed by multiple distinct IP addresses within a short timeframe.
- **CIDR Subnet Clustering**: Identifies distributed attack campaigns originating from adjacent IP ranges (e.g., `/24` subnets) commonly leased by proxy networks or cloud-based botnets.
- **Zero Third-Party Dependencies**: Written entirely in standard library Python.

## Usage
```bash
python3 distributed_detector.py

## 🌐 
