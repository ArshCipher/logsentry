# LogSentry

**LogSentry** is a real-time log analyzer for detecting suspicious login attempts in system logs. Built with Python, it uses async I/O, machine learning, GeoIP lookup, and visualizations to catch brute-force attacks, unusual login times, and anomalies. Perfect for security enthusiasts and sysadmins.

## Features
- **Real-Time Monitoring**: Watches logs for live updates.
- **GeoIP Lookup**: Maps IPs to locations using MaxMind GeoLite2.
- **Anomaly Detection**: Uses `IsolationForest` for ML-based pattern detection.
- **Async I/O**: High-performance log processing with `asyncio` and `uvloop`.
- **CLI Interface**: Easy-to-use with `typer`.
- **Visualizations**: Interactive heatmaps and geo plots with `plotly`.
- **Exports**: Save results to JSON, CSV, or SQLite.
- **Firewall Integration**: Block suspicious IPs with `iptables` (Linux).

## Installation
1. Clone the repo:
   ```bash
   git clone https://github.com/yourusername/logsentry.git
   cd logsentry