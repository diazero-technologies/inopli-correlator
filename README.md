# Inopli Correlator v1.1.4

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-GPL--3.0-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.1.4-orange.svg)]()

A powerful, multi-tenant security event correlation and monitoring system designed for SIEM-free continuous monitoring processes. Inopli Correlator provides real-time log analysis, threat intelligence enrichment, and automated alerting capabilities.

## 🚀 Features

- **Multi-tenant Architecture**: Support for multiple organizations with isolated configurations
- **Real-time Log Monitoring**: Continuous monitoring of various log sources using file system watchers
- **Threat Intelligence Integration**: Built-in support for VirusTotal, AbuseIPDB, and Hybrid Analysis
- **Flexible Data Sources**: Support for Linux logs, Wazuh alerts, CrowdStrike events, and Office 365 alerts
- **Rule-based Analysis**: Configurable security rules for detecting various threat patterns
- **Webhook Integration**: Automated alert delivery to external systems
- **Configurable Alert Modes**: Choose between all alerts, CTI-validated only, or test mode

## 📋 Prerequisites

- Python 3.7 or higher
- Access to log files and security data sources
- API keys for threat intelligence services (optional)

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   gh repo clone diazero-technologies/inopli-correlator
   cd inopli-correlator
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the application** (see Configuration section below)

## ⚙️ Configuration

### 1. Data Sources Configuration (`config/sources_config.yaml`)

Configure your data sources and tenants:

```yaml
tenants:
  tenant1:
    name: "Company A"
    token: "YOUR_INOPLI_TOKEN_HERE"
    data_sources:
      - name: "linux_auth"
        path: "/var/log/auth.log"
        enabled: true
        module: "linux"
        event_types: [1001, 1002, 1007, 1004, 1006]
        filters: {}
      
      - name: "wazuh_alerts"
        path: "/var/ossec/logs/alerts/alerts.json"
        enabled: true
        module: "wazuh_file"
        event_types: [100001, 100002, 81633]
        filters:
          agent_ids: ["*"]
```

### 2. Threat Intelligence Configuration (`config/integrations_config.yaml`)

Enable and configure threat intelligence services:

```yaml
integrations:
  virustotal:
    enabled: true
    api_key: "YOUR_VIRUSTOTAL_API_KEY"
    fields: ["ip", "domain", "file_hash"]
  abuseipdb:
    enabled: true
    api_key: "YOUR_ABUSEIPDB_API_KEY"
    fields: ["ip"]
  hybrid_analysis:
    enabled: true
    api_key: "YOUR_HYBRID_ANALYSIS_API_KEY"
    fields: ["file_hash", "ip", "url"]
```

### 3. Business Rules Configuration (`config/business_rules.yaml`)

Configure alert behavior:

```yaml
# Alert mode options:
#   all      - Send all triggered alerts and all CTI alerts (default)
#   cti_only - Only send alerts if validated by CTI
#   none     - Do not send any alerts (test mode)
alert_mode: all
```

## 🚀 Usage

### Basic Usage

Run the correlator:

```bash
python inopli_correlator.py
```

### Debug Mode

Enable debug mode by setting `DEBUG_MODE = True` in `config/debug.py`:

```python
DEBUG_MODE = True
```

### Monitoring Specific Sources

The system automatically monitors all enabled data sources configured in your `sources_config.yaml`. Each source runs in its own thread for optimal performance.

## 📊 Supported Data Sources

### Linux Log Monitoring
- **Authentication logs** (`/var/log/auth.log`)
- **System logs** (`/var/log/syslog`)
- **Security rules**: Brute force attacks, user enumeration, sudo violations, root shell execution, new user creation, crontab modifications, systemd persistence, SSH key injection

### Wazuh Integration
- **File-based alerts** (`/var/ossec/logs/alerts/alerts.json`)
- **Office 365 alerts** via Wazuh
- Configurable event type filtering

### CrowdStrike Integration
- **Event logs** monitoring
- Sensor-based filtering
- Real-time threat detection

## 🔍 Security Rules

The system includes various security rules for different threat scenarios:

- **Brute Force Detection**: Monitors failed login attempts
- **User Enumeration**: Detects user enumeration activities
- **Sudo Violations**: Tracks unauthorized sudo usage
- **Root Shell Execution**: Monitors root shell access
- **New User Creation**: Alerts on unauthorized user creation
- **Crontab Modifications**: Detects persistence mechanisms
- **Systemd Persistence**: Monitors systemd service modifications
- **SSH Key Injection**: Detects unauthorized SSH key additions

## 🔗 Threat Intelligence Integration

### VirusTotal
- IP address reputation
- Domain analysis
- File hash verification

### AbuseIPDB
- IP address blacklist checking
- Reputation scoring

### Hybrid Analysis
- File hash analysis
- IP and URL reputation
- Malware detection

## 📝 Logging and Monitoring

The system provides comprehensive logging through the `utils/event_logger.py` module:

- Event tracking with unique IDs
- Error logging and debugging
- Performance monitoring
- Audit trails

## 🏗️ Architecture

```
inopli-correlator/
├── config/                 # Configuration files
├── cti/                   # Threat intelligence modules
├── datasources/           # Data source monitors
│   └── linux_rules/      # Linux security rules
├── integrations/          # Integration modules
├── utils/                 # Utility modules
├── tests/                 # Test files
└── inopli_correlator.py  # Main application
```

## 🧪 Testing

Run the test suite:

```bash
python -m pytest tests/
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:

- Create an issue in the GitHub repository
- Check the configuration examples in the `config/` directory
- Review the debug logs when `DEBUG_MODE` is enabled

## 🔄 Version History

- **v1.1.4**: Current version with multi-tenant support and enhanced threat intelligence
- **v1.1.0**: Added webhook integration and improved rule engine
- **v1.0.0**: Initial release with basic monitoring capabilities

## ⚠️ Security Considerations

- Store API keys securely and never commit them to version control
- Use appropriate file permissions for log files
- Regularly update dependencies for security patches
- Monitor system resources and adjust thread limits as needed
- Implement proper network security for webhook endpoints

---

**Note**: This is a security monitoring tool. Ensure you have proper authorization to monitor the systems and logs you're configuring.

## 👨‍💻 Author

**Oscar Antonangelo**  
CEO, Diazero Technologies

This tool was developed by Oscar Antonangelo for Diazero Technologies to provide SIEM-free continuous monitoring capabilities combined with [Inopli](https://www.inopli.com/), the cybersecurity cockpit platform.

---

*For more information about Inopli, visit [inopli.com](https://www.inopli.com/) or contact us for enterprise solutions.*
