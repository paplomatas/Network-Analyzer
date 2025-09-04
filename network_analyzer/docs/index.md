# Network Analyzer Documentation

Welcome to the developer documentation for the **Network Analyzer**.

## Project Structure

- `capture/` - Packet sniffing and filtering
- `parser/` - Protocol-specific parsers (HTTP, TCP, DNS, etc.)
- `analyzer/` - Modules for traffic, security, and anomaly analysis
- `visualizer/` - Dashboard and visual reports
- `database/` - ORM models and storage logic
- `utils/` - Common utility functions

## ⚙️ Configuration

Default config is in `config.yaml`. It supports options for:
- Capture filters
- Dashboard settings
- Anomaly detection

## 🧪 Running Tests

```bash
pytest tests/
