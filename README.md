# 🛡️ Android Security Analyzer

A comprehensive security analysis tool for Android applications with both command-line and **web interface** support. Detects vulnerabilities, malicious dependencies, and security misconfigurations with real-time threat intelligence.

![Version](https://img.shields.io/badge/version-1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 🌟 Key Features

### 🚀 **Dual Interface Support**
- **🌐 Web Interface** - Modern FastAPI-powered dashboard with interactive reports
- **💻 Command Line** - Automated analysis for CI/CD integration
- **📊 Database Storage** - Persistent report storage with SQLite backend
- **📄 Multiple Export Formats** - HTML, PDF, and JSON reports

### 🔍 **Advanced Security Detection**
- **🔥 Real-time Vulnerability Scanning** - OSV database integration for CVE detection
- **📦 Smart Dependency Analysis** - Support for Maven Central & Google Maven repositories  
- **🎯 Malicious Dependency Detection** - Identifies known vulnerable libraries
- **⚙️ Gradle Version Catalog Support** - Modern Android project compatibility
- **🔐 API Key & Secret Detection** - Context-aware pattern matching
- **📱 Android Manifest Analysis** - Security configuration auditing

### 🎨 **Interactive Web UI Features**
- **📈 Visual Security Dashboard** - Risk level breakdown and statistics
- **🗂️ Report Management** - Browse, filter, and manage analysis reports
- **👁️ Issue Ignore/Unignore** - Smart pattern-based issue management
- **📋 Real-time Analysis** - Submit projects for analysis via web interface
- **💾 PDF Export** - Professional security reports for stakeholders
- **🔄 Live Updates** - Real-time progress tracking during analysis

## 🖥️ Web Interface

### Dashboard Features
The web interface provides an intuitive dashboard for managing security analyses:

- **📊 Report Overview** - Visual summary of all analyzed projects
- **🔍 Detailed Analysis Views** - In-depth security issue breakdown
- **⚡ Quick Actions** - Start new analyses, download reports, manage issues
- **📱 Responsive Design** - Works on desktop, tablet, and mobile devices

### Report Management
- **🗃️ Historical Reports** - Access all previous security analyses
- **🏷️ Issue Categorization** - Critical, High, Medium, Low risk levels
- **🎯 Smart Filtering** - Filter by app name, package, risk level, or date
- **📄 Export Options** - HTML, PDF, and JSON download formats

### Advanced Issue Management
- **🚫 Issue Ignoring** - Mark false positives or accepted risks
- **🧠 Smart Pattern Recognition** - Global ignore patterns for similar issues
- **🔄 Bulk Operations** - Manage multiple issues simultaneously
- **📝 Ignore Tracking** - Separate display of ignored vs active issues

## 🛠️ Installation & Setup

### Prerequisites
- **Python 3.8+**
- **Internet connection** (for vulnerability databases)
- **Git** (for repository management)

### Quick Start
```bash
# Clone the repository
git clone git@github.com:bewithdhanu/android-security-analyzer.git
cd android-security-analyzer

# Install dependencies
pip install -r requirements.txt

# Start the web interface
python app.py
# Access at: http://localhost:8000

# Or run command-line analysis
python android_security_analyzer.py /path/to/android/project
```

### Web Server Configuration
```bash
# Development server (default)
uvicorn app:app --reload --host 0.0.0.0 --port 8000

# Production server
uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4
```

## 📋 Usage

### 🌐 Web Interface Usage

1. **Start the Web Server**
   ```bash
   python app.py
   ```

2. **Access the Dashboard**
   - Open `http://localhost:8000` in your browser
   - Navigate to "Submit Analysis Request"

3. **Submit Android Project**
   - Enter project path (local directory)
   - Click "Start Security Analysis"
   - Monitor real-time progress

4. **View Results**
   - Browse reports in "Security Reports" section
   - View detailed analysis with risk breakdowns
   - Download PDF or JSON reports
   - Manage issues with ignore/unignore functionality

### 💻 Command Line Usage

```bash
# Basic analysis
python android_security_analyzer.py /path/to/android/project

# Save to specific location
python android_security_analyzer.py /path/to/project --output /custom/path/report

# JSON output for CI/CD
python android_security_analyzer.py /path/to/project --format json
```

### 🔧 API Endpoints

The FastAPI backend provides RESTful endpoints:

```bash
# Submit analysis request
POST /api/analyze
{
  "project_path": "/path/to/android/project",
  "app_name": "MyApp"
}

# Get all reports
GET /api/reports

# Get specific report
GET /api/reports/{report_id}

# Download PDF report
GET /api/reports/{report_id}/pdf

# Ignore/unignore issues
POST /api/reports/{report_id}/ignore-issue
POST /api/reports/{report_id}/unignore-issue
```

## 🔍 Security Analysis Capabilities

### 📦 **Dependency Vulnerability Detection**
- **✅ Real-time CVE Scanning** - OSV database integration
- **✅ Version Comparison** - Latest stable version checking
- **✅ Maven Central & Google Maven** - Comprehensive repository support
- **✅ Known Malicious Libraries** - Detection of compromised packages

**Example Detection:**
```
🚨 CRITICAL: Jackson Databind 2.9.8
├─ 53 vulnerabilities found
├─ CVE-2020-36518: XML External Entity (XXE) injection
├─ Recommendation: Update to 2.19.0
└─ Risk Level: CRITICAL
```

### 🔐 **API Key & Secret Detection**
- **✅ Context-aware Patterns** - Reduces false positives
- **✅ Multiple Service Support** - Google, AWS, Stripe, Firebase, etc.
- **✅ Assignment Context** - Only flags actual key assignments
- **✅ Comment Filtering** - Ignores keys in documentation

### 📱 **Android Manifest Analysis**
- **✅ Dangerous Permissions** - Privacy and security risk assessment
- **✅ Network Security** - Cleartext traffic detection
- **✅ Backup Configuration** - Data protection analysis
- **✅ Google Play Compliance** - Billing and policy validation

### 🏗️ **Build Configuration Security**
- **✅ Deprecated Repositories** - JCenter and security risks
- **✅ Target SDK Compliance** - Google Play requirements
- **✅ Gradle Security** - Build script analysis
- **✅ Version Catalog Support** - Modern Gradle features

## 📊 Example Analysis Results

### Critical Issues Detected
```
🔴 CRITICAL ISSUES (3 found)
├─ Jackson Databind 2.9.8: 53 CVEs including XXE injection
├─ Cleartext Traffic Enabled: Network security vulnerability  
└─ Hardcoded API Key: Google Maps API key in source code

🟠 HIGH ISSUES (2 found)
├─ Dangerous Permission: WRITE_EXTERNAL_STORAGE without justification
└─ Backup Enabled: Sensitive data exposure risk

🟡 MEDIUM ISSUES (4 found)
├─ Outdated Dependencies: 8 libraries have updates available
├─ Debug Logging: Production build contains debug statements
├─ Missing Certificate Pinning: Network communication not pinned
└─ Vulnerable Gson Version: Deserialization vulnerability

📊 DEPENDENCIES ANALYZED: 47 total
├─ 🚨 Vulnerable: 2 libraries
├─ ⚠️ Outdated: 8 libraries  
└─ ✅ Current: 37 libraries
```

## 🎯 **Advanced Features**

### 🧠 Smart Issue Management
- **Pattern-based Ignoring** - Ignore all instances of similar issues
- **Global vs Specific** - Project-wide or instance-specific ignoring
- **Issue Tracking** - Maintain history of ignored items
- **False Positive Reduction** - Learn from user feedback

### 📈 Analytics & Reporting
- **Risk Trend Analysis** - Track security posture over time  
- **Dependency Health** - Monitor library update status
- **Compliance Tracking** - Google Play policy adherence
- **Executive Summaries** - High-level security reports for management

### 🔄 Continuous Integration
```yaml
# GitHub Actions Example
name: Security Analysis
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    - name: Run security analysis
      run: |
        python android_security_analyzer.py . --format json
        if [ $? -eq 1 ]; then
          echo "Critical security issues found"
          exit 1
        fi
    - name: Upload security report
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: security_report.json
```

## 🔧 Configuration & Customization

### Environment Variables
```bash
# Database configuration
SECURITY_DB_PATH="./security_reports.db"

# API endpoints
OSV_API_URL="https://api.osv.dev/v1/query"
MAVEN_CENTRAL_API="https://search.maven.org/solrsearch/select"

# Server configuration  
FASTAPI_HOST="0.0.0.0"
FASTAPI_PORT="8000"
```

### Custom Security Patterns
```python
# Extend keyword detection
CUSTOM_KEYWORDS = [
    "your_secret_pattern",
    "internal_api_key",
    "private_token"
]

# Add domain monitoring
CUSTOM_DOMAINS = [
    "suspicious-domain.com",
    "malware-cdn.net"
]
```

## 📂 Project Structure
```
android-security-analyzer/
├── android_security_analyzer.py    # Core analysis engine
├── app.py                         # FastAPI web server
├── requirements.txt               # Python dependencies
├── domains.txt                    # Suspicious domains database
├── keywords.txt                   # Security keywords database
├── templates/                     # HTML templates
│   ├── base.html                 # Base template
│   ├── reports_list.html         # Report listing page
│   ├── submit_request.html       # Analysis submission
│   ├── view_report.html          # Detailed report view
│   └── view_report_pdf.html      # PDF report template
└── security_reports.db           # SQLite database (auto-created)
```

## 🚨 **Known Limitations**

### Requires Manual Review (15-20%)
- **Business Logic Vulnerabilities** - Application-specific security flaws
- **Complex Authentication Issues** - Multi-step authentication bypasses  
- **Runtime Security** - Dynamic analysis and penetration testing
- **Custom Security Implementations** - Non-standard security patterns

### False Positives
- **Comments containing API key patterns** - Use ignore functionality
- **Test files with debug code** - Configure analysis scope
- **Development-only configurations** - Context-specific filtering

## 🤝 Contributing

We welcome contributions! Here's how to help:

1. **🐛 Bug Reports** - Submit detailed issue reports
2. **✨ Feature Requests** - Propose new security checks
3. **🔧 Code Contributions** - Improve analysis accuracy
4. **📚 Documentation** - Enhance usage guides

```bash
# Development setup
git clone git@github.com:bewithdhanu/android-security-analyzer.git
cd android-security-analyzer
pip install -r requirements.txt

# Run tests
python -m pytest tests/

# Submit pull request
git checkout -b feature/your-improvement
git commit -m "Add: New security check for XYZ"
git push origin feature/your-improvement
```

## 📜 License

MIT License - Free for commercial and personal use. See [LICENSE](LICENSE) for details.

## 🆘 Support & Community

- **🐛 Issues**: [GitHub Issues](https://github.com/bewithdhanu/android-security-analyzer/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/bewithdhanu/android-security-analyzer/discussions)  
- **📧 Security Reports**: Report security issues privately via email

## 🔄 Changelog

### Version 1.0.0
- ✅ Initial release with web interface
- ✅ Real-time vulnerability scanning
- ✅ Advanced dependency analysis
- ✅ PDF report generation
- ✅ Issue ignore/unignore functionality
- ✅ SQLite database integration
- ✅ FastAPI web backend

---

## 🚀 **Quick Start Commands**

```bash
# 1. Clone and setup
git clone git@github.com:bewithdhanu/android-security-analyzer.git
cd android-security-analyzer && pip install -r requirements.txt

# 2. Start web interface
python app.py
# → Open http://localhost:8000

# 3. Or run CLI analysis
python android_security_analyzer.py /path/to/android/project

# 4. View results
open security_report.html  # CLI generated report
# or use web interface at http://localhost:8000
```

**🛡️ Protect your Android applications with comprehensive automated security analysis and an intuitive web interface for managing security reports.** 