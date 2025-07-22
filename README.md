# Mobile Security Analyzer

<img src="static/images/logo.svg" width="128" height="128" alt="Mobile Security Analyzer Logo" align="right">

A powerful security analysis tool designed to scan mobile applications for potential security vulnerabilities, sensitive data exposure, and best practice violations.

## Features

### Security Analysis
- **Dependency Analysis**: Scans app dependencies for security vulnerabilities
- **Code Pattern Analysis**: Identifies potential security risks in source code
- **Manifest Analysis**: Checks configuration files for security misconfigurations
- **API Key Detection**: Identifies exposed API keys and sensitive credentials
- **Debug Log Analysis**: Detects debug logging in production code
- **Billing Library Analysis**: Validates billing implementation security

### Report Management
- **Detailed Reports**: Comprehensive security analysis with severity levels
- **Report Comparison**: Compare multiple analysis reports side by side
- **PDF Export**: Export reports in PDF format for documentation
- **Issue Management**: Track and manage identified security issues
- **Rerun Analysis**: Easily rerun analysis on previously scanned apps

### User Management
- **Role-based Access**: Admin and regular user roles
- **Secure Authentication**: JWT-based authentication system
- **User Administration**: Manage users, reset passwords, and control access
- **Strong Password Policy**: Enforced security requirements for passwords

## Getting Started

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Virtual environment (recommended)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/mobile-security-analyzer.git
cd mobile-security-analyzer
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### First-time Setup

1. Start the application:
```bash
python app.py
```

2. Open your browser and navigate to `http://localhost:8000`

3. On first run, you'll be prompted to create an admin account:
   - Enter your name, email, and a strong password
   - This account will have full administrative privileges

### Usage

1. **Submit Analysis**:
   - Upload an APK file or provide a project directory path
   - The analyzer will scan the application and generate a detailed report

2. **View Reports**:
   - Access the reports list to view all analyses
   - Click on any report to see detailed findings
   - Download reports as PDF for documentation

3. **Compare Reports**:
   - Select multiple reports (2-10) for comparison
   - View differences and similarities in security findings
   - Track security improvements over time

4. **User Management** (Admin only):
   - Create new user accounts
   - Manage user roles and permissions
   - Reset user passwords
   - Delete user accounts

## Security Features

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

### Authentication
- JWT (JSON Web Token) based authentication
- Secure password hashing using bcrypt
- Session management and timeout
- CSRF protection

## API Documentation

The application provides a REST API for automation:

- `POST /api/analyze`: Submit a new analysis
- `GET /api/reports`: List all reports
- `GET /api/reports/{id}`: Get specific report details
- `POST /api/reports/{id}/rerun`: Rerun analysis
- `GET /api/reports/compare`: Compare multiple reports

Detailed API documentation is available in [API.md](API.md).

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - The web framework used
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM
- [WeasyPrint](https://weasyprint.org/) - PDF generation
- [TailwindCSS](https://tailwindcss.com/) - CSS framework 