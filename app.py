from fastapi import FastAPI, HTTPException, Request, Form, Depends, File, UploadFile, Cookie, Response
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from passlib.context import CryptContext
import weasyprint
import io
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, JSON, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, timezone
import json
import os
from typing import List, Optional
import shutil
import tempfile
import zipfile
from pathlib import Path
import secrets
from jose import JWTError, jwt

# Security settings
SECRET_KEY = "your-secret-key-here"  # In production, use a secure secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database setup
SQLITE_DATABASE_URL = "sqlite:///./security_reports.db"
engine = create_engine(SQLITE_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# User Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Database Models
class SecurityReport(Base):
    __tablename__ = "security_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    app_name = Column(String, index=True)
    package_name = Column(String, index=True)
    version = Column(String)
    project_path = Column(String)
    scan_time = Column(DateTime, default=datetime.utcnow)
    total_issues = Column(Integer, default=0)
    critical_issues = Column(Integer, default=0)
    high_issues = Column(Integer, default=0)
    medium_issues = Column(Integer, default=0)
    low_issues = Column(Integer, default=0)
    status = Column(String, default="pending")  # pending, in_progress, completed, failed
    report_data = Column(JSON)
    app_logo = Column(Text, nullable=True)

class IgnoredIssue(Base):
    __tablename__ = "ignored_issues"
    
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("security_reports.id"))
    issue_title = Column(String)
    issue_category = Column(String)
    issue_file_path = Column(String)
    issue_line_number = Column(Integer)
    issue_description = Column(Text)
    keyword_pattern = Column(String, nullable=True)
    is_global_ignore = Column(Integer, default=0)
    ignored_at = Column(DateTime, default=datetime.utcnow)

# Pydantic Models
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    is_admin: bool = False

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    is_admin: bool
    created_at: datetime

    class Config:
        from_attributes = True  # New way to enable ORM mode in Pydantic v2

class Token(BaseModel):
    access_token: str
    token_type: str

class SecurityReportCreate(BaseModel):
    app_name: str
    package_name: str
    version: str
    project_path: str
    report_data: dict

class SecurityReportResponse(BaseModel):
    id: int
    app_name: str
    package_name: str
    version: str
    scan_time: datetime
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    status: str
    app_logo: Optional[str] = None

    class Config:
        from_attributes = True

class IgnoreIssueRequest(BaseModel):
    issue_title: str
    issue_category: str
    issue_file_path: str = ""
    issue_line_number: int = 0
    issue_description: str = ""
    keyword_pattern: str = ""
    is_global_ignore: int = 0

class IgnoredIssueResponse(BaseModel):
    id: int
    report_id: int
    issue_title: str
    issue_category: str
    issue_file_path: str
    issue_line_number: int
    issue_description: str
    keyword_pattern: str
    is_global_ignore: int
    ignored_at: datetime

    class Config:
        from_attributes = True

class AnalysisRequest(BaseModel):
    project_path: str
    app_name: Optional[str] = None

# Authentication functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str):
    return pwd_context.hash(password)

def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        return None
    return user

def get_current_user(db: Session, token: str = Cookie(None)):
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            return None
        return db.query(User).filter(User.id == user_id).first()
    except JWTError:
        return None

def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password strength
    Returns (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character"
    
    return True, ""

# Initialize admin user
def init_admin():
    db = SessionLocal()
    try:
        # Check if any users exist
        user_count = db.query(User).count()
        return user_count == 0
    finally:
        db.close()

# Create all tables
Base.metadata.create_all(bind=engine)
# Check if first-time setup is needed
needs_setup = init_admin()

# FastAPI app
app = FastAPI(title="Android Security Analyzer API", version="1.0.0")
templates = Jinja2Templates(directory="templates")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure maximum request size to 1GB
class LargeUploadMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "POST" and "multipart/form-data" in request.headers.get("content-type", ""):
            # Set max upload size to 1GB
            request._max_body_size = 1024 * 1024 * 1024  # 1GB in bytes
        return await call_next(request)

app.add_middleware(LargeUploadMiddleware)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request, error: str = None):
    """First-time setup page for creating admin account"""
    db = SessionLocal()
    try:
        # If users already exist, redirect to login
        if db.query(User).count() > 0:
            return RedirectResponse(url="/login", status_code=303)
        
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "error": error
        })
    finally:
        db.close()

@app.post("/setup")
async def create_first_admin(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Create the first admin user"""
    # If users already exist, redirect to login
    if db.query(User).count() > 0:
        return RedirectResponse(url="/login", status_code=303)
    
    # Validate email format
    try:
        from email_validator import validate_email, EmailNotValidError
        validate_email(email)
    except EmailNotValidError:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "error": "Invalid email format"
        })
    
    # Validate password strength
    is_valid, error_message = validate_password(password)
    if not is_valid:
        return templates.TemplateResponse("setup.html", {
            "request": request,
            "error": error_message
        })
    
    # Create admin user
    admin_user = User(
        name=name,
        email=email,
        password_hash=get_password_hash(password),
        is_admin=True
    )
    db.add(admin_user)
    db.commit()
    
    # Create access token and redirect to home
    access_token = create_access_token({"sub": str(admin_user.id)})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="token", value=access_token, httponly=True)
    return response

# Authentication routes
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None):
    """Login page that redirects to setup if no users exist"""
    db = SessionLocal()
    try:
        # If no users exist, redirect to setup
        if db.query(User).count() == 0:
            return RedirectResponse(url="/setup", status_code=303)
        
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": error
        })
    finally:
        db.close()

@app.post("/login")
async def login(
    request: Request,
    response: Response,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, email, password)
    if not user:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid email or password"
        })
    
    access_token = create_access_token({"sub": str(user.id)})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="token", value=access_token, httponly=True)
    return response

@app.get("/logout")
async def logout(response: Response):
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(key="token")
    return response

# User management routes
@app.get("/users", response_class=HTMLResponse)
async def list_users(
    request: Request,
    db: Session = Depends(get_db)
):
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    if not current_user.is_admin:
        return RedirectResponse(url="/", status_code=303)
    
    users = db.query(User).all()
    return templates.TemplateResponse("users.html", {
        "request": request,
        "users": users,
        "current_user": current_user,
        "active_page": "users"
    })

@app.get("/users/new", response_class=HTMLResponse)
async def new_user_page(
    request: Request,
    db: Session = Depends(get_db)
):
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user or not current_user.is_admin:
        return RedirectResponse(url="/login", status_code=303)
    
    return templates.TemplateResponse("user_form.html", {
        "request": request,
        "current_user": current_user,
        "active_page": "users"
    })

@app.post("/users/new")
async def create_user(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    is_admin: bool = Form(False),
    db: Session = Depends(get_db)
):
    """Create a new user"""
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user or not current_user.is_admin:
        return RedirectResponse(url="/login", status_code=303)
    
    # Check if user exists
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse("user_form.html", {
            "request": request,
            "error": "Email already registered",
            "current_user": current_user,
            "active_page": "users"
        })
    
    # Validate email format
    try:
        from email_validator import validate_email, EmailNotValidError
        validate_email(email)
    except EmailNotValidError:
        return templates.TemplateResponse("user_form.html", {
            "request": request,
            "error": "Invalid email format",
            "current_user": current_user,
            "active_page": "users"
        })
    
    # Validate password strength
    is_valid, error_message = validate_password(password)
    if not is_valid:
        return templates.TemplateResponse("user_form.html", {
            "request": request,
            "error": error_message,
            "current_user": current_user,
            "active_page": "users"
        })
    
    # Create new user
    new_user = User(
        name=name,
        email=email,
        password_hash=get_password_hash(password),
        is_admin=is_admin
    )
    db.add(new_user)
    db.commit()
    
    return RedirectResponse(url="/users", status_code=303)

@app.get("/change-password", response_class=HTMLResponse)
async def change_password_page(
    request: Request,
    error: str = None,
    db: Session = Depends(get_db)
):
    """Page for changing own password"""
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    return templates.TemplateResponse("change_password.html", {
        "request": request,
        "error": error,
        "current_user": current_user
    })

@app.post("/change-password")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Change user's own password"""
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    # Verify current password
    if not verify_password(current_password, current_user.password_hash):
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "error": "Current password is incorrect",
            "current_user": current_user
        })
    
    # Verify new passwords match
    if new_password != confirm_password:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "error": "New passwords do not match",
            "current_user": current_user
        })
    
    # Validate new password strength
    is_valid, error_message = validate_password(new_password)
    if not is_valid:
        return templates.TemplateResponse("change_password.html", {
            "request": request,
            "error": error_message,
            "current_user": current_user
        })
    
    # Update password
    current_user.password_hash = get_password_hash(new_password)
    db.commit()
    
    return RedirectResponse(url="/", status_code=303)

@app.get("/users/{user_id}/reset-password", response_class=HTMLResponse)
async def reset_user_password_page(
    request: Request,
    user_id: int,
    error: str = None,
    db: Session = Depends(get_db)
):
    """Page for admin to reset a user's password"""
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user or not current_user.is_admin:
        return RedirectResponse(url="/login", status_code=303)
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return RedirectResponse(url="/users", status_code=303)
    
    return templates.TemplateResponse("reset_password.html", {
        "request": request,
        "user": user,
        "error": error,
        "current_user": current_user,
        "active_page": "users"
    })

@app.post("/users/{user_id}/reset-password")
async def reset_user_password(
    request: Request,
    user_id: int,
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Admin resets a user's password"""
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user or not current_user.is_admin:
        return RedirectResponse(url="/login", status_code=303)
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return RedirectResponse(url="/users", status_code=303)
    
    # Verify passwords match
    if new_password != confirm_password:
        return templates.TemplateResponse("reset_password.html", {
            "request": request,
            "user": user,
            "error": "Passwords do not match",
            "current_user": current_user,
            "active_page": "users"
        })
    
    # Validate password strength
    is_valid, error_message = validate_password(new_password)
    if not is_valid:
        return templates.TemplateResponse("reset_password.html", {
            "request": request,
            "user": user,
            "error": error_message,
            "current_user": current_user,
            "active_page": "users"
        })
    
    # Update password
    user.password_hash = get_password_hash(new_password)
    db.commit()
    
    return RedirectResponse(url="/users", status_code=303)

@app.get("/users/{user_id}/delete", response_class=HTMLResponse)
async def delete_user_page(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db)
):
    """Confirmation page for deleting a user"""
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user or not current_user.is_admin:
        return RedirectResponse(url="/login", status_code=303)
    
    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if not user_to_delete:
        return RedirectResponse(url="/users", status_code=303)
    
    # Don't allow deleting yourself
    if user_to_delete.id == current_user.id:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": "You cannot delete your own account",
            "current_user": current_user,
            "active_page": "users"
        })
    
    return templates.TemplateResponse("delete_user.html", {
        "request": request,
        "user": user_to_delete,
        "current_user": current_user,
        "active_page": "users"
    })

@app.post("/users/{user_id}/delete")
async def delete_user(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db)
):
    """Delete a user"""
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user or not current_user.is_admin:
        return RedirectResponse(url="/login", status_code=303)
    
    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if not user_to_delete:
        return RedirectResponse(url="/users", status_code=303)
    
    # Don't allow deleting yourself
    if user_to_delete.id == current_user.id:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": "You cannot delete your own account",
            "current_user": current_user,
            "active_page": "users"
        })
    
    db.delete(user_to_delete)
    db.commit()
    
    return RedirectResponse(url="/users", status_code=303)

# Update root route to handle first-time setup
@app.get("/")
async def root(request: Request, db: Session = Depends(get_db)):
    # If no users exist, redirect to setup
    if db.query(User).count() == 0:
        return RedirectResponse(url="/setup", status_code=303)
    
    # Check authentication for normal flow
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    return RedirectResponse(url="/reports", status_code=303)

# Reports routes
@app.get("/reports", response_class=HTMLResponse)
async def list_reports(request: Request, db: Session = Depends(get_db)):
    """List all security reports"""
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    try:
        reports = db.query(SecurityReport).order_by(SecurityReport.scan_time.desc()).all()
        
        # Update each report with filtered issue counts
        for report in reports:
            if report.report_data and report.status == "completed":
                try:
                    # Get ignored issues for this report
                    ignored_issues = db.query(IgnoredIssue).filter(
                        IgnoredIssue.report_id == report.id
                    ).all()
                    
                    if ignored_issues:
                        # Parse report data if it's a string
                        report_data = report.report_data if isinstance(report.report_data, dict) else json.loads(report.report_data)
                        filtered_report_data = filter_ignored_issues(report_data, ignored_issues)
                        
                        # Update the report object with filtered counts
                        filtered_summary = filtered_report_data["summary"]["by_severity"]
                        report.critical_issues = filtered_summary.get("critical", 0)
                        report.high_issues = filtered_summary.get("high", 0)
                        report.medium_issues = filtered_summary.get("medium", 0)
                        report.low_issues = filtered_summary.get("low", 0)
                        report.total_issues = filtered_report_data["metadata"]["total_issues"]
                except (json.JSONDecodeError, KeyError, AttributeError):
                    # If there's an error parsing, keep original counts
                    pass
        
        # Calculate statistics based on updated (filtered) counts
        stats = {
            "total_reports": len(reports),
            "completed_reports": len([r for r in reports if r.status == "completed"]),
            "total_critical": sum(r.critical_issues for r in reports),
            "total_high": sum(r.high_issues for r in reports)
        }
        
        return templates.TemplateResponse("reports_list.html", {
            "request": request,
            "reports": reports,
            "stats": stats,
            "active_page": "reports",
            "current_user": current_user
        })
    finally:
        db.close()

@app.get("/reports/compare", response_class=HTMLResponse)  # This route must come before /reports/{report_id}
async def compare_reports_page(
    request: Request,
    db: Session = Depends(get_db)
):
    """Compare multiple security reports"""
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    try:
        # Get all completed reports
        reports = db.query(SecurityReport).filter(
            SecurityReport.status == "completed"
        ).order_by(SecurityReport.scan_time.desc()).all()
        
        # Get report IDs from query params
        selected_ids = request.query_params.getlist("report")
        selected_ids = [int(id) for id in selected_ids if id.isdigit()]
        
        # If reports are selected, prepare comparison data
        comparison_data = None
        if selected_ids:
            selected_reports = []
            for report in reports:
                if report.id in selected_ids:
                    # Parse report data if it's a string
                    report_data = report.report_data if isinstance(report.report_data, dict) else json.loads(report.report_data)
                    
                    # Get ignored issues
                    ignored_issues = db.query(IgnoredIssue).filter(
                        IgnoredIssue.report_id == report.id
                    ).all()
                    
                    # Filter ignored issues if any exist
                    if ignored_issues:
                        report_data = filter_ignored_issues(report_data, ignored_issues)
                    
                    selected_reports.append({
                        "id": report.id,
                        "app_name": report.app_name,
                        "package_name": report.package_name,
                        "version": report.version,
                        "scan_time": report.scan_time,
                        "data": report_data
                    })
            
            comparison_data = prepare_comparison_data(selected_reports)
        
        return templates.TemplateResponse("compare_reports.html", {
            "request": request,
            "reports": reports,
            "selected_ids": selected_ids,
            "comparison_data": comparison_data,
            "active_page": "compare",
            "current_user": current_user
        })
    finally:
        db.close()

@app.get("/reports/{report_id}", response_class=HTMLResponse)  # This route must come after /reports/compare
async def view_report_page(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db)
):
    """View a single security report"""
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    try:
        report = db.query(SecurityReport).filter(SecurityReport.id == report_id).first()
        if not report:
            return templates.TemplateResponse("error.html", {
                "request": request,
                "error": "Report not found",
                "current_user": current_user
            })
        
        # Get ignored issues for this report
        ignored_issues = db.query(IgnoredIssue).filter(
            IgnoredIssue.report_id == report_id
        ).all()
        
        # Parse report data if it's a string
        report_data = report.report_data if isinstance(report.report_data, dict) else json.loads(report.report_data)
        
        # Filter ignored issues if any exist
        if ignored_issues:
            report_data = filter_ignored_issues(report_data, ignored_issues)
        
        return templates.TemplateResponse("view_report.html", {
            "request": request,
            "report": report,
            "report_data": report_data,
            "ignored_issues": ignored_issues,
            "active_page": "reports",
            "current_user": current_user
        })
    finally:
        db.close()

@app.post("/api/validate-project")
async def validate_project(request: AnalysisRequest):
    """Validate project structure"""
    try:
        project_path = request.project_path
        
        if not os.path.exists(project_path):
            raise HTTPException(status_code=400, detail="Project path does not exist")
        
        # Check for AndroidManifest.xml
        manifest_files = []
        gradle_files = []
        
        for root, dirs, files in os.walk(project_path):
            for file in files:
                if file == "AndroidManifest.xml":
                    manifest_files.append(os.path.join(root, file))
                elif file.endswith(".gradle"):
                    gradle_files.append(os.path.join(root, file))
        
        # Try to extract basic info
        app_name = "Unknown"
        package_name = "Unknown"
        target_sdk = "Unknown"
        
        if manifest_files:
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(manifest_files[0])
                root = tree.getroot()
                
                package_name = root.get('package', 'Unknown')
                
                # Try to get app name from manifest
                application = root.find('application')
                if application is not None:
                    label = application.get('{http://schemas.android.com/apk/res/android}label')
                    if label and not label.startswith('@'):
                        app_name = label
                
                # Try to get target SDK
                uses_sdk = root.find('uses-sdk')
                if uses_sdk is not None:
                    target_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', 'Unknown')
                    
            except Exception:
                pass
        
        return {
            "app_name": app_name,
            "package_name": package_name,
            "target_sdk": target_sdk,
            "has_manifest": len(manifest_files) > 0,
            "gradle_files": len(gradle_files)
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/docs", include_in_schema=False)
async def get_api_docs():
    """Redirect to API documentation"""
    return RedirectResponse(url="/docs")

@app.post("/api/analyze", response_model=dict)
async def submit_analysis_request(request: AnalysisRequest):
    """Submit a new security analysis request"""
    from android_security_analyzer import AndroidSecurityAnalyzer
    
    db = None
    pending_report = None
    
    try:
        # Validate project path
        if not os.path.exists(request.project_path):
            raise HTTPException(status_code=400, detail="Project path does not exist")
        
        # Create pending record
        db = SessionLocal()
        pending_report = SecurityReport(
            app_name=request.app_name or "Unknown",
            package_name="Unknown",
            version="Unknown",
            project_path=request.project_path,
            status="in_progress",
            total_issues=0
        )
        db.add(pending_report)
        db.commit()
        db.refresh(pending_report)
        
        # Get the ID after commit and refresh
        report_id = pending_report.id
        
        # Run analysis
        analyzer = AndroidSecurityAnalyzer(request.project_path)
        analysis_result = await analyzer.analyze_async(request.project_path)
        report_data = analyzer.report_generator.prepare_json_data(analysis_result)
        
        # Update database record with results - use a fresh query to avoid stale data
        pending_report = db.query(SecurityReport).filter(SecurityReport.id == report_id).first()
        if pending_report:
            pending_report.app_name = report_data["app_metadata"]["app_name"]
            pending_report.package_name = report_data["app_metadata"]["package_name"]
            pending_report.version = report_data["app_metadata"]["version_name"]
            pending_report.total_issues = report_data["metadata"]["total_issues"]
            pending_report.critical_issues = report_data["summary"]["by_severity"]["critical"]
            pending_report.high_issues = report_data["summary"]["by_severity"]["high"]
            pending_report.medium_issues = report_data["summary"]["by_severity"]["medium"]
            pending_report.low_issues = report_data["summary"]["by_severity"]["low"]
            pending_report.app_logo = report_data["app_metadata"].get("app_logo_base64", "")
            pending_report.status = "completed"
            pending_report.report_data = json.dumps(report_data)
            
            db.commit()
            
            # Get values for response
            total_issues = pending_report.total_issues
            
            return {
                "status": "success",
                "message": "Analysis completed successfully",
                "report_id": report_id,
                "total_issues": total_issues
            }
        else:
            raise Exception("Could not find pending report after creation")
            
    except Exception as e:
        # Mark report as failed if it exists
        if pending_report and hasattr(pending_report, 'id'):
            try:
                if db:
                    failed_report = db.query(SecurityReport).filter(SecurityReport.id == pending_report.id).first()
                    if failed_report:
                        failed_report.status = "failed"
                        db.commit()
            except Exception:
                pass  # Don't let cleanup errors override the main error
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        if db:
            db.close()

@app.get("/api/reports", response_model=List[SecurityReportResponse])
async def get_all_reports():
    """Get list of all security analysis reports"""
    db = SessionLocal()
    try:
        reports = db.query(SecurityReport).order_by(SecurityReport.scan_time.desc()).all()
        
        # Update each report with filtered issue counts
        for report in reports:
            if report.report_data and report.status == "completed":
                try:
                    # Get ignored issues for this report
                    ignored_issues = db.query(IgnoredIssue).filter(
                        IgnoredIssue.report_id == report.id
                    ).all()
                    
                    if ignored_issues:
                        # Parse report data and filter ignored issues
                        report_data = json.loads(report.report_data)
                        filtered_report_data = filter_ignored_issues(report_data, ignored_issues)
                        
                        # Update the report object with filtered counts
                        filtered_summary = filtered_report_data["summary"]["by_severity"]
                        report.critical_issues = filtered_summary.get("critical", 0)
                        report.high_issues = filtered_summary.get("high", 0)
                        report.medium_issues = filtered_summary.get("medium", 0)
                        report.low_issues = filtered_summary.get("low", 0)
                        report.total_issues = filtered_report_data["metadata"]["total_issues"]
                except (json.JSONDecodeError, KeyError):
                    # If there's an error parsing, keep original counts
                    pass
        
        return [
            SecurityReportResponse(
                id=report.id,
                app_name=report.app_name,
                package_name=report.package_name,
                version=report.version,
                scan_time=report.scan_time,
                total_issues=report.total_issues,
                critical_issues=report.critical_issues,
                high_issues=report.high_issues,
                medium_issues=report.medium_issues,
                low_issues=report.low_issues,
                status=report.status,
                app_logo=report.app_logo
            )
            for report in reports
        ]
    finally:
        db.close()

@app.get("/api/reports/{report_id}")
async def get_report_data(report_id: int):
    """Get full report data by ID"""
    db = SessionLocal()
    try:
        report = db.query(SecurityReport).filter(SecurityReport.id == report_id).first()
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        if report.report_data:
            return json.loads(report.report_data)
        else:
            raise HTTPException(status_code=404, detail="Report data not available")
    finally:
        db.close()

@app.get("/reports/{report_id}/pdf")
async def download_report_pdf(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db)
):
    """Download report as PDF"""
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    try:
        report = db.query(SecurityReport).filter(SecurityReport.id == report_id).first()
        if not report:
            return templates.TemplateResponse("error.html", {
                "request": request,
                "error": "Report not found",
                "current_user": current_user
            })
        
        # Get ignored issues for this report
        ignored_issues = db.query(IgnoredIssue).filter(
            IgnoredIssue.report_id == report_id
        ).all()
        
        # Parse report data if it's a string
        report_data = report.report_data if isinstance(report.report_data, dict) else json.loads(report.report_data)
        
        # Filter ignored issues if any exist
        if ignored_issues:
            report_data = filter_ignored_issues(report_data, ignored_issues)
        
        # Generate PDF using template
        html = templates.TemplateResponse("view_report_pdf.html", {
            "request": request,
            "report": report,
            "report_data": report_data,
            "ignored_issues": ignored_issues,
            "current_user": current_user
        }).body.decode()
        
        # Convert HTML to PDF
        pdf = weasyprint.HTML(string=html).write_pdf()
        
        # Return PDF as download
        filename = f"security_report_{report.id}_{report.app_name}.pdf"
        headers = {
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Content-Type': 'application/pdf'
        }
        return Response(content=pdf, headers=headers)
    finally:
        db.close()

@app.get("/report/{report_id}", response_class=HTMLResponse)
async def render_security_report(request: Request, report_id: int):
    """Legacy route - redirect to new template-based route"""
    return RedirectResponse(url=f"/reports/{report_id}")

@app.delete("/api/reports/{report_id}")
async def delete_report(report_id: int):
    """Delete a security report"""
    db = SessionLocal()
    try:
        report = db.query(SecurityReport).filter(SecurityReport.id == report_id).first()
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        # Also delete associated ignored issues
        db.query(IgnoredIssue).filter(IgnoredIssue.report_id == report_id).delete()
        
        db.delete(report)
        db.commit()
        return {"message": "Report deleted successfully"}
    finally:
        db.close()

@app.post("/api/reports/{report_id}/ignore-issue")
async def ignore_issue(report_id: int, request: IgnoreIssueRequest):
    """Ignore a specific issue in a report"""
    db = SessionLocal()
    try:
        # Verify report exists
        report = db.query(SecurityReport).filter(SecurityReport.id == report_id).first()
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        # Detect if this is a keyword/domain-based issue that should be globally ignored
        keyword_pattern = ""
        is_global_ignore = 0
        
        if request.issue_category in ["Security Keywords", "Suspicious Domains"]:
            keyword_pattern = extract_keyword_from_title(request.issue_title, request.issue_category)
            if keyword_pattern:
                is_global_ignore = 1
                
                # Check if this keyword/domain is already globally ignored
                existing_global = db.query(IgnoredIssue).filter(
                    IgnoredIssue.report_id == report_id,
                    IgnoredIssue.issue_category == request.issue_category,
                    IgnoredIssue.keyword_pattern == keyword_pattern,
                    IgnoredIssue.is_global_ignore == 1
                ).first()
                
                if existing_global:
                    raise HTTPException(status_code=400, detail=f"All instances of '{keyword_pattern}' are already ignored")
        
        if not is_global_ignore:
            # Check if specific issue is already ignored
            existing = db.query(IgnoredIssue).filter(
                IgnoredIssue.report_id == report_id,
                IgnoredIssue.issue_title == request.issue_title,
                IgnoredIssue.issue_category == request.issue_category,
                IgnoredIssue.issue_file_path == request.issue_file_path,
                IgnoredIssue.issue_line_number == request.issue_line_number
            ).first()
            
            if existing:
                raise HTTPException(status_code=400, detail="Issue is already ignored")
        
        # Create ignored issue record
        ignored_issue = IgnoredIssue(
            report_id=report_id,
            issue_title=request.issue_title,
            issue_category=request.issue_category,
            issue_file_path=request.issue_file_path,
            issue_line_number=request.issue_line_number,
            issue_description=request.issue_description,
            keyword_pattern=keyword_pattern,
            is_global_ignore=is_global_ignore
        )
        
        db.add(ignored_issue)
        db.commit()
        db.refresh(ignored_issue)
        
        message = "Issue ignored successfully"
        if is_global_ignore:
            message = f"All instances of '{keyword_pattern}' ignored successfully"
        
        return {
            "message": message,
            "ignored_issue_id": ignored_issue.id,
            "is_global_ignore": bool(is_global_ignore),
            "keyword_pattern": keyword_pattern
        }
    finally:
        db.close()

@app.delete("/api/reports/{report_id}/ignore-issue/{ignored_issue_id}")
async def unignore_issue(report_id: int, ignored_issue_id: int):
    """Remove an issue from the ignored list"""
    db = SessionLocal()
    try:
        # Verify report exists
        report = db.query(SecurityReport).filter(SecurityReport.id == report_id).first()
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        # Find and delete ignored issue
        ignored_issue = db.query(IgnoredIssue).filter(
            IgnoredIssue.id == ignored_issue_id,
            IgnoredIssue.report_id == report_id
        ).first()
        
        if not ignored_issue:
            raise HTTPException(status_code=404, detail="Ignored issue not found")
        
        db.delete(ignored_issue)
        db.commit()
        
        return {"message": "Issue unignored successfully"}
    finally:
        db.close()

@app.get("/api/reports/{report_id}/ignored-issues", response_model=List[IgnoredIssueResponse])
async def get_ignored_issues(report_id: int):
    """Get list of ignored issues for a report"""
    db = SessionLocal()
    try:
        # Verify report exists
        report = db.query(SecurityReport).filter(SecurityReport.id == report_id).first()
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        ignored_issues = db.query(IgnoredIssue).filter(
            IgnoredIssue.report_id == report_id
        ).order_by(IgnoredIssue.ignored_at.desc()).all()
        
        return [
            IgnoredIssueResponse(
                id=issue.id,
                report_id=issue.report_id,
                issue_title=issue.issue_title,
                issue_category=issue.issue_category,
                issue_file_path=issue.issue_file_path,
                issue_line_number=issue.issue_line_number,
                issue_description=issue.issue_description,
                keyword_pattern=issue.keyword_pattern or "",
                is_global_ignore=issue.is_global_ignore or 0,
                ignored_at=issue.ignored_at
            )
            for issue in ignored_issues
        ]
    finally:
        db.close()

# Helper functions
def extract_keyword_from_title(title: str, category: str) -> str:
    """Extract keyword/domain from issue title for pattern matching"""
    if category == "Security Keywords" and "Security-Related Keyword: " in title:
        return title.replace("Security-Related Keyword: ", "").strip()
    elif category == "Suspicious Domains" and "Suspicious Domain Reference: " in title:
        return title.replace("Suspicious Domain Reference: ", "").strip()
    return ""

def filter_ignored_issues(report_data: dict, ignored_issues: List[IgnoredIssue]) -> dict:
    """Filter out ignored issues from report data and recalculate statistics"""
    if not ignored_issues:
        return report_data
    
    # Create sets for different types of ignoring
    ignored_exact_set = set()
    ignored_keywords = set()
    ignored_domains = set()
    
    for ignored in ignored_issues:
        if ignored.is_global_ignore and ignored.keyword_pattern:
            # Global pattern-based ignore
            if ignored.issue_category == "Security Keywords":
                ignored_keywords.add(ignored.keyword_pattern.lower())
            elif ignored.issue_category == "Suspicious Domains":
                ignored_domains.add(ignored.keyword_pattern.lower())
        else:
            # Exact issue ignore
            ignored_exact_set.add((
                ignored.issue_title,
                ignored.issue_category,
                ignored.issue_file_path,
                ignored.issue_line_number
            ))
    
    # Filter issues from categorized data
    filtered_categories = []
    new_total_issues = 0
    new_severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for category in report_data["issues"]["categorized"]:
        filtered_issues = []
        
        for issue in category["issues"]:
            should_ignore = False
            
            # Check exact match first
            issue_key = (
                issue["title"],
                issue["category"],
                issue.get("file_path", ""),
                issue.get("line_number", 0)
            )
            
            if issue_key in ignored_exact_set:
                should_ignore = True
            
            # Check pattern-based ignore for keywords and domains
            if not should_ignore:
                if issue["category"] == "Security Keywords" and ignored_keywords:
                    keyword = extract_keyword_from_title(issue["title"], issue["category"])
                    if keyword.lower() in ignored_keywords:
                        should_ignore = True
                elif issue["category"] == "Suspicious Domains" and ignored_domains:
                    domain = extract_keyword_from_title(issue["title"], issue["category"])
                    if domain.lower() in ignored_domains:
                        should_ignore = True
            
            # Only include if not ignored
            if not should_ignore:
                filtered_issues.append(issue)
                # Count by severity
                severity = issue["risk_level"].lower()
                if severity in new_severity_counts:
                    new_severity_counts[severity] += 1
                new_total_issues += 1
        
        # Only include category if it has non-ignored issues
        if filtered_issues:
            category_copy = category.copy()
            category_copy["issues"] = filtered_issues
            category_copy["issue_count"] = len(filtered_issues)
            
            # Recalculate category risk level based on remaining issues
            if filtered_issues:
                category_risk = max([issue["risk_level"] for issue in filtered_issues], 
                                  key=lambda r: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(r, 0))
                category_copy["risk_level"] = category_risk
            
            filtered_categories.append(category_copy)
    
    # Create updated report data
    filtered_report_data = report_data.copy()
    filtered_report_data["issues"]["categorized"] = filtered_categories
    filtered_report_data["issues"]["total_count"] = new_total_issues
    filtered_report_data["metadata"]["total_issues"] = new_total_issues
    filtered_report_data["summary"]["by_severity"] = new_severity_counts
    
    return filtered_report_data

def prepare_comparison_data(reports: List[dict]) -> dict:
    """Prepare data for comparison view"""
    comparison = {
        "reports": reports,
        "summary": {
            "total_issues": [],
            "by_severity": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": []
            },
            "by_category": {}
        },
        "details": {
            "by_category": {}
        }
    }
    
    # Collect all unique categories
    categories = set()
    for report in reports:
        data = report["data"]
        for issue in data["issues"]["categorized"]:
            categories.add(issue["category"])
    
    # Initialize category counters and details
    for category in categories:
        comparison["summary"]["by_category"][category] = []
        comparison["details"]["by_category"][category] = []
    
    # Collect data from each report
    for report in reports:
        data = report["data"]
        
        # Summary data
        comparison["summary"]["total_issues"].append(data["metadata"]["total_issues"])
        comparison["summary"]["by_severity"]["critical"].append(data["summary"]["by_severity"]["critical"])
        comparison["summary"]["by_severity"]["high"].append(data["summary"]["by_severity"]["high"])
        comparison["summary"]["by_severity"]["medium"].append(data["summary"]["by_severity"]["medium"])
        comparison["summary"]["by_severity"]["low"].append(data["summary"]["by_severity"]["low"])
        
        # Category counts
        for category in categories:
            count = 0
            issues = []
            for cat_data in data["issues"]["categorized"]:
                if cat_data["category"] == category:
                    count = len(cat_data["issues"])
                    issues = cat_data["issues"]
                    break
            comparison["summary"]["by_category"][category].append(count)
            comparison["details"]["by_category"][category].append(issues)
    
    return comparison

# Submit routes
@app.get("/submit", response_class=HTMLResponse)
async def submit_request_page(
    request: Request,
    db: Session = Depends(get_db)
):
    """Show analysis submission form"""
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    return templates.TemplateResponse("submit_request.html", {
        "request": request,
        "active_page": "submit",
        "current_user": current_user
    })

@app.post("/submit")
async def submit_analysis(
    request: Request,
    source_type: str = Form(...),
    project_path: str = Form(None),
    project_zip: UploadFile = File(None),
    app_name: str = Form(None),
    db: Session = Depends(get_db)
):
    """Handle form submission for analysis"""
    current_user = get_current_user(db, request.cookies.get("token"))
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    
    pending_report = None
    temp_dir = None
    
    try:
        if source_type == "path":
            if not project_path:
                return templates.TemplateResponse("submit_request.html", {
                    "request": request,
                    "active_page": "submit",
                    "errors": {"project_path": "Project path is required"},
                    "form_data": {"project_path": project_path, "app_name": app_name},
                    "current_user": current_user
                })
            
            # Validate project path exists
            if not os.path.exists(project_path):
                return templates.TemplateResponse("submit_request.html", {
                    "request": request,
                    "active_page": "submit",
                    "errors": {"project_path": "Project path does not exist"},
                    "form_data": {"project_path": project_path, "app_name": app_name},
                    "current_user": current_user
                })
            
            analysis_path = project_path
            
        else:  # source_type == "zip"
            if not project_zip:
                return templates.TemplateResponse("submit_request.html", {
                    "request": request,
                    "active_page": "submit",
                    "errors": {"project_zip": "ZIP file is required"},
                    "form_data": {"app_name": app_name},
                    "current_user": current_user
                })
            
            # Create temporary directory with unique name
            temp_dir = tempfile.mkdtemp(prefix="android_security_analysis_")
            
            try:
                # Save and extract ZIP file
                zip_path = os.path.join(temp_dir, "project.zip")
                with open(zip_path, "wb") as buffer:
                    shutil.copyfileobj(project_zip.file, buffer)
                
                # Extract ZIP
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                os.remove(zip_path)  # Remove the ZIP file after extraction
                
                # Find the actual project root
                analysis_path = _find_project_root(temp_dir)
                
                if analysis_path == temp_dir:
                    # No clear Android project structure found
                    shutil.rmtree(temp_dir)
                    return templates.TemplateResponse("submit_request.html", {
                        "request": request,
                        "active_page": "submit",
                        "errors": {"project_zip": "Could not find Android project structure in ZIP file"},
                        "form_data": {"app_name": app_name},
                        "current_user": current_user
                    })
                
            except zipfile.BadZipFile:
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                return templates.TemplateResponse("submit_request.html", {
                    "request": request,
                    "active_page": "submit",
                    "errors": {"project_zip": "Invalid ZIP file"},
                    "form_data": {"app_name": app_name},
                    "current_user": current_user
                })
            except Exception as e:
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                return templates.TemplateResponse("submit_request.html", {
                    "request": request,
                    "active_page": "submit",
                    "errors": {"project_zip": f"Error extracting ZIP file: {str(e)}"},
                    "form_data": {"app_name": app_name},
                    "current_user": current_user
                })
        
        # Run analysis
        from android_security_analyzer import AndroidSecurityAnalyzer
        
        # Create pending record
        pending_report = SecurityReport(
            app_name=app_name or "Unknown",
            package_name="Unknown",
            version="Unknown",
            project_path=analysis_path,
            status="in_progress",
            total_issues=0
        )
        db.add(pending_report)
        db.commit()
        db.refresh(pending_report)
        
        # Get the ID after commit and refresh
        report_id = pending_report.id
        
        try:
            # Run analysis
            analyzer = AndroidSecurityAnalyzer(analysis_path)
            analysis_result = await analyzer.analyze_async(analysis_path)
            report_data = analyzer.report_generator.prepare_json_data(analysis_result)
            
            # Update database record with results
            pending_report = db.query(SecurityReport).filter(SecurityReport.id == report_id).first()
            if pending_report:
                pending_report.app_name = report_data["app_metadata"]["app_name"]
                pending_report.package_name = report_data["app_metadata"]["package_name"]
                pending_report.version = report_data["app_metadata"]["version_name"]
                pending_report.total_issues = report_data["metadata"]["total_issues"]
                pending_report.critical_issues = report_data["summary"]["by_severity"]["critical"]
                pending_report.high_issues = report_data["summary"]["by_severity"]["high"]
                pending_report.medium_issues = report_data["summary"]["by_severity"]["medium"]
                pending_report.low_issues = report_data["summary"]["by_severity"]["low"]
                pending_report.app_logo = report_data["app_metadata"].get("app_logo_base64", "")
                pending_report.status = "completed"
                pending_report.report_data = report_data
                
                db.commit()
                
                # Clean up temp directory if used
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                
                # Redirect to report view
                return RedirectResponse(url=f"/reports/{report_id}", status_code=303)
            else:
                raise Exception("Could not find pending report after creation")
                
        except Exception as e:
            # Clean up temp directory if used
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            
            # Mark report as failed
            if pending_report and hasattr(pending_report, 'id'):
                try:
                    failed_report = db.query(SecurityReport).filter(SecurityReport.id == pending_report.id).first()
                    if failed_report:
                        failed_report.status = "failed"
                        db.commit()
                except Exception:
                    pass  # Don't let cleanup errors override the main error
            
            return templates.TemplateResponse("submit_request.html", {
                "request": request,
                "active_page": "submit",
                "form_data": {"project_path": project_path, "app_name": app_name},
                "messages": [("error", f"Analysis failed: {str(e)}")],
                "current_user": current_user
            })
            
    except Exception as e:
        # Clean up temp directory if used
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        
        # Mark report as failed if it exists
        if pending_report and hasattr(pending_report, 'id'):
            try:
                failed_report = db.query(SecurityReport).filter(SecurityReport.id == pending_report.id).first()
                if failed_report:
                    failed_report.status = "failed"
                    db.commit()
            except Exception:
                pass  # Don't let cleanup errors override the main error
        
        return templates.TemplateResponse("submit_request.html", {
            "request": request,
            "active_page": "submit",
            "form_data": {"project_path": project_path, "app_name": app_name},
            "messages": [("error", f"Analysis failed: {str(e)}")],
            "current_user": current_user
        })

def _find_project_root(temp_dir: str) -> str:
    """Find the actual project root directory in the extracted contents"""
    # Look for key Android project files/directories
    android_indicators = [
        'app/build.gradle',
        'app/build.gradle.kts',
        'build.gradle',
        'build.gradle.kts',
        'gradlew',
        'settings.gradle',
        'settings.gradle.kts',
        'app/src/main/AndroidManifest.xml'
    ]
    
    # First check if any indicators exist in the temp directory itself
    if any(os.path.exists(os.path.join(temp_dir, indicator)) for indicator in android_indicators):
        return temp_dir
    
    # Check immediate subdirectories
    for item in os.listdir(temp_dir):
        item_path = os.path.join(temp_dir, item)
        if os.path.isdir(item_path):
            # Check if this directory has any of the Android project indicators
            if any(os.path.exists(os.path.join(item_path, indicator)) for indicator in android_indicators):
                return item_path
            
            # Check one level deeper (for cases where the project is in a subdirectory)
            for subitem in os.listdir(item_path):
                subitem_path = os.path.join(item_path, subitem)
                if os.path.isdir(subitem_path):
                    if any(os.path.exists(os.path.join(subitem_path, indicator)) for indicator in android_indicators):
                        return subitem_path
    
    # If no clear Android project structure is found, return the temp directory
    return temp_dir

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 