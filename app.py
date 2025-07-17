from fastapi import FastAPI, HTTPException, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import weasyprint
import io
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, JSON, inspect
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime
import json
import os
from typing import List, Optional

# Database setup
SQLITE_DATABASE_URL = "sqlite:///./security_reports.db"
engine = create_engine(SQLITE_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class SecurityReport(Base):
    __tablename__ = "security_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    app_name = Column(String, index=True)
    package_name = Column(String, index=True)
    version = Column(String)
    scan_time = Column(DateTime, default=datetime.utcnow)
    total_issues = Column(Integer)
    critical_issues = Column(Integer, default=0)
    high_issues = Column(Integer, default=0)
    medium_issues = Column(Integer, default=0)
    low_issues = Column(Integer, default=0)
    project_path = Column(String)
    status = Column(String, default="completed")  # pending, in_progress, completed, failed
    app_logo = Column(Text)  # Base64 encoded logo image
    report_data = Column(Text)  # JSON string of full report

class IgnoredIssue(Base):
    __tablename__ = "ignored_issues"
    
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, index=True)  # Foreign key to SecurityReport
    issue_title = Column(String, index=True)
    issue_category = Column(String, index=True)
    issue_file_path = Column(String)
    issue_line_number = Column(Integer)
    issue_description = Column(Text)
    keyword_pattern = Column(String)  # For keyword/domain-wide ignoring
    is_global_ignore = Column(Integer, default=0)  # 1 if ignoring all instances of keyword/domain
    ignored_at = Column(DateTime, default=datetime.utcnow)

# Create tables (only if they don't exist)
Base.metadata.create_all(bind=engine)

# Database migration for new columns
def migrate_database():
    """Add new columns to existing tables if they don't exist"""
    db = SessionLocal()
    try:
        # Check if the ignored_issues table exists first
        inspector = inspect(engine)
        if 'ignored_issues' not in inspector.get_table_names():
            print("ignored_issues table doesn't exist yet, will be created by create_all()")
            return
            
        # Check if the new columns exist in ignored_issues table
        existing_columns = [col['name'] for col in inspector.get_columns('ignored_issues')]
        
        # Add keyword_pattern column if it doesn't exist
        if 'keyword_pattern' not in existing_columns:
            db.execute('ALTER TABLE ignored_issues ADD COLUMN keyword_pattern VARCHAR')
            print("✅ Added keyword_pattern column to ignored_issues table")
        
        # Add is_global_ignore column if it doesn't exist
        if 'is_global_ignore' not in existing_columns:
            db.execute('ALTER TABLE ignored_issues ADD COLUMN is_global_ignore INTEGER DEFAULT 0')
            print("✅ Added is_global_ignore column to ignored_issues table")
        
        db.commit()
        print("🎉 Database migration completed successfully")
    except Exception as e:
        print(f"Database migration completed or not needed: {e}")
        db.rollback()
    finally:
        db.close()

# Run migration
migrate_database()

# Pydantic Models
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

class AnalysisRequest(BaseModel):
    project_path: str
    app_name: Optional[str] = None

# FastAPI app
app = FastAPI(title="Android Security Analyzer API", version="1.0.0")
templates = Jinja2Templates(directory="templates")


# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
async def root():
    return RedirectResponse(url="/reports")

@app.get("/reports", response_class=HTMLResponse)
async def list_reports(request: Request):
    """List all security reports"""
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
            "active_page": "reports"
        })
    finally:
        db.close()

@app.get("/submit", response_class=HTMLResponse)
async def submit_request_page(request: Request):
    """Show submit analysis request form"""
    db = SessionLocal()
    try:
        # Get recent projects for quick access
        recent_projects = db.query(SecurityReport)\
            .filter(SecurityReport.status == "completed")\
            .order_by(SecurityReport.scan_time.desc())\
            .limit(5).all()
        
        return templates.TemplateResponse("submit_request.html", {
            "request": request,
            "recent_projects": recent_projects,
            "active_page": "submit"
        })
    finally:
        db.close()

@app.post("/submit")
async def submit_analysis(
    request: Request,
    project_path: str = Form(...),
    app_name: str = Form(None)
):
    """Handle form submission for analysis"""
    db = None
    pending_report = None
    
    try:
        # Submit analysis request via API
        analysis_request = AnalysisRequest(
            project_path=project_path,
            app_name=app_name
        )
        
        # Validate project path
        if not os.path.exists(project_path):
            db = SessionLocal()
            try:
                recent_projects = db.query(SecurityReport)\
                    .filter(SecurityReport.status == "completed")\
                    .order_by(SecurityReport.scan_time.desc())\
                    .limit(5).all()
                
                return templates.TemplateResponse("submit_request.html", {
                    "request": request,
                    "active_page": "submit",
                    "form_data": {"project_path": project_path, "app_name": app_name},
                    "errors": {"project_path": "Project path does not exist"},
                    "recent_projects": recent_projects
                })
            finally:
                db.close()
        
        # Run analysis
        from android_security_analyzer import AndroidSecurityAnalyzer
        
        # Create pending record
        db = SessionLocal()
        try:
            pending_report = SecurityReport(
                app_name=app_name or "Unknown",
                package_name="Unknown",
                version="Unknown",
                project_path=project_path,
                status="in_progress",
                total_issues=0
            )
            db.add(pending_report)
            db.commit()
            db.refresh(pending_report)
            
            # Get the ID after commit and refresh
            report_id = pending_report.id
            
            # Run analysis
            analyzer = AndroidSecurityAnalyzer(project_path)
            analysis_result = await analyzer.analyze_async(project_path)
            report_data = analyzer.report_generator.prepare_json_data(analysis_result)
            
            # Save to file in project directory  
            output_file = os.path.join(project_path, "security_report.json")
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
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
                
                # Redirect to report view
                return RedirectResponse(url=f"/reports/{report_id}", status_code=303)
            else:
                raise Exception("Could not find pending report after creation")
                
        except Exception as analysis_error:
            # Mark report as failed if it exists
            if pending_report and hasattr(pending_report, 'id'):
                try:
                    failed_report = db.query(SecurityReport).filter(SecurityReport.id == pending_report.id).first()
                    if failed_report:
                        failed_report.status = "failed"
                        db.commit()
                except Exception:
                    pass  # Don't let cleanup errors override the main error
            raise analysis_error
        finally:
            if db:
                db.close()
            
    except Exception as e:
        # Get recent projects for error page
        recent_projects = []
        try:
            db_temp = SessionLocal()
            recent_projects = db_temp.query(SecurityReport)\
                .filter(SecurityReport.status == "completed")\
                .order_by(SecurityReport.scan_time.desc())\
                .limit(5).all()
            db_temp.close()
        except Exception:
            pass
        
        return templates.TemplateResponse("submit_request.html", {
            "request": request,
            "active_page": "submit",
            "form_data": {"project_path": project_path, "app_name": app_name},
            "messages": [("error", f"Analysis failed: {str(e)}")],
            "recent_projects": recent_projects
        })

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

@app.get("/reports/{report_id}", response_class=HTMLResponse)
async def view_report_page(request: Request, report_id: int):
    """View detailed security report"""
    db = SessionLocal()
    try:
        report = db.query(SecurityReport).filter(SecurityReport.id == report_id).first()
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        if not report.report_data:
            raise HTTPException(status_code=404, detail="Report data not available")
        
        report_data = json.loads(report.report_data)
        
        # Get ignored issues for this report
        ignored_issues = db.query(IgnoredIssue).filter(
            IgnoredIssue.report_id == report_id
        ).all()
        
        # Filter out ignored issues from report data
        filtered_report_data = filter_ignored_issues(report_data, ignored_issues)
        
        return templates.TemplateResponse("view_report.html", {
            "request": request,
            "report": report,
            "report_data": filtered_report_data,
            "ignored_issues": ignored_issues,
            "active_page": "reports"
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
        try:
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
            
            # Save to file in project directory  
            import json
            output_file = os.path.join(request.project_path, "security_report.json")
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
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
            
        except Exception as analysis_error:
            # Mark report as failed if it exists
            if pending_report and hasattr(pending_report, 'id'):
                try:
                    failed_report = db.query(SecurityReport).filter(SecurityReport.id == pending_report.id).first()
                    if failed_report:
                        failed_report.status = "failed"
                        db.commit()
                except Exception:
                    pass  # Don't let cleanup errors override the main error
            raise analysis_error
        finally:
            if db:
                db.close()
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

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
async def download_report_pdf(request: Request, report_id: int):
    """Generate and download PDF report"""
    db = SessionLocal()
    try:
        report = db.query(SecurityReport).filter(SecurityReport.id == report_id).first()
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        if not report.report_data:
            raise HTTPException(status_code=404, detail="Report data not available")
        
        report_data = json.loads(report.report_data)
        
        # Get ignored issues for this report and filter them out
        ignored_issues = db.query(IgnoredIssue).filter(
            IgnoredIssue.report_id == report_id
        ).all()
        
        # Filter out ignored issues from report data
        filtered_report_data = filter_ignored_issues(report_data, ignored_issues)
        
        # Render HTML template with print-optimized styles
        html_content = templates.get_template("view_report_pdf.html").render(
            request=request,
            report=report,
            report_data=filtered_report_data
        )
        
        # Generate PDF
        pdf_buffer = io.BytesIO()
        weasyprint.HTML(string=html_content, base_url=str(request.url)).write_pdf(pdf_buffer)
        pdf_buffer.seek(0)
        
        # Create filename
        app_name = filtered_report_data["app_metadata"]["app_name"].replace(" ", "_").replace("/", "_")
        filename = f"{app_name}_security_report.pdf"
        
        return StreamingResponse(
            io.BytesIO(pdf_buffer.read()),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
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

# Function removed - now using Jinja2 templates

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 