#!/usr/bin/env python3
"""
Android Security Analyzer
A comprehensive security analysis tool for Android applications
"""

import os
import sys
import json
import re
import xml.etree.ElementTree as ET
import requests
import asyncio
import aiohttp
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import argparse
from packaging import version
import subprocess
import time
import base64
from PIL import Image
import io

class Logger:
    """Custom logger for Android Security Analyzer"""
    
    def __init__(self, level="INFO"):
        self.level = level
        self.level_num = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}.get(level, 1)
        self.indent_level = 0
    
    def _log(self, level: str, message: str, emoji: str = "", indent_override: int = None):
        """Internal logging method"""
        level_num = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}[level]
        if level_num >= self.level_num:
            indent_level = indent_override if indent_override is not None else self.indent_level
            indent = "   " * indent_level
            timestamp = datetime.now().strftime("%H:%M:%S")
            prefix = f"{emoji} " if emoji else ""
            print(f"[{timestamp}] {level}: {indent}{prefix}{message}")
    
    def debug(self, message: str, emoji: str = ""):
        self._log("DEBUG", message, emoji)
    
    def info(self, message: str, emoji: str = ""):
        self._log("INFO", message, emoji)
    
    def warning(self, message: str, emoji: str = ""):
        self._log("WARNING", message, emoji)
    
    def error(self, message: str, emoji: str = ""):
        self._log("ERROR", message, emoji)
    
    def step(self, step_num: int, title: str):
        """Log a step header"""
        self._log("INFO", f"Step {step_num}: {title}", "📋", 0)
    
    def sub_step(self, message: str, emoji: str = "🔍"):
        """Log a substep with proper indentation"""
        self._log("INFO", message, emoji, 1)
    
    def progress(self, current: int, total: int, message: str, emoji: str = "📦"):
        """Log progress with current/total format"""
        self._log("INFO", f"[{current}/{total}] {message}", emoji, 1)
    
    def success(self, message: str):
        """Log a success message"""
        self._log("INFO", message, "✅", 1)
    
    def error_msg(self, message: str):
        """Log an error message"""
        self._log("ERROR", message, "❌", 1)
    
    def warning_msg(self, message: str):
        """Log a warning message"""
        self._log("WARNING", message, "⚠️", 1)
    
    def detail(self, message: str, emoji: str = ""):
        """Log detailed information with deeper indentation"""
        self._log("INFO", message, emoji, 2)
    
    def separator(self, char: str = "=", length: int = 60):
        """Print a separator line"""
        if self.level_num <= 1:  # Only show for INFO and below
            print(char * length)
    
    def indent(self):
        """Increase indentation level"""
        self.indent_level += 1
    
    def dedent(self):
        """Decrease indentation level"""
        self.indent_level = max(0, self.indent_level - 1)

# Global logger instance
logger = Logger()

# Configuration
class Config:
    OSV_API_URL = "https://api.osv.dev/v1/query"
    GITHUB_ADVISORY_API = "https://api.github.com/advisories"
    MAVEN_CENTRAL_API = "https://search.maven.org/solrsearch/select"
    
    # Risk levels
    CRITICAL = "CRITICAL"
    HIGH = "HIGH" 
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    
    # Patterns for security issues
    API_KEY_PATTERNS = [
        r'AIza[0-9A-Za-z\\-_]{35}',  # Google API keys
        r'sk_live_[0-9a-zA-Z]{24}',  # Stripe keys
        r'pk_live_[0-9a-zA-Z]{24}',  # Stripe public keys
        r'sk_test_[0-9a-zA-Z]{24}',  # Stripe test keys
        r'pk_test_[0-9a-zA-Z]{24}',  # Stripe test public keys
        r'ya29\.[0-9A-Za-z\-_]+',    # Google OAuth tokens
        r'AKIA[0-9A-Z]{16}',         # AWS Access Keys
        r'[0-9a-f]{32}',             # Generic 32-char hex (only in assignment context)
    ]
    
    # Context-aware patterns for potential API keys (more specific)
    API_KEY_CONTEXT_PATTERNS = [
        r'(?:api[_-]?key|apikey|secret|token|password|pwd)\s*[=:]\s*["\']([A-Za-z0-9]{20,})["\']',
        r'Authorization\s*[=:]\s*["\']([A-Za-z0-9+/]{20,})["\']',
        r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)',
        r'(?:client[_-]?secret|client[_-]?id)\s*[=:]\s*["\']([A-Za-z0-9]{16,})["\']',
    ]
    
    LOG_PATTERNS = [
        r'Log\.[deiw]\(',
        r'System\.out\.print',
        r'\.printStackTrace\(',
        r'console\.log\(',
    ]

@dataclass
class SecurityIssue:
    title: str
    description: str
    risk_level: str
    category: str
    file_path: str = ""
    line_number: int = 0
    recommendation: str = ""
    code_snippet: str = ""

@dataclass
class Dependency:
    group_id: str
    artifact_id: str
    version: str
    latest_version: str = ""
    vulnerabilities: List[Dict] = None
    is_outdated: bool = False
    risk_level: str = Config.LOW

@dataclass
class AppMetadata:
    """App metadata extracted from manifest and resources"""
    app_name: str = "Unknown App"
    package_name: str = "Unknown Package"
    version_name: str = "Unknown Version"
    version_code: str = "Unknown"
    target_sdk: str = "Unknown"
    min_sdk: str = "Unknown"
    app_icon_path: str = ""
    app_logo_base64: str = ""
    permissions: List[str] = None

@dataclass
class AnalysisResult:
    project_path: str
    scan_time: datetime
    issues: List[SecurityIssue]
    dependencies: List[Dependency]
    summary: Dict[str, int]
    recommendations: List[str]
    app_metadata: AppMetadata = None

class FileParser:
    """Parse various Android project files"""
    
    @staticmethod
    def _should_exclude_directory(dir_path: str, project_path: str) -> bool:
        """Check if directory should be excluded from scanning"""
        # Get relative path from project root
        rel_path = os.path.relpath(dir_path, project_path)
        
        # Comprehensive .gitignore style patterns
        excluded_patterns = [
            # Build directories
            'build',
            'app/build',
            '.gradle',
            'gradle',
            'target',
            'dist',
            'out',
            # IDE directories
            '.idea',
            '.vscode',
            '.settings',
            '.project',
            '.classpath',
            '.metadata',
            # Version control
            '.git',
            '.svn',
            '.hg',
            '.bzr',
            'CVS',
            # Dependencies/libraries
            'node_modules',
            '.pub-cache',
            'vendor',
            'bower_components',
            # Generated code
            'generated',
            'intermediates',
            'gen',
            'release',
            'debug',
            # Cache directories
            'cache',
            '.cache',
            '.npm',
            '.yarn',
            # Temporary directories
            'tmp',
            'temp',
            '.tmp',
            '.temp',
            # Android specific
            'lint-results',
            'proguard',
            '.externalNativeBuild',
            'captures',
            # Gradle wrapper
            'gradle/wrapper',
            # Logs
            'logs',
            '*.log',
            # OS generated files
            '.DS_Store',
            'Thumbs.db',
            # Package files
            '*.jar',
            '*.war',
            '*.nar',
            '*.ear',
            '*.zip',
            '*.tar.gz',
            '*.rar',
            # Test results
            'test-results',
            'jacoco',
            # Documentation
            'javadoc',
            'apidocs',
            # Backup files
            '*.bak',
            '*.backup',
            '*~'
        ]
        
        # Check if the relative path starts with any excluded pattern
        for pattern in excluded_patterns:
            if rel_path.startswith(pattern) or rel_path == pattern:
                return True
            # Also check if any parent directory matches
            path_parts = rel_path.split(os.sep)
            if any(part in excluded_patterns for part in path_parts):
                return True
        
        return False
    
    @staticmethod
    def find_files(project_path: str, pattern: str) -> List[str]:
        """Find files matching pattern in project, excluding build/cache directories"""
        files = []
        for root, dirs, filenames in os.walk(project_path):
            # Skip excluded directories
            if FileParser._should_exclude_directory(root, project_path):
                continue
                
            # Remove excluded directories from dirs to prevent os.walk from descending into them
            dirs[:] = [d for d in dirs if not FileParser._should_exclude_directory(os.path.join(root, d), project_path)]
            
            for filename in filenames:
                if re.match(pattern, filename):
                    files.append(os.path.join(root, filename))
        return files
    
    @staticmethod
    def get_relative_path(file_path: str, project_path: str) -> str:
        """Get relative path from project root"""
        try:
            return os.path.relpath(file_path, project_path)
        except:
            return file_path
    
    @staticmethod
    def extract_app_metadata(manifest_path: str, project_path: str) -> AppMetadata:
        """Extract app metadata from AndroidManifest.xml and build.gradle"""
        metadata = AppMetadata()
        
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Extract package name from manifest first
            metadata.package_name = root.get('package', '')
            
            # Try to extract version and SDK info from build.gradle first (modern Android)
            gradle_info = FileParser._extract_gradle_info(project_path)
            if gradle_info:
                metadata.version_name = gradle_info.get('versionName', 'Unknown')
                metadata.version_code = gradle_info.get('versionCode', 'Unknown')
                metadata.target_sdk = gradle_info.get('targetSdk', 'Unknown')
                metadata.min_sdk = gradle_info.get('minSdk', 'Unknown')
                
                # If package not found in manifest, try to get namespace from gradle
                if not metadata.package_name:
                    metadata.package_name = gradle_info.get('namespace', 'Unknown Package')
            else:
                # Fallback to manifest (legacy Android)
                metadata.version_name = root.get('{http://schemas.android.com/apk/res/android}versionName', 'Unknown')
                metadata.version_code = root.get('{http://schemas.android.com/apk/res/android}versionCode', 'Unknown')
                
                # Extract SDK info from manifest
                uses_sdk = root.find('.//uses-sdk')
                if uses_sdk is not None:
                    metadata.target_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', 'Unknown')
                    metadata.min_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion', 'Unknown')
            
            # Fallback for package name if still empty
            if not metadata.package_name:
                metadata.package_name = 'Unknown Package'
            
            # Extract permissions
            permissions = []
            for perm in root.findall('.//uses-permission'):
                perm_name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
                if perm_name:
                    permissions.append(perm_name.split('.')[-1])  # Get short name
            metadata.permissions = permissions
            
            # Extract app name and icon from application element
            application = root.find('.//application')
            if application is not None:
                app_label = application.get('{http://schemas.android.com/apk/res/android}label', '')
                app_icon = application.get('{http://schemas.android.com/apk/res/android}icon', '')
                
                # Try to resolve app name from strings.xml
                if app_label.startswith('@string/'):
                    string_name = app_label.replace('@string/', '')
                    app_name = FileParser._resolve_string_resource(project_path, string_name)
                    metadata.app_name = app_name or metadata.package_name.split('.')[-1]
                elif app_label:
                    metadata.app_name = app_label
                else:
                    metadata.app_name = metadata.package_name.split('.')[-1]
                
                # Try to find app icon
                if app_icon:
                    metadata.app_icon_path = FileParser._find_app_icon(project_path, app_icon)
                    # Extract and encode logo as base64
                    metadata.app_logo_base64 = FileParser._extract_logo_base64(project_path, app_icon)
            
        except Exception as e:
            logger.error(f"Error extracting app metadata: {e}")
            
        return metadata
    
    @staticmethod
    def _extract_gradle_info(project_path: str) -> Optional[Dict[str, str]]:
        """Extract version and SDK info from build.gradle or build.gradle.kts"""
        try:
            # Look for both .gradle and .gradle.kts files
            gradle_paths = [
                os.path.join(project_path, 'app', 'build.gradle'),
                os.path.join(project_path, 'app', 'build.gradle.kts'),
                os.path.join(project_path, 'build.gradle'),
                os.path.join(project_path, 'build.gradle.kts')
            ]
            
            gradle_content = ""
            gradle_file_used = None
            for gradle_path in gradle_paths:
                if os.path.exists(gradle_path):
                    with open(gradle_path, 'r', encoding='utf-8') as f:
                        gradle_content = f.read()
                    gradle_file_used = gradle_path
                    break
            
            if not gradle_content:
                return None
            
            gradle_info = {}
            is_kotlin_dsl = gradle_file_used.endswith('.kts') if gradle_file_used else False
            
            # Extract namespace (modern Android package identifier) - support both syntaxes
            namespace_patterns = [
                r'namespace\s*=\s*["\']([^"\']+)["\']',  # Kotlin DSL style: namespace = "com.example"
                r'namespace\s+["\']([^"\']+)["\']'       # Regular Gradle style: namespace "com.example"
            ]
            
            for pattern in namespace_patterns:
                namespace_match = re.search(pattern, gradle_content)
                if namespace_match:
                    gradle_info['namespace'] = namespace_match.group(1)
                    break
            
            # Extract targetSdk (compileSdk or targetSdk) - support both syntaxes in any file
            target_sdk_patterns = [
                r'(?:targetSdk|compileSdk)\s*=\s*(\d+)',           # Kotlin DSL: targetSdk = 35
                r'(?:targetSdk|compileSdk)\s+(\d+)',               # Regular Gradle: targetSdk 35
                r'(?:targetSdkVersion|compileSdkVersion)\s*=\s*(\d+)', # Legacy Kotlin DSL
                r'(?:targetSdkVersion|compileSdkVersion)\s+(\d+)'   # Legacy regular Gradle
            ]
            
            for pattern in target_sdk_patterns:
                target_sdk_match = re.search(pattern, gradle_content)
                if target_sdk_match:
                    gradle_info['targetSdk'] = target_sdk_match.group(1)
                    break
            
            # Extract minSdk - support both syntaxes in any file
            min_sdk_patterns = [
                r'minSdk\s*=\s*(\d+)',  # Kotlin DSL style: minSdk = 29
                r'minSdk\s+(\d+)'       # Regular Gradle style: minSdk 29
            ]
            
            for pattern in min_sdk_patterns:
                min_sdk_match = re.search(pattern, gradle_content)
                if min_sdk_match:
                    gradle_info['minSdk'] = min_sdk_match.group(1)
                    break
            
            # Extract versionName - support both syntaxes in any file
            version_name_patterns = [
                r'versionName\s*=\s*["\']([^"\']+)["\']',  # Kotlin DSL: versionName = "1.0.0"
                r'versionName\s+["\']([^"\']+)["\']',      # Regular Gradle: versionName "1.0.0"
                r'versionName\s*=\s*versionNameCalculator\((\d+),\s*(\d+),\s*(\d+)\)',  # Calculator functions
                r'versionName\s+versionNameCalculator\((\d+),\s*(\d+),\s*(\d+)\)',
            ]
            
            for pattern in version_name_patterns:
                matches = re.findall(pattern, gradle_content)
                if matches:
                    if 'versionNameCalculator' in pattern:
                        # Use the first found calculator call
                        major, minor, build = matches[0]
                        gradle_info['versionName'] = f"{major}.{minor}.{build}"
                    else:
                        # Use the first found version string
                        gradle_info['versionName'] = matches[0]
                    break
            
            # Extract versionCode - support both syntaxes in any file
            version_code_patterns = [
                r'versionCode\s*=\s*(\d+)',  # Kotlin DSL: versionCode = 16
                r'versionCode\s+(\d+)',      # Regular Gradle: versionCode 16
                r'versionCode\s*=\s*versionCodeCalculator\((\d+),\s*(\d+),\s*(\d+)\)',  # Calculator functions
                r'versionCode\s+versionCodeCalculator\((\d+),\s*(\d+),\s*(\d+)\)',
            ]
            
            for pattern in version_code_patterns:
                matches = re.findall(pattern, gradle_content)
                if matches:
                    if 'versionCodeCalculator' in pattern:
                        # Calculate version code from first found calculator call
                        major, minor, build = map(int, matches[0])
                        gradle_info['versionCode'] = str(major + minor + build)
                    else:
                        # Use the first found version code
                        gradle_info['versionCode'] = matches[0]
                    break
            
            return gradle_info if gradle_info else None
            
        except Exception as e:
            logger.error(f"Error extracting gradle info: {e}")
            return None
    
    @staticmethod
    def _resolve_string_resource(project_path: str, string_name: str) -> Optional[str]:
        """Resolve string resource from strings.xml"""
        try:
            # Look for strings.xml in various locations
            possible_paths = [
                os.path.join(project_path, 'app', 'src', 'main', 'res', 'values', 'strings.xml'),
                os.path.join(project_path, 'src', 'main', 'res', 'values', 'strings.xml'),
                os.path.join(project_path, 'res', 'values', 'strings.xml')
            ]
            
            for strings_path in possible_paths:
                if os.path.exists(strings_path):
                    tree = ET.parse(strings_path)
                    root = tree.getroot()
                    
                    for string_elem in root.findall('.//string'):
                        if string_elem.get('name') == string_name:
                            return string_elem.text
        except:
            pass
        return None
    
    @staticmethod
    def _find_app_icon(project_path: str, icon_ref: str) -> str:
        """Find app icon file"""
        try:
            # Remove @drawable/ or @mipmap/ prefix
            icon_name = icon_ref.replace('@drawable/', '').replace('@mipmap/', '')
            
            # Look for icon in various drawable/mipmap folders
            res_paths = [
                os.path.join(project_path, 'app', 'src', 'main', 'res'),
                os.path.join(project_path, 'src', 'main', 'res'),
                os.path.join(project_path, 'res')
            ]
            
            for res_path in res_paths:
                if os.path.exists(res_path):
                    for folder in os.listdir(res_path):
                        if folder.startswith(('drawable', 'mipmap')):
                            folder_path = os.path.join(res_path, folder)
                            if os.path.isdir(folder_path):
                                for file in os.listdir(folder_path):
                                    if file.startswith(icon_name) and file.endswith(('.png', '.jpg', '.jpeg', '.webp', '.xml')):
                                        # Return relative path for better display
                                        return FileParser.get_relative_path(os.path.join(folder_path, file), project_path)
        except:
            pass
        return ""
    
    @staticmethod
    def _extract_logo_base64(project_path: str, icon_ref: str) -> str:
        """Extract app logo and convert to base64"""
        try:
            # Remove @drawable/ or @mipmap/ prefix
            icon_name = icon_ref.replace('@drawable/', '').replace('@mipmap/', '')
            
            # Look for the highest resolution icon
            res_paths = [
                os.path.join(project_path, 'app', 'src', 'main', 'res'),
                os.path.join(project_path, 'src', 'main', 'res'),
                os.path.join(project_path, 'res')
            ]
            
            best_icon_path = None
            best_resolution = 0
            
            # Priority order for drawable folders (highest to lowest resolution)
            resolution_priorities = {
                'xxxhdpi': 4,
                'xxhdpi': 3,
                'xhdpi': 2,
                'hdpi': 1,
                'mdpi': 0
            }
            
            for res_path in res_paths:
                if os.path.exists(res_path):
                    for folder in os.listdir(res_path):
                        if folder.startswith(('drawable', 'mipmap')):
                            # Get resolution priority
                            resolution = 0
                            for res_type, priority in resolution_priorities.items():
                                if res_type in folder:
                                    resolution = priority
                                    break
                            
                            folder_path = os.path.join(res_path, folder)
                            if os.path.isdir(folder_path):
                                for file in os.listdir(folder_path):
                                    if file.startswith(icon_name) and file.endswith(('.png', '.jpg', '.jpeg', '.webp')):
                                        if resolution >= best_resolution:
                                            best_resolution = resolution
                                            best_icon_path = os.path.join(folder_path, file)
            
            if best_icon_path and os.path.exists(best_icon_path):
                # Open and resize image to 64x64 for storage efficiency
                with Image.open(best_icon_path) as img:
                    # Convert to RGBA if necessary
                    if img.mode != 'RGBA':
                        img = img.convert('RGBA')
                    
                    # Resize to 64x64
                    img = img.resize((64, 64), Image.Resampling.LANCZOS)
                    
                    # Convert to PNG bytes
                    buffer = io.BytesIO()
                    img.save(buffer, format='PNG')
                    buffer.seek(0)
                    
                    # Encode as base64
                    return base64.b64encode(buffer.getvalue()).decode('utf-8')
        except Exception as e:
            logger.debug(f"Could not extract logo: {e}")
        
        return ""
    
    @staticmethod
    def parse_android_manifest(manifest_path: str) -> Optional[ET.Element]:
        """Parse AndroidManifest.xml"""
        try:
            tree = ET.parse(manifest_path)
            return tree.getroot()
        except Exception as e:
            logger.error(f"Error parsing AndroidManifest.xml: {e}")
            return None
    
    @staticmethod
    def parse_gradle_file(gradle_path: str) -> str:
        """Read gradle file content"""
        try:
            with open(gradle_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading gradle file: {e}")
            return ""
    
    @staticmethod
    def parse_xml_file(xml_path: str) -> Optional[ET.Element]:
        """Parse any XML file"""
        try:
            tree = ET.parse(xml_path)
            return tree.getroot()
        except Exception:
            return None

class DependencyAnalyzer:
    """Analyze project dependencies for security issues"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AndroidSecurityAnalyzer/1.0'
        })
    
    def extract_dependencies(self, gradle_content: str, project_path: str = None) -> List[Dependency]:
        """Extract dependencies from gradle file (supports both .gradle, .gradle.kts, and version catalogs)"""
        dependencies = []
        
        # Split content into lines to process line by line and avoid multi-line matching
        lines = gradle_content.split('\n')
        
        # Traditional patterns for direct dependency declarations - made more restrictive
        traditional_patterns = [
            # Regular Gradle: implementation 'group:artifact:version' - single line only
            r'^[\s]*(?:(?:api|implementation|compile|testImplementation|androidTestImplementation|annotationProcessor|kapt)\s+)[\'"]([a-zA-Z0-9\.\-_]+:[a-zA-Z0-9\.\-_]+:[a-zA-Z0-9\.\-_\+\$\{\}]+)[\'"][\s]*(?://.*)?$',
            # Kotlin DSL: implementation("group:artifact:version") - single line only
            r'^[\s]*(?:(?:api|implementation|compile|testImplementation|androidTestImplementation|annotationProcessor|kapt)\s*\(\s*)[\'"]([a-zA-Z0-9\.\-_]+:[a-zA-Z0-9\.\-_]+:[a-zA-Z0-9\.\-_\+\$\{\}]+)[\'"][\s]*\)[\s]*(?://.*)?$',
            # Platform/BOM: implementation(platform("group:artifact:version"))
            r'^[\s]*(?:(?:implementation|compile|api)\s*\(\s*platform\s*\(\s*)[\'"]([a-zA-Z0-9\.\-_]+:[a-zA-Z0-9\.\-_]+:[a-zA-Z0-9\.\-_\+\$\{\}]+)[\'"][\s]*\)\s*\)[\s]*(?://.*)?$',
        ]
        
        # Separate pattern for variable references
        variable_pattern = r'^[\s]*(?:(?:api|implementation|compile|testImplementation|androidTestImplementation|annotationProcessor|kapt)\s+)[\'"]([a-zA-Z0-9\.\-_]+:[a-zA-Z0-9\.\-_]+):\$([a-zA-Z0-9_]+)[\'"][\s]*(?://.*)?$'
        
        # Extract variables first
        variables = self._extract_gradle_variables(gradle_content)
        
        # Process each line individually to avoid multi-line matches
        for line in lines:
            line = line.strip()
            
            # Skip empty lines, comments, and lines that look like configuration blocks
            if not line or line.startswith('//') or line.startswith('*') or line.startswith('#'):
                continue
            
            # Skip lines that contain build configuration keywords
            if any(keyword in line.lower() for keyword in [
                'android {', 'buildTypes', 'productFlavors', 'defaultConfig', 'compileSdk', 
                'targetSdk', 'minSdk', 'versionCode', 'versionName', 'applicationId', 
                'namespace', 'buildFeatures', 'compileOptions', 'kotlinOptions'
            ]):
                continue
            
            # Extract traditional dependencies
            for pattern in traditional_patterns:
                match = re.match(pattern, line)
                if match:
                    full_dep = match.group(1)
                    parts = full_dep.split(':')
                    if len(parts) == 3:
                        group_id, artifact_id, version = parts
                        
                        # Validate that it looks like a real dependency
                        if self._is_valid_dependency(group_id, artifact_id, version):
                            dependencies.append(Dependency(
                                group_id=group_id,
                                artifact_id=artifact_id,
                                version=version
                            ))
            
            # Extract variable references
            var_match = re.match(variable_pattern, line)
            if var_match:
                dep_part, var_name = var_match.groups()
                parts = dep_part.split(':')
                if len(parts) == 2:
                    group_id, artifact_id = parts
                    version = variables.get(var_name, f"${var_name}")
                    
                    if self._is_valid_dependency(group_id, artifact_id, version):
                        dependencies.append(Dependency(
                            group_id=group_id,
                            artifact_id=artifact_id,
                            version=version
                        ))
        
        # Extract dependencies without explicit versions (relying on BOM) - also line by line
        bom_pattern = r'^[\s]*(?:(?:implementation|compile|api|testImplementation|androidTestImplementation)\s*\(\s*)[\'"]([a-zA-Z0-9\.\-_]+:[a-zA-Z0-9\.\-_]+)[\'"]\s*\)[\s]*(?://.*)?$'
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('//'):
                continue
                
            bom_match = re.match(bom_pattern, line)
            if bom_match:
                dep_part = bom_match.group(1)
                parts = dep_part.split(':')
                if len(parts) == 2:
                    group_id, artifact_id = parts
                    
                    # Skip if already captured by other patterns
                    if any(dep.group_id == group_id and dep.artifact_id == artifact_id for dep in dependencies):
                        continue
                    
                    if self._is_valid_dependency(group_id, artifact_id, "BOM-managed"):
                        dependencies.append(Dependency(
                            group_id=group_id,
                            artifact_id=artifact_id,
                            version="BOM-managed"
                        ))
        
        # Check for version catalog dependencies (libs.*)
        version_catalog_patterns = [
            # Simple format: implementation libs.name
            r'^[\s]*(?:(?:implementation|compile|api|testImplementation|androidTestImplementation|annotationProcessor|kapt)\s+)libs\.([a-zA-Z0-9\.\-_]+)[\s]*(?://.*)?$',
            # Parentheses format: implementation(libs.name)
            r'^[\s]*(?:(?:implementation|compile|api|testImplementation|androidTestImplementation|annotationProcessor|kapt)\s*\(\s*)libs\.([a-zA-Z0-9\.\-_]+)\s*\)[\s]*(?://.*)?$',
        ]
        
        version_catalog_matches = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith('//'):
                continue
                
            for pattern in version_catalog_patterns:
                match = re.match(pattern, line)
                if match:
                    version_catalog_matches.append(match.group(1))
        
        if version_catalog_matches and project_path:
            # Load version catalog if it exists
            version_catalog = self._load_version_catalog(project_path)
            if version_catalog:
                for lib_ref in version_catalog_matches:
                    # Convert libs.androidx.core.ktx -> androidx.core.ktx
                    lib_key = lib_ref.replace('.', '-')
                    
                    if lib_key in version_catalog:
                        dep_info = version_catalog[lib_key]
                        dependencies.append(Dependency(
                            group_id=dep_info['group'],
                            artifact_id=dep_info['artifact'],
                            version=dep_info['version']
                        ))
        
        return dependencies
    
    def _is_valid_dependency(self, group_id: str, artifact_id: str, version: str) -> bool:
        """Validate that this looks like a real dependency"""
        # Skip if it's a project dependency
        if group_id.startswith(':') or artifact_id.startswith(':'):
            return False
        
        # Basic format validation
        if not group_id or not artifact_id or not version:
            return False
        
        # Skip if group_id or artifact_id are actually build configuration blocks
        # These are keywords that indicate build configuration, not dependency names
        build_config_keywords = [
            'buildTypes', 'productFlavors', 'defaultConfig', 'compileSdk',
            'targetSdk', 'minSdk', 'versionCode', 'versionName', 'applicationId',
            'namespace', 'buildFeatures', 'compileOptions', 'kotlinOptions', 'splits',
            'abi', 'enable', 'reset', 'include', 'universal', 'exclude', 'testInstrumentationRunner'
        ]
        
        # Only reject if the entire group_id or artifact_id exactly matches these keywords
        for keyword in build_config_keywords:
            if group_id.lower() == keyword.lower() or artifact_id.lower() == keyword.lower():
                return False
        
        # Allow common dependency patterns
        # Group ID can be single word (like 'junit') or dotted (like 'com.example')
        # Artifact ID should be reasonable length and not contain spaces
        if len(artifact_id) > 100 or ' ' in artifact_id:
            return False
        
        # Version should not be extremely long
        if len(version) > 50:
            return False
        
        # Additional validation: reject if it looks like gradle syntax
        if any(char in group_id for char in ['{', '}', '(', ')', '=']) or \
           any(char in artifact_id for char in ['{', '}', '(', ')', '=']):
            return False
        
        return True
    
    def _extract_gradle_variables(self, gradle_content: str) -> Dict[str, str]:
        """Extract variable definitions from gradle content"""
        variables = {}
        
        # Pattern for variable definitions: def variable_name = "value"
        def_pattern = r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\']([^"\']+)["\']'
        def_matches = re.findall(def_pattern, gradle_content)
        for var_name, var_value in def_matches:
            variables[var_name] = var_value
        
        # Pattern for direct variable assignments: variable_name = "value"  
        direct_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\']([^"\']+)["\']'
        direct_matches = re.findall(direct_pattern, gradle_content)
        for var_name, var_value in direct_matches:
            # Only capture if it looks like a version (contains numbers/dots)
            if re.search(r'[\d\.]', var_value):
                variables[var_name] = var_value
        
        return variables
    
    def _load_version_catalog(self, project_path: str) -> Dict[str, Dict[str, str]]:
        """Load and parse gradle/libs.versions.toml version catalog"""
        catalog_path = os.path.join(project_path, 'gradle', 'libs.versions.toml')
        
        if not os.path.exists(catalog_path):
            return {}
        
        try:
            # Try to import tomllib (Python 3.11+)
            try:
                import tomllib
            except ImportError:
                tomllib = None
            
            if tomllib is None:
                # Fallback manual parsing for older Python versions
                return self._parse_toml_manually(catalog_path)
            
            with open(catalog_path, 'rb') as f:
                catalog_data = tomllib.load(f)
                
            versions = catalog_data.get('versions', {})
            libraries = catalog_data.get('libraries', {})
            
            resolved_catalog = {}
            
            for lib_name, lib_info in libraries.items():
                if isinstance(lib_info, dict):
                    # Handle both "group + name" and "module" formats
                    if 'module' in lib_info:
                        # module = "group:artifact"
                        module_parts = lib_info['module'].split(':')
                        if len(module_parts) == 2:
                            group_id, artifact_id = module_parts
                        else:
                            continue
                    elif 'group' in lib_info and 'name' in lib_info:
                        # group = "group", name = "artifact"
                        group_id = lib_info['group']
                        artifact_id = lib_info['name']
                    else:
                        continue
                    
                    # Resolve version reference
                    version_ref = lib_info.get('version', {})
                    if isinstance(version_ref, dict) and 'ref' in version_ref:
                        version = versions.get(version_ref['ref'], 'unknown')
                    elif isinstance(version_ref, str):
                        version = version_ref
                    else:
                        version = 'unknown'
                    
                    resolved_catalog[lib_name] = {
                        'group': group_id,
                        'artifact': artifact_id,
                        'version': version
                    }
            
            return resolved_catalog
            
        except Exception as e:
            logger.error(f"Error parsing version catalog: {e}")
            return {}
    
    def _parse_toml_manually(self, catalog_path: str) -> Dict[str, Dict[str, str]]:
        """Manual TOML parsing fallback for older Python versions"""
        try:
            with open(catalog_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            resolved_catalog = {}
            versions = {}
            
            # Extract versions section
            versions_match = re.search(r'\[versions\]\s*\n(.*?)(?=\n\[|\Z)', content, re.DOTALL)
            if versions_match:
                versions_content = versions_match.group(1)
                for line in versions_content.strip().split('\n'):
                    if '=' in line and not line.strip().startswith('#'):
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"')
                        versions[key] = value
            
            # Extract libraries section
            libraries_match = re.search(r'\[libraries\]\s*\n(.*?)(?=\n\[|\Z)', content, re.DOTALL)
            if libraries_match:
                libraries_content = libraries_match.group(1)
                
                # Parse each library entry
                current_lib = None
                for line in libraries_content.strip().split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    if '=' in line and '.' not in line.split('=')[0]:
                        # New library definition
                        lib_name, lib_def = line.split('=', 1)
                        lib_name = lib_name.strip()
                        lib_def = lib_def.strip()
                        
                        # Parse the library definition
                        group_id = artifact_id = version = None
                        
                        # Extract module format: { module = "group:artifact", version.ref = "versionRef" }
                        module_match = re.search(r'module\s*=\s*"([^"]+)"', lib_def)
                        if module_match:
                            module_parts = module_match.group(1).split(':')
                            if len(module_parts) == 2:
                                group_id, artifact_id = module_parts
                        
                        # Extract group/name format: { group = "group", name = "artifact", version.ref = "versionRef" }
                        if not group_id:
                            group_match = re.search(r'group\s*=\s*"([^"]+)"', lib_def)
                            name_match = re.search(r'name\s*=\s*"([^"]+)"', lib_def)
                            if group_match and name_match:
                                group_id = group_match.group(1)
                                artifact_id = name_match.group(1)
                        
                        # Extract version
                        version_ref_match = re.search(r'version\.ref\s*=\s*"([^"]+)"', lib_def)
                        if version_ref_match:
                            version_ref = version_ref_match.group(1)
                            version = versions.get(version_ref, 'unknown')
                        else:
                            version_match = re.search(r'version\s*=\s*"([^"]+)"', lib_def)
                            if version_match:
                                version = version_match.group(1)
                        
                        if group_id and artifact_id and version:
                            resolved_catalog[lib_name] = {
                                'group': group_id,
                                'artifact': artifact_id,
                                'version': version
                            }
            
            return resolved_catalog
            
        except Exception as e:
            logger.error(f"Error manually parsing TOML: {e}")
            return {}
    
    def check_deprecated_repositories(self, gradle_content: str) -> List[SecurityIssue]:
        """Check for deprecated repositories"""
        issues = []
        
        if 'jcenter()' in gradle_content:
            issues.append(SecurityIssue(
                title="Deprecated JCenter Repository",
                description="Using deprecated jcenter() repository that was shut down in 2022",
                risk_level=Config.CRITICAL,
                category="Dependencies",
                recommendation="Remove jcenter() and use mavenCentral() instead"
            ))
        
        return issues
    
    def check_alpha_beta_versions(self, dependencies: List[Dependency]) -> List[SecurityIssue]:
        """Check for alpha/beta versions in production"""
        issues = []
        
        for dep in dependencies:
            if any(keyword in dep.version.lower() for keyword in ['alpha', 'beta', 'rc', 'snapshot']):
                issues.append(SecurityIssue(
                    title=f"Alpha/Beta Dependency: {dep.group_id}:{dep.artifact_id}",
                    description=f"Using unstable version {dep.version} in production",
                    risk_level=Config.CRITICAL if 'alpha' in dep.version.lower() else Config.HIGH,
                    category="Dependencies",
                    recommendation=f"Update to stable version of {dep.group_id}:{dep.artifact_id}"
                ))
        
        return issues
    
    def get_latest_version(self, group_id: str, artifact_id: str) -> str:
        """Get latest version with support for both Maven Central and Google Maven"""
        try:
            # For AndroidX and Google libraries, try Google Maven first
            if group_id.startswith('androidx.') or group_id.startswith('com.google.android') or group_id.startswith('com.android'):
                latest = self._get_version_from_google_maven(group_id, artifact_id)
                if latest:
                    return latest
            
            # Try Maven Central search API
            try:
                url = f"https://search.maven.org/solrsearch/select?q=g:{group_id}+AND+a:{artifact_id}&rows=1&wt=json"
                response = self.session.get(url, timeout=15)
                
                if response.status_code == 200:
                    data = response.json()
                    docs = data.get('response', {}).get('docs', [])
                    if docs and len(docs) > 0:
                        latest = docs[0].get('latestVersion') or docs[0].get('v')
                        if latest:
                            logger.detail(f"Found latest version via Maven Central: {latest}", "✅")
                            return latest
            except Exception as e:
                logger.debug(f"Maven Central search failed: {e}")
            
            # Try Maven Central metadata XML
            try:
                group_path = group_id.replace('.', '/')
                metadata_url = f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}/maven-metadata.xml"
                
                response = self.session.get(metadata_url, timeout=15)
                if response.status_code == 200:
                    latest = self._parse_maven_metadata(response.content)
                    if latest:
                        logger.detail(f"Found latest version via Maven metadata: {latest}", "✅")
                        return latest
            except Exception as e:
                logger.debug(f"Maven metadata failed: {e}")
            
            # Final fallback: Try Google Maven for any remaining dependencies
            if not group_id.startswith('androidx.'):
                latest = self._get_version_from_google_maven(group_id, artifact_id)
                if latest:
                    return latest
            
            logger.debug(f"All version lookup methods failed for {group_id}:{artifact_id}")
            return ""
            
        except Exception as e:
            logger.error(f"Error fetching latest version for {group_id}:{artifact_id}: {e}")
            return ""
    
    def _get_version_from_google_maven(self, group_id: str, artifact_id: str) -> str:
        """Get version from Google's Maven repository"""
        try:
            # Try Google Maven repository metadata
            group_path = group_id.replace('.', '/')
            google_metadata_url = f"https://maven.google.com/{group_path}/{artifact_id}/maven-metadata.xml"
            
            response = self.session.get(google_metadata_url, timeout=10)
            if response.status_code == 200:
                latest = self._parse_maven_metadata(response.content)
                if latest:
                    logger.detail(f"Found version via Google Maven: {latest}", "✅")
                    return latest
                    
        except Exception as e:
            logger.debug(f"Google Maven lookup failed for {group_id}:{artifact_id}: {e}")
        
        return ""
    
    def _parse_maven_metadata(self, content: bytes) -> str:
        """Parse Maven metadata XML to extract latest stable version"""
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)
            
            # Get all available versions
            versions = root.findall('.//version')
            if not versions:
                return ""
            
            all_versions = [v.text for v in versions if v.text]
            if not all_versions:
                return ""
            
            # Filter out pre-release versions (alpha, beta, rc, snapshot)
            stable_versions = [v for v in all_versions if not any(suffix in v.lower() for suffix in ['snapshot', 'alpha', 'beta', 'rc'])]
            
            if stable_versions:
                # Sort stable versions and get the latest
                try:
                    from packaging import version
                    sorted_versions = sorted(stable_versions, key=lambda x: version.parse(x), reverse=True)
                    return sorted_versions[0]
                except:
                    # Fallback to last stable version in list
                    return stable_versions[-1]
            else:
                # If no stable versions found, try release or latest from metadata
                release_elem = root.find('.//release')
                if release_elem is not None and release_elem.text:
                    return release_elem.text
                
                latest_elem = root.find('.//latest')
                if latest_elem is not None and latest_elem.text:
                    return latest_elem.text
                
                # Last resort: use the most recent version even if pre-release
                try:
                    from packaging import version
                    sorted_all = sorted(all_versions, key=lambda x: version.parse(x), reverse=True)
                    return sorted_all[0]
                except:
                    return all_versions[-1]
                    
        except Exception as e:
            logger.debug(f"Error parsing Maven metadata: {e}")
        
        return ""

    
    async def check_vulnerabilities(self, dependency: Dependency) -> List[Dict]:
        """Check OSV database for vulnerabilities"""
        try:
            async with aiohttp.ClientSession() as session:
                query = {
                    "package": {
                        "ecosystem": "Maven",
                        "name": f"{dependency.group_id}:{dependency.artifact_id}"
                    },
                    "version": dependency.version
                }
                
                async with session.post(Config.OSV_API_URL, json=query) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('vulns', [])
        except Exception as e:
            logger.error(f"Error checking vulnerabilities for {dependency.group_id}:{dependency.artifact_id}: {e}")
        
        return []

class ManifestAnalyzer:
    """Analyze AndroidManifest.xml for security issues"""
    
    def analyze(self, manifest_root: ET.Element, dependencies: List[Dependency] = None) -> List[SecurityIssue]:
        """Analyze manifest for security issues"""
        issues = []
        
        # Check for billing compliance only if billing library is used
        if dependencies and self._has_billing_dependencies(dependencies):
            issues.extend(self._check_billing_compliance(manifest_root))
        
        # Check for cleartext traffic
        issues.extend(self._check_cleartext_traffic(manifest_root))
        
        # Check for dangerous permissions
        issues.extend(self._check_dangerous_permissions(manifest_root))
        
        # Check for backup settings
        issues.extend(self._check_backup_settings(manifest_root))
        
        return issues
    
    def _has_billing_dependencies(self, dependencies: List[Dependency]) -> bool:
        """Check if the project uses Google Play Billing library"""
        billing_artifacts = [
            'com.android.billingclient:billing',
            'com.android.billingclient:billing-ktx',
            'com.google.android.gms:play-services-wallet',
            'billing'  # Generic billing-related artifacts
        ]
        
        for dep in dependencies:
            dep_name = f"{dep.group_id}:{dep.artifact_id}"
            if any(billing in dep_name.lower() for billing in billing_artifacts):
                logger.detail(f"Found billing dependency: {dep_name}", "💳")
                return True
        
        logger.detail("No billing dependencies found - skipping billing compliance checks", "⏭️")
        return False
    
    def _check_billing_compliance(self, root: ET.Element) -> List[SecurityIssue]:
        """Check Google Play Billing compliance"""
        issues = []
        
        # Check for billing permission
        billing_permission = False
        billing_version_meta = False
        
        for perm in root.findall('.//uses-permission'):
            name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
            if name == 'com.android.vending.BILLING':
                billing_permission = True
                break
        
        # Check for billing version metadata
        for meta in root.findall('.//meta-data'):
            name = meta.get('{http://schemas.android.com/apk/res/android}name', '')
            if name == 'com.google.android.play.billingclient.version':
                billing_version_meta = True
                break
        
        if not billing_permission:
            issues.append(SecurityIssue(
                title="Missing Billing Permission",
                description="Required billing permission not declared",
                risk_level=Config.CRITICAL,
                category="Billing Compliance",
                recommendation='Add <uses-permission android:name="com.android.vending.BILLING" />'
            ))
        
        if not billing_version_meta:
            issues.append(SecurityIssue(
                title="Missing Billing Client Version",
                description="Billing client version metadata not declared",
                risk_level=Config.CRITICAL,
                category="Billing Compliance",
                recommendation='Add billing client version meta-data in AndroidManifest.xml'
            ))
        
        return issues
    
    def _check_cleartext_traffic(self, root: ET.Element) -> List[SecurityIssue]:
        """Check for cleartext traffic configuration"""
        issues = []
        
        app_element = root.find('.//application')
        if app_element is not None:
            cleartext = app_element.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic')
            if cleartext == 'true':
                issues.append(SecurityIssue(
                    title="Cleartext Traffic Enabled",
                    description="Application allows unencrypted HTTP communication",
                    risk_level=Config.CRITICAL,
                    category="Network Security",
                    recommendation="Set android:usesCleartextTraffic='false' or remove the attribute"
                ))
        
        return issues
    
    def _check_dangerous_permissions(self, root: ET.Element) -> List[SecurityIssue]:
        """Check for dangerous permissions"""
        issues = []
        
        dangerous_perms = {
            'android.permission.WRITE_EXTERNAL_STORAGE': 'Consider using scoped storage',
            'android.permission.READ_PHONE_STATE': 'Verify if phone state access is necessary',
            'android.permission.ACCESS_FINE_LOCATION': 'Ensure location access is properly justified',
            'android.permission.CAMERA': 'Verify camera access is necessary',
            'android.permission.RECORD_AUDIO': 'Verify audio recording is necessary'
        }
        
        for perm in root.findall('.//uses-permission'):
            name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
            if name in dangerous_perms:
                issues.append(SecurityIssue(
                    title=f"Dangerous Permission: {name}",
                    description=f"Application requests dangerous permission: {name}",
                    risk_level=Config.MEDIUM,
                    category="Permissions",
                    recommendation=dangerous_perms[name]
                ))
        
        return issues
    
    def _check_backup_settings(self, root: ET.Element) -> List[SecurityIssue]:
        """Check backup configuration"""
        issues = []
        
        app_element = root.find('.//application')
        if app_element is not None:
            backup = app_element.get('{http://schemas.android.com/apk/res/android}allowBackup')
            if backup == 'true':
                issues.append(SecurityIssue(
                    title="Unrestricted Backup Enabled",
                    description="Application allows unrestricted backup of data",
                    risk_level=Config.MEDIUM,
                    category="Data Protection",
                    recommendation="Configure backup rules to exclude sensitive data"
                ))
        
        return issues

class DomainKeywordAnalyzer:
    """Analyze codebase for suspicious domains and keywords"""
    
    def __init__(self):
        self.domains = self._load_domains()
        self.keywords = self._load_keywords()
    
    def _load_domains(self) -> List[str]:
        """Load domain list from domains.txt"""
        try:
            with open('domains.txt', 'r', encoding='utf-8') as f:
                domains = [line.strip().lower() for line in f if line.strip()]
            logger.detail(f"Loaded {len(domains)} domains to monitor", "🌐")
            return domains
        except FileNotFoundError:
            logger.warning_msg("domains.txt not found, skipping domain analysis")
            return []
        except Exception as e:
            logger.error_msg(f"Error loading domains.txt: {e}")
            return []
    
    def _load_keywords(self) -> List[str]:
        """Load keyword list from keywords.txt"""
        try:
            with open('keywords.txt', 'r', encoding='utf-8') as f:
                keywords = [line.strip().lower() for line in f if line.strip()]
            logger.detail(f"Loaded {len(keywords)} keywords to monitor", "🔍")
            return keywords
        except FileNotFoundError:
            logger.warning_msg("keywords.txt not found, skipping keyword analysis")
            return []
        except Exception as e:
            logger.error_msg(f"Error loading keywords.txt: {e}")
            return []
    
    def analyze_directory(self, project_path: str) -> List[SecurityIssue]:
        """Analyze entire project for domains and keywords"""
        issues = []
        
        if not self.domains and not self.keywords:
            logger.detail("No domains or keywords to search for", "⏭️")
            return issues
        
        # Find all text-based files to search
        search_files = []
        text_extensions = ('.java', '.kt', '.xml', '.gradle', '.properties', '.json', '.yaml', '.yml', '.txt', '.md')
        
        for root, dirs, files in os.walk(project_path):
            # Skip excluded directories
            if FileParser._should_exclude_directory(root, project_path):
                continue
                
            # Remove excluded directories from dirs to prevent os.walk from descending into them
            dirs[:] = [d for d in dirs if not FileParser._should_exclude_directory(os.path.join(root, d), project_path)]
            
            for file in files:
                if file.endswith(text_extensions):
                    file_path = os.path.join(root, file)
                    search_files.append(file_path)
        
        logger.detail(f"Scanning {len(search_files)} files for domains and keywords", "📄")
        
        for i, file_path in enumerate(search_files, 1):
            if i % 20 == 0 or i == len(search_files):  # Log every 20th file
                logger.detail(f"Scanning file {i}/{len(search_files)}: {os.path.basename(file_path)}", "📄")
            
            file_issues = self._scan_file(file_path, project_path)
            if file_issues:
                logger.detail(f"Found {len(file_issues)} domain/keyword matches in {os.path.basename(file_path)}", "⚠️")
            issues.extend(file_issues)
        
        return issues
    
    def _scan_file(self, file_path: str, project_path: str) -> List[SecurityIssue]:
        """Scan individual file for domains and keywords"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            relative_path = FileParser.get_relative_path(file_path, project_path)
            content_lower = content.lower()
            
            # Check for domains
            for domain in self.domains:
                if domain in content_lower:
                    # Find line number where domain appears
                    for line_num, line in enumerate(lines, 1):
                        if domain in line.lower():
                            issues.append(SecurityIssue(
                                title=f"Suspicious Domain Reference: {domain}",
                                description=f"Found reference to monitored domain '{domain}' which may indicate data collection, tracking, or third-party service usage.",
                                risk_level=Config.LOW,  # Mark as minor (LOW) as requested
                                category="Suspicious Domains",
                                file_path=relative_path,
                                line_number=line_num,
                                code_snippet=line.strip(),
                                recommendation=f"Review usage of domain '{domain}' to ensure it's necessary and complies with privacy policies"
                            ))
                            break  # Only report first occurrence per file
            
            # Check for keywords
            for keyword in self.keywords:
                if keyword in content_lower:
                    # Find line number where keyword appears
                    for line_num, line in enumerate(lines, 1):
                        if keyword in line.lower():
                            issues.append(SecurityIssue(
                                title=f"Security-Related Keyword: {keyword}",
                                description=f"Found security-related keyword '{keyword}' which may indicate sensitive functionality or potential security concerns.",
                                risk_level=Config.LOW,  # Mark as minor (LOW) as requested
                                category="Security Keywords",
                                file_path=relative_path,
                                line_number=line_num,
                                code_snippet=line.strip(),
                                recommendation=f"Review usage of keyword '{keyword}' to ensure secure implementation and proper handling"
                            ))
                            break  # Only report first occurrence per file
        
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
        
        return issues

class CodePatternAnalyzer:
    """Analyze source code for security patterns"""
    
    def analyze_directory(self, project_path: str) -> List[SecurityIssue]:
        """Analyze source code in directory"""
        issues = []
        
        # Find all relevant files
        analyzable_files = []
        text_extensions = (
            '.java', '.kt', '.xml', '.gradle', '.gradle.kts', '.properties',
            '.json', '.yaml', '.yml', '.txt', '.md', '.env', '.config',
            '.ini', '.conf', '.plist', '.pbxproj', '.xcconfig'
        )
        
        for root, dirs, files in os.walk(project_path):
            # Skip excluded directories
            if FileParser._should_exclude_directory(root, project_path):
                continue
                
            # Remove excluded directories from dirs
            dirs[:] = [d for d in dirs if not FileParser._should_exclude_directory(os.path.join(root, d), project_path)]
            
            for file in files:
                if file.endswith(text_extensions):
                    file_path = os.path.join(root, file)
                    analyzable_files.append(file_path)
        
        logger.detail(f"Found {len(analyzable_files)} files to analyze for security patterns", "📄")
        
        # Analyze each file
        for i, file_path in enumerate(analyzable_files, 1):
            if i % 10 == 0 or i == len(analyzable_files):
                logger.detail(f"Analyzing file {i}/{len(analyzable_files)}: {os.path.basename(file_path)}", "🔍")
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                relative_path = FileParser.get_relative_path(file_path, project_path)
                
                # Special handling for XML files
                if file_path.endswith('.xml'):
                    xml_issues = self._analyze_xml_security(file_path, content, relative_path)
                    if xml_issues:
                        logger.warning_msg(f"Found {len(xml_issues)} security issues in XML file: {os.path.basename(file_path)}")
                    issues.extend(xml_issues)
                else:
                    # Regular file analysis
                    lines = content.split('\n')
                    
                    # Check for API keys with context
                    api_key_issues = self._check_api_keys_with_context(relative_path, lines)
                    if api_key_issues:
                        logger.warning_msg(f"Found {len(api_key_issues)} potential API keys in {os.path.basename(file_path)}")
                    issues.extend(api_key_issues)
                    
                    # If it's a gradle file, also check for specific gradle security issues
                    if file_path.endswith(('.gradle', '.gradle.kts')):
                        gradle_issues = self._analyze_gradle_security(file_path, project_path)
                        issues.extend(gradle_issues)
                
            except Exception as e:
                logger.error(f"Error analyzing file {file_path}: {e}")
        
        return issues
    
    def _analyze_xml_security(self, file_path: str, content: str, relative_path: str) -> List[SecurityIssue]:
        """Analyze XML files for security issues"""
        issues = []
        try:
            # First check for known security patterns in the raw content
            # Check for dangerous configurations
            dangerous_configs = {
                'android:debuggable="true"': {
                    'title': "Debug Mode Enabled",
                    'description': "Application is debuggable which is a security risk in production",
                    'risk_level': Config.CRITICAL,
                    'category': "Configuration",
                    'recommendation': "Remove android:debuggable attribute for production builds"
                },
                'android:allowBackup="true"': {
                    'title': "Auto Backup Enabled",
                    'description': "Auto backup is enabled which could expose sensitive data",
                    'risk_level': Config.MEDIUM,
                    'category': "Data Protection",
                    'recommendation': "Disable auto backup or configure backup rules to exclude sensitive data"
                },
                'android:exported="true"': {
                    'title': "Component Exported",
                    'description': "Component is explicitly exported and accessible to other apps",
                    'risk_level': Config.HIGH,
                    'category': "Component Security",
                    'recommendation': "Only export components that need to be accessed by other apps and implement proper security"
                },
                'cleartextTrafficPermitted="true"': {
                    'title': "Cleartext Traffic Allowed",
                    'description': "Application allows unencrypted network traffic",
                    'risk_level': Config.HIGH,
                    'category': "Network Security",
                    'recommendation': "Disable cleartext traffic and use HTTPS for all network communication"
                }
            }

            for pattern, issue_info in dangerous_configs.items():
                if pattern in content:
                    issues.append(SecurityIssue(
                        title=issue_info['title'],
                        description=issue_info['description'],
                        risk_level=issue_info['risk_level'],
                        category=issue_info['category'],
                        file_path=relative_path,
                        recommendation=issue_info['recommendation']
                    ))

            # Now parse as XML to check values
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)

            # Check all text content and attribute values recursively
            for elem in root.iter():
                # Check element text
                if elem.text and elem.text.strip():
                    self._check_value_for_secrets(elem.text.strip(), elem, relative_path, issues)

                # Check all attribute values
                for attr_value in elem.attrib.values():
                    if attr_value and attr_value.strip():
                        self._check_value_for_secrets(attr_value.strip(), elem, relative_path, issues)

        except ET.ParseError:
            # Not a valid XML file or contains syntax errors
            pass
        except Exception as e:
            logger.error(f"Error analyzing XML file {file_path}: {e}")

        return issues

    def _check_value_for_secrets(self, value: str, elem: ET.Element, file_path: str, issues: List[SecurityIssue]):
        """Check a value for potential secrets or sensitive data"""
        # Additional patterns for API keys and secrets
        additional_patterns = {
            'GitHub PAT': r'ghp_[0-9a-zA-Z]{36}',
            'GitHub Fine-grained PAT': r'github_pat_[0-9a-zA-Z]{82}',
            'Slack Token': r'xox[baprs]-([0-9a-zA-Z]{10,48})',
            'Firebase Config': r'AIza[0-9A-Za-z\-_]{35}',
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'Stripe Live Key': r'sk_live_[0-9a-zA-Z]{24}',
            'Stripe Public Key': r'pk_live_[0-9a-zA-Z]{24}',
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'Generic Secret': r'[0-9a-f]{32,40}'
        }

        # Check for known API key patterns
        for key_type, pattern in additional_patterns.items():
            matches = re.findall(pattern, value)
            for match in matches:
                issues.append(SecurityIssue(
                    title=f"Hardcoded {key_type}",
                    description=f"Found hardcoded {key_type} in XML file",
                    risk_level=Config.CRITICAL,
                    category="API Security",
                    file_path=file_path,
                    line_number=self._get_line_number(value, elem),
                    code_snippet=value[:50] + "..." if len(value) > 50 else value,
                    recommendation=f"Move {key_type} to secure storage or environment variables"
                ))

        # Check for potential sensitive values
        sensitive_value_patterns = [
            (r'(?i)password\s*[:=]\s*["\']?[^"\'\s]+["\']?', "Password Value"),
            (r'(?i)secret\s*[:=]\s*["\']?[^"\'\s]+["\']?', "Secret Value"),
            (r'(?i)api[-_]?key\s*[:=]\s*["\']?[^"\'\s]+["\']?', "API Key"),
            (r'(?i)token\s*[:=]\s*["\']?[^"\'\s]+["\']?', "Token Value"),
            (r'(?i)auth[-_]?token\s*[:=]\s*["\']?[^"\'\s]+["\']?', "Auth Token"),
            (r'(?i)private[-_]?key\s*[:=]\s*["\']?[^"\'\s]+["\']?', "Private Key"),
            (r'(?i)bearer\s+[^"\'\s]+', "Bearer Token")
        ]

        for pattern, issue_type in sensitive_value_patterns:
            if re.search(pattern, value):
                # Only report if the value looks like a real secret (not a placeholder or reference)
                if not self._is_likely_false_positive_value(value):
                    issues.append(SecurityIssue(
                        title=f"Hardcoded {issue_type}",
                        description=f"Found potentially sensitive {issue_type.lower()} in XML file",
                        risk_level=Config.HIGH,
                        category="API Security",
                        file_path=file_path,
                        line_number=self._get_line_number(value, elem),
                        code_snippet=value[:50] + "..." if len(value) > 50 else value,
                        recommendation=f"Move {issue_type.lower()} to secure storage"
                    ))

    def _is_likely_false_positive_value(self, value: str) -> bool:
        """Check if a value is likely a false positive"""
        # Skip obvious non-secrets
        false_positive_indicators = [
            r'@string/',          # Resource reference
            r'@\w+/',            # Any resource reference
            r'\$\{.*\}',         # Variable placeholder
            r'%[sd]',            # Format specifiers
            r'<!--.*-->',        # XML comments
            r'^\s*$',            # Empty or whitespace
            r'^[a-z_]+$',        # Simple lowercase identifier
            r'^R\.',             # R.string reference
            r'placeholder',      # Obvious placeholder
            r'example',          # Example text
            r'default',          # Default text
            r'[<>/]',            # XML/HTML tags
            r'^https?://',       # URLs
            r'^tel:',            # Phone number links
            r'^mailto:',         # Email links
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'  # IP addresses
        ]

        return any(re.search(pattern, value, re.IGNORECASE) for pattern in false_positive_indicators)
    
    def _get_line_number(self, content: str, element: ET.Element) -> int:
        """Get line number for an XML element"""
        try:
            # Convert element to string
            element_str = ET.tostring(element, encoding='unicode')
            # Find the element in the content
            lines = content.split('\n')
            for i, line in enumerate(lines, 1):
                if any(part in line for part in element_str.split()):
                    return i
        except:
            pass
        return 0
    
    def _check_api_keys_with_context(self, file_path: str, lines: List[str]) -> List[SecurityIssue]:
        """Check for API keys with improved context awareness"""
        issues = []
        
        # Additional patterns for modern API keys
        additional_patterns = {
            'GitHub PAT': r'ghp_[0-9a-zA-Z]{36}',
            'GitHub Fine-grained PAT': r'github_pat_[0-9a-zA-Z]{82}',
            'Slack Token': r'xox[baprs]-([0-9a-zA-Z]{10,48})',
            'Firebase Config': r'firebase.*["\']\s*:\s*["\'](AIza[0-9A-Za-z\-_]{35})["\']',
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'Stripe Live Key': r'sk_live_[0-9a-zA-Z]{24}',
            'Stripe Public Key': r'pk_live_[0-9a-zA-Z]{24}',
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'Generic Secret': r'[0-9a-f]{32,40}'
        }
        
        # Context patterns that indicate API key assignments
        context_patterns = [
            r'(?:api[_-]?key|apikey|secret|token|password|pwd)\s*[=:]\s*["\']([A-Za-z0-9]{16,})["\']',
            r'Authorization\s*[=:]\s*["\']([A-Za-z0-9+/]{20,})["\']',
            r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)',
            r'(?:client[_-]?secret|client[_-]?id)\s*[=:]\s*["\']([A-Za-z0-9]{16,})["\']',
            r'(?:firebase|fb).*(?:key|secret|token)\s*[=:]\s*["\']([^"\']+)["\']',
            r'(?:oauth|auth).*(?:key|secret|token)\s*[=:]\s*["\']([^"\']+)["\']',
            r'private_key\s*[=:]\s*["\']([^"\']+)["\']'
        ]
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Skip obvious false positives
            if self._is_likely_false_positive(line_stripped):
                continue
            
            # Check for known API key patterns
            for key_type, pattern in additional_patterns.items():
                matches = re.findall(pattern, line)
                for match in matches:
                    # Get context (previous and next lines if available)
                    context_before = lines[max(0, line_num-3):line_num-1]
                    context_after = lines[line_num:min(len(lines), line_num+2)]
                    
                    # Only report if it looks like a real key in assignment context
                    if self._is_in_assignment_context(line, match) or any(
                        re.search(cp, '\n'.join(context_before + [line] + context_after), re.IGNORECASE)
                        for cp in context_patterns
                    ):
                        issues.append(SecurityIssue(
                            title=f"Hardcoded {key_type}",
                            description=f"Found hardcoded {key_type} in code",
                            risk_level=Config.CRITICAL,
                            category="API Security",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=line_stripped,
                            recommendation=f"Move {key_type} to environment variables or secure storage"
                        ))
            
            # Check for generic patterns that look like API keys
            for pattern in context_patterns:
                matches = re.findall(pattern, line, re.IGNORECASE)
                for match in matches:
                    key_value = match if isinstance(match, str) else match[0] if match else ""
                    if len(key_value) >= 16:  # Minimum reasonable API key length
                        issues.append(SecurityIssue(
                            title="Potential Secret Found",
                            description=f"Found potential API key or secret: {key_value[:10]}...",
                            risk_level=Config.HIGH,
                            category="API Security",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=line_stripped,
                            recommendation="Move sensitive data to environment variables or secure storage"
                        ))
        
        return issues
    
    def _is_likely_false_positive(self, line: str) -> bool:
        """Enhanced false positive detection"""
        line_lower = line.lower()
        
        # Skip obvious non-key content
        false_positive_patterns = [
            r'\w+\s*\(',           # Method calls
            r'(fun|function|def|class|interface|public|private|protected)\s+\w+',  # Declarations
            r'//.*',               # Comments
            r'/\*.*\*/',          # Block comments
            r'import\s+',          # Import statements
            r'package\s+',         # Package declarations
            r'@\w+',               # Annotations
            r'^\s*\*',             # Javadoc comments
            r'Log\.[deiw]',        # Log statements
            r'\.kt$|\.java$',      # File extensions
            r'^\s*#',              # Shell/properties comments
            r'^\s*<!--',           # XML comments
            r'^\s*---',            # YAML markers
            r'"?use strict"?;?$',  # JavaScript strict mode
            r'^\s*\{?\s*"[\w-]+"\s*:\s*\{',  # JSON object start
            r'^\s*version\s*[:=]',  # Version declarations
            r'implementation\s+["\']',  # Gradle dependencies
        ]
        
        for pattern in false_positive_patterns:
            if re.search(pattern, line):
                return True
        
        # Skip lines that are clearly method names or identifiers
        words = re.findall(r'\b[A-Za-z][A-Za-z0-9]*\b', line)
        if len(words) == 1 and len(words[0]) > 30:
            if (re.search(r'[a-z][A-Z]', words[0]) or  # camelCase
                words[0].endswith(('Activity', 'Service', 'Fragment', 'Adapter', 'Manager', 
                                 'Helper', 'Controller', 'Handler', 'Listener', 'Callback',
                                 'Data', 'Info', 'Details', 'Settings', 'Config', 'Utils',
                                 'Builder'))):
                return True
        
        return False
    
    def _is_in_assignment_context(self, line: str, match: str) -> bool:
        """Enhanced assignment context detection"""
        # Look for assignment patterns around the match
        assignment_patterns = [
            r'\w+\s*[=:]\s*["\']?' + re.escape(match),  # Basic assignment
            r'["\']' + re.escape(match) + r'["\']',     # String literal
            r'String\s+\w+\s*=.*' + re.escape(match),   # Java String
            r'val\s+\w+\s*=.*' + re.escape(match),      # Kotlin val
            r'var\s+\w+\s*=.*' + re.escape(match),      # Kotlin var
            r'const\s+\w+\s*=.*' + re.escape(match),    # JavaScript const
            r'let\s+\w+\s*=.*' + re.escape(match),      # JavaScript let
            r'\w+:\s*["\']?' + re.escape(match),        # YAML/JSON style
            r'export\s+(?:const|let|var)\s+\w+\s*=.*' + re.escape(match),  # JavaScript export
            r'-D\w+=.*' + re.escape(match),             # Command line argument
            r'System\.setProperty\([^,]+,\s*["\']?' + re.escape(match),    # Java system property
        ]
        
        for pattern in assignment_patterns:
            if re.search(pattern, line):
                return True
        
        return False
    
    def _analyze_gradle_security(self, gradle_path: str, project_path: str) -> List[SecurityIssue]:
        """Analyze gradle file for security issues"""
        issues = []
        
        content = FileParser.parse_gradle_file(gradle_path)
        relative_path = FileParser.get_relative_path(gradle_path, project_path)
        
        # Check for minify disabled
        if 'minifyEnabled false' in content:
            issues.append(SecurityIssue(
                title="Code Obfuscation Disabled",
                description="Code minification/obfuscation is disabled in release builds",
                risk_level=Config.HIGH,
                category="Code Protection",
                file_path=relative_path,
                recommendation="Enable minifyEnabled true for release builds"
            ))
        
        return issues

class ComplianceChecker:
    """Check compliance with various standards"""
    
    def check_target_sdk(self, gradle_content: str) -> List[SecurityIssue]:
        """Check target SDK compliance (supports both .gradle and .gradle.kts)"""
        issues = []
        
        # Patterns for both regular Gradle and Kotlin DSL
        target_sdk_patterns = [
            r'targetSdk\s+(\d+)',           # Regular Gradle: targetSdk 34
            r'targetSdk\s*=\s*(\d+)',       # Kotlin DSL: targetSdk = 34
            r'compileSdk\s+(\d+)',          # Regular Gradle: compileSdk 34
            r'compileSdk\s*=\s*(\d+)',      # Kotlin DSL: compileSdk = 34
            r'targetSdkVersion\s+(\d+)',    # Legacy regular Gradle: targetSdkVersion 34
            r'targetSdkVersion\s*=\s*(\d+)' # Legacy Kotlin DSL: targetSdkVersion = 34
        ]
        
        target_sdk = None
        for pattern in target_sdk_patterns:
            target_sdk_match = re.search(pattern, gradle_content)
            if target_sdk_match:
                target_sdk = int(target_sdk_match.group(1))
                break
        
        if target_sdk:
            # Check against latest Google Play requirements
            current_year = datetime.now().year
            current_month = datetime.now().month
            
            # After August 31, 2025: Must target Android 15 (API 35) or higher
            if current_year > 2025 or (current_year == 2025 and current_month > 8):
                if target_sdk < 35:
                    issues.append(SecurityIssue(
                        title="Non-Compliant Target SDK",
                        description=f"Target SDK {target_sdk} does not meet Google Play requirements. Starting August 31, 2025, apps must target Android 15 (API 35) or higher.",
                        risk_level=Config.CRITICAL,
                        category="Compliance",
                        recommendation="Update targetSdk to 35 (Android 15) or higher to comply with Google Play requirements"
                    ))
            # After August 31, 2024: Must target Android 14 (API 34) or higher
            elif current_year > 2024 or (current_year == 2024 and current_month > 8):
                if target_sdk < 34:
                    issues.append(SecurityIssue(
                        title="Non-Compliant Target SDK",
                        description=f"Target SDK {target_sdk} does not meet Google Play requirements. Starting August 31, 2024, apps must target Android 14 (API 34) or higher.",
                        risk_level=Config.CRITICAL,
                        category="Compliance",
                        recommendation="Update targetSdk to 34 (Android 14) or higher to comply with Google Play requirements"
                    ))
            # Current recommendation
            elif target_sdk < 34:
                issues.append(SecurityIssue(
                    title="Outdated Target SDK",
                    description=f"Target SDK {target_sdk} is below current recommendations. Google Play will require Android 14 (API 34) by August 31, 2024, and Android 15 (API 35) by August 31, 2025.",
                    risk_level=Config.HIGH,
                    category="Compliance",
                    recommendation="Consider updating targetSdk to at least 34 (Android 14) to prepare for upcoming Google Play requirements"
                ))
            
            # Check for specific platform requirements
            if 'com.google.android.wear' in gradle_content:  # Wear OS app
                if current_year > 2025 or (current_year == 2025 and current_month > 8):
                    if target_sdk < 34:
                        issues.append(SecurityIssue(
                            title="Non-Compliant Wear OS Target SDK",
                            description=f"Wear OS apps must target Android 14 (API 34) or higher by August 31, 2025.",
                            risk_level=Config.CRITICAL,
                            category="Compliance",
                            recommendation="Update targetSdk to 34 (Android 14) or higher for Wear OS compliance"
                        ))
            elif 'android.software.leanback' in gradle_content:  # Android TV app
                if current_year > 2025 or (current_year == 2025 and current_month > 8):
                    if target_sdk < 34:
                        issues.append(SecurityIssue(
                            title="Non-Compliant Android TV Target SDK",
                            description=f"Android TV apps must target Android 14 (API 34) or higher by August 31, 2025.",
                            risk_level=Config.CRITICAL,
                            category="Compliance",
                            recommendation="Update targetSdk to 34 (Android 14) or higher for Android TV compliance"
                        ))
            elif 'android.hardware.type.automotive' in gradle_content:  # Android Automotive app
                if current_year > 2025 or (current_year == 2025 and current_month > 8):
                    if target_sdk < 34:
                        issues.append(SecurityIssue(
                            title="Non-Compliant Android Automotive Target SDK",
                            description=f"Android Automotive apps must target Android 14 (API 34) or higher by August 31, 2025.",
                            risk_level=Config.CRITICAL,
                            category="Compliance",
                            recommendation="Update targetSdk to 34 (Android 14) or higher for Android Automotive compliance"
                        ))
        else:
            issues.append(SecurityIssue(
                title="Missing Target SDK",
                description="Could not find target SDK version in Gradle configuration",
                risk_level=Config.HIGH,
                category="Compliance",
                recommendation="Specify targetSdk in your build.gradle file"
            ))
        
        return issues

import json
from dataclasses import asdict
from datetime import datetime
import logging


class ReportGenerator:
    """Generate security analysis reports with enhanced UI"""
    
    def prepare_json_data(self, result) -> dict:
        """Prepare JSON report data without writing to file"""
        # Group issues by category with fallback to "Miscellaneous"
        def group_issues_by_category_with_fallback(issues):
            grouped = {}
            for issue in issues:
                category = issue.category if issue.category else "Miscellaneous"
                if category not in grouped:
                    grouped[category] = []
                grouped[category].append(issue)
            return grouped
        
        # Define category information (same as HTML report)
        category_info = {
            'Billing Compliance': {'icon': 'fas fa-credit-card', 'priority': 1},
            'Network Security': {'icon': 'fas fa-network-wired', 'priority': 2},
            'Permissions': {'icon': 'fas fa-key', 'priority': 3},
            'Data Protection': {'icon': 'fas fa-shield-alt', 'priority': 4},
            'Code Protection': {'icon': 'fas fa-code', 'priority': 5},
            'API Security': {'icon': 'fas fa-plug', 'priority': 6},
            'Information Disclosure': {'icon': 'fas fa-eye-slash', 'priority': 7},
            'Suspicious Domains': {'icon': 'fas fa-globe', 'priority': 8},
            'Security Keywords': {'icon': 'fas fa-search', 'priority': 9},
            'Compliance': {'icon': 'fas fa-clipboard-check', 'priority': 10},
            'Dependencies': {'icon': 'fas fa-cubes', 'priority': 11},
            'Miscellaneous': {'icon': 'fas fa-question-circle', 'priority': 999}  # Fallback category
        }
        
        # Group and organize issues by category (including fallback)
        grouped_issues = group_issues_by_category_with_fallback(result.issues)
        
        # Sort categories by priority and severity
        sorted_categories = sorted(grouped_issues.keys(), 
            key=lambda x: (category_info.get(x, {'priority': 999})['priority'], 
                          -({'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(
                              max([issue.risk_level for issue in grouped_issues[x]], 
                                  key=lambda r: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(r, 0)), 0))))
        
        # Build categorized issues structure
        categorized_issues = []
        for category in sorted_categories:
            category_issues = grouped_issues[category]
            
            # Calculate category risk level based on highest severity
            category_risk = max([issue.risk_level for issue in category_issues], 
                              key=lambda r: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(r, 0))
            
            category_data = {
                'category': category,
                'risk_level': category_risk,
                'priority': category_info.get(category, {'priority': 999})['priority'],
                'icon': category_info.get(category, {'icon': 'fas fa-exclamation-triangle'})['icon'],
                'issue_count': len(category_issues),
                'issues': [asdict(issue) for issue in category_issues]
            }
            categorized_issues.append(category_data)
        
        # Convert app metadata if available
        app_metadata_dict = None
        if result.app_metadata:
            app_metadata_dict = asdict(result.app_metadata)
        
        # Filter general recommendations
        general_recommendations = []
        for rec in result.recommendations:
            # Skip recommendations that are just repeating issue-specific advice
            if not any(issue.recommendation in rec for issue in result.issues):
                general_recommendations.append(rec)
        
        # Build comprehensive report data
        report_data = {
            'metadata': {
                'project_path': result.project_path,
                'scan_time': result.scan_time.isoformat(),
                'total_issues': len(result.issues),
                'total_categories': len(categorized_issues),
                'analyzer_version': '1.0.0'
            },
            'app_metadata': app_metadata_dict,
            'summary': {
                'by_severity': result.summary,
                'by_category': {cat['category']: cat['issue_count'] for cat in categorized_issues},
                'highest_risk_categories': [
                    cat['category'] for cat in categorized_issues 
                    if cat['risk_level'] in ['CRITICAL', 'HIGH']
                ]
            },
            'issues': {
                'categorized': categorized_issues,
                'total_count': len(result.issues)
            },
            'dependencies': {
                'total_count': len(result.dependencies),
                'by_risk': {
                    'critical': len([d for d in result.dependencies if getattr(d, 'risk_level', 'LOW') == 'CRITICAL']),
                    'high': len([d for d in result.dependencies if getattr(d, 'risk_level', 'LOW') == 'HIGH']),
                    'medium': len([d for d in result.dependencies if getattr(d, 'risk_level', 'LOW') == 'MEDIUM']),
                    'low': len([d for d in result.dependencies if getattr(d, 'risk_level', 'LOW') == 'LOW'])
                },
                'details': [asdict(dep) for dep in result.dependencies]
            },
            'recommendations': {
                'general': general_recommendations
            }
        }
        
        return report_data


class AndroidSecurityAnalyzer:
    """Main analyzer class"""
    
    def __init__(self, project_path: str = None):
        self.project_path = project_path
        self.file_parser = FileParser()
        self.dependency_analyzer = DependencyAnalyzer()
        self.manifest_analyzer = ManifestAnalyzer()
        self.code_analyzer = CodePatternAnalyzer()
        self.domain_keyword_analyzer = DomainKeywordAnalyzer()
        self.compliance_checker = ComplianceChecker()
        self.report_generator = ReportGenerator()
    
    def analyze(self) -> Dict:
        """Synchronous analyze method for FastAPI integration"""
        if not self.project_path:
            raise ValueError("Project path not provided")
        
        # Run async analysis synchronously
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(self.analyze_async(self.project_path))
        
        # Convert to dictionary and save JSON
        result_dict = self.report_generator.prepare_json_data(result)
        
        return result_dict
    
    async def analyze_async(self, project_path: str) -> AnalysisResult:
        """Perform complete security analysis"""
        logger.info(f"Starting security analysis of: {project_path}")
        logger.separator()
        
        issues = []
        dependencies = []
        app_metadata = None
        manifest_data = []  # Store manifest data separately
        
        # Step 1: Find key files
        logger.step(1, "Scanning for key files")
        manifest_files = self.file_parser.find_files(project_path, r'AndroidManifest\.xml')
        gradle_files = self.file_parser.find_files(project_path, r'.*\.gradle(\.kts)?$')
        
        logger.success(f"Found {len(manifest_files)} manifest files and {len(gradle_files)} gradle files")
        if manifest_files:
            logger.detail(f"Manifest files: {', '.join([os.path.basename(f) for f in manifest_files])}", "📄")
        if gradle_files:
            logger.detail(f"Gradle files: {', '.join([os.path.basename(f) for f in gradle_files])}", "📄")
        
        # Step 2: Extract app metadata and store manifest data for later analysis
        logger.step(2, "Extracting app metadata and preparing manifests")
        for i, manifest_path in enumerate(manifest_files, 1):
            logger.sub_step(f"Processing manifest {i}/{len(manifest_files)}: {os.path.basename(manifest_path)}")
            
            # Extract app metadata from the main manifest
            if i == 1:  # Use first manifest for metadata
                app_metadata = self.file_parser.extract_app_metadata(manifest_path, project_path)
                logger.detail(f"App: {app_metadata.app_name} ({app_metadata.package_name})", "📱")
                logger.detail(f"Version: {app_metadata.version_name} (Code: {app_metadata.version_code})", "🔢")
                logger.detail(f"SDK: Target {app_metadata.target_sdk}, Min {app_metadata.min_sdk}", "🎯")
            
            manifest_root = self.file_parser.parse_android_manifest(manifest_path)
            if manifest_root is not None:
                # Store manifest data for later analysis after dependencies are extracted
                manifest_data.append((manifest_root, self.file_parser.get_relative_path(manifest_path, project_path)))
            else:
                logger.error_msg(f"Failed to parse manifest: {manifest_path}")
        
        # Step 3: Analyze gradle files
        logger.step(3, "Analyzing Gradle files")
        all_gradle_content = ""
        for i, gradle_path in enumerate(gradle_files, 1):
            logger.sub_step(f"Analyzing gradle file {i}/{len(gradle_files)}: {os.path.basename(gradle_path)}")
            gradle_content = self.file_parser.parse_gradle_file(gradle_path)
            all_gradle_content += gradle_content + "\n"
            
            # Check for deprecated repositories
            repo_issues = self.dependency_analyzer.check_deprecated_repositories(gradle_content)
            logger.detail(f"Repository issues: {len(repo_issues)}", "📋")
            for issue in repo_issues:
                issue.file_path = self.file_parser.get_relative_path(gradle_path, project_path)
            issues.extend(repo_issues)
            
            # Check target SDK compliance
            sdk_issues = self.compliance_checker.check_target_sdk(gradle_content)
            logger.detail(f"SDK compliance issues: {len(sdk_issues)}", "📱")
            for issue in sdk_issues:
                issue.file_path = self.file_parser.get_relative_path(gradle_path, project_path)
            issues.extend(sdk_issues)
        
        # Step 4: Extract and analyzing dependencies
        logger.step(4, "Extracting and analyzing dependencies")
        dependencies = self.dependency_analyzer.extract_dependencies(all_gradle_content, project_path)
        logger.success(f"Extracted {len(dependencies)} dependencies")
        
        # Now analyze manifests with dependency context
        logger.sub_step("Analyzing manifests with dependency context...")
        for manifest_root, relative_path in manifest_data:
            manifest_issues = self.manifest_analyzer.analyze(manifest_root, dependencies)
            logger.success(f"Found {len(manifest_issues)} issues in manifest")
            for issue in manifest_issues:
                issue.file_path = relative_path
            issues.extend(manifest_issues)
        
        # Alpha/beta version checking disabled - allowing pre-release dependencies
        logger.sub_step("Skipping alpha/beta version checks (pre-release dependencies allowed)")
        logger.detail("Alpha/beta dependencies will not be flagged as security issues", "✅")
        
        # Step 5: Get latest versions and check vulnerabilities
        logger.step(5, "Checking for updates and vulnerabilities")
        logger.sub_step(f"Checking {len(dependencies)} dependencies in parallel...")
        
        # Create async tasks for parallel processing
        async def check_dependency(dep, index):
            """Check a single dependency for updates and vulnerabilities"""
            logger.progress(index, len(dependencies), f"Checking {dep.group_id}:{dep.artifact_id} v{dep.version}")
            
            # Get latest version (synchronous, but we'll run it in thread pool)
            loop = asyncio.get_event_loop()
            latest = await loop.run_in_executor(None, self.dependency_analyzer.get_latest_version, dep.group_id, dep.artifact_id)
            
            if latest:
                dep.latest_version = latest
                logger.detail(f"Latest version: {latest}", "✅")
                try:
                    if version.parse(dep.version) < version.parse(latest):
                        dep.is_outdated = True
                        dep.risk_level = Config.MEDIUM
                        logger.warning_msg("Dependency is outdated!")
                except:
                    logger.error_msg("Could not compare versions")
            else:
                logger.error_msg("Could not fetch latest version")
            
            # Check vulnerabilities (async)
            vulns = await self.dependency_analyzer.check_vulnerabilities(dep)
            if vulns:
                dep.vulnerabilities = vulns
                dep.risk_level = Config.HIGH
                logger.warning_msg(f"Found {len(vulns)} vulnerabilities!")
            else:
                logger.detail("No vulnerabilities found", "✅")
            
            return dep
        
        # Run all dependency checks in parallel with limited concurrency
        semaphore = asyncio.Semaphore(10)  # Limit to 10 concurrent requests
        
        async def check_dependency_with_semaphore(dep, index):
            async with semaphore:
                return await check_dependency(dep, index)
        
        # Create tasks for all dependencies
        tasks = [check_dependency_with_semaphore(dep, i+1) for i, dep in enumerate(dependencies)]
        
        # Wait for all tasks to complete
        logger.sub_step(f"Starting parallel analysis of {len(dependencies)} dependencies...")
        updated_dependencies = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle any exceptions and update dependencies
        for i, result in enumerate(updated_dependencies):
            if isinstance(result, Exception):
                logger.error_msg(f"Error checking dependency {i+1}: {result}")
            else:
                dependencies[i] = result
        
        # Step 6: Analyze source code patterns
        logger.step(6, "Analyzing source code patterns")
        code_issues = self.code_analyzer.analyze_directory(project_path)
        logger.success(f"Found {len(code_issues)} code pattern issues")
        issues.extend(code_issues)
        
        # Step 7: Scan for suspicious domains and keywords
        logger.step(7, "Scanning for suspicious domains and keywords")
        domain_keyword_issues = self.domain_keyword_analyzer.analyze_directory(project_path)
        logger.success(f"Found {len(domain_keyword_issues)} domain/keyword matches")
        issues.extend(domain_keyword_issues)
        
        # Step 8: Generate summary and recommendations
        logger.step(8, "Generating analysis summary")
        summary = {
            'critical': len([i for i in issues if i.risk_level == Config.CRITICAL]),
            'high': len([i for i in issues if i.risk_level == Config.HIGH]),
            'medium': len([i for i in issues if i.risk_level == Config.MEDIUM]),
            'low': len([i for i in issues if i.risk_level == Config.LOW])
        }
        
        logger.detail(f"Summary: {summary['critical']} critical, {summary['high']} high, {summary['medium']} medium, {summary['low']} low issues", "📈")
        
        # Generate recommendations
        recommendations = self._generate_recommendations(issues, dependencies)
        logger.detail(f"Generated {len(recommendations)} recommendations", "💡")
        
        logger.separator()
        logger.success("Security analysis completed!")
        logger.separator()
        
        return AnalysisResult(
            project_path=project_path,
            scan_time=datetime.now(),
            issues=issues,
            dependencies=dependencies,
            summary=summary,
            recommendations=recommendations,
            app_metadata=app_metadata
        )
    
    def _generate_recommendations(self, issues: List[SecurityIssue], dependencies: List[Dependency]) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Critical issues first
        critical_issues = [i for i in issues if i.risk_level == Config.CRITICAL]
        if critical_issues:
            recommendations.append("🔴 IMMEDIATE ACTION REQUIRED:")
            for issue in critical_issues[:5]:  # Top 5 critical
                recommendations.append(f"  - {issue.title}: {issue.recommendation}")
        
        # Dependency recommendations
        outdated_deps = [d for d in dependencies if d.is_outdated]
        if outdated_deps:
            recommendations.append("📦 UPDATE DEPENDENCIES:")
            for dep in outdated_deps[:10]:  # Top 10 outdated
                recommendations.append(f"  - Update {dep.group_id}:{dep.artifact_id} from {dep.version} to {dep.latest_version}")
        
        # High priority issues
        high_issues = [i for i in issues if i.risk_level == Config.HIGH]
        if high_issues:
            recommendations.append("🟠 HIGH PRIORITY:")
            for issue in high_issues[:5]:  # Top 5 high
                recommendations.append(f"  - {issue.title}: {issue.recommendation}")
        
        return recommendations

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Android Security Analyzer')
    parser.add_argument('project_path', help='Path to Android project')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.project_path):
        logger.error_msg(f"Error: Project path '{args.project_path}' does not exist")
        sys.exit(1)
    
    async def run_analysis():
        analyzer = AndroidSecurityAnalyzer()
        result = await analyzer.analyze_async(args.project_path)
        
        # Print summary
        logger.separator()
        logger.info("SECURITY ANALYSIS SUMMARY")
        logger.separator()
        logger.info(f"Project: {result.project_path}")
        logger.info(f"Scan Time: {result.scan_time}")
        logger.info(f"Total Issues Found: {len(result.issues)}")
        logger.detail(f"Critical: {result.summary['critical']}", "🔴")
        logger.detail(f"High: {result.summary['high']}", "🟠")
        logger.detail(f"Medium: {result.summary['medium']}", "🟡")
        logger.detail(f"Low: {result.summary['low']}", "🟢")
        logger.info(f"Dependencies Analyzed: {len(result.dependencies)}")
        logger.separator()
        
        # Exit with error code if critical issues found
        if result.summary['critical'] > 0:
            logger.error_msg("CRITICAL ISSUES FOUND - Build should be blocked")
            sys.exit(1)
        elif result.summary['high'] > 0:
            logger.warning_msg("HIGH RISK ISSUES FOUND - Review required")
            sys.exit(2)
        else:
            logger.success("No critical security issues found")
            sys.exit(0)
    
    # Run async analysis
    asyncio.run(run_analysis())

if __name__ == "__main__":
    main() 