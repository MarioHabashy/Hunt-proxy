"""
api_key_tab.py – API Key Detection and Testing Tab

Three subtabs:
  • Fetch    – Fetch URL(s) from queue, analyze response source code, detect API keys, test them
  • Key      – Manually input a key and type (auto-detect if not selected), then test
  • Text     – Enter raw text, detect API keys within it, then test

All detection uses regex patterns for common API key formats.
Testing attempts to validate keys against their respective services with comprehensive checks.
"""

import os
import re
import json
import time
import base64
import math
import logging
import threading
import concurrent.futures
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime
from collections import defaultdict

import requests
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QTextEdit, QPushButton, QLabel, QSplitter, QHeaderView, QMessageBox,
    QProgressBar, QComboBox, QMenu, QApplication, QTabWidget, QLineEdit,
    QDialog, QDialogButtonBox, QCheckBox, QGroupBox, QFrame, QScrollArea,
    QSizePolicy, QSpinBox, QFileDialog, QGridLayout, QRadioButton, QButtonGroup
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl
from PyQt5.QtGui import QColor, QBrush, QFont, QTextCursor, QDesktopServices

from constants import (
    COLOR_ELEVATED_BG, COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_BORDER,
    COLOR_ACCENT, COLOR_SUCCESS, COLOR_HIGH, COLOR_CRITICAL,
    COLOR_TEXT_MUTED, COLOR_DARK_BG, COLOR_CARD_BG,
    FONT_SIZE_NORMAL, FONT_SIZE_SMALL, HttpSyntaxHighlighter
)

# Disable SSL warnings for security testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# =============================================================================
# API KEY DETECTION PATTERNS
# =============================================================================

API_KEY_PATTERNS = {
    "AWS Access Key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "confidence": "HIGH",
        "validation": "aws",
        "description": "AWS Access Key ID (starts with AKIA)"
    },
    "AWS Secret Key": {
        "pattern": r"[A-Za-z0-9/+=]{40}",
        "confidence": "MEDIUM",
        "validation": "aws_secret",
        "description": "AWS Secret Access Key (40 chars)"
    },
    "Google API Key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "confidence": "HIGH",
        "validation": "google",
        "description": "Google API Key (starts with AIza)"
    },
    "Google OAuth": {
        "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "confidence": "HIGH",
        "validation": "google_oauth",
        "description": "Google OAuth Client ID"
    },
    "GitHub Token": {
        "pattern": r"gh[pousr]_[0-9A-Za-z]{36,251}",
        "confidence": "HIGH",
        "validation": "github",
        "description": "GitHub Personal Access Token"
    },
    "GitHub Fine-grained": {
        "pattern": r"github_pat_[0-9A-Za-z]{22}_[0-9A-Za-z]{59}",
        "confidence": "HIGH",
        "validation": "github",
        "description": "GitHub Fine-grained PAT"
    },
    "GitLab Token": {
        "pattern": r"glpat-[0-9a-zA-Z\-_]{20}",
        "confidence": "HIGH",
        "validation": "gitlab",
        "description": "GitLab Personal Access Token"
    },
    "Slack Token": {
        "pattern": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",
        "confidence": "HIGH",
        "validation": "slack",
        "description": "Slack API Token"
    },
    "Slack Webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+",
        "confidence": "HIGH",
        "validation": "slack_webhook",
        "description": "Slack Webhook URL"
    },
    "Discord Webhook": {
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[0-9A-Za-z\-_]+",
        "confidence": "HIGH",
        "validation": "discord",
        "description": "Discord Webhook URL"
    },
    "Stripe Live": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24}",
        "confidence": "CRITICAL",
        "validation": "stripe",
        "description": "Stripe Live Secret Key"
    },
    "Stripe Test": {
        "pattern": r"sk_test_[0-9a-zA-Z]{24}",
        "confidence": "MEDIUM",
        "validation": "stripe",
        "description": "Stripe Test Secret Key"
    },
    "Stripe Publishable": {
        "pattern": r"pk_(?:live|test)_[0-9a-zA-Z]{24}",
        "confidence": "LOW",
        "validation": "stripe_pub",
        "description": "Stripe Publishable Key"
    },
    "Twilio SID": {
        "pattern": r"AC[0-9a-fA-F]{32}",
        "confidence": "HIGH",
        "validation": "twilio",
        "description": "Twilio Account SID"
    },
    "Twilio Token": {
        "pattern": r"[0-9a-fA-F]{32}",
        "confidence": "MEDIUM",
        "validation": "twilio_token",
        "description": "Twilio Auth Token (32 hex chars)"
    },
    "SendGrid": {
        "pattern": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
        "confidence": "HIGH",
        "validation": "sendgrid",
        "description": "SendGrid API Key"
    },
    "Mailgun": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "confidence": "HIGH",
        "validation": "mailgun",
        "description": "Mailgun API Key"
    },
    "Mailchimp": {
        "pattern": r"[0-9a-f]{32}-us[0-9]+",
        "confidence": "MEDIUM",
        "validation": "mailchimp",
        "description": "Mailchimp API Key"
    },
    "HubSpot": {
        "pattern": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "confidence": "MEDIUM",
        "validation": "hubspot",
        "description": "HubSpot API Key (UUID format)"
    },
    "Salesforce": {
        "pattern": r"00D[a-zA-Z0-9]{14,15}![a-zA-Z0-9]{40,45}",
        "confidence": "HIGH",
        "validation": "salesforce",
        "description": "Salesforce Session ID"
    },
    "JWT Token": {
        "pattern": r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
        "confidence": "MEDIUM",
        "validation": "jwt",
        "description": "JWT Token (may contain credentials)"
    },
    "Bearer Token": {
        "pattern": r"Bearer\s+[A-Za-z0-9\-\._~+/]+=*",
        "confidence": "MEDIUM",
        "validation": "bearer",
        "description": "Bearer Authentication Token"
    },
    "Basic Auth": {
        "pattern": r"Basic\s+[A-Za-z0-9+/=]+",
        "confidence": "MEDIUM",
        "validation": "basic",
        "description": "Basic Authentication (base64 encoded)"
    },
    "Generic Base64": {
        "pattern": r"[A-Za-z0-9+/]{40,}={0,2}",
        "confidence": "LOW",
        "validation": "base64",
        "description": "Long base64 string (potential credential)"
    },
    "Generic Secret": {
        "pattern": r"(?:api[_-]?key|secret|token|password)\s*[=:]\s*['\"]?([A-Za-z0-9\-._~+/]{16,})['\"]?",
        "confidence": "MEDIUM",
        "validation": "generic",
        "description": "Generic API key pattern with common variable names"
    },
    "Private Key": {
        "pattern": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
        "confidence": "CRITICAL",
        "validation": "private_key",
        "description": "Private Key (RSA/DSA/EC/OpenSSH)"
    },
    # ── New patterns from KeyHacks ──────────────────────────────────────────
    "Dropbox Token": {
        "pattern": r"sl\.[0-9A-Za-z\-_]{130,140}",
        "confidence": "HIGH",
        "validation": "dropbox",
        "description": "Dropbox OAuth2 access token"
    },
    "Firebase API Key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",   # same prefix as Google; caught separately for POC
        "confidence": "HIGH",
        "validation": "firebase",
        "description": "Firebase/GCP API Key (AIza…)"
    },
    "Firebase FCM Key": {
        "pattern": r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}",
        "confidence": "HIGH",
        "validation": "firebase_fcm",
        "description": "Firebase Cloud Messaging (FCM) Server Key"
    },
    "Cloudflare API Key": {
        "pattern": r"[0-9a-f]{37}",
        "confidence": "LOW",
        "validation": "cloudflare",
        "description": "Cloudflare Global API Key (37 hex chars) – needs email context"
    },
    "Heroku API Key": {
        "pattern": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "confidence": "MEDIUM",
        "validation": "heroku",
        "description": "Heroku API Key (UUID v4 format)"
    },
    "Telegram Bot Token": {
        "pattern": r"[0-9]{8,10}:[0-9A-Za-z_\-]{35}",
        "confidence": "HIGH",
        "validation": "telegram",
        "description": "Telegram Bot API Token"
    },
    "Twitter/X API Key": {
        "pattern": r"(?:twitter|tweet)[^\n]{0,30}['\"]([A-Za-z0-9]{25,30})['\"]",
        "confidence": "MEDIUM",
        "validation": "twitter_key",
        "description": "Twitter/X API Key (context-matched)"
    },
    "Twitter/X Bearer Token": {
        "pattern": r"AAAAAAAAAA[A-Za-z0-9%]{50,}",
        "confidence": "HIGH",
        "validation": "twitter_bearer",
        "description": "Twitter/X Bearer Token (starts with AAAAAAAAAA)"
    },
    "Pagerduty Token": {
        "pattern": r"(?:pagerduty|pd)[^\n]{0,20}['\"]([A-Za-z0-9+_\-]{20})['\"]",
        "confidence": "MEDIUM",
        "validation": "pagerduty",
        "description": "PagerDuty API token (context-matched)"
    },
    "Zendesk API Token": {
        "pattern": r"[a-zA-Z0-9]{40}/token",
        "confidence": "MEDIUM",
        "validation": "zendesk",
        "description": "Zendesk API Token"
    },
    "NPM Token": {
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "confidence": "HIGH",
        "validation": "npm",
        "description": "NPM Access Token"
    },
    "Square Access Token": {
        "pattern": r"EAAA[a-zA-Z0-9]{60}",
        "confidence": "HIGH",
        "validation": "square",
        "description": "Square OAuth Access Token"
    },
    "Square App Secret": {
        "pattern": r"sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}",
        "confidence": "HIGH",
        "validation": "square_secret",
        "description": "Square App ID / Client Secret"
    },
    "Infura Project ID": {
        "pattern": r"[0-9a-f]{32}",
        "confidence": "LOW",
        "validation": "infura",
        "description": "Infura Project ID (32 hex chars) – needs infura context"
    },
    "Contentful Token": {
        "pattern": r"(?:contentful)[^\n]{0,30}['\"]([A-Za-z0-9\-_]{43,46})['\"]",
        "confidence": "MEDIUM",
        "validation": "contentful",
        "description": "Contentful Access Token (context-matched)"
    },
    "HubSpot API Key (v1)": {
        "pattern": r"(?:hapikey|hubspot)[^\n]{0,20}['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]",
        "confidence": "HIGH",
        "validation": "hubspot",
        "description": "HubSpot API Key (UUID, context-matched to reduce FP)"
    },
    "Datadog API Key": {
        "pattern": r"(?:datadog|dd)[^\n]{0,20}['\"]([a-f0-9]{32})['\"]",
        "confidence": "MEDIUM",
        "validation": "datadog",
        "description": "Datadog API/APP Key (context-matched)"
    },
    "Facebook Access Token": {
        "pattern": r"EAACEdEose0cBA[0-9A-Za-z]+",
        "confidence": "HIGH",
        "validation": "facebook",
        "description": "Facebook Access Token"
    },
    "Stripe Restricted Key": {
        "pattern": r"rk_(?:live|test)_[0-9a-zA-Z]{24}",
        "confidence": "HIGH",
        "validation": "stripe",
        "description": "Stripe Restricted Key"
    },
    "Microsoft Teams Webhook": {
        "pattern": r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[^\s\"']+",
        "confidence": "HIGH",
        "validation": "teams_webhook",
        "description": "Microsoft Teams Incoming Webhook URL"
    },
    "Azure Client Secret": {
        "pattern": r"(?:client.secret|clientSecret)[^\n]{0,20}['\"]([0-9A-Za-z\+\=\-_\.~]{32,50})['\"]",
        "confidence": "MEDIUM",
        "validation": "azure",
        "description": "Azure App Client Secret (context-matched)"
    },
    "Shopify Token": {
        "pattern": r"shpss_[a-fA-F0-9]{32}|shpat_[a-fA-F0-9]{32}|shppa_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32}",
        "confidence": "HIGH",
        "validation": "shopify",
        "description": "Shopify Access/Private App Token"
    },
    "Asana Access Token": {
        "pattern": r"[0-9]/[0-9]{16}:[0-9a-f]{32}",
        "confidence": "HIGH",
        "validation": "asana",
        "description": "Asana Personal Access Token"
    },
}

# =============================================================================
# API ENDPOINT PATTERNS
# =============================================================================

API_ENDPOINT_PATTERNS = [
    r'https?://[^\s"\']+/(?:api|v[0-9]+|graphql|rest|service)/[^\s"\']*',
    r'["\'](?:/api/|/v[0-9]+/|/rest/|/graphql)[^\s"\']*["\']',
    r'url\s*[:=]\s*["\'](https?://[^\s"\']+)["\']',
    r'fetch\([\'"]([^\'"]+)[\'"]',
    r'axios\.(?:get|post|put|delete)\([\'"]([^\'"]+)[\'"]',
    r'ajax\([\'"]([^\'"]+)[\'"]',
    r'xmlhttprequest\.open\([\'"]GET[\'"],\s*[\'"]([^\'"]+)[\'"]',
    r'endpoint\s*[:=]\s*["\']([^\s"\']+)["\']',
]

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def _shannon_entropy(data: str) -> float:
    """Return the Shannon entropy (bits per character) of a string."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

# =============================================================================
# COMPREHENSIVE API KEY VALIDATION METHODS
# =============================================================================

def validate_google_key(key: str) -> Tuple[bool, str, dict]:
    """
    Validate Google API Key using multiple Google APIs
    Returns: (is_valid, message, details)
    """
    results = []
    details = {
        "valid_endpoints": [],
        "failed_endpoints": [],
        "services_detected": [],
        "quota_info": {},
        "error_details": {},
        "project_id": None
    }
    
    # Test 1: Google Drive API - Check if actually enabled
    try:
        url = "https://www.googleapis.com/drive/v3/files"
        params = {"key": key}
        response = requests.get(url, params=params, timeout=10, verify=False)
        
        if response.status_code == 200:
            results.append("✅ Google Drive API: Valid and enabled")
            details["valid_endpoints"].append("drive_api")
            details["services_detected"].append("Google Drive")
        elif response.status_code == 403:
            data = response.json()
            error = data.get('error', {})
            # Check if it's just disabled (can be enabled) vs actually invalid
            if error.get('status') == 'PERMISSION_DENIED' and 'SERVICE_DISABLED' in str(error):
                # Extract project ID from error message
                project_match = re.search(r'project (\d+)', str(error))
                if project_match:
                    details["project_id"] = project_match.group(1)
                results.append("⚠️ Google Drive API: Service disabled (can be enabled in console)")
                details["failed_endpoints"].append("drive_api_disabled")
                details["error_details"]["drive_api"] = "SERVICE_DISABLED - Can be enabled"
            else:
                results.append("❌ Google Drive API: Access denied")
                details["failed_endpoints"].append("drive_api")
    except Exception as e:
        pass
    
    # Test 2: Google Sheets API
    try:
        url = "https://sheets.googleapis.com/v4/spreadsheets"
        params = {"key": key}
        response = requests.get(url, params=params, timeout=10, verify=False)
        
        if response.status_code == 200:
            results.append("✅ Google Sheets API: Valid and enabled")
            details["valid_endpoints"].append("sheets_api")
            details["services_detected"].append("Google Sheets")
        elif response.status_code == 403:
            data = response.json()
            error = data.get('error', {})
            if error.get('status') == 'PERMISSION_DENIED' and 'SERVICE_DISABLED' in str(error):
                results.append("⚠️ Google Sheets API: Service disabled")
                details["failed_endpoints"].append("sheets_api_disabled")
            else:
                results.append("❌ Google Sheets API: Access denied")
                details["failed_endpoints"].append("sheets_api")
    except Exception as e:
        pass
    
    # Test 3: Google Custom Search API - Check if actually enabled
    try:
        url = "https://customsearch.googleapis.com/customsearch/v1"
        params = {
            "q": "test",
            "cx": "test",  # This will fail but tells us if API is enabled
            "key": key
        }
        response = requests.get(url, params=params, timeout=10, verify=False)
        
        if response.status_code == 200:
            results.append("✅ Custom Search API: Valid and enabled")
            details["valid_endpoints"].append("custom_search")
            details["services_detected"].append("Custom Search")
        elif response.status_code == 403:
            data = response.json()
            error = data.get('error', {})
            if error.get('status') == 'PERMISSION_DENIED' and 'SERVICE_DISABLED' in str(error):
                results.append("⚠️ Custom Search API: Service disabled")
                details["failed_endpoints"].append("custom_search_disabled")
            else:
                results.append("❌ Custom Search API: Access denied")
                details["failed_endpoints"].append("custom_search")
    except Exception as e:
        pass
    
    # Test 4: Google Cloud Resource Manager (shows project info - always works if key is valid)
    try:
        url = "https://cloudresourcemanager.googleapis.com/v1/projects"
        params = {"key": key}
        response = requests.get(url, params=params, timeout=10, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            projects = data.get('projects', [])
            if projects:
                details["project_id"] = projects[0].get('projectId')
            results.append(f"✅ Cloud Resource Manager: Can access ({len(projects)} projects)")
            details["valid_endpoints"].append("cloud_resource_manager")
            details["services_detected"].append("Google Cloud Platform")
        elif response.status_code == 403:
            data = response.json()
            error = data.get('error', {})
            if 'permission' in str(error).lower():
                results.append("✅ Cloud Resource Manager: Key valid (needs additional permissions)")
                details["valid_endpoints"].append("cloud_resource_manager_limited")
    except Exception as e:
        pass
    
    # Determine overall validity
    # A key is valid if:
    # 1. It has at least one fully working endpoint, OR
    # 2. It has project info and at least one API can be enabled (SERVICE_DISABLED)
    has_working = len([e for e in details["valid_endpoints"] if not e.endswith('_disabled') and not e.endswith('_limited')]) > 0
    has_disabled = any(e.endswith('_disabled') for e in details["failed_endpoints"])
    has_project = details.get("project_id") is not None
    
    is_valid = has_working or (has_project and has_disabled)
    
    if has_working:
        message = f"✅ Valid Google API Key - Working APIs: {', '.join(details['services_detected'])}"
    elif has_project and has_disabled:
        message = f"⚠️ Valid Google API Key - No enabled APIs (Project: {details['project_id']})"
        message += f"\n   Enable APIs at: https://console.developers.google.com/apis?project={details['project_id']}"
    else:
        message = "❌ Invalid or restricted Google API Key"
    
    return is_valid, message, details

def validate_aws_key(key: str, secret: Optional[str] = None) -> Tuple[bool, str, dict]:
    """
    Validate AWS credentials with comprehensive testing
    """
    details = {
        "valid_services": [],
        "account_info": {},
        "region_info": {},
        "permissions": [],
        "error_details": {}
    }
    
    # Try to import boto3
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
        boto3_available = True
    except ImportError:
        boto3_available = False
    
    if not boto3_available:
        # Basic format validation
        if key.startswith('AKIA') and len(key) == 20:
            return True, "Valid AWS Key format (install boto3 for full validation)", details
        return False, "Invalid AWS Key format", details
    
    if not secret:
        return False, "Secret key required for AWS validation", details
    
    # Test different regions
    regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']
    
    for region in regions:
        try:
            session = boto3.Session(
                aws_access_key_id=key,
                aws_secret_access_key=secret,
                region_name=region
            )
            
            # Test 1: STS GetCallerIdentity (always works if credentials are valid)
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            
            details["account_info"] = {
                "account_id": identity['Account'],
                "user_id": identity['UserId'],
                "arn": identity['Arn']
            }
            details["valid_services"].append("sts")
            break
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'InvalidClientTokenId':
                return False, "Invalid AWS Access Key ID", details
            elif error_code == 'SignatureDoesNotMatch':
                return False, "Invalid AWS Secret Access Key", details
            continue
        except Exception as e:
            continue
    
    if not details["account_info"]:
        return False, "Could not validate AWS credentials in any region", details
    
    # Test 2: S3 ListBuckets
    try:
        s3 = session.client('s3')
        buckets = s3.list_buckets()
        bucket_count = len(buckets.get('Buckets', []))
        details["valid_services"].append("s3")
        details["permissions"].append("s3:ListBuckets")
    except ClientError as e:
        pass
    
    # Test 3: EC2 DescribeRegions
    try:
        ec2 = session.client('ec2')
        regions_resp = ec2.describe_regions()
        region_count = len(regions_resp.get('Regions', []))
        details["valid_services"].append("ec2")
        details["permissions"].append("ec2:DescribeRegions")
    except ClientError as e:
        pass
    
    # Test 4: IAM GetUser
    try:
        iam = session.client('iam')
        user = iam.get_user()
        username = user['User']['UserName']
        details["valid_services"].append("iam")
        details["permissions"].append("iam:GetUser")
    except ClientError as e:
        pass
    
    # Test 5: Lambda ListFunctions
    try:
        lambda_client = session.client('lambda')
        functions = lambda_client.list_functions()
        func_count = len(functions.get('Functions', []))
        details["valid_services"].append("lambda")
    except ClientError as e:
        pass
    
    # Test 6: CloudWatch Logs
    try:
        logs = session.client('logs')
        log_groups = logs.describe_log_groups()
        group_count = len(log_groups.get('logGroups', []))
        details["valid_services"].append("cloudwatch")
    except ClientError as e:
        pass
    
    message = f"✅ Valid AWS credentials for account {details['account_info']['account_id']}\n"
    message += f"   Active services: {', '.join(details['valid_services'][:5])}"
    if len(details['valid_services']) > 5:
        message += f" +{len(details['valid_services'])-5} more"
    
    return True, message, details

def validate_github_token(token: str) -> Tuple[bool, str, dict]:
    """
    Comprehensive GitHub token validation
    """
    details = {
        "user_info": {},
        "scopes": [],
        "organizations": [],
        "repositories": [],
        "rate_limit": {}
    }
    
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'Hunt-API-Scanner'
    }
    
    # Test 1: Get authenticated user
    try:
        response = requests.get('https://api.github.com/user', headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            user_data = response.json()
            details["user_info"] = {
                "login": user_data.get('login'),
                "name": user_data.get('name'),
                "email": user_data.get('email'),
                "plan": user_data.get('plan', {}).get('name', 'Free') if user_data.get('plan') else 'Unknown',
                "public_repos": user_data.get('public_repos'),
                "followers": user_data.get('followers')
            }
            
            # Check scopes from headers
            if 'X-OAuth-Scopes' in response.headers:
                scopes = response.headers['X-OAuth-Scopes'].split(', ')
                details["scopes"] = scopes
        elif response.status_code == 401:
            return False, "Invalid GitHub token", details
    except Exception as e:
        pass
    
    if not details["user_info"]:
        return False, "Could not validate GitHub token", details
    
    # Test 2: List organizations
    try:
        response = requests.get('https://api.github.com/user/orgs', headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            orgs = response.json()
            details["organizations"] = [org['login'] for org in orgs[:5]]
    except:
        pass
    
    # Test 3: List repositories
    try:
        response = requests.get('https://api.github.com/user/repos?per_page=5', headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            repos = response.json()
            details["repositories"] = [f"{repo['owner']['login']}/{repo['name']}" for repo in repos[:5]]
    except:
        pass
    
    # Test 4: Check rate limit
    try:
        response = requests.get('https://api.github.com/rate_limit', headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            rate_data = response.json()
            core = rate_data.get('resources', {}).get('core', {})
            details["rate_limit"] = {
                "limit": core.get('limit'),
                "remaining": core.get('remaining'),
                "reset": core.get('reset')
            }
    except:
        pass
    
    message = f"✅ Valid GitHub token for {details['user_info']['login']}"
    if details["scopes"]:
        message += f"\n   Scopes: {', '.join(details['scopes'])}"
    if details["organizations"]:
        message += f"\n   Orgs: {', '.join(details['organizations'])}"
    if details["repositories"]:
        message += f"\n   Recent repos: {', '.join(details['repositories'])}"
    
    return True, message, details

def validate_gitlab_token(token: str) -> Tuple[bool, str, dict]:
    """
    Comprehensive GitLab token validation
    """
    details = {
        "user_info": {},
        "scopes": [],
        "projects": [],
        "groups": []
    }
    
    headers = {'Authorization': f'Bearer {token}'}
    
    # Test 1: Get current user
    try:
        response = requests.get('https://gitlab.com/api/v4/user', headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            user_data = response.json()
            details["user_info"] = {
                "username": user_data.get('username'),
                "name": user_data.get('name'),
                "email": user_data.get('email'),
                "state": user_data.get('state'),
                "last_activity": user_data.get('last_activity_on')
            }
            
            # Check token scopes from headers
            if 'GitLab-License' in response.headers:
                details["scopes"].append("api_access")
        elif response.status_code == 401:
            return False, "Invalid GitLab token", details
    except Exception as e:
        pass
    
    if not details["user_info"]:
        return False, "Could not validate GitLab token", details
    
    # Test 2: List projects
    try:
        response = requests.get('https://gitlab.com/api/v4/projects?membership=true&per_page=5', 
                               headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            projects = response.json()
            details["projects"] = [p['path_with_namespace'] for p in projects]
    except:
        pass
    
    # Test 3: List groups
    try:
        response = requests.get('https://gitlab.com/api/v4/groups?per_page=5', 
                               headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            groups = response.json()
            details["groups"] = [g['full_path'] for g in groups]
    except:
        pass
    
    message = f"✅ Valid GitLab token for {details['user_info']['username']}"
    if details["projects"]:
        message += f"\n   Projects: {', '.join(details['projects'])}"
    if details["groups"]:
        message += f"\n   Groups: {', '.join(details['groups'])}"
    
    return True, message, details

def validate_slack_token(token: str) -> Tuple[bool, str, dict]:
    """
    Comprehensive Slack token validation
    """
    details = {
        "team_info": {},
        "user_info": {},
        "channels": [],
        "permissions": [],
        "workspace_info": {}
    }
    
    headers = {'Authorization': f'Bearer {token}'}
    
    # Test 1: Basic auth test
    try:
        response = requests.get('https://slack.com/api/auth.test', headers=headers, timeout=10, verify=False)
        data = response.json()
        
        if data.get('ok'):
            details["team_info"] = {
                "team": data.get('team'),
                "team_id": data.get('team_id'),
                "user": data.get('user'),
                "user_id": data.get('user_id'),
                "url": data.get('url')
            }
        else:
            error = data.get('error', 'Unknown error')
            return False, f"Invalid Slack token: {error}", details
    except Exception as e:
        return False, f"Error testing Slack token: {str(e)}", details
    
    # Test 2: List conversations (channels)
    try:
        response = requests.get(
            'https://slack.com/api/conversations.list',
            headers=headers,
            params={'limit': 5, 'types': 'public_channel,private_channel'},
            timeout=10, verify=False
        )
        data = response.json()
        if data.get('ok'):
            channels = data.get('channels', [])
            details["channels"] = [{
                'name': c['name'],
                'private': c.get('is_private', False),
                'member_count': c.get('num_members', 0)
            } for c in channels[:5]]
            details["permissions"].append("channels:read")
    except:
        pass
    
    # Test 3: Get workspace info
    try:
        response = requests.get('https://slack.com/api/team.info', headers=headers, timeout=10, verify=False)
        data = response.json()
        if data.get('ok'):
            team = data.get('team', {})
            details["workspace_info"] = {
                "name": team.get('name'),
                "domain": team.get('domain'),
                "email_domain": team.get('email_domain'),
                "icon": team.get('icon', {}).get('image_34') if team.get('icon') else None
            }
    except:
        pass
    
    # Test 4: List users
    try:
        response = requests.get(
            'https://slack.com/api/users.list',
            headers=headers,
            params={'limit': 5},
            timeout=10, verify=False
        )
        data = response.json()
        if data.get('ok'):
            members = data.get('members', [])
            active_users = [m for m in members if not m.get('deleted')][:3]
            if active_users:
                details["permissions"].append("users:read")
    except:
        pass
    
    message = f"✅ Valid Slack token for workspace: {details['team_info'].get('team')}"
    message += f"\n   Authenticated as: {details['team_info'].get('user')}"
    if details["channels"]:
        channel_names = [c['name'] for c in details["channels"]]
        message += f"\n   Channels: {', '.join(channel_names)}"
    
    return True, message, details

def validate_slack_webhook(url: str) -> Tuple[bool, str, dict]:
    """Validate Slack webhook URL without sending a real message.
    Sending an empty JSON body returns 'missing_text_or_fallback_or_attachments'
    which confirms the URL is valid without posting visible content.
    """
    details = {}
    try:
        response = requests.post(url, json={}, timeout=10, verify=False)
        body = response.text.strip()
        # Slack returns this specific error when the URL is valid but the payload is empty
        if response.status_code == 400 and "missing_text_or_fallback_or_attachments" in body:
            return True, "✅ Valid Slack Webhook URL (empty probe confirmed – no message sent)", details
        elif response.status_code == 200 and body == "ok":
            return True, "✅ Valid Slack Webhook URL", details
        elif response.status_code == 403 or "invalid_token" in body or "no_service" in body:
            return False, f"❌ Invalid or revoked Slack Webhook URL", details
        else:
            return False, f"❌ Webhook returned unexpected status {response.status_code}: {body[:100]}", details
    except Exception as e:
        return False, f"❌ Validation error: {str(e)}", details

def validate_discord_webhook(url: str) -> Tuple[bool, str, dict]:
    """Validate Discord webhook URL by fetching its info (GET), not posting a message."""
    details = {}
    try:
        # GET the webhook URL returns its name/channel info without sending anything
        response = requests.get(url, timeout=10, verify=False)
        if response.status_code == 200:
            data = response.json()
            details["name"] = data.get("name", "")
            details["channel_id"] = data.get("channel_id", "")
            details["guild_id"] = data.get("guild_id", "")
            name_str = f" – Name: {details['name']}" if details.get("name") else ""
            return True, f"✅ Valid Discord Webhook URL{name_str} (read-only probe, no message sent)", details
        elif response.status_code == 401:
            return False, "❌ Invalid Discord Webhook (401 Unauthorized)", details
        else:
            return False, f"❌ Webhook returned status {response.status_code}", details
    except Exception as e:
        return False, f"❌ Validation error: {str(e)}", details

def validate_stripe_key(key: str) -> Tuple[bool, str, dict]:
    """
    Comprehensive Stripe key validation
    """
    details = {
        "account_info": {},
        "mode": "live" if key.startswith(('sk_live_', 'pk_live_')) else "test",
        "key_type": "secret" if key.startswith(('sk_', 'rk_')) else "publishable",
        "capabilities": [],
        "balance": {},
        "products": []
    }
    
    headers = {
        'Authorization': f'Bearer {key}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # Try to import stripe
    try:
        import stripe
        stripe_available = True
    except ImportError:
        stripe_available = False
    
    if not stripe_available:
        # Just validate format
        if key.startswith(('sk_live_', 'sk_test_', 'pk_live_', 'pk_test_')) and len(key) >= 24:
            return True, f"Valid Stripe key format (install stripe for full validation)", details
        return False, "Invalid Stripe key format", details
    
    # Test 1: Get account info
    try:
        stripe.api_key = key
        account = stripe.Account.retrieve()
        
        details["account_info"] = {
            "id": account.get('id'),
            "business_name": account.get('business_profile', {}).get('name') if account.get('business_profile') else None,
            "country": account.get('country'),
            "type": account.get('type'),
            "email": account.get('email'),
            "charges_enabled": account.get('charges_enabled'),
            "payouts_enabled": account.get('payouts_enabled')
        }
    except stripe.error.AuthenticationError:
        return False, "❌ Invalid Stripe key", details
    except stripe.error.PermissionError:
        # Key works but lacks permissions for account info
        details["capabilities"].append("limited_access")
    except Exception as e:
        pass
    
    if not details["account_info"] and not details["capabilities"]:
        return False, "Could not validate Stripe key", details
    
    # Test 2: Get balance
    try:
        balance = stripe.Balance.retrieve()
        available = balance.get('available', [])
        if available:
            details["balance"] = {
                "currency": available[0].get('currency', 'usd').upper(),
                "amount": available[0].get('amount', 0) / 100
            }
    except:
        pass
    
    # Test 3: List products (if secret key)
    if details["key_type"] == "secret":
        try:
            products = stripe.Product.list(limit=5)
            details["products"] = [p['name'] for p in products['data']]
        except:
            pass
    
    message = f"✅ Valid Stripe {details['mode']} {details['key_type']} key"
    if details["account_info"].get('business_name'):
        message += f"\n   Account: {details['account_info']['business_name']}"
    if details["account_info"].get('email'):
        message += f"\n   Email: {details['account_info']['email']}"
    if details["balance"]:
        message += f"\n   Balance: {details['balance']['amount']} {details['balance']['currency']}"
    if details["products"]:
        message += f"\n   Products: {', '.join(details['products'])}"
    
    return True, message, details

def validate_twilio_sid(sid: str, token: Optional[str] = None) -> Tuple[bool, str, dict]:
    """
    Comprehensive Twilio credentials validation
    """
    details = {
        "account_info": {},
        "phone_numbers": [],
        "applications": [],
        "usage": {},
        "capabilities": []
    }
    
    if not token:
        return False, "Auth token required for Twilio validation", details
    
    # Twilio uses basic auth with SID as username and token as password
    auth = (sid, token)
    
    # Test 1: Get account info
    try:
        response = requests.get(f'https://api.twilio.com/2010-04-01/Accounts/{sid}.json', 
                               auth=auth, timeout=10, verify=False)
        if response.status_code == 200:
            account = response.json()
            details["account_info"] = {
                "name": account.get('friendly_name'),
                "status": account.get('status'),
                "type": account.get('type'),
                "created": account.get('date_created'),
                "owner_email": account.get('owner_email')
            }
            
            if account.get('status') == 'active':
                details["capabilities"].append("active_account")
        elif response.status_code == 401:
            return False, "❌ Invalid Twilio credentials", details
    except Exception as e:
        pass
    
    if not details["account_info"]:
        return False, "Could not validate Twilio credentials", details
    
    # Test 2: List phone numbers
    try:
        response = requests.get(
            f'https://api.twilio.com/2010-04-01/Accounts/{sid}/IncomingPhoneNumbers.json',
            auth=auth,
            params={'PageSize': 5},
            timeout=10, verify=False
        )
        if response.status_code == 200:
            numbers = response.json().get('incoming_phone_numbers', [])
            details["phone_numbers"] = [{
                'number': n['phone_number'],
                'friendly': n.get('friendly_name')
            } for n in numbers]
    except:
        pass
    
    # Test 3: Get usage records
    try:
        response = requests.get(
            f'https://api.twilio.com/2010-04-01/Accounts/{sid}/Usage/Records.json',
            auth=auth,
            params={'PageSize': 1},
            timeout=10, verify=False
        )
        if response.status_code == 200:
            usage = response.json().get('usage_records', [])
            if usage:
                details["usage"] = {
                    "category": usage[0].get('category'),
                    "usage": usage[0].get('usage'),
                    "price": usage[0].get('price')
                }
                details["capabilities"].append("can_view_usage")
    except:
        pass
    
    # Test 4: List applications
    try:
        response = requests.get(
            f'https://api.twilio.com/2010-04-01/Accounts/{sid}/Applications.json',
            auth=auth,
            params={'PageSize': 3},
            timeout=10, verify=False
        )
        if response.status_code == 200:
            apps = response.json().get('applications', [])
            details["applications"] = [app['friendly_name'] for app in apps]
    except:
        pass
    
    message = f"✅ Valid Twilio credentials"
    if details["account_info"].get('name'):
        message += f"\n   Account: {details['account_info']['name']}"
    if details["account_info"].get('status'):
        message += f"\n   Status: {details['account_info']['status']}"
    if details["phone_numbers"]:
        numbers = [n['number'] for n in details["phone_numbers"][:3]]
        message += f"\n   Phone numbers: {', '.join(numbers)}"
    
    return True, message, details

def validate_sendgrid_key(key: str) -> Tuple[bool, str, dict]:
    """
    Comprehensive SendGrid key validation
    """
    details = {
        "user_info": {},
        "scopes": [],
        "stats": {},
        "suppressions": []
    }
    
    headers = {'Authorization': f'Bearer {key}'}
    
    # Test 1: Check scopes
    try:
        response = requests.get('https://api.sendgrid.com/v3/scopes', headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            scopes = response.json().get('scopes', [])
            details["scopes"] = scopes[:10]  # First 10 scopes
            
            # Categorize scopes
            if 'mail.send' in scopes:
                details["capabilities"] = "Can send emails"
            if 'stats.read' in scopes:
                details["capabilities"] = "Can read stats"
        elif response.status_code == 401:
            return False, "❌ Invalid SendGrid key", details
    except Exception as e:
        pass
    
    # Test 2: Get user info
    try:
        response = requests.get('https://api.sendgrid.com/v3/user/profile', headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            profile = response.json()
            details["user_info"] = {
                "username": profile.get('username'),
                "email": profile.get('email'),
                "first_name": profile.get('first_name'),
                "last_name": profile.get('last_name'),
                "address": profile.get('address')
            }
    except:
        pass
    
    # Test 3: Get account stats
    try:
        response = requests.get(
            'https://api.sendgrid.com/v3/stats',
            headers=headers,
            params={'start_date': '2024-01-01', 'end_date': '2024-01-07'},
            timeout=10, verify=False
        )
        if response.status_code == 200:
            stats = response.json()
            if stats:
                details["stats"] = {"available": True, "count": len(stats)}
    except:
        pass
    
    # Test 4: Check suppressions (blocks)
    try:
        response = requests.get('https://api.sendgrid.com/v3/suppression/blocks', headers=headers, timeout=10, verify=False)
        if response.status_code == 200:
            blocks = response.json()
            details["suppressions"] = {
                "blocks": len(blocks)
            }
    except:
        pass
    
    message = f"✅ Valid SendGrid key"
    if details["user_info"].get('username'):
        message += f"\n   Account: {details['user_info']['username']}"
    if details["user_info"].get('email'):
        message += f"\n   Email: {details['user_info']['email']}"
    if details["scopes"]:
        scope_count = len(details["scopes"])
        message += f"\n   Scopes: {scope_count} permissions available"
    
    return True, message, details

def validate_mailgun_key(key: str, domain: Optional[str] = None) -> Tuple[bool, str, dict]:
    """
    Comprehensive Mailgun key validation
    """
    details = {
        "domains": [],
        "account_info": {},
        "stats": {},
        "logs": []
    }
    
    # Mailgun uses basic auth with 'api' as username and key as password
    auth = ('api', key)
    
    # Test 1: List domains
    try:
        response = requests.get('https://api.mailgun.net/v3/domains', auth=auth, timeout=10, verify=False)
        if response.status_code == 200:
            data = response.json()
            domains = data.get('items', [])
            details["domains"] = [{
                'name': d['name'],
                'state': d.get('state'),
                'created_at': d.get('created_at')
            } for d in domains[:5]]
        elif response.status_code == 401:
            return False, "❌ Invalid Mailgun key", details
    except Exception as e:
        pass
    
    if not details["domains"]:
        return False, "Could not validate Mailgun key", details
    
    # If a specific domain was provided, test it
    test_domain = domain if domain else (details["domains"][0]['name'] if details["domains"] else None)
    
    if test_domain:
        # Test 2: Get domain stats
        try:
            response = requests.get(
                f'https://api.mailgun.net/v3/{test_domain}/stats/total',
                auth=auth,
                params={'event': ['accepted', 'delivered', 'failed']},
                timeout=10, verify=False
            )
            if response.status_code == 200:
                stats = response.json()
                details["stats"] = stats.get('stats', [])
        except:
            pass
        
        # Test 3: Get recent logs
        try:
            response = requests.get(
                f'https://api.mailgun.net/v3/{test_domain}/events',
                auth=auth,
                params={'limit': 5},
                timeout=10, verify=False
            )
            if response.status_code == 200:
                events = response.json().get('items', [])
                details["logs"] = [{
                    'event': e.get('event'),
                    'timestamp': e.get('timestamp')
                } for e in events[:3]]
        except:
            pass
    
    message = f"✅ Valid Mailgun key"
    if details["domains"]:
        domain_names = [d['name'] for d in details["domains"]]
        message += f"\n   Domains: {', '.join(domain_names[:3])}"
        if len(domain_names) > 3:
            message += f" +{len(domain_names)-3} more"
    
    return True, message, details

def validate_jwt_token(token: str) -> Tuple[bool, str, dict]:
    """
    Comprehensive JWT token analysis
    """
    details = {
        "header": {},
        "payload": {},
        "signature": {},
        "expired": False,
        "algorithm": "",
        "sensitive_data": []
    }
    
    try:
        # Split JWT parts
        parts = token.split('.')
        if len(parts) != 3:
            return False, "Invalid JWT format (should have 3 parts)", details
        
        # Decode header
        header_b64 = parts[0]
        # Add padding if needed
        header_b64 += '=' * (4 - len(header_b64) % 4) if len(header_b64) % 4 else ''
        header_json = base64.b64decode(header_b64).decode('utf-8')
        details["header"] = json.loads(header_json)
        
        # Decode payload
        payload_b64 = parts[1]
        payload_b64 += '=' * (4 - len(payload_b64) % 4) if len(payload_b64) % 4 else ''
        payload_json = base64.b64decode(payload_b64).decode('utf-8')
        details["payload"] = json.loads(payload_json)
        
        # Get algorithm
        details["algorithm"] = details["header"].get('alg', 'unknown')
        
        # Check for sensitive data in payload
        sensitive_fields = [
            'email', 'username', 'name', 'given_name', 'family_name',
            'phone_number', 'address', 'birthdate', 'ssn', 'credit_card',
            'password', 'secret', 'token', 'key', 'api_key'
        ]
        
        for field in sensitive_fields:
            if field in details["payload"]:
                value = details["payload"][field]
                if len(str(value)) > 0:
                    details["sensitive_data"].append({
                        "field": field,
                        "value_preview": str(value)[:20] + "..." if len(str(value)) > 20 else str(value)
                    })
        
        # Check expiration
        if 'exp' in details["payload"]:
            exp_timestamp = details["payload"]['exp']
            exp_time = datetime.fromtimestamp(exp_timestamp)
            now = datetime.now()
            
            if exp_time < now:
                details["expired"] = True
                details["expired_seconds"] = (now - exp_time).total_seconds()
        
        # Check issuer
        issuer_info = []
        if 'iss' in details["payload"]:
            issuer_info.append(f"issuer: {details['payload']['iss']}")
        if 'aud' in details["payload"]:
            issuer_info.append(f"audience: {details['payload']['aud']}")
        if 'sub' in details["payload"]:
            issuer_info.append(f"subject: {details['payload']['sub']}")
        
        # Build message
        message = f"✅ JWT Analysis - Algorithm: {details['algorithm']}"
        
        if details["expired"]:
            message += f"\n   ⚠️ EXPIRED: {details['expired_seconds']:.0f} seconds ago"
        
        if 'email' in details["payload"]:
            message += f"\n   Email: {details['payload']['email']}"
        
        if details["sensitive_data"]:
            message += f"\n   🔑 Sensitive data: {len(details['sensitive_data'])} fields"
            for sd in details["sensitive_data"][:3]:
                message += f"\n      - {sd['field']}: {sd['value_preview']}"
        
        if issuer_info:
            message += f"\n   ℹ️ {', '.join(issuer_info)}"
        
        return True, message, details
        
    except json.JSONDecodeError as e:
        return False, f"❌ Invalid JWT format: {str(e)}", details
    except Exception as e:
        return False, f"❌ Error decoding JWT: {str(e)}", details

def validate_bearer_token(token: str) -> Tuple[bool, str, dict]:
    """Test bearer token against common endpoints"""
    details = {
        "valid_endpoints": [],
        "tested_endpoints": []
    }
    
    # Strip 'Bearer ' prefix if present
    if token.lower().startswith('bearer '):
        token = token[7:]
    
    # Try common validation endpoints
    endpoints = [
        ('GitHub', 'https://api.github.com/user'),
        ('Facebook', 'https://graph.facebook.com/me'),
        ('Spotify', 'https://api.spotify.com/v1/me'),
        ('Google', 'https://www.googleapis.com/oauth2/v1/userinfo'),
        ('Twitter', 'https://api.twitter.com/2/users/me'),
        ('LinkedIn', 'https://api.linkedin.com/v2/me'),
        ('Microsoft', 'https://graph.microsoft.com/v1.0/me')
    ]
    
    headers = {'Authorization': f'Bearer {token}'}
    
    for service, endpoint in endpoints:
        try:
            response = requests.get(endpoint, headers=headers, timeout=5, verify=False)
            details["tested_endpoints"].append(service)
            if response.status_code == 200:
                data = response.json()
                details["valid_endpoints"].append(service)
                # Try to get user info
                if service == 'GitHub' and 'login' in data:
                    return True, f"✅ Valid bearer token for {service} - User: {data['login']}", details
                elif service == 'Google' and 'email' in data:
                    return True, f"✅ Valid bearer token for {service} - Email: {data['email']}", details
                else:
                    return True, f"✅ Valid bearer token for {service}", details
        except:
            continue
    
    if details["valid_endpoints"]:
        return True, f"✅ Valid bearer token for: {', '.join(details['valid_endpoints'])}", details
    else:
        return False, "❌ Bearer token not valid against common APIs", details

def validate_basic_auth(auth_str: str) -> Tuple[bool, str, dict]:
    """Decode and analyze Basic Authentication"""
    details = {
        "username": "",
        "password": "",
        "decoded": ""
    }
    
    try:
        # Strip 'Basic ' prefix if present
        if auth_str.lower().startswith('basic '):
            auth_str = auth_str[6:]
        
        # Decode base64
        decoded = base64.b64decode(auth_str).decode('utf-8', errors='ignore')
        details["decoded"] = decoded
        
        if ':' in decoded:
            username, password = decoded.split(':', 1)
            details["username"] = username
            details["password"] = password
            return True, f"✅ Basic Auth decoded - Username: {username}, Password: {password}", details
        else:
            return True, f"✅ Basic Auth decoded (no colon): {decoded}", details
    except Exception as e:
        return False, f"❌ Failed to decode Basic Auth: {str(e)}", details

def validate_generic_secret(secret: str) -> Tuple[bool, str, dict]:
    """Generic validation for unknown secret types"""
    details = {
        "length": len(secret),
        "entropy": 0,
        "character_classes": 0,
        "analysis": []
    }
    
    # Calculate Shannon entropy
    freq = {}
    for c in secret:
        freq[c] = freq.get(c, 0) + 1
    
    entropy = 0
    for count in freq.values():
        p = count / len(secret)
        entropy -= p * math.log2(p)
    
    details["entropy"] = round(entropy, 2)
    
    # Check character classes
    has_lower = any(c.islower() for c in secret)
    has_upper = any(c.isupper() for c in secret)
    has_digit = any(c.isdigit() for c in secret)
    has_special = any(not c.isalnum() for c in secret)
    
    classes = sum([has_lower, has_upper, has_digit, has_special])
    details["character_classes"] = classes
    
    result = f"Secret analysis - Length: {len(secret)}, Entropy: {entropy:.2f}"
    result += f"\n   Character classes: {classes}/4"
    
    if len(secret) >= 32 and entropy > 4.5 and classes >= 3:
        result += "\n   ✅ High entropy secret (likely valid API key)"
        details["analysis"].append("High entropy - likely real key")
    elif len(secret) >= 20 and entropy > 3.5:
        result += "\n   ⚠️ Medium entropy (could be valid)"
        details["analysis"].append("Medium entropy - might be valid")
    else:
        result += "\n   ⚠️ Low entropy (might be placeholder or test key)"
        details["analysis"].append("Low entropy - possibly test/placeholder")
    
    return True, result, details

def validate_private_key(content: str) -> Tuple[bool, str, dict]:
    """Validate private key format"""
    details = {
        "key_type": None,
        "encrypted": False
    }
    
    patterns = {
        'RSA': r'-----BEGIN RSA PRIVATE KEY-----',
        'DSA': r'-----BEGIN DSA PRIVATE KEY-----',
        'EC': r'-----BEGIN EC PRIVATE KEY-----',
        'OPENSSH': r'-----BEGIN OPENSSH PRIVATE KEY-----',
        'ENCRYPTED': r'-----BEGIN ENCRYPTED PRIVATE KEY-----'
    }
    
    for key_type, pattern in patterns.items():
        if re.search(pattern, content):
            details["key_type"] = key_type
            if key_type == 'ENCRYPTED':
                details["encrypted"] = True
            return True, f"✅ Valid {key_type} private key format", details
    
    return False, "❌ Not a recognized private key format", details

# =============================================================================
# ADDITIONAL VALIDATORS (KeyHacks-sourced techniques)
# =============================================================================

def validate_dropbox_token(token: str) -> Tuple[bool, str, dict]:
    """Validate Dropbox OAuth2 access token"""
    details = {"account_info": {}}
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.post(
            "https://api.dropboxapi.com/2/users/get_current_account",
            headers=headers, timeout=10, verify=False
        )
        if response.status_code == 200:
            data = response.json()
            details["account_info"] = {
                "name": data.get("name", {}).get("display_name"),
                "email": data.get("email"),
                "account_id": data.get("account_id"),
                "account_type": data.get("account_type", {}).get(".tag"),
            }
            name = details["account_info"].get("name", "")
            email = details["account_info"].get("email", "")
            return True, f"✅ Valid Dropbox token – {name} ({email})", details
        elif response.status_code == 401:
            return False, "❌ Invalid Dropbox token", details
        else:
            return False, f"❌ Dropbox API returned {response.status_code}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_firebase_fcm(key: str) -> Tuple[bool, str, dict]:
    """Validate Firebase Cloud Messaging server key (KeyHacks technique)"""
    details = {}
    headers = {
        "Authorization": f"key={key}",
        "Content-Type": "application/json"
    }
    # Send to a dummy registration ID – we're checking whether the key is accepted,
    # not actually delivering a message.
    payload = {"registration_ids": ["test_invalid_device_id_probe"]}
    try:
        response = requests.post(
            "https://fcm.googleapis.com/fcm/send",
            headers=headers, json=payload, timeout=10, verify=False
        )
        if response.status_code == 200:
            data = response.json()
            # A valid key returns results (even if the device ID is invalid)
            if "results" in data or "failure" in data:
                return True, "✅ Valid Firebase FCM Server Key (accepted by FCM API)", details
        elif response.status_code == 401:
            return False, "❌ Invalid FCM Server Key", details
        return False, f"❌ FCM API returned {response.status_code}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_telegram_bot(token: str) -> Tuple[bool, str, dict]:
    """Validate Telegram Bot API token using getMe"""
    details = {"bot_info": {}}
    try:
        response = requests.get(
            f"https://api.telegram.org/bot{token}/getMe",
            timeout=10, verify=False
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("ok"):
                bot = data.get("result", {})
                details["bot_info"] = {
                    "id": bot.get("id"),
                    "username": bot.get("username"),
                    "first_name": bot.get("first_name"),
                    "can_join_groups": bot.get("can_join_groups"),
                    "can_read_all_group_messages": bot.get("can_read_all_group_messages"),
                }
                username = bot.get("username", "unknown")
                name = bot.get("first_name", "")
                return True, f"✅ Valid Telegram Bot Token – @{username} ({name})", details
        elif response.status_code == 401:
            return False, "❌ Invalid Telegram Bot Token", details
        return False, f"❌ Telegram API returned {response.status_code}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_twitter_bearer(token: str) -> Tuple[bool, str, dict]:
    """Validate Twitter/X Bearer token"""
    details = {}
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(
            "https://api.twitter.com/1.1/account_activity/all/subscriptions/count.json",
            headers=headers, timeout=10, verify=False
        )
        if response.status_code == 200:
            data = response.json()
            details["subscriptions_count"] = data.get("subscriptions_count", 0)
            details["environments_count"] = data.get("environments_count", 0)
            return True, f"✅ Valid Twitter/X Bearer Token (subscriptions: {details['subscriptions_count']})", details
        elif response.status_code == 401:
            return False, "❌ Invalid Twitter/X Bearer Token", details
        elif response.status_code == 403:
            # Token is valid but endpoint requires higher plan – confirm it works with /2/users/me
            r2 = requests.get(
                "https://api.twitter.com/2/users/me",
                headers=headers, timeout=10, verify=False
            )
            if r2.status_code == 200:
                user = r2.json().get("data", {})
                return True, f"✅ Valid Twitter/X Bearer Token – @{user.get('username', 'unknown')}", details
            return False, f"❌ Twitter/X API returned 403 Forbidden", details
        return False, f"❌ Twitter/X API returned {response.status_code}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_pagerduty_token(token: str) -> Tuple[bool, str, dict]:
    """Validate PagerDuty API token"""
    details = {"user_info": {}}
    headers = {"Authorization": f"Token token={token}", "Accept": "application/vnd.pagerduty+json;version=2"}
    try:
        response = requests.get(
            "https://api.pagerduty.com/users",
            headers=headers, params={"limit": 1}, timeout=10, verify=False
        )
        if response.status_code == 200:
            data = response.json()
            users = data.get("users", [])
            total = data.get("total", 0)
            if users:
                u = users[0]
                details["user_info"] = {"name": u.get("name"), "email": u.get("email"), "role": u.get("role")}
            return True, f"✅ Valid PagerDuty Token (total users: {total})", details
        elif response.status_code == 401:
            return False, "❌ Invalid PagerDuty Token", details
        return False, f"❌ PagerDuty API returned {response.status_code}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_zendesk_token(token: str, domain: Optional[str] = None) -> Tuple[bool, str, dict]:
    """Validate Zendesk API token (requires subdomain)"""
    details = {}
    if not domain:
        return False, "⚠️ Zendesk subdomain required for validation (e.g. 'yourcompany.zendesk.com')", details
    subdomain = domain.replace(".zendesk.com", "").rstrip("/")
    try:
        response = requests.get(
            f"https://{subdomain}.zendesk.com/api/v2/tickets.json?page[size]=1",
            headers={"Authorization": f"Bearer {token}"}, timeout=10, verify=False
        )
        if response.status_code == 200:
            count = response.json().get("count", "?")
            return True, f"✅ Valid Zendesk Token for {subdomain} (tickets: {count})", details
        elif response.status_code == 401:
            return False, "❌ Invalid Zendesk Token", details
        return False, f"❌ Zendesk API returned {response.status_code}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_npm_token(token: str) -> Tuple[bool, str, dict]:
    """Validate NPM access token"""
    details = {}
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(
            "https://registry.npmjs.org/-/whoami",
            headers=headers, timeout=10, verify=False
        )
        if response.status_code == 200:
            username = response.json().get("username", "unknown")
            details["username"] = username
            return True, f"✅ Valid NPM Token – user: {username}", details
        elif response.status_code == 401:
            return False, "❌ Invalid NPM Token", details
        return False, f"❌ NPM registry returned {response.status_code}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_square_token(token: str) -> Tuple[bool, str, dict]:
    """Validate Square OAuth Access Token"""
    details = {}
    headers = {"Authorization": f"Bearer {token}", "Square-Version": "2023-12-13"}
    try:
        response = requests.get(
            "https://connect.squareup.com/v2/locations",
            headers=headers, timeout=10, verify=False
        )
        if response.status_code == 200:
            locations = response.json().get("locations", [])
            details["locations"] = [loc.get("name") for loc in locations[:3]]
            return True, f"✅ Valid Square Token – {len(locations)} location(s): {', '.join(details['locations'])}", details
        elif response.status_code == 401:
            return False, "❌ Invalid Square Access Token", details
        return False, f"❌ Square API returned {response.status_code}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_infura_key(key: str) -> Tuple[bool, str, dict]:
    """Validate Infura project ID against Ethereum mainnet"""
    details = {}
    payload = {"jsonrpc": "2.0", "method": "eth_accounts", "params": [], "id": 1}
    try:
        response = requests.post(
            f"https://mainnet.infura.io/v3/{key}",
            json=payload, timeout=10, verify=False
        )
        if response.status_code == 200:
            data = response.json()
            if "result" in data or "error" in data:
                # Even an auth error from Infura with 200 means the project exists
                if data.get("error", {}).get("code") == -32600:
                    return True, f"✅ Valid Infura Project ID (Ethereum mainnet accessible)", details
                return True, f"✅ Valid Infura Project ID", details
        elif response.status_code == 401:
            return False, "❌ Invalid Infura Project ID", details
        return False, f"❌ Infura API returned {response.status_code}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_hubspot_key(key: str) -> Tuple[bool, str, dict]:
    """Validate HubSpot API key using contacts endpoint"""
    details = {}
    try:
        response = requests.get(
            "https://api.hubapi.com/owners/v2/owners",
            params={"hapikey": key}, timeout=10, verify=False
        )
        if response.status_code == 200:
            owners = response.json()
            details["owner_count"] = len(owners)
            names = [f"{o.get('firstName','')} {o.get('lastName','')}".strip() for o in owners[:3]]
            return True, f"✅ Valid HubSpot API Key – {len(owners)} owner(s): {', '.join(filter(None, names))}", details
        elif response.status_code == 401 or response.status_code == 403:
            return False, "❌ Invalid HubSpot API Key", details
        return False, f"❌ HubSpot API returned {response.status_code}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_datadog_key(key: str) -> Tuple[bool, str, dict]:
    """Validate Datadog API key"""
    details = {}
    headers = {"DD-API-KEY": key}
    try:
        response = requests.get(
            "https://api.datadoghq.com/api/v1/validate",
            headers=headers, timeout=10, verify=False
        )
        if response.status_code == 200 and response.json().get("valid"):
            return True, "✅ Valid Datadog API Key", details
        elif response.status_code == 403:
            return False, "❌ Invalid Datadog API Key", details
        return False, f"❌ Datadog API returned {response.status_code}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_facebook_token(token: str) -> Tuple[bool, str, dict]:
    """Validate Facebook Graph API access token"""
    details = {}
    try:
        response = requests.get(
            "https://graph.facebook.com/me",
            params={"access_token": token}, timeout=10, verify=False
        )
        if response.status_code == 200:
            data = response.json()
            details["user_id"] = data.get("id")
            details["name"] = data.get("name")
            return True, f"✅ Valid Facebook Token – {data.get('name', 'unknown')} (id: {data.get('id')})", details
        else:
            err = response.json().get("error", {}).get("message", "Unknown")
            return False, f"❌ Invalid Facebook Token: {err}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_teams_webhook(url: str) -> Tuple[bool, str, dict]:
    """Validate Microsoft Teams webhook without sending a visible message.
    Sending an empty JSON body returns a descriptive error if the URL is valid.
    """
    details = {}
    try:
        # Empty JSON body – Teams returns 400 with a descriptive error for valid URLs
        response = requests.post(url, json={}, timeout=10, verify=False)
        body = response.text.strip()
        if response.status_code in (200, 202):
            return True, "✅ Valid Microsoft Teams Webhook URL", details
        elif response.status_code == 400 and body:
            # A 400 with a Teams-style error message still confirms the URL is live
            if "BadRequest" in body or "text" in body.lower() or "summary" in body.lower():
                return True, f"✅ Valid Microsoft Teams Webhook URL (probe accepted, no message sent)", details
        elif response.status_code == 403:
            return False, "❌ Invalid or expired Microsoft Teams Webhook", details
        return False, f"❌ Teams Webhook returned {response.status_code}: {body[:100]}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_shopify_token(token: str, shop_domain: Optional[str] = None) -> Tuple[bool, str, dict]:
    """Validate Shopify access token (requires shop domain)"""
    details = {}
    if not shop_domain:
        return False, "⚠️ Shopify shop domain required for validation (e.g. 'mystore.myshopify.com')", details
    try:
        response = requests.get(
            f"https://{shop_domain}/admin/api/2023-10/shop.json",
            headers={"X-Shopify-Access-Token": token}, timeout=10, verify=False
        )
        if response.status_code == 200:
            shop = response.json().get("shop", {})
            details["shop_name"] = shop.get("name")
            details["email"] = shop.get("email")
            return True, f"✅ Valid Shopify Token – Shop: {shop.get('name', shop_domain)}", details
        elif response.status_code == 401:
            return False, "❌ Invalid Shopify Token", details
        return False, f"❌ Shopify API returned {response.status_code}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_asana_token(token: str) -> Tuple[bool, str, dict]:
    """Validate Asana personal access token"""
    details = {}
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(
            "https://app.asana.com/api/1.0/users/me",
            headers=headers, timeout=10, verify=False
        )
        if response.status_code == 200:
            data = response.json().get("data", {})
            details["name"] = data.get("name")
            details["email"] = data.get("email")
            details["gid"] = data.get("gid")
            return True, f"✅ Valid Asana Token – {data.get('name', 'unknown')} ({data.get('email', '')})", details
        elif response.status_code == 401:
            return False, "❌ Invalid Asana Token", details
        return False, f"❌ Asana API returned {response.status_code}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details


def validate_mailchimp_key(key: str) -> Tuple[bool, str, dict]:
    """Validate Mailchimp API key (extracts datacenter from key suffix)"""
    details = {}
    if "-" not in key:
        return False, "❌ Invalid Mailchimp key format (expected key-usXX)", details
    dc = key.split("-")[-1]
    try:
        response = requests.get(
            f"https://{dc}.api.mailchimp.com/3.0/",
            auth=("anystring", key), timeout=10, verify=False
        )
        if response.status_code == 200:
            data = response.json()
            account_name = data.get("account_name", "")
            email = data.get("email", "")
            details["account_name"] = account_name
            details["email"] = email
            details["datacenter"] = dc
            return True, f"✅ Valid Mailchimp Key – Account: {account_name} ({email}), DC: {dc}", details
        elif response.status_code == 401:
            return False, "❌ Invalid Mailchimp Key", details
        return False, f"❌ Mailchimp API returned {response.status_code}", details
    except Exception as e:
        return False, f"❌ Error: {str(e)}", details

# =============================================================================
# VALIDATION DISPATCHER
# =============================================================================

def validate_api_key(key_type: str, key: str, extra: Optional[str] = None) -> Tuple[bool, str, dict]:
    """Dispatch key validation to appropriate function with comprehensive results"""
    
    validators = {
        # ── Existing validators ──────────────────────────────────────────────
        "AWS Access Key": lambda k: validate_aws_key(k, extra),
        "AWS Secret Key": lambda k: validate_aws_key("AKIAEXAMPLE", k),
        "Google API Key": validate_google_key,
        "Firebase API Key": validate_google_key,           # same underlying API
        "Google OAuth": lambda k: (True, f"✅ OAuth Client ID format valid – {k}", {}),
        "GitHub Token": validate_github_token,
        "GitHub Fine-grained": validate_github_token,
        "GitLab Token": validate_gitlab_token,
        "Slack Token": validate_slack_token,
        "Slack Webhook": validate_slack_webhook,
        "Discord Webhook": validate_discord_webhook,
        "Stripe Live": validate_stripe_key,
        "Stripe Test": validate_stripe_key,
        "Stripe Restricted Key": validate_stripe_key,
        "Stripe Publishable": lambda k: (True, f"✅ Stripe publishable key format valid – {k}", {}),
        "Twilio SID": lambda k: validate_twilio_sid(k, extra),
        "Twilio Token": lambda k: (True, f"✅ Twilio token format valid (pair with SID to test)", {}),
        "SendGrid": validate_sendgrid_key,
        "Mailgun": lambda k: validate_mailgun_key(k, extra),
        "Mailchimp": validate_mailchimp_key,                # was a stub – now real
        "HubSpot": validate_hubspot_key,                    # was UUID-only stub
        "HubSpot API Key (v1)": validate_hubspot_key,
        "Salesforce": lambda k: (True, f"✅ Salesforce session format valid – {k}", {}),
        "JWT Token": validate_jwt_token,
        "Bearer Token": validate_bearer_token,
        "Basic Auth": validate_basic_auth,
        "Generic Base64": lambda k: (True, f"✅ Base64 string length {len(k)}", {}),
        "Generic Secret": validate_generic_secret,
        "Private Key": validate_private_key,
        # ── New KeyHacks-sourced validators ─────────────────────────────────
        "Dropbox Token": validate_dropbox_token,
        "Firebase FCM Key": validate_firebase_fcm,
        "Telegram Bot Token": validate_telegram_bot,
        "Twitter/X Bearer Token": validate_twitter_bearer,
        "Twitter/X API Key": lambda k: (True, f"ℹ️ Twitter/X API Key format – pair with secret to test OAuth1", {}),
        "Pagerduty Token": validate_pagerduty_token,
        "Zendesk API Token": lambda k: validate_zendesk_token(k, extra),
        "NPM Token": validate_npm_token,
        "Square Access Token": validate_square_token,
        "Square App Secret": lambda k: (True, f"ℹ️ Square App Secret format valid – combine with App ID to test OAuth", {}),
        "Infura Project ID": validate_infura_key,
        "Contentful Token": lambda k: (True, f"ℹ️ Contentful Token format valid – provide Space ID via 'extra' to test", {}),
        "Datadog API Key": validate_datadog_key,
        "Facebook Access Token": validate_facebook_token,
        "Microsoft Teams Webhook": validate_teams_webhook,
        "Azure Client Secret": lambda k: (True, f"ℹ️ Azure Client Secret detected – provide tenant+client IDs to test", {}),
        "Shopify Token": lambda k: validate_shopify_token(k, extra),
        "Asana Access Token": validate_asana_token,
        "Cloudflare API Key": lambda k: (True, f"ℹ️ Potential Cloudflare key detected – provide email via 'extra' to test", {}),
        "Heroku API Key": lambda k: (True, f"ℹ️ Potential Heroku key detected – UUID format; needs context to confirm", {}),
    }
    
    if key_type in validators:
        return validators[key_type](key)
    else:
        return True, f"ℹ️ Key type '{key_type}' – no validation implemented", {}

# =============================================================================
# API KEY ENTRY CLASS
# =============================================================================

class ApiKeyEntry:
    """Represents a discovered API key with metadata"""
    
    def __init__(self, key: str, key_type: str, confidence: str,
                 source: str, context: str = "", line_num: int = 0,
                 endpoint: Optional[str] = None):
        self.key = key
        self.key_type = key_type
        self.confidence = confidence
        self.source = source  # URL or filename
        self.context = context[:200]  # Surrounding context
        self.line_num = line_num
        self.endpoint = endpoint  # Related API endpoint if found
        self.timestamp = datetime.now()
        self.validated = False
        self.validation_result = ""
        self.validation_error = ""
        self.valid = False
        self.validation_details = {}
        self.entropy = 0.0

# =============================================================================
# API ENDPOINT ENTRY CLASS
# =============================================================================

class ApiEndpointEntry:
    """Represents a discovered API endpoint"""
    
    def __init__(self, url: str, method: str = "GET", source: str = ""):
        self.url = url
        self.method = method
        self.source = source
        self.timestamp = datetime.now()
        self.parameters = []
        self.auth_type = ""

# =============================================================================
# WORKER THREAD FOR KEY DETECTION AND TESTING
# =============================================================================

class ApiKeyWorker(QThread):
    """Background worker for API key detection and testing"""
    
    progress = pyqtSignal(str)          # Progress message
    key_found = pyqtSignal(object)       # ApiKeyEntry found
    endpoint_found = pyqtSignal(object)  # ApiEndpointEntry found
    test_result = pyqtSignal(dict)       # Test result
    complete = pyqtSignal()               # Scan complete
    error = pyqtSignal(str)               # Error message
    
    def __init__(self):
        super().__init__()
        self.running = True
        self.urls = []  # For fetch mode
        self.text = ""   # For text mode
        self.source = ""  # Source name for text mode
        self.single_key = None  # For key mode
        self.single_type = None
        self.extra = None  # Extra info (e.g., domain for Mailgun)
        self.mode = "fetch"  # fetch, key, text
        self.max_workers = 5
        self.test_keys = True  # Whether to test found keys
        self.scan_for_endpoints = True
        self.custom_headers = {}
        # Persistent deduplication across all URLs in one scan run
        self._seen_keys: Set[Tuple[str, str]] = set()
        self._seen_lock = threading.Lock()
        
    def stop(self):
        self.running = False
        
    def run(self):
        if self.mode == "fetch":
            self._run_fetch_mode()
        elif self.mode == "key":
            self._run_key_mode()
        elif self.mode == "text":
            self._run_text_mode()
            
    def _run_fetch_mode(self):
        """Fetch and analyze URLs"""
        if not self.urls:
            self.error.emit("No URLs to fetch")
            return
            
        self.progress.emit(f"SECTION|Starting API key scan on {len(self.urls)} URL(s)")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._fetch_and_analyze, url): url for url in self.urls}
            
            for future in concurrent.futures.as_completed(futures):
                if not self.running:
                    executor.shutdown(wait=False)
                    break
                    
                url = futures[future]
                try:
                    result = future.result(timeout=30)
                    if result:
                        self.progress.emit(f"INFO|Completed: {url}")
                except Exception as e:
                    self.error.emit(f"Error with {url}: {str(e)}")
                    
        self.complete.emit()
        
    def _run_key_mode(self):
        """Test a single key"""
        if not self.single_key:
            self.error.emit("No key provided")
            return
            
        self.progress.emit(f"INFO|Testing key: {self.single_key[:30]}...")
        
        # Auto-detect type if not specified
        if not self.single_type or self.single_type == "Auto-detect":
            detected_type = self._detect_key_type(self.single_key)
            if detected_type:
                self.single_type = detected_type
                self.progress.emit(f"INFO|Auto-detected type: {detected_type}")
            else:
                self.single_type = "Generic Secret"
                
        # Create entry
        entry = ApiKeyEntry(
            key=self.single_key,
            key_type=self.single_type,
            confidence="MANUAL",
            source="Manual input",
            context=""
        )
        
        # Test the key
        result = self._test_key(entry)
        self.test_result.emit(result)
        
        self.complete.emit()
        
    def _run_text_mode(self):
        """Analyze text for API keys"""
        if not self.text:
            self.error.emit("No text provided")
            return
            
        source = self.source if self.source else "Manual input"
        self.progress.emit("INFO|Analyzing text for API keys...")
        
        # Detect keys in text
        keys = self._detect_keys_in_text(self.text, source)
        
        self.progress.emit(f"INFO|Found {len(keys)} potential API key(s)")
        
        # Detect endpoints in text
        if self.scan_for_endpoints:
            endpoints = self._detect_endpoints_in_text(self.text, source)
            for endpoint in endpoints:
                self.endpoint_found.emit(endpoint)
            self.progress.emit(f"INFO|Found {len(endpoints)} potential API endpoint(s)")
        
        # Emit found keys
        for key_entry in keys:
            self.key_found.emit(key_entry)
            
            # Test if enabled
            if self.test_keys:
                result = self._test_key(key_entry)
                self.test_result.emit(result)
                
        self.complete.emit()
        
    def _fetch_and_analyze(self, url: str) -> bool:
        """Fetch a URL and analyze its content"""
        try:
            self.progress.emit(f"INFO|Fetching: {url}")
            
            # Prepare request
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
            }
            headers.update(self.custom_headers)
            
            # Fetch the URL
            response = requests.get(
                url,
                headers=headers,
                timeout=15,
                verify=False,
                allow_redirects=True
            )
            
            self.progress.emit(f"INFO|HTTP {response.status_code} ({len(response.content)} bytes)")
            
            # Get content type
            content_type = response.headers.get('Content-Type', '').lower()
            
            # Only analyze text content
            if 'text/' in content_type or 'application/json' in content_type or 'javascript' in content_type:
                # Try to decode content
                try:
                    # Try UTF-8 first
                    content = response.content.decode('utf-8', errors='replace')
                except:
                    # Fallback to latin-1
                    content = response.content.decode('latin-1', errors='replace')
                
                # Analyze content
                self._analyze_content(content, url)
                
                # Also analyze response headers
                headers_str = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
                self._analyze_content(headers_str, f"{url} [Headers]")
                
            else:
                self.progress.emit(f"WARNING|Non-text content: {content_type}")
                
            return True
            
        except requests.exceptions.Timeout:
            self.error.emit(f"Timeout fetching {url}")
        except requests.exceptions.ConnectionError:
            self.error.emit(f"Connection error for {url}")
        except Exception as e:
            self.error.emit(f"Error fetching {url}: {str(e)}")
            
        return False
        
    def _analyze_content(self, content: str, source: str):
        """Analyze content for API keys and endpoints"""
        
        # Detect API keys
        keys = self._detect_keys_in_text(content, source)
        for key_entry in keys:
            self.key_found.emit(key_entry)
            
            # Test if enabled
            if self.test_keys:
                result = self._test_key(key_entry)
                self.test_result.emit(result)
        
        # Detect API endpoints
        if self.scan_for_endpoints:
            endpoints = self._detect_endpoints_in_text(content, source)
            for endpoint in endpoints:
                self.endpoint_found.emit(endpoint)
                
    def _detect_keys_in_text(self, text: str, source: str = "") -> List[ApiKeyEntry]:
        """Detect API keys in text using regex patterns (globally deduplicated per worker)."""
        found_keys = []
        lines = text.split('\n')

        for i, line in enumerate(lines, 1):
            if not self.running:
                break

            for key_type, info in API_KEY_PATTERNS.items():
                pattern = info["pattern"]
                matches = re.finditer(pattern, line, re.IGNORECASE)

                for match in matches:
                    key = match.group(0)
                    dedup_key = (key, key_type)
                    with self._seen_lock:
                        if dedup_key in self._seen_keys:
                            continue
                        self._seen_keys.add(dedup_key)

                    # Get context (surrounding text)
                    start = max(0, match.start() - 50)
                    end = min(len(line), match.end() + 50)
                    context = line[start:end]

                    entry = ApiKeyEntry(
                        key=key,
                        key_type=key_type,
                        confidence=info["confidence"],
                        source=source,
                        context=context,
                        line_num=i
                    )
                    entry.entropy = _shannon_entropy(key)
                    found_keys.append(entry)

        return found_keys
        
    def _detect_endpoints_in_text(self, text: str, source: str = "") -> List[ApiEndpointEntry]:
        """Detect API endpoints in text"""
        found_endpoints = []
        
        for pattern in API_ENDPOINT_PATTERNS:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            
            for match in matches:
                # Extract the URL/path (group 1 if available, else full match)
                if match.groups():
                    endpoint = match.group(1)
                else:
                    endpoint = match.group(0)
                    
                # Clean up
                endpoint = endpoint.strip('"\'')
                
                # Skip if too short
                if len(endpoint) < 5:
                    continue
                    
                # If it's a relative path, we can't fully resolve
                if endpoint.startswith('/'):
                    endpoint = f"[Relative path] {endpoint}"
                    
                entry = ApiEndpointEntry(
                    url=endpoint,
                    source=source,
                    method="GET"  # Default
                )
                found_endpoints.append(entry)
                
        return found_endpoints
        
    def _detect_key_type(self, key: str) -> Optional[str]:
        """Auto-detect key type based on patterns"""
        for key_type, info in API_KEY_PATTERNS.items():
            if re.match(info["pattern"], key, re.IGNORECASE):
                return key_type
        return None
        
    def _test_key(self, entry: ApiKeyEntry) -> Dict[str, Any]:
        """Test a discovered API key"""
        result = {
            'key': entry.key,
            'type': entry.key_type,
            'source': entry.source,
            'timestamp': datetime.now().isoformat(),
            'valid': False,
            'message': '',
            'details': {},
            'poc': []  # Add POC list
        }
        
        try:
            # Attempt validation
            self.progress.emit(f"INFO|Testing {entry.key_type}: {entry.key[:30]}...")
            
            # Pass extra info if available (e.g., domain for Mailgun)
            extra = getattr(self, 'extra', None)
            
            valid, message, details = validate_api_key(entry.key_type, entry.key, extra)
            
            result['valid'] = valid
            result['message'] = message
            result['details'] = details
            
            # Generate POC commands if valid
            if valid:
                poc_commands = self._generate_poc(entry.key_type, entry.key, details)
                result['poc'] = poc_commands
                
            if valid:
                self.progress.emit(f"SUCCESS|Valid {entry.key_type}: {message[:80]}")
                # Emit POC to logs
                for poc in result['poc']:
                    if poc.strip():
                        self.progress.emit(f"POC|{poc}")
            else:
                self.progress.emit(f"WARNING|Invalid {entry.key_type}: {message[:80]}")
                
        except Exception as e:
            result['message'] = f"Error during validation: {str(e)}"
            self.progress.emit(f"ERROR|Validation error: {str(e)}")
            
        return result

    def _generate_poc(self, key_type: str, key: str, details: dict) -> List[str]:
        """Generate POC commands for valid keys based on actually working endpoints"""
        poc_commands = []
        
        if "Google" in key_type:
            poc_commands.append(f"# Google API Key Analysis:")
            poc_commands.append(f"")
            
            if details.get("project_id"):
                poc_commands.append(f"📌 Project ID: {details['project_id']}")
                poc_commands.append(f"📌 GCP Console: https://console.cloud.google.com/project/{details['project_id']}")
                poc_commands.append(f"")
            
            # Only include endpoints that were fully working (not disabled)
            valid_endpoints = details.get('valid_endpoints', [])
            services = details.get('services_detected', [])
            
            if 'drive_api' in valid_endpoints:
                poc_commands.append(f"✅ Google Drive API (enabled and working):")
                poc_commands.append(f"curl 'https://www.googleapis.com/drive/v3/files?key={key}'")
                poc_commands.append(f"")
                
            if 'sheets_api' in valid_endpoints:
                poc_commands.append(f"✅ Google Sheets API (enabled and working):")
                poc_commands.append(f"curl 'https://sheets.googleapis.com/v4/spreadsheets?key={key}'")
                poc_commands.append(f"")
                
            if 'custom_search' in valid_endpoints:
                poc_commands.append(f"✅ Google Custom Search API (enabled and working):")
                poc_commands.append(f"curl 'https://customsearch.googleapis.com/customsearch/v1?q=test&cx=YOUR_SEARCH_ENGINE_ID&key={key}'")
                poc_commands.append(f"")
                
            # Show disabled APIs that can be enabled
            disabled_apis = []
            if 'drive_api_disabled' in details.get('failed_endpoints', []):
                disabled_apis.append("Google Drive API")
            if 'sheets_api_disabled' in details.get('failed_endpoints', []):
                disabled_apis.append("Google Sheets API")
            if 'custom_search_disabled' in details.get('failed_endpoints', []):
                disabled_apis.append("Custom Search API")
                
            if disabled_apis and details.get("project_id"):
                poc_commands.append(f"⚠️ Disabled APIs that can be enabled:")
                for api in disabled_apis:
                    poc_commands.append(f"   • {api}")
                poc_commands.append(f"")
                poc_commands.append(f"🔧 Enable APIs at:")
                poc_commands.append(f"   https://console.developers.google.com/apis?project={details['project_id']}")
                poc_commands.append(f"")
                
            if not poc_commands and details.get("project_id"):
                poc_commands.append(f"✅ Key is valid but no APIs are enabled.")
                poc_commands.append(f"Enable APIs at: https://console.developers.google.com/apis?project={details['project_id']}")
                
        elif "AWS" in key_type:
            if details.get("account_info", {}).get("account_id"):
                account_id = details["account_info"]["account_id"]
                poc_commands.append(f"# AWS CLI Commands (requires AWS CLI installed)")
                poc_commands.append(f"aws sts get-caller-identity --profile hacked-profile")
                
                valid_services = details.get('valid_services', [])
                
                if 's3' in valid_services:
                    poc_commands.append(f"aws s3 ls --profile hacked-profile")
                if 'ec2' in valid_services:
                    poc_commands.append(f"aws ec2 describe-instances --profile hacked-profile")
                if 'lambda' in valid_services:
                    poc_commands.append(f"aws lambda list-functions --profile hacked-profile")
                if 'iam' in valid_services:
                    poc_commands.append(f"aws iam list-users --profile hacked-profile")
                    
                poc_commands.append(f"")
                poc_commands.append(f"# Add to ~/.aws/credentials:")
                poc_commands.append(f"[hacked-profile]")
                poc_commands.append(f"aws_access_key_id = {key}")
                poc_commands.append(f"aws_secret_access_key = {details.get('secret', 'SECRET_KEY_HERE')}")
                
        elif "GitHub" in key_type:
            if details.get("user_info", {}).get("login"):
                username = details["user_info"]["login"]
                poc_commands.append(f"# GitHub API - Working Endpoints:")
                poc_commands.append(f"")
                poc_commands.append(f"curl -H 'Authorization: token {key}' https://api.github.com/user")
                
                if details.get("repositories"):
                    poc_commands.append(f"curl -H 'Authorization: token {key}' https://api.github.com/user/repos")
                    
                if details.get("organizations"):
                    poc_commands.append(f"curl -H 'Authorization: token {key}' https://api.github.com/user/orgs")
                    
                poc_commands.append(f"")
                poc_commands.append(f"# Git clone with token")
                poc_commands.append(f"git clone https://{username}:{key}@github.com/{username}/private-repo.git")
                
        elif "Slack" in key_type:
            poc_commands.append(f"# Slack API - Working Endpoints:")
            poc_commands.append(f"")
            poc_commands.append(f"curl -H 'Authorization: Bearer {key}' https://slack.com/api/auth.test")
            
            if details.get("channels"):
                poc_commands.append(f"curl -H 'Authorization: Bearer {key}' https://slack.com/api/conversations.list")
                
            if details.get("workspace_info"):
                poc_commands.append(f"curl -H 'Authorization: Bearer {key}' https://slack.com/api/team.info")
                
        elif "Stripe" in key_type:
            mode = details.get('mode', 'unknown')
            poc_commands.append(f"# Stripe {mode.upper()} Key - Working Endpoints:")
            poc_commands.append(f"")
            
            if details.get("account_info"):
                poc_commands.append(f"curl https://api.stripe.com/v1/account \\")
                poc_commands.append(f"  -u {key}:")
                
            if details.get("balance"):
                poc_commands.append(f"curl https://api.stripe.com/v1/balance \\")
                poc_commands.append(f"  -u {key}:")
                
            if details.get("products"):
                poc_commands.append(f"curl https://api.stripe.com/v1/products \\")
                poc_commands.append(f"  -u {key}: \\")
                poc_commands.append(f"  -d 'limit=3'")
                
        elif "Twilio" in key_type:
            if details.get("account_info", {}).get("name"):
                poc_commands.append(f"# Twilio API - Working Endpoints:")
                poc_commands.append(f"# SID: {key}")
                poc_commands.append(f"# Token: {details.get('token', 'TOKEN_HERE')}")
                poc_commands.append(f"")
                
                if details.get("phone_numbers"):
                    poc_commands.append(f"curl -X GET 'https://api.twilio.com/2010-04-01/Accounts/{key}/IncomingPhoneNumbers.json' \\")
                    poc_commands.append(f"  -u '{key}:{details.get('token', 'TOKEN_HERE')}'")
                    
                if details.get("usage"):
                    poc_commands.append(f"curl -X GET 'https://api.twilio.com/2010-04-01/Accounts/{key}/Usage/Records.json' \\")
                    poc_commands.append(f"  -u '{key}:{details.get('token', 'TOKEN_HERE')}'")
                    
        elif "SendGrid" in key_type:
            poc_commands.append(f"# SendGrid API - Working Endpoints:")
            poc_commands.append(f"")
            
            if details.get("scopes"):
                poc_commands.append(f"curl -X GET https://api.sendgrid.com/v3/scopes \\")
                poc_commands.append(f"  -H 'Authorization: Bearer {key}'")
                
            if details.get("user_info"):
                poc_commands.append(f"curl -X GET https://api.sendgrid.com/v3/user/profile \\")
                poc_commands.append(f"  -H 'Authorization: Bearer {key}'")
                
        elif "Mailgun" in key_type:
            if details.get("domains"):
                poc_commands.append(f"# Mailgun API - Working Endpoints:")
                poc_commands.append(f"")
                poc_commands.append(f"curl -s --user 'api:{key}' \\")
                poc_commands.append(f"  https://api.mailgun.net/v3/domains")
                
                if details.get("stats"):
                    domain = details["domains"][0]['name']
                    poc_commands.append(f"")
                    poc_commands.append(f"# Stats for {domain}")
                    poc_commands.append(f"curl -s --user 'api:{key}' \\")
                    poc_commands.append(f"  https://api.mailgun.net/v3/{domain}/stats/total \\")
                    poc_commands.append(f"  -d 'event=accepted&event=delivered&event=failed'")
                    
        elif "JWT" in key_type:
            poc_commands.append(f"# JWT Token Analysis - Decoded Content:")
            poc_commands.append(f"")
            
            if details.get("header"):
                poc_commands.append(f"Header: {json.dumps(details['header'], indent=2)}")
                
            if details.get("payload"):
                poc_commands.append(f"Payload: {json.dumps(details['payload'], indent=2)}")
                
            if details.get("expired"):
                poc_commands.append(f"⚠️ Token expired: {details.get('expired_seconds', 0):.0f} seconds ago")
                
            poc_commands.append(f"")
            poc_commands.append(f"# Decode with Python:")
            poc_commands.append(f"import jwt")
            poc_commands.append(f"decoded = jwt.decode('{key}', options={{'verify_signature': False}})")
            poc_commands.append(f"print(decoded)")
            
        else:
            # ── KeyHacks new services ──────────────────────────────────────
            if "Dropbox" in key_type and details.get("account_info"):
                poc_commands.append("# Dropbox – Working Endpoints:")
                poc_commands.append(f"curl -X POST https://api.dropboxapi.com/2/users/get_current_account \\")
                poc_commands.append(f"  --header 'Authorization: Bearer {key}'")
                poc_commands.append(f"curl -X POST https://api.dropboxapi.com/2/files/list_folder \\")
                poc_commands.append(f"  --header 'Authorization: Bearer {key}' \\")
                poc_commands.append(f"  --header 'Content-Type: application/json' \\")
                poc_commands.append(f"  --data '{{\"path\": \"\", \"recursive\": false}}'")
            elif "Telegram" in key_type and details.get("bot_info"):
                username = details["bot_info"].get("username", "unknown")
                poc_commands.append(f"# Telegram Bot – @{username}")
                poc_commands.append(f"curl https://api.telegram.org/bot{key}/getMe")
                poc_commands.append(f"curl https://api.telegram.org/bot{key}/getUpdates")
            elif "Twitter" in key_type or "X Bearer" in key_type:
                poc_commands.append("# Twitter/X – Bearer Token:")
                poc_commands.append(f"curl --request GET \\")
                poc_commands.append(f"  --url 'https://api.twitter.com/2/users/me' \\")
                poc_commands.append(f"  --header 'Authorization: Bearer {key}'")
            elif "Pagerduty" in key_type:
                poc_commands.append("# PagerDuty – List users:")
                poc_commands.append(f"curl -H 'Authorization: Token token={key}' \\")
                poc_commands.append(f"  -H 'Accept: application/vnd.pagerduty+json;version=2' \\")
                poc_commands.append(f"  https://api.pagerduty.com/users")
            elif "NPM" in key_type and details.get("username"):
                poc_commands.append("# NPM – Whoami:")
                poc_commands.append(f"curl -H 'Authorization: Bearer {key}' \\")
                poc_commands.append(f"  https://registry.npmjs.org/-/whoami")
            elif "Square" in key_type and details.get("locations"):
                poc_commands.append("# Square – List locations:")
                poc_commands.append(f"curl https://connect.squareup.com/v2/locations \\")
                poc_commands.append(f"  -H 'Authorization: Bearer {key}'")
            elif "Facebook" in key_type and details.get("user_id"):
                poc_commands.append("# Facebook Graph API:")
                poc_commands.append(f"curl 'https://graph.facebook.com/me?access_token={key}'")
            elif "Datadog" in key_type:
                poc_commands.append("# Datadog – Validate key:")
                poc_commands.append(f"curl -X GET 'https://api.datadoghq.com/api/v1/validate' \\")
                poc_commands.append(f"  -H 'DD-API-KEY: {key}'")
            elif "HubSpot" in key_type:
                poc_commands.append("# HubSpot – List owners:")
                poc_commands.append(f"curl 'https://api.hubapi.com/owners/v2/owners?hapikey={key}'")
                poc_commands.append("# HubSpot – List all contacts:")
                poc_commands.append(f"curl 'https://api.hubapi.com/contacts/v1/lists/all/contacts/all?hapikey={key}'")
            elif "Asana" in key_type and details.get("name"):
                poc_commands.append("# Asana – Current user:")
                poc_commands.append(f"curl -H 'Authorization: Bearer {key}' \\")
                poc_commands.append(f"  https://app.asana.com/api/1.0/users/me")
            elif "Infura" in key_type:
                poc_commands.append("# Infura – Ethereum call:")
                poc_commands.append(f"curl https://mainnet.infura.io/v3/{key} \\")
                poc_commands.append(f"  -X POST -H 'Content-Type: application/json' \\")
                poc_commands.append(f"  -d '{{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}}'")
            elif "Mailchimp" in key_type and details.get("account_name"):
                dc = details.get("datacenter", "us1")
                poc_commands.append(f"# Mailchimp – Account info (DC: {dc}):")
                poc_commands.append(f"curl -u 'anystring:{key}' \\")
                poc_commands.append(f"  https://{dc}.api.mailchimp.com/3.0/")
            elif "Teams Webhook" in key_type:
                poc_commands.append("# Microsoft Teams Webhook – Send message:")
                poc_commands.append(f"curl -X POST '{key}' \\")
                poc_commands.append(f"  -H 'Content-Type: application/json' \\")
                poc_commands.append(f"  -d '{{\"text\": \"Test from Hunt\"}}'")
            elif "Firebase FCM" in key_type:
                poc_commands.append("# Firebase FCM – Send test push:")
                poc_commands.append(f"curl -s -X POST \\")
                poc_commands.append(f"  --header 'Authorization: key={key}' \\")
                poc_commands.append(f"  --header 'Content-Type:application/json' \\")
                poc_commands.append(f"  'https://fcm.googleapis.com/fcm/send' \\")
                poc_commands.append(f"  -d '{{\"registration_ids\":[\"<DEVICE_TOKEN>\"]}}'")
            else:
                # Generic POC for unknown types
                poc_commands.append(f"# Generic API Key Test Commands:")
                poc_commands.append(f"")
                poc_commands.append(f"# Try as Bearer token:")
                poc_commands.append(f"curl -H 'Authorization: Bearer {key}' https://api.target.com/endpoint")
                poc_commands.append(f"")
                poc_commands.append(f"# Try as X-API-Key header:")
                poc_commands.append(f"curl -H 'X-API-Key: {key}' https://api.target.com/endpoint")
                poc_commands.append(f"")
                poc_commands.append(f"# Try as Basic Auth (base64 encoded):")
                poc_commands.append(f"echo -n 'user:{key}' | base64")
                poc_commands.append(f"curl -H 'Authorization: Basic BASE64_HERE' https://api.target.com/endpoint")
        
        return poc_commands

# =============================================================================
# FETCH SUBTAB
# =============================================================================

class FetchSubTab(QWidget):
    """Fetch URLs and analyze for API keys"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.queue = []  # URLs to fetch
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Toolbar
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)
        
        # Main splitter
        splitter = QSplitter(Qt.Vertical)
        
        # Queue widget
        queue_widget = self._create_queue_widget()
        splitter.addWidget(queue_widget)
        
        # Options widget
        options_widget = self._create_options_widget()
        splitter.addWidget(options_widget)
        
        splitter.setSizes([300, 200])
        layout.addWidget(splitter)
        
    def _create_toolbar(self) -> QWidget:
        toolbar = QWidget()
        toolbar.setFixedHeight(50)
        toolbar.setStyleSheet(f"background-color: {COLOR_ELEVATED_BG}; border-bottom: 1px solid {COLOR_BORDER};")
        
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(10, 5, 10, 5)
        
        # Title
        title = QLabel("🌐 API Key Scanner - Fetch Mode")
        title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        layout.addWidget(title)
        
        layout.addStretch()
        
        btn_style = (
            f"QPushButton {{"
            f"  background-color: {COLOR_ACCENT};"
            f"  color: {COLOR_TEXT_BRIGHT};"
            f"  border: none;"
            f"  padding: 8px 15px;"
            f"  border-radius: 4px;"
            f"  font-weight: bold;"
            f"}}"
            f"QPushButton:hover {{"
            f"  background-color: {COLOR_SUCCESS}   ;"
            f"}}"
            f"QPushButton:disabled {{"
            f"  background-color: {COLOR_BORDER};"
            f"  color: {COLOR_TEXT_MUTED};"
            f"}}"
        )

        # Add URL button
        add_btn = QPushButton("➕ Add URL")
        add_btn.clicked.connect(self.add_url_dialog)
        add_btn.setStyleSheet(btn_style)
        layout.addWidget(add_btn)
        
        # Start scan button
        self.start_btn = QPushButton("▶ Start Scan")
        self.start_btn.clicked.connect(self.start_scan)
        self.start_btn.setStyleSheet(btn_style)
        layout.addWidget(self.start_btn)
        
        # Stop button
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet(btn_style)
        layout.addWidget(self.stop_btn)
        
        # Clear button
        clear_btn = QPushButton("🗑️ Clear Queue")
        clear_btn.clicked.connect(self.clear_queue)
        clear_btn.setStyleSheet(btn_style)
        layout.addWidget(clear_btn)
        
        return toolbar
        
    def _create_queue_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Header
        header = QLabel("📋 URL Queue")
        header.setFont(QFont("Segoe UI", 10, QFont.Bold))
        layout.addWidget(header)
        
        # Queue table
        self.queue_table = QTableWidget()
        self.queue_table.setColumnCount(4)
        self.queue_table.setHorizontalHeaderLabels(["#", "URL", "Method", "Status"])
        self.queue_table.setColumnWidth(0, 50)
        self.queue_table.setColumnWidth(1, 400)
        self.queue_table.setColumnWidth(2, 80)
        self.queue_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        
        self.queue_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.queue_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.queue_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.queue_table.customContextMenuRequested.connect(self.show_queue_context_menu)
        
        layout.addWidget(self.queue_table)
        
        return widget
        
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Header
        header = QLabel("⚙️ Scan Options")
        header.setFont(QFont("Segoe UI", 10, QFont.Bold))
        layout.addWidget(header)
        
        # Options grid
        grid = QGridLayout()
        grid.setVerticalSpacing(10)
        
        row = 0
        
        # Max workers
        grid.addWidget(QLabel("Parallel workers:"), row, 0)
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 20)
        self.workers_spin.setValue(5)
        grid.addWidget(self.workers_spin, row, 1)
        row += 1
        
        # Test keys checkbox
        self.test_keys_cb = QCheckBox("Test found keys (validate against APIs)")
        self.test_keys_cb.setChecked(True)
        grid.addWidget(self.test_keys_cb, row, 0, 1, 2)
        row += 1
        
        # Scan for endpoints checkbox
        self.scan_endpoints_cb = QCheckBox("Scan for API endpoints")
        self.scan_endpoints_cb.setChecked(True)
        grid.addWidget(self.scan_endpoints_cb, row, 0, 1, 2)
        row += 1
        
        # Custom headers (simplified)
        grid.addWidget(QLabel("Custom headers (JSON):"), row, 0)
        self.headers_edit = QLineEdit()
        self.headers_edit.setPlaceholderText('{"Authorization": "Bearer token"}')
        grid.addWidget(self.headers_edit, row, 1)
        row += 1
        
        layout.addLayout(grid)
        layout.addStretch()
        
        return widget
        
    def add_url_dialog(self):
        """Show dialog to add URL(s)"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add URL")
        dialog.setMinimumWidth(500)
        
        layout = QVBoxLayout(dialog)
        
        layout.addWidget(QLabel("Enter URL(s) to scan (one per line):"))
        
        url_edit = QTextEdit()
        url_edit.setPlaceholderText("https://example.com/api\nhttps://example2.com/swagger.json")
        layout.addWidget(url_edit)
        
        # Method selection
        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel("Method:"))
        method_combo = QComboBox()
        method_combo.addItems(["GET", "POST", "PUT", "DELETE"])
        method_layout.addWidget(method_combo)
        method_layout.addStretch()
        layout.addLayout(method_layout)
        
        # Buttons
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.accepted.connect(dialog.accept)
        btn_box.rejected.connect(dialog.reject)
        layout.addWidget(btn_box)
        
        if dialog.exec_() == QDialog.Accepted:
            urls = url_edit.toPlainText().strip().split('\n')
            method = method_combo.currentText()
            
            for url in urls:
                url = url.strip()
                if url:
                    self.add_to_queue(url, method)
                    
    def add_to_queue(self, url: str, method: str = "GET"):
        """Add URL to queue"""
        self.queue.append({"url": url, "method": method})
        
        row = self.queue_table.rowCount()
        self.queue_table.insertRow(row)
        
        # Number
        num_item = QTableWidgetItem(f"#{row + 1}")
        self.queue_table.setItem(row, 0, num_item)
        
        # URL
        url_item = QTableWidgetItem(url)
        url_item.setToolTip(url)
        self.queue_table.setItem(row, 1, url_item)
        
        # Method
        method_item = QTableWidgetItem(method)
        self.queue_table.setItem(row, 2, method_item)
        
        # Status
        status_item = QTableWidgetItem("Queued")
        self.queue_table.setItem(row, 3, status_item)
        
    def add_from_history(self, url: str, method: str = "GET"):
        """Add URL from HTTP history (called from main window)"""
        self.add_to_queue(url, method)
        
    def start_scan(self):
        """Start scanning URLs"""
        if not self.queue:
            QMessageBox.warning(self, "Empty Queue", "No URLs in queue to scan")
            return
            
        # Clear previous results in parent
        if hasattr(self.parent, 'clear_results'):
            self.parent.clear_results()
            
        # Get URLs
        urls = [item["url"] for item in self.queue]
        
        # Parse custom headers
        headers = {}
        headers_text = self.headers_edit.text().strip()
        if headers_text:
            try:
                headers = json.loads(headers_text)
            except:
                QMessageBox.warning(self, "Invalid JSON", "Custom headers must be valid JSON")
                return
                
        # Create and start worker
        self.parent.worker = ApiKeyWorker()
        self.parent.worker.mode = "fetch"
        self.parent.worker.urls = urls
        self.parent.worker.max_workers = self.workers_spin.value()
        self.parent.worker.test_keys = self.test_keys_cb.isChecked()
        self.parent.worker.scan_for_endpoints = self.scan_endpoints_cb.isChecked()
        self.parent.worker.custom_headers = headers
        
        # Connect signals
        self.parent.worker.progress.connect(self.parent.append_log)
        self.parent.worker.key_found.connect(self.parent.add_key_finding)
        self.parent.worker.endpoint_found.connect(self.parent.add_endpoint_finding)
        self.parent.worker.test_result.connect(self.parent.add_test_result)
        self.parent.worker.complete.connect(self.parent.on_scan_complete)
        self.parent.worker.error.connect(self.parent.on_error)
        
        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        for row in range(self.queue_table.rowCount()):
            self.queue_table.setItem(row, 3, QTableWidgetItem("Scanning..."))
            
        self.parent.results_tab_widget.setCurrentIndex(0)  # Results tab
        
        # Start worker
        self.parent.worker.start()
        
    def stop_scan(self):
        """Stop current scan"""
        if self.parent.worker and self.parent.worker.isRunning():
            self.parent.worker.stop()
            self.parent.worker.wait()
            
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        for row in range(self.queue_table.rowCount()):
            self.queue_table.setItem(row, 3, QTableWidgetItem("Stopped"))
            
    def clear_queue(self):
        """Clear the queue"""
        self.queue.clear()
        self.queue_table.setRowCount(0)
        
    def show_queue_context_menu(self, position):
        """Show context menu for queue"""
        row = self.queue_table.rowAt(position.y())
        if row < 0 or row >= len(self.queue):
            return
            
        menu = QMenu()
        
        remove_action = menu.addAction("🗑️ Remove from Queue")
        
        action = menu.exec_(self.queue_table.viewport().mapToGlobal(position))
        
        if action == remove_action:
            self.queue_table.removeRow(row)
            if row < len(self.queue):
                del self.queue[row]
                
    def update_queue_status(self, row: int, status: str):
        """Update status for a queue item"""
        if row < self.queue_table.rowCount():
            self.queue_table.setItem(row, 3, QTableWidgetItem(status))


# =============================================================================
# KEY SUBTAB
# =============================================================================

class KeySubTab(QWidget):
    """Manually test a single API key"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)
        
        # Title
        title = QLabel("🔑 Manual API Key Testing")
        title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        layout.addWidget(title)
        
        # Key input
        key_group = QGroupBox("API Key")
        key_layout = QVBoxLayout(key_group)
        
        self.key_edit = QTextEdit()
        self.key_edit.setPlaceholderText("Enter API key to test...")
        self.key_edit.setMaximumHeight(100)
        key_layout.addWidget(self.key_edit)
        
        layout.addWidget(key_group)
        
        # Type selection
        type_group = QGroupBox("Key Type (leave blank for auto-detect)")
        type_layout = QVBoxLayout(type_group)
        
        type_selector_layout = QHBoxLayout()
        type_selector_layout.addWidget(QLabel("Type:"))
        
        self.type_combo = QComboBox()
        self.type_combo.addItem("Auto-detect")
        for key_type in sorted(API_KEY_PATTERNS.keys()):
            self.type_combo.addItem(key_type)
        type_selector_layout.addWidget(self.type_combo)
        type_selector_layout.addStretch()
        
        type_layout.addLayout(type_selector_layout)
        
        # Additional info for specific types
        self.extra_info = QLineEdit()
        self.extra_info.setPlaceholderText("Additional info (e.g., domain for Mailgun)")
        type_layout.addWidget(self.extra_info)
        
        layout.addWidget(type_group)
        
        # Options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout(options_group)
        
        self.include_context_cb = QCheckBox("Include in results table")
        self.include_context_cb.setChecked(True)
        options_layout.addWidget(self.include_context_cb)
        
        layout.addWidget(options_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.test_btn = QPushButton("▶ Test Key")
        self.test_btn.clicked.connect(self.test_key)
        self.test_btn.setMinimumWidth(150)
        button_layout.addWidget(self.test_btn)
        
        self.clear_btn = QPushButton("🗑️ Clear")
        self.clear_btn.clicked.connect(self.clear)
        button_layout.addWidget(self.clear_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        layout.addStretch()
        
    def test_key(self):
        """Test the entered key"""
        key = self.key_edit.toPlainText().strip()
        if not key:
            QMessageBox.warning(self, "No Key", "Please enter an API key to test")
            return
            
        key_type = self.type_combo.currentText()
        extra = self.extra_info.text().strip()
        
        # Clear previous results in parent
        if hasattr(self.parent, 'clear_results'):
            self.parent.clear_results()
            
        # Create and start worker
        self.parent.worker = ApiKeyWorker()
        self.parent.worker.mode = "key"
        self.parent.worker.single_key = key
        self.parent.worker.single_type = key_type
        self.parent.worker.extra = extra if extra else None
        
        # Connect signals
        self.parent.worker.progress.connect(self.parent.append_log)
        self.parent.worker.test_result.connect(self.parent.add_test_result)
        self.parent.worker.complete.connect(self.parent.on_scan_complete)
        self.parent.worker.error.connect(self.parent.on_error)
        
        # Update UI
        self.test_btn.setEnabled(False)
        self.parent.results_tab_widget.setCurrentIndex(0)  # Results tab
        self.parent.log_text.clear()
        self.parent.append_log(f"🔑 Testing key: {key[:30]}...")
        
        # Start worker
        self.parent.worker.start()
        
    def clear(self):
        """Clear input fields"""
        self.key_edit.clear()
        self.type_combo.setCurrentIndex(0)
        self.extra_info.clear()


# =============================================================================
# TEXT SUBTAB
# =============================================================================

class TextSubTab(QWidget):
    """Analyze raw text for API keys"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Title
        title = QLabel("📄 Text Analysis")
        title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        layout.addWidget(title)
        
        # Text input
        text_group = QGroupBox("Input Text")
        text_layout = QVBoxLayout(text_group)
        
        self.text_edit = QTextEdit()
        self.text_edit.setPlaceholderText("Paste raw text to analyze for API keys...")
        text_layout.addWidget(self.text_edit)
        
        layout.addWidget(text_group)
        
        # Options
        options_group = QGroupBox("Options")
        options_layout = QGridLayout(options_group)
        
        row = 0
        
        self.test_keys_cb = QCheckBox("Test found keys (validate against APIs)")
        self.test_keys_cb.setChecked(True)
        options_layout.addWidget(self.test_keys_cb, row, 0, 1, 2)
        row += 1
        
        self.scan_endpoints_cb = QCheckBox("Scan for API endpoints")
        self.scan_endpoints_cb.setChecked(True)
        options_layout.addWidget(self.scan_endpoints_cb, row, 0, 1, 2)
        row += 1
        
        # Source name (for context)
        options_layout.addWidget(QLabel("Source name:"), row, 0)
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("e.g., config.js, response.txt")
        options_layout.addWidget(self.source_edit, row, 1)
        row += 1
        
        layout.addWidget(options_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.analyze_btn = QPushButton("▶ Analyze Text")
        self.analyze_btn.clicked.connect(self.analyze_text)
        self.analyze_btn.setMinimumWidth(150)
        button_layout.addWidget(self.analyze_btn)
        
        self.clear_btn = QPushButton("🗑️ Clear")
        self.clear_btn.clicked.connect(self.clear)
        button_layout.addWidget(self.clear_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
    def analyze_text(self):
        """Analyze the entered text"""
        text = self.text_edit.toPlainText()
        if not text:
            QMessageBox.warning(self, "No Text", "Please enter text to analyze")
            return
            
        source = self.source_edit.text().strip()
        if not source:
            source = "Manual input"
            
        # Clear previous results in parent
        if hasattr(self.parent, 'clear_results'):
            self.parent.clear_results()
            
        # Create and start worker
        self.parent.worker = ApiKeyWorker()
        self.parent.worker.mode = "text"
        self.parent.worker.text = text
        self.parent.worker.source = source
        self.parent.worker.test_keys = self.test_keys_cb.isChecked()
        self.parent.worker.scan_for_endpoints = self.scan_endpoints_cb.isChecked()
        
        # Connect signals
        self.parent.worker.progress.connect(self.parent.append_log)
        self.parent.worker.key_found.connect(self.parent.add_key_finding)
        self.parent.worker.endpoint_found.connect(self.parent.add_endpoint_finding)
        self.parent.worker.test_result.connect(self.parent.add_test_result)
        self.parent.worker.complete.connect(self.parent.on_scan_complete)
        self.parent.worker.error.connect(self.parent.on_error)
        
        # Update UI
        self.analyze_btn.setEnabled(False)
        self.parent.results_tab_widget.setCurrentIndex(0)  # Results tab
        self.parent.log_text.clear()
        self.parent.append_log(f"Analyzing text...")
        
        # Start worker
        self.parent.worker.start()
        
    def clear(self):
        """Clear input fields"""
        self.text_edit.clear()
        self.source_edit.clear()


# =============================================================================
# MAIN API KEY TAB
# =============================================================================

class ApiKeyTab(QWidget):
    """Main API Key tab with three subtabs: Fetch, Key, Text"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.worker = None
        self.findings = []  # List of ApiKeyEntry objects
        self.endpoints = []  # List of ApiEndpointEntry objects
        self.test_results = []  # List of test result dicts
        
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Input subtabs (top)
        self.sub_tabs = QTabWidget()
        self.fetch_tab = FetchSubTab(self)
        self.sub_tabs.addTab(self.fetch_tab, "🌐 Fetch")
        self.key_tab = KeySubTab(self)
        self.sub_tabs.addTab(self.key_tab, "🔑 Key")
        self.text_tab = TextSubTab(self)
        self.sub_tabs.addTab(self.text_tab, "📄 Text")

        # Flat result tabs (bottom) — all 4 tabs at the same level
        self.results_tab_widget = QTabWidget()
        self.results_tab_widget.addTab(self._create_test_results_widget(), "📊 Test Results")
        self.results_tab_widget.addTab(self._create_keys_found_widget(),   "🔑 Keys Found")
        self.results_tab_widget.addTab(self._create_endpoints_widget(),    "🔗 Endpoints")
        self.results_tab_widget.addTab(self._create_logs_tab(),            "📋 Logs")

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.sub_tabs)
        splitter.addWidget(self.results_tab_widget)
        splitter.setSizes([280, 520])
        layout.addWidget(splitter)

        self.apply_styling()
        
    def _create_test_results_widget(self) -> QWidget:
        """Test Results tab: validated keys table + export buttons."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(2, 4, 2, 2)
        layout.setSpacing(4)

        # ── Export toolbar ──────────────────────────────────────────────────
        toolbar = QWidget()
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(0, 0, 0, 0)
        toolbar_layout.setSpacing(6)
        toolbar_layout.addStretch()
        export_csv_btn = QPushButton("⬇ Export CSV")
        export_csv_btn.setToolTip("Export all findings to CSV")
        export_csv_btn.clicked.connect(self._export_csv)
        toolbar_layout.addWidget(export_csv_btn)
        export_json_btn = QPushButton("⬇ Export JSON")
        export_json_btn.setToolTip("Export all findings to JSON")
        export_json_btn.clicked.connect(self._export_json)
        toolbar_layout.addWidget(export_json_btn)
        layout.addWidget(toolbar)

        self.test_table = QTableWidget()
        self.test_table.setColumnCount(5)
        self.test_table.setHorizontalHeaderLabels(["Key", "Type", "✓", "Message", "Time"])
        self.test_table.setColumnWidth(0, 200)
        self.test_table.setColumnWidth(1, 130)
        self.test_table.setColumnWidth(2, 30)
        self.test_table.setColumnWidth(3, 350)
        self.test_table.setColumnWidth(4, 75)
        self.test_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.test_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.test_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.test_table.setAlternatingRowColors(True)
        self.test_table.cellDoubleClicked.connect(self._show_test_detail_dialog)
        layout.addWidget(self.test_table)
        return widget

    def _create_keys_found_widget(self) -> QWidget:
        """Keys Found tab: filter bar + keys table."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(2, 4, 2, 2)
        layout.setSpacing(4)

        filter_bar = QWidget()
        filter_layout = QHBoxLayout(filter_bar)
        filter_layout.setContentsMargins(0, 0, 0, 0)
        filter_layout.setSpacing(6)

        filter_layout.addWidget(QLabel("🔍"))
        self._key_search = QLineEdit()
        self._key_search.setPlaceholderText("Filter by key / type…")
        self._key_search.setMaximumWidth(200)
        self._key_search.textChanged.connect(self._apply_key_filter)
        filter_layout.addWidget(self._key_search)

        filter_layout.addWidget(QLabel("  Show:"))
        self._conf_crit = QCheckBox("CRITICAL")
        self._conf_crit.setChecked(True)
        self._conf_crit.toggled.connect(self._apply_key_filter)
        filter_layout.addWidget(self._conf_crit)
        self._conf_high = QCheckBox("HIGH")
        self._conf_high.setChecked(True)
        self._conf_high.toggled.connect(self._apply_key_filter)
        filter_layout.addWidget(self._conf_high)
        self._conf_med = QCheckBox("MEDIUM")
        self._conf_med.setChecked(True)
        self._conf_med.toggled.connect(self._apply_key_filter)
        filter_layout.addWidget(self._conf_med)
        self._conf_low = QCheckBox("LOW")
        self._conf_low.setChecked(False)
        self._conf_low.toggled.connect(self._apply_key_filter)
        filter_layout.addWidget(self._conf_low)
        self._valid_only = QCheckBox("Valid only")
        self._valid_only.setChecked(False)
        self._valid_only.toggled.connect(self._apply_key_filter)
        filter_layout.addWidget(self._valid_only)
        filter_layout.addStretch()
        layout.addWidget(filter_bar)

        self.keys_table = QTableWidget()
        self.keys_table.setColumnCount(8)
        self.keys_table.setHorizontalHeaderLabels([
            "Type", "Key", "Conf.", "Entropy", "✓", "Validation", "Source", "Line"
        ])
        self.keys_table.setColumnWidth(0, 130)
        self.keys_table.setColumnWidth(1, 230)
        self.keys_table.setColumnWidth(2, 75)
        self.keys_table.setColumnWidth(3, 60)
        self.keys_table.setColumnWidth(4, 30)
        self.keys_table.setColumnWidth(5, 220)
        self.keys_table.setColumnWidth(6, 175)
        self.keys_table.setColumnWidth(7, 45)
        self.keys_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.keys_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.keys_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.keys_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.keys_table.customContextMenuRequested.connect(self.show_keys_context_menu)
        self.keys_table.cellDoubleClicked.connect(self._show_key_detail_dialog)
        self.keys_table.setAlternatingRowColors(True)
        self.keys_table.setSortingEnabled(True)
        layout.addWidget(self.keys_table)
        return widget

    def _create_endpoints_widget(self) -> QWidget:
        """Endpoints tab: search bar + endpoints table."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(2, 4, 2, 2)
        layout.setSpacing(4)

        ep_bar = QWidget()
        ep_bar_layout = QHBoxLayout(ep_bar)
        ep_bar_layout.setContentsMargins(0, 0, 0, 0)
        ep_bar_layout.addWidget(QLabel("🔍"))
        self._ep_search = QLineEdit()
        self._ep_search.setPlaceholderText("Filter endpoints…")
        self._ep_search.setMaximumWidth(200)
        self._ep_search.textChanged.connect(self._apply_ep_filter)
        ep_bar_layout.addWidget(self._ep_search)
        ep_bar_layout.addStretch()
        layout.addWidget(ep_bar)

        self.endpoints_table = QTableWidget()
        self.endpoints_table.setColumnCount(4)
        self.endpoints_table.setHorizontalHeaderLabels(["URL", "Method", "Source", "Found"])
        self.endpoints_table.setColumnWidth(0, 400)
        self.endpoints_table.setColumnWidth(1, 75)
        self.endpoints_table.setColumnWidth(2, 175)
        self.endpoints_table.setColumnWidth(3, 75)
        self.endpoints_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.endpoints_table.setAlternatingRowColors(True)
        self.endpoints_table.setSortingEnabled(True)
        layout.addWidget(self.endpoints_table)
        return widget
        
    def _create_logs_tab(self) -> QWidget:
        """Create logs tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Logs text
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        layout.addWidget(self.log_text)
        
        return widget
        
    # =========================================================================
    # Public API - called from HTTP History tab
    # =========================================================================
    
    def add_from_history(self, url: str, method: str = "GET", cookies: str = ""):
        """Add URL from HTTP history to Fetch tab queue"""
        self.fetch_tab.add_from_history(url, method)
        self.sub_tabs.setCurrentWidget(self.fetch_tab)
        self.append_log(f"➕ Added to queue: {url}")
        
    def send_url(self, url: str, cookies: str = ""):
        """Alias for add_from_history for backward compatibility"""
        self.add_from_history(url, "GET", cookies)
        
    # =========================================================================
    # Signal handlers
    # =========================================================================
    
    def append_log(self, message: str, level: str = "INFO"):
        """Append message to log with colored level indicator.
        
        Levels: INFO, SUCCESS, WARNING, ERROR, CRITICAL, SECTION, POC, FOUND
        When called from worker progress signals, message may carry a LEVEL| prefix.
        """
        # Parse embedded level prefix emitted by worker (e.g. "SUCCESS|message text")
        if "|" in message and message.split("|", 1)[0].upper() in (
            "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL", "SECTION", "POC", "FOUND"
        ):
            level, message = message.split("|", 1)
            level = level.upper()

        timestamp = datetime.now().strftime("%H:%M:%S")

        # Choose prefix and HTML color per level
        level_styles = {
            "INFO":     ("·",  "#a0a0a0"),
            "SUCCESS":  ("✅", "#4caf50"),
            "WARNING":  ("⚠️", "#ff9800"),
            "ERROR":    ("❌", "#f44336"),
            "CRITICAL": ("🔴", "#e53935"),
            "SECTION":  ("══", "#5c9bd4"),
            "POC":      ("📋", "#ce93d8"),
            "FOUND":    ("🔑", "#ffeb3b"),
        }

        icon, color = level_styles.get(level, ("·", "#a0a0a0"))
        html_line = (
            f'<span style="color:#666666">[{timestamp}]</span> '
            f'<span style="color:{color}">{icon} {message}</span>'
        )
        self.log_text.append(html_line)
        # Auto-scroll
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.log_text.setTextCursor(cursor)

    def log_section(self, title: str):
        """Print a clearly visible section separator."""
        bar = "─" * 55
        self.append_log(f"{bar}", "SECTION")
        self.append_log(f"  {title}", "SECTION")
        self.append_log(f"{bar}", "SECTION")
        
    def add_key_finding(self, entry: ApiKeyEntry):
        """Add a key finding to the results table."""
        self.findings.append(entry)
        self.keys_table.setSortingEnabled(False)  # prevent sort disruption mid-insert

        row = self.keys_table.rowCount()
        self.keys_table.insertRow(row)

        # Col 0 – Type
        self.keys_table.setItem(row, 0, QTableWidgetItem(entry.key_type))

        # Col 1 – Key (truncated for display, full key as tooltip)
        key_display = entry.key[:55] + "…" if len(entry.key) > 55 else entry.key
        key_item = QTableWidgetItem(key_display)
        key_item.setToolTip(entry.key)
        self.keys_table.setItem(row, 1, key_item)

        # Col 2 – Confidence
        conf_item = QTableWidgetItem(entry.confidence)
        color_map = {
            "CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
            "MEDIUM": COLOR_ACCENT, "LOW": COLOR_TEXT_MUTED, "MANUAL": COLOR_SUCCESS,
        }
        conf_item.setForeground(QBrush(QColor(color_map.get(entry.confidence, COLOR_TEXT))))
        self.keys_table.setItem(row, 2, conf_item)

        # Col 3 – Entropy (colour: ≥3.5 = likely random ✅, <2.5 = low ⚠)
        ent_item = QTableWidgetItem(f"{entry.entropy:.2f}")
        ent_item.setTextAlignment(Qt.AlignCenter)
        if entry.entropy >= 3.5:
            ent_item.setForeground(QBrush(QColor(COLOR_SUCCESS)))
        elif entry.entropy < 2.5:
            ent_item.setForeground(QBrush(QColor(COLOR_HIGH)))
        self.keys_table.setItem(row, 3, ent_item)

        # Col 4 – Valid (placeholder until tested)
        self.keys_table.setItem(row, 4, QTableWidgetItem(""))

        # Col 5 – Validation (placeholder)
        self.keys_table.setItem(row, 5, QTableWidgetItem("Pending…"))

        # Col 6 – Source
        src_display = entry.source[:55] + "…" if len(entry.source) > 55 else entry.source
        src_item = QTableWidgetItem(src_display)
        src_item.setToolTip(entry.source)
        self.keys_table.setItem(row, 6, src_item)

        # Col 7 – Line
        line_item = QTableWidgetItem(str(entry.line_num) if entry.line_num else "")
        line_item.setTextAlignment(Qt.AlignCenter)
        self.keys_table.setItem(row, 7, line_item)

        self.keys_table.setSortingEnabled(True)
        self._apply_key_filter()   # apply current filter (may hide this row)

        self.append_log(
            f"Found [{entry.confidence}] {entry.key_type}: {entry.key[:30]}…"
            f"  entropy={entry.entropy:.2f}  (line {entry.line_num})", "FOUND"
        )
        
    def add_endpoint_finding(self, entry: ApiEndpointEntry):
        """Add an endpoint finding to the endpoints table."""
        self.endpoints.append(entry)

        row = self.endpoints_table.rowCount()
        self.endpoints_table.insertRow(row)

        url_item = QTableWidgetItem(entry.url)
        url_item.setToolTip(entry.url)
        self.endpoints_table.setItem(row, 0, url_item)

        self.endpoints_table.setItem(row, 1, QTableWidgetItem(entry.method))

        src_display = entry.source[:55] + "…" if len(entry.source) > 55 else entry.source
        src_item = QTableWidgetItem(src_display)
        src_item.setToolTip(entry.source)
        self.endpoints_table.setItem(row, 2, src_item)

        self.endpoints_table.setItem(row, 3, QTableWidgetItem(entry.timestamp.strftime("%H:%M:%S")))

    def add_test_result(self, result: Dict[str, Any]):
        """Add a test result to the test results table with row colour-coding."""
        self.test_results.append(result)

        row = self.test_table.rowCount()
        self.test_table.insertRow(row)

        key_display = result['key'][:45] + "…" if len(result['key']) > 45 else result['key']
        key_item = QTableWidgetItem(key_display)
        key_item.setToolTip(result['key'])
        self.test_table.setItem(row, 0, key_item)

        self.test_table.setItem(row, 1, QTableWidgetItem(result['type']))

        valid_item = QTableWidgetItem("✅" if result['valid'] else "❌")
        valid_item.setForeground(QBrush(QColor(COLOR_SUCCESS if result['valid'] else COLOR_CRITICAL)))
        valid_item.setTextAlignment(Qt.AlignCenter)
        self.test_table.setItem(row, 2, valid_item)

        self.test_table.setItem(row, 3, QTableWidgetItem(result['message'][:200]))

        timestamp = result.get('timestamp', '')
        if timestamp and 'T' in timestamp:
            timestamp = timestamp.split('T')[1][:8]
        self.test_table.setItem(row, 4, QTableWidgetItem(timestamp))

        # Subtle row background tint
        bg = QColor(COLOR_SUCCESS if result['valid'] else COLOR_CRITICAL)
        bg.setAlpha(28)
        for col in range(self.test_table.columnCount()):
            item = self.test_table.item(row, col)
            if item:
                item.setBackground(QBrush(bg))

        self._update_key_validation(result)

        # Log POC commands when key is valid
        if result.get('valid') and result.get('poc'):
            self.append_log("")
            self.log_section(f"PROOF OF CONCEPT  –  {result.get('type', 'Unknown')}")
            for poc in result['poc']:
                if poc.strip():
                    self.append_log(poc, "POC")
            self.append_log("")

    def _update_key_validation(self, result: Dict[str, Any]):
        """Update validation status in keys table (cols 4 and 5)."""
        for row in range(self.keys_table.rowCount()):
            key_item = self.keys_table.item(row, 1)
            if key_item and key_item.toolTip() == result['key']:
                valid_item = QTableWidgetItem("✅" if result['valid'] else "❌")
                valid_item.setForeground(QBrush(QColor(COLOR_SUCCESS if result['valid'] else COLOR_CRITICAL)))
                valid_item.setTextAlignment(Qt.AlignCenter)
                self.keys_table.setItem(row, 4, valid_item)
                self.keys_table.setItem(row, 5, QTableWidgetItem(result['message'][:100]))
                # Re-apply filter in case "Valid only" is checked
                self._apply_key_filter()
                break
                
    def on_scan_complete(self):
        """Handle scan completion."""
        self.log_section("SCAN COMPLETE")

        # Re-enable buttons
        self.fetch_tab.start_btn.setEnabled(True)
        self.fetch_tab.stop_btn.setEnabled(False)
        self.key_tab.test_btn.setEnabled(True)
        self.text_tab.analyze_btn.setEnabled(True)

        # Update queue status
        for row in range(self.fetch_tab.queue_table.rowCount()):
            self.fetch_tab.queue_table.setItem(row, 3, QTableWidgetItem("Complete"))

        key_count = self.keys_table.rowCount()
        endpoint_count = self.endpoints_table.rowCount()
        test_count = self.test_table.rowCount()
        valid_count = sum(1 for r in self.test_results if r.get("valid"))
        self.append_log(
            f"Keys: {key_count}  |  Endpoints: {endpoint_count}  |  Tests: {test_count}  |  Valid: {valid_count}",
            "SUCCESS" if valid_count else "INFO"
        )

        # Switch to results tab
        self.results_tab_widget.setCurrentIndex(0)
        
    def on_error(self, error_msg: str):
        """Handle error"""
        self.append_log(f"Error: {error_msg}", "ERROR")
        
        # Re-enable buttons
        self.fetch_tab.start_btn.setEnabled(True)
        self.fetch_tab.stop_btn.setEnabled(False)
        self.key_tab.test_btn.setEnabled(True)
        self.text_tab.analyze_btn.setEnabled(True)
        
    def clear_results(self):
        """Clear all results tables and reset stats."""
        self.findings.clear()
        self.endpoints.clear()
        self.test_results.clear()

        self.keys_table.setRowCount(0)
        self.endpoints_table.setRowCount(0)
        self.test_table.setRowCount(0)

    def show_keys_context_menu(self, position):
        """Show context menu for keys table (right-click)."""
        row = self.keys_table.rowAt(position.y())
        if row < 0:
            return

        # Resolve the real ApiKeyEntry via the key tooltip (handles filtered/sorted rows)
        key_item = self.keys_table.item(row, 1)
        if not key_item:
            return
        entry_key = key_item.toolTip()
        entry = next((f for f in self.findings if f.key == entry_key), None)
        if not entry:
            return

        menu = QMenu()
        copy_key_action = menu.addAction("📋 Copy Key")
        copy_ctx_action = menu.addAction("📋 Copy Context")
        menu.addSeparator()
        detail_action = menu.addAction("🔍 View Details")
        retest_action = menu.addAction("🔄 Re-test Key")

        # Collect matching POC commands (properly tracked)
        poc_actions: List[Tuple[Any, str]] = []
        matching_result = next(
            (r for r in self.test_results if r['key'] == entry.key and r.get('valid') and r.get('poc')),
            None
        )
        if matching_result:
            menu.addSeparator()
            poc_menu = menu.addMenu("📋 Copy POC Command")
            poc_index = 0
            for poc in matching_result['poc']:
                if poc.strip() and not poc.startswith('#'):
                    poc_index += 1
                    label = poc[:80] + ("…" if len(poc) > 80 else "")
                    act = poc_menu.addAction(f"#{poc_index}  {label}")
                    poc_actions.append((act, poc))

        if entry.endpoint:
            menu.addSeparator()
            menu.addAction(f"🔗 {entry.endpoint[:80]}")

        action = menu.exec_(self.keys_table.viewport().mapToGlobal(position))
        if not action:
            return

        if action == copy_key_action:
            QApplication.clipboard().setText(entry.key)
            self.append_log("📋 Key copied to clipboard")
        elif action == copy_ctx_action:
            QApplication.clipboard().setText(entry.context)
            self.append_log("📋 Context copied to clipboard")
        elif action == detail_action:
            self._show_key_detail_dialog(row)
        elif action == retest_action:
            self._retest_key(entry)
        else:
            for act, poc in poc_actions:
                if action == act:
                    QApplication.clipboard().setText(poc)
                    self.append_log("📋 POC command copied to clipboard")
                    break
                    
    # =========================================================================
    # Helper methods: stats, filter, export, detail dialogs, re-test
    # =========================================================================

    def _apply_key_filter(self):
        """Filter the keys table by search text and confidence checkboxes."""
        text = self._key_search.text().lower()
        allowed = set()
        if self._conf_crit.isChecked():
            allowed.add("CRITICAL")
        if self._conf_high.isChecked():
            allowed.add("HIGH")
        if self._conf_med.isChecked():
            allowed.add("MEDIUM")
        if self._conf_low.isChecked():
            allowed.add("LOW")
        allowed.add("MANUAL")
        valid_only = self._valid_only.isChecked()
        for row in range(self.keys_table.rowCount()):
            conf_item = self.keys_table.item(row, 2)
            conf = conf_item.text() if conf_item else ""
            key_item = self.keys_table.item(row, 1)
            key_val = (key_item.toolTip() if key_item else "").lower()
            type_item = self.keys_table.item(row, 0)
            type_val = (type_item.text() if type_item else "").lower()
            valid_item = self.keys_table.item(row, 4)
            is_valid = valid_item and valid_item.text() == "✅"
            hide = (
                conf not in allowed
                or (text and text not in key_val and text not in type_val)
                or (valid_only and not is_valid)
            )
            self.keys_table.setRowHidden(row, hide)

    def _apply_ep_filter(self):
        """Filter the endpoints table by search text."""
        text = self._ep_search.text().lower()
        for row in range(self.endpoints_table.rowCount()):
            url_item = self.endpoints_table.item(row, 0)
            url = (url_item.text() if url_item else "").lower()
            self.endpoints_table.setRowHidden(row, bool(text) and text not in url)

    def _export_csv(self):
        """Export all key findings to a CSV file."""
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "api_keys.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Type", "Key", "Confidence", "Entropy", "Valid",
                    "Validation", "Source", "Line", "Context"
                ])
                for entry in self.findings:
                    result = next((r for r in self.test_results if r['key'] == entry.key), {})
                    writer.writerow([
                        entry.key_type, entry.key, entry.confidence,
                        f"{entry.entropy:.2f}",
                        "Yes" if result.get('valid') else ("No" if result else "—"),
                        result.get('message', ''),
                        entry.source, entry.line_num, entry.context.strip()
                    ])
            self.append_log(f"Exported {len(self.findings)} findings → {path}", "SUCCESS")
        except Exception as e:
            self.append_log(f"CSV export failed: {e}", "ERROR")

    def _export_json(self):
        """Export all key findings and test results to a JSON file."""
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "api_keys.json", "JSON Files (*.json)")
        if not path:
            return
        try:
            data = []
            for entry in self.findings:
                result = next((r for r in self.test_results if r['key'] == entry.key), {})
                data.append({
                    "type": entry.key_type,
                    "key": entry.key,
                    "confidence": entry.confidence,
                    "entropy": round(entry.entropy, 2),
                    "source": entry.source,
                    "line": entry.line_num,
                    "context": entry.context.strip(),
                    "valid": result.get('valid'),
                    "validation_message": result.get('message', ''),
                    "poc": result.get('poc', []),
                    "details": result.get('details', {}),
                    "timestamp": entry.timestamp.isoformat(),
                })
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            self.append_log(f"Exported {len(data)} findings → {path}", "SUCCESS")
        except Exception as e:
            self.append_log(f"JSON export failed: {e}", "ERROR")

    def _retest_key(self, entry: 'ApiKeyEntry'):
        """Re-validate a single key entry from the context menu."""
        self.append_log(f"🔄 Re-testing: {entry.key[:40]}…")
        worker = ApiKeyWorker()
        worker.mode = "key"
        worker.single_key = entry.key
        worker.single_type = entry.key_type
        worker.test_result.connect(self.add_test_result)
        worker.complete.connect(lambda: self.append_log("🔄 Re-test complete"))
        worker.error.connect(self.on_error)
        worker.start()

    def _show_key_detail_dialog(self, row: int, col: int = 0):
        """Show a detailed view of a key finding (triggered by double-click)."""
        key_item = self.keys_table.item(row, 1)
        if not key_item:
            return
        entry = next((f for f in self.findings if f.key == key_item.toolTip()), None)
        if not entry:
            return
        matching_result = next(
            (r for r in self.test_results if r['key'] == entry.key), None
        )

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Key Details – {entry.key_type}")
        dialog.setMinimumSize(700, 480)
        dlg_layout = QVBoxLayout(dialog)

        info = QTextEdit()
        info.setReadOnly(True)
        info.setFont(QFont("Consolas", 9))

        lines = [
            f"Type:       {entry.key_type}",
            f"Confidence: {entry.confidence}",
            f"Entropy:    {entry.entropy:.2f} bits",
            f"Source:     {entry.source}",
            f"Line:       {entry.line_num}",
            f"Detected:   {entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "Key Value:",
            f"  {entry.key}",
            "",
            "Context:",
            f"  {entry.context}",
        ]
        if matching_result:
            lines += [
                "",
                f"Validation: {'✅ VALID' if matching_result['valid'] else '❌ INVALID'}",
                f"Message:    {matching_result['message']}",
            ]
            if matching_result.get('poc'):
                lines += ["", "──── POC Commands ────"]
                lines += matching_result['poc']
            if matching_result.get('details'):
                lines += ["", "──── Details ────"]
                try:
                    lines.append(json.dumps(matching_result['details'], indent=2, default=str))
                except Exception:
                    lines.append(str(matching_result['details']))

        info.setPlainText("\n".join(lines))
        dlg_layout.addWidget(info)

        btn_row = QHBoxLayout()
        copy_key_btn = QPushButton("📋 Copy Key")
        copy_key_btn.clicked.connect(lambda: QApplication.clipboard().setText(entry.key))
        copy_all_btn = QPushButton("📋 Copy All")
        copy_all_btn.clicked.connect(lambda: QApplication.clipboard().setText(info.toPlainText()))
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        btn_row.addWidget(copy_key_btn)
        btn_row.addWidget(copy_all_btn)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        dlg_layout.addLayout(btn_row)
        dialog.exec_()

    def _show_test_detail_dialog(self, row: int, col: int = 0):
        """Show full details for a test result row (triggered by double-click)."""
        if row >= len(self.test_results):
            return
        result = self.test_results[row]

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Test Result – {result.get('type', '?')}")
        dialog.setMinimumSize(700, 480)
        dlg_layout = QVBoxLayout(dialog)

        info = QTextEdit()
        info.setReadOnly(True)
        info.setFont(QFont("Consolas", 9))

        lines = [
            f"Type:    {result.get('type', '')}",
            f"Valid:   {'✅ YES' if result.get('valid') else '❌ NO'}",
            f"Time:    {result.get('timestamp', '')}",
            "",
            "Key:",
            f"  {result.get('key', '')}",
            "",
            "Message:",
            f"  {result.get('message', '')}",
        ]
        if result.get('poc'):
            lines += ["", "──── POC Commands ────"]
            lines += result['poc']
        if result.get('details'):
            lines += ["", "──── Details ────"]
            try:
                lines.append(json.dumps(result['details'], indent=2, default=str))
            except Exception:
                lines.append(str(result['details']))

        info.setPlainText("\n".join(lines))
        dlg_layout.addWidget(info)

        btn_row = QHBoxLayout()
        copy_btn = QPushButton("📋 Copy All")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(info.toPlainText()))
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        btn_row.addWidget(copy_btn)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        dlg_layout.addLayout(btn_row)
        dialog.exec_()

    # =========================================================================
    # Styling
    # =========================================================================
    
    def apply_styling(self):
        """Apply dark theme styling"""
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT};
            }}
            QTableWidget {{
                background-color: {COLOR_ELEVATED_BG};
                border: 1px solid {COLOR_BORDER};
                gridline-color: {COLOR_BORDER};
            }}
            QTableWidget::item {{
                padding: 5px;
            }}
            QTableWidget::item:selected {{
                background-color: {COLOR_ACCENT};
            }}
            QHeaderView::section {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                padding: 5px;
                border: 1px solid {COLOR_BORDER};
                font-weight: bold;
            }}
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: {COLOR_TEXT_BRIGHT};
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLOR_SUCCESS};
            }}
            QPushButton:disabled {{
                background-color: {COLOR_BORDER};
                color: {COLOR_TEXT_MUTED};
            }}
            QTextEdit {{
                background-color: {COLOR_ELEVATED_BG};
                border: 1px solid {COLOR_BORDER};
                color: {COLOR_TEXT};
            }}
            QComboBox {{
                background-color: {COLOR_ELEVATED_BG};
                border: 1px solid {COLOR_BORDER};
                padding: 5px;
                color: {COLOR_TEXT};
            }}
            QLineEdit {{
                background-color: {COLOR_ELEVATED_BG};
                border: 1px solid {COLOR_BORDER};
                padding: 5px;
                color: {COLOR_TEXT};
            }}
            QTabWidget::pane {{
                border: 1px solid {COLOR_BORDER};
            }}
            QTabBar::tab {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT};
                padding: 8px 15px;
                border: 1px solid {COLOR_BORDER};
            }}
            QTabBar::tab:selected {{
                background-color: {COLOR_ACCENT};
                color: {COLOR_TEXT_BRIGHT};
            }}
            QGroupBox {{
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 10px;
                color: {COLOR_TEXT_BRIGHT};
                font-weight: bold;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }}
        """)


# =============================================================================
# Helper function to add the tab to the main window
# =============================================================================

def add_api_key_tab(parent) -> ApiKeyTab:
    """Add API Key tab to the main window"""
    api_key_tab = ApiKeyTab(parent)
    parent.tab_widget.addTab(api_key_tab, "Key Tester")
    parent.api_key_tab = api_key_tab
    
    # Store reference for HTTP History to use
    if hasattr(parent, 'http_history_tab'):
        parent.http_history_tab.api_key_tab_ref = api_key_tab
        
    return api_key_tab