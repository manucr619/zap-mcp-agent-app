import asyncio
import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import httpx
from zapv2 import ZAPv2
import chromadb
from loguru import logger

# Initialize FastAPI app
app = FastAPI(
    title="MODEROR MCP Security Scanner",
    description="MCP Server for AI Agent-driven API security scanning",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
ZAP_HOST = os.getenv("ZAP_HOST", "localhost")
ZAP_PORT = int(os.getenv("ZAP_PORT", 8080))
CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", 8000))

# Global clients
zap_client = None
chroma_client = None
vulnerability_collection = None

class ScanRequest(BaseModel):
    target_url: str
    scan_type: str = "api"
    scan_policy: str = "default"
    authentication: Optional[Dict[str, Any]] = None

class ScanResult(BaseModel):
    scan_id: str
    status: str
    target_url: str
    vulnerabilities_found: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[Dict[str, Any]] = []

class AIAnalysisRequest(BaseModel):
    vulnerability_data: Dict[str, Any]
    business_context: Optional[str] = None

# In-memory storage for MVP
active_scans: Dict[str, ScanResult] = {}

@app.on_event("startup")
async def startup_event():
    """Initialize connections on startup"""
    global zap_client, chroma_client, vulnerability_collection

    logger.info("Starting MCP Security Scanner Server...")

    # Initialize ZAP client
    try:
        zap_client = ZAPv2(proxies={
            'http': f'http://{ZAP_HOST}:{ZAP_PORT}',
            'https': f'http://{ZAP_HOST}:{ZAP_PORT}'
        })
        logger.info(f"Connected to ZAP at {ZAP_HOST}:{ZAP_PORT}")
    except Exception as e:
        logger.error(f"Failed to connect to ZAP: {e}")
        zap_client = None

    # Initialize ChromaDB client
    try:
        chroma_client = chromadb.HttpClient(
            host=CHROMA_HOST,
            port=CHROMA_PORT
        )

        # Create or get vulnerability collection
        vulnerability_collection = chroma_client.get_or_create_collection(
            name="vulnerability_knowledge",
            metadata={"description": "Security vulnerability knowledge base"}
        )
        logger.info(f"Connected to ChromaDB at {CHROMA_HOST}:{CHROMA_PORT}")
    except Exception as e:
        logger.error(f"Failed to connect to ChromaDB: {e}")
        chroma_client = None

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "zap": zap_client is not None,
            "chromadb": chroma_client is not None
        }
    }
    return status

@app.post("/api/v1/scan/start", response_model=Dict[str, Any])
async def start_security_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """Start a security scan using OWASP ZAP"""

    if not zap_client:
        raise HTTPException(status_code=503, detail="ZAP service not available")

    # Generate unique scan ID
    scan_id = str(uuid.uuid4())

    # Create scan result object
    scan_result = ScanResult(
        scan_id=scan_id,
        status="queued",
        target_url=scan_request.target_url,
        vulnerabilities_found=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        start_time=datetime.now()
    )

    # Store in active scans
    active_scans[scan_id] = scan_result

    # Start background scan
    background_tasks.add_task(execute_zap_scan, scan_id, scan_request)

    return {
        "scan_id": scan_id,
        "status": "queued",
        "message": "Security scan initiated",
        "target_url": scan_request.target_url
    }

@app.get("/api/v1/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get scan status and results"""

    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    return active_scans[scan_id].dict()

@app.get("/api/v1/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    """Get detailed scan report with AI analysis"""

    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_result = active_scans[scan_id]

    if scan_result.status != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed")

    # Generate AI-enhanced report
    ai_analysis = await generate_ai_analysis(scan_result.findings)

    return {
        "scan_summary": scan_result.dict(),
        "ai_analysis": ai_analysis,
        "owasp_compliance": analyze_owasp_compliance(scan_result.findings),
        "remediation_recommendations": generate_remediation_recommendations(scan_result.findings)
    }

@app.post("/api/v1/ai/analyze")
async def ai_vulnerability_analysis(request: AIAnalysisRequest):
    """Perform AI-powered vulnerability analysis"""

    if not vulnerability_collection:
        raise HTTPException(status_code=503, detail="Vector database not available")

    # Query similar vulnerabilities
    similar_vulns = await query_similar_vulnerabilities(
        request.vulnerability_data.get("description", "")
    )

    # Generate analysis (simplified for MVP)
    analysis = {
        "vulnerability_type": classify_vulnerability(request.vulnerability_data),
        "risk_score": calculate_risk_score(request.vulnerability_data),
        "exploitability": assess_exploitability(request.vulnerability_data),
        "similar_vulnerabilities": similar_vulns,
        "remediation_steps": generate_remediation_steps(request.vulnerability_data)
    }

    return analysis

async def execute_zap_scan(scan_id: str, scan_request: ScanRequest):
    """Execute ZAP security scan in background"""

    scan_result = active_scans[scan_id]
    scan_result.status = "running"

    try:
        logger.info(f"Starting ZAP scan for {scan_request.target_url}")

        # Start ZAP spider
        spider_id = zap_client.spider.scan(scan_request.target_url)

        # Wait for spider to complete
        while int(zap_client.spider.status(spider_id)) < 100:
            await asyncio.sleep(2)

        logger.info("Spider scan completed, starting active scan")

        # Start active scan
        active_scan_id = zap_client.ascan.scan(scan_request.target_url)

        # Wait for active scan to complete
        while int(zap_client.ascan.status(active_scan_id)) < 100:
            await asyncio.sleep(5)

        logger.info("Active scan completed, processing results")

        # Get scan results
        alerts = zap_client.core.alerts(baseurl=scan_request.target_url)

        # Process findings
        findings = []
        critical_count = high_count = medium_count = low_count = 0

        for alert in alerts:
            risk_level = alert.get('risk', 'Low')

            if risk_level == 'High':
                if 'SQL Injection' in alert.get('name', '') or 'Remote Code' in alert.get('name', ''):
                    risk_level = 'Critical'
                    critical_count += 1
                else:
                    high_count += 1
            elif risk_level == 'Medium':
                medium_count += 1
            else:
                low_count += 1

            finding = {
                "id": alert.get('pluginId'),
                "name": alert.get('name'),
                "risk": risk_level,
                "confidence": alert.get('confidence'),
                "description": alert.get('desc'),
                "solution": alert.get('solution'),
                "reference": alert.get('reference'),
                "url": alert.get('url'),
                "param": alert.get('param'),
                "evidence": alert.get('evidence')
            }
            findings.append(finding)

        # Update scan result
        scan_result.status = "completed"
        scan_result.end_time = datetime.now()
        scan_result.vulnerabilities_found = len(findings)
        scan_result.critical_count = critical_count
        scan_result.high_count = high_count
        scan_result.medium_count = medium_count
        scan_result.low_count = low_count
        scan_result.findings = findings

        # Store findings in vector database for AI analysis
        if vulnerability_collection and findings:
            await store_findings_in_vector_db(findings, scan_request.target_url)

        logger.info(f"Scan {scan_id} completed with {len(findings)} findings")

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        scan_result.status = "failed"
        scan_result.end_time = datetime.now()

async def store_findings_in_vector_db(findings: List[Dict], target_url: str):
    """Store vulnerability findings in ChromaDB for AI analysis"""

    try:
        documents = []
        metadatas = []
        ids = []

        for i, finding in enumerate(findings):
            doc_id = f"{target_url}_{finding.get('id', i)}_{datetime.now().timestamp()}"

            documents.append(f"{finding.get('name', '')} - {finding.get('description', '')}")
            metadatas.append({
                "url": target_url,
                "risk": finding.get('risk', 'Low'),
                "plugin_id": finding.get('id', ''),
                "confidence": finding.get('confidence', ''),
                "timestamp": datetime.now().isoformat()
            })
            ids.append(doc_id)

        vulnerability_collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )

        logger.info(f"Stored {len(findings)} findings in vector database")

    except Exception as e:
        logger.error(f"Failed to store findings in vector DB: {e}")

async def query_similar_vulnerabilities(description: str, n_results: int = 5):
    """Query similar vulnerabilities from vector database"""

    if not vulnerability_collection:
        return []

    try:
        results = vulnerability_collection.query(
            query_texts=[description],
            n_results=n_results
        )

        similar_vulns = []
        for i in range(len(results['ids'][0])):
            similar_vulns.append({
                "description": results['documents'][0][i],
                "metadata": results['metadatas'][0][i],
                "similarity_score": 1 - results['distances'][0][i]
            })

        return similar_vulns

    except Exception as e:
        logger.error(f"Failed to query similar vulnerabilities: {e}")
        return []

async def generate_ai_analysis(findings: List[Dict]) -> Dict[str, Any]:
    """Generate AI-powered analysis of scan findings"""

    # Simplified AI analysis for MVP
    total_findings = len(findings)
    risk_distribution = {
        "Critical": sum(1 for f in findings if f.get('risk') == 'Critical'),
        "High": sum(1 for f in findings if f.get('risk') == 'High'),
        "Medium": sum(1 for f in findings if f.get('risk') == 'Medium'),
        "Low": sum(1 for f in findings if f.get('risk') == 'Low')
    }

    # Calculate overall risk score
    risk_score = (
        risk_distribution["Critical"] * 10 +
        risk_distribution["High"] * 7 +
        risk_distribution["Medium"] * 4 +
        risk_distribution["Low"] * 1
    ) / max(total_findings, 1)

    return {
        "total_findings": total_findings,
        "risk_distribution": risk_distribution,
        "overall_risk_score": round(risk_score, 2),
        "risk_level": "Critical" if risk_score >= 8 else "High" if risk_score >= 5 else "Medium" if risk_score >= 3 else "Low",
        "top_vulnerabilities": sorted(findings, key=lambda x: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(x.get('risk', 'Low'), 0), reverse=True)[:5],
        "analysis_timestamp": datetime.now().isoformat()
    }

def classify_vulnerability(vuln_data: Dict[str, Any]) -> str:
    """Classify vulnerability type based on data"""
    name = vuln_data.get("name", "").lower()

    if "sql injection" in name:
        return "SQL Injection"
    elif "xss" in name or "cross-site scripting" in name:
        return "Cross-Site Scripting"
    elif "authentication" in name:
        return "Authentication Bypass"
    elif "authorization" in name:
        return "Authorization Issues"
    elif "injection" in name:
        return "Injection Attack"
    else:
        return "Security Misconfiguration"

def calculate_risk_score(vuln_data: Dict[str, Any]) -> float:
    """Calculate numerical risk score"""
    risk_mapping = {
        "Critical": 9.5,
        "High": 7.5,
        "Medium": 5.0,
        "Low": 2.5
    }
    return risk_mapping.get(vuln_data.get("risk", "Low"), 2.5)

def assess_exploitability(vuln_data: Dict[str, Any]) -> Dict[str, Any]:
    """Assess vulnerability exploitability"""
    confidence = vuln_data.get("confidence", "Medium")
    risk = vuln_data.get("risk", "Low")

    exploitability_score = 0.5
    if confidence == "High" and risk in ["Critical", "High"]:
        exploitability_score = 0.9
    elif confidence == "Medium" and risk == "High":
        exploitability_score = 0.7
    elif confidence == "Low" or risk == "Low":
        exploitability_score = 0.3

    return {
        "score": exploitability_score,
        "level": "High" if exploitability_score >= 0.8 else "Medium" if exploitability_score >= 0.5 else "Low",
        "factors": {
            "confidence": confidence,
            "risk_level": risk,
            "public_exploits": "Unknown"  # Would integrate with exploit databases
        }
    }

def generate_remediation_steps(vuln_data: Dict[str, Any]) -> List[str]:
    """Generate remediation steps for vulnerability"""
    vuln_type = classify_vulnerability(vuln_data)

    remediation_templates = {
        "SQL Injection": [
            "Use parameterized queries or prepared statements",
            "Implement input validation and sanitization",
            "Apply principle of least privilege to database accounts",
            "Enable SQL query logging and monitoring"
        ],
        "Cross-Site Scripting": [
            "Implement output encoding/escaping",
            "Use Content Security Policy (CSP) headers",
            "Validate and sanitize all user inputs",
            "Consider using HTTP-only cookies"
        ],
        "Authentication Bypass": [
            "Review authentication mechanisms",
            "Implement multi-factor authentication",
            "Use secure session management",
            "Regular security testing of auth flows"
        ],
        "Authorization Issues": [
            "Implement proper access controls",
            "Use role-based access control (RBAC)",
            "Validate permissions on every request",
            "Regular access reviews and audits"
        ]
    }

    return remediation_templates.get(vuln_type, [
        "Review security configuration",
        "Apply security patches",
        "Implement security monitoring",
        "Conduct regular security assessments"
    ])

def analyze_owasp_compliance(findings: List[Dict]) -> Dict[str, Any]:
    """Analyze OWASP API Top 10 compliance"""

    owasp_categories = {
        "API1_BOLA": 0,
        "API2_BROKEN_AUTH": 0,
        "API3_DATA_EXPOSURE": 0,
        "API4_RESOURCE_CONSUMPTION": 0,
        "API5_FUNCTION_AUTHORIZATION": 0,
        "API6_BUSINESS_FLOWS": 0,
        "API7_SSRF": 0,
        "API8_MISCONFIGURATION": 0,
        "API9_INVENTORY": 0,
        "API10_UNSAFE_CONSUMPTION": 0
    }

    for finding in findings:
        name = finding.get("name", "").lower()

        if "authorization" in name:
            owasp_categories["API1_BOLA"] += 1
        elif "authentication" in name:
            owasp_categories["API2_BROKEN_AUTH"] += 1
        elif "information disclosure" in name or "data exposure" in name:
            owasp_categories["API3_DATA_EXPOSURE"] += 1
        elif "configuration" in name:
            owasp_categories["API8_MISCONFIGURATION"] += 1

    total_issues = sum(owasp_categories.values())
    compliance_score = max(0, 100 - (total_issues * 10))

    return {
        "compliance_score": compliance_score,
        "owasp_breakdown": owasp_categories,
        "total_issues": total_issues,
        "compliance_level": "High" if compliance_score >= 80 else "Medium" if compliance_score >= 60 else "Low"
    }

def generate_remediation_recommendations(findings: List[Dict]) -> List[Dict[str, Any]]:
    """Generate prioritized remediation recommendations"""

    recommendations = []
    critical_highs = [f for f in findings if f.get('risk') in ['Critical', 'High']]

    for finding in critical_highs[:5]:  # Top 5 critical/high findings
        recommendations.append({
            "vulnerability": finding.get("name"),
            "priority": "High" if finding.get('risk') == 'Critical' else "Medium",
            "impact": f"Risk Level: {finding.get('risk')} - {finding.get('confidence')} Confidence",
            "remediation_steps": generate_remediation_steps(finding),
            "estimated_effort": "2-4 hours" if finding.get('risk') == 'High' else "4-8 hours",
            "url": finding.get("url")
        })

    return recommendations

if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=3000,
        reload=True,
        log_level="info"
    )
