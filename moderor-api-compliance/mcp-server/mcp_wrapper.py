#!/usr/bin/env python3
"""
MCP Wrapper for Moderor API Compliance Server
This wrapper provides MCP protocol compatibility for Claude Desktop
"""

import asyncio
import json
import sys
import httpx
from typing import Dict, Any, List
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ModerorMCPWrapper:
    def __init__(self, base_url: str = "http://localhost:8081"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=30.0)

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP requests and proxy to HTTP API"""

        method = request.get("method", "")
        params = request.get("params", {})

        try:
            if method == "initialize":
                return await self.handle_initialize(request)
            elif method == "tools/list":
                return await self.handle_tools_list(request)
            elif method == "tools/call":
                return await self.handle_tools_call(request)
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {
                        "code": -32601,
                        "message": f"Method {method} not found"
                    }
                }
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {
                    "code": -32000,
                    "message": str(e)
                }
            }

    async def handle_initialize(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP initialization"""
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "Moderor API Security Scanner",
                    "version": "1.0.0"
                }
            }
        }

    async def handle_tools_list(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """List available tools"""
        tools = [
            {
                "name": "start_security_scan",
                "description": "Start a security scan on a target URL using OWASP ZAP",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_url": {
                            "type": "string",
                            "description": "The URL to scan for security vulnerabilities"
                        },
                        "scan_type": {
                            "type": "string",
                            "description": "Type of scan (api, web)",
                            "default": "api"
                        }
                    },
                    "required": ["target_url"]
                }
            },
            {
                "name": "get_scan_status",
                "description": "Get the status of a running or completed scan",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scan_id": {
                            "type": "string",
                            "description": "The scan ID to check"
                        }
                    },
                    "required": ["scan_id"]
                }
            },
            {
                "name": "get_scan_report",
                "description": "Get detailed scan report with AI analysis",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scan_id": {
                            "type": "string",
                            "description": "The scan ID to get report for"
                        }
                    },
                    "required": ["scan_id"]
                }
            }
        ]

        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "tools": tools
            }
        }

    async def handle_tools_call(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tool calls"""
        tool_name = request.get("params", {}).get("name")
        tool_args = request.get("params", {}).get("arguments", {})

        if tool_name == "start_security_scan":
            return await self.start_security_scan(request.get("id"), tool_args)
        elif tool_name == "get_scan_status":
            return await self.get_scan_status(request.get("id"), tool_args)
        elif tool_name == "get_scan_report":
            return await self.get_scan_report(request.get("id"), tool_args)
        else:
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {
                    "code": -32601,
                    "message": f"Tool {tool_name} not found"
                }
            }

    async def start_security_scan(self, request_id: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Start a security scan"""
        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/scan/start",
                json={
                    "target_url": args["target_url"],
                    "scan_type": args.get("scan_type", "api")
                }
            )
            response.raise_for_status()
            result = response.json()

            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Security scan started successfully!\n\nScan ID: {result['scan_id']}\nStatus: {result['status']}\nTarget: {result['target_url']}\n\nUse the scan ID to check status or get the final report."
                        }
                    ]
                }
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32000,
                    "message": f"Failed to start scan: {str(e)}"
                }
            }

    async def get_scan_status(self, request_id: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get scan status"""
        try:
            scan_id = args["scan_id"]
            response = await self.client.get(f"{self.base_url}/api/v1/scan/{scan_id}/status")
            response.raise_for_status()
            result = response.json()

            status_text = f"Scan Status: {result['status']}\n"
            status_text += f"Target: {result['target_url']}\n"
            status_text += f"Vulnerabilities Found: {result['vulnerabilities_found']}\n"
            status_text += f"Critical: {result['critical_count']}, High: {result['high_count']}, Medium: {result['medium_count']}, Low: {result['low_count']}\n"

            if result.get('start_time'):
                status_text += f"Started: {result['start_time']}\n"
            if result.get('end_time'):
                status_text += f"Completed: {result['end_time']}\n"

            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": status_text
                        }
                    ]
                }
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32000,
                    "message": f"Failed to get scan status: {str(e)}"
                }
            }

    async def get_scan_report(self, request_id: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get scan report"""
        try:
            scan_id = args["scan_id"]
            response = await self.client.get(f"{self.base_url}/api/v1/scan/{scan_id}/report")
            response.raise_for_status()
            result = response.json()

            report_text = "=== SECURITY SCAN REPORT ===\n\n"

            # Summary
            summary = result.get("scan_summary", {})
            report_text += f"Scan ID: {summary.get('scan_id')}\n"
            report_text += f"Target: {summary.get('target_url')}\n"
            report_text += f"Status: {summary.get('status')}\n"
            report_text += f"Vulnerabilities Found: {summary.get('vulnerabilities_found')}\n\n"

            # Risk distribution
            risk_dist = summary.get("findings", [])
            critical = sum(1 for f in risk_dist if f.get('risk') == 'Critical')
            high = sum(1 for f in risk_dist if f.get('risk') == 'High')
            medium = sum(1 for f in risk_dist if f.get('risk') == 'Medium')
            low = sum(1 for f in risk_dist if f.get('risk') == 'Low')

            report_text += f"Risk Distribution:\n"
            report_text += f"  Critical: {critical}\n"
            report_text += f"  High: {high}\n"
            report_text += f"  Medium: {medium}\n"
            report_text += f"  Low: {low}\n\n"

            # AI Analysis
            ai_analysis = result.get("ai_analysis", {})
            if ai_analysis:
                report_text += f"AI Analysis:\n"
                report_text += f"  Overall Risk Score: {ai_analysis.get('overall_risk_score', 'N/A')}\n"
                report_text += f"  Risk Level: {ai_analysis.get('risk_level', 'N/A')}\n\n"

            # Findings
            findings = summary.get("findings", [])
            if findings:
                report_text += "Top Findings:\n"
                for i, finding in enumerate(findings[:5]):  # Top 5
                    report_text += f"{i+1}. {finding.get('name')} ({finding.get('risk')})\n"
                    report_text += f"   {finding.get('description')[:100]}...\n\n"

            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": report_text
                        }
                    ]
                }
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32000,
                    "message": f"Failed to get scan report: {str(e)}"
                }
            }

async def main():
    """Main MCP server loop"""
    wrapper = ModerorMCPWrapper()

    try:
        for line in sys.stdin:
            try:
                request = json.loads(line.strip())
                logger.info(f"Received request: {request.get('method')}")

                response = await wrapper.handle_request(request)
                print(json.dumps(response))
                sys.stdout.flush()

            except json.JSONDecodeError:
                logger.error("Invalid JSON received")
                continue
    except KeyboardInterrupt:
        logger.info("Shutting down MCP wrapper")
    finally:
        await wrapper.client.aclose()

if __name__ == "__main__":
    asyncio.run(main())
