"""Claude reasoning engine via AWS Bedrock with tool use."""

from __future__ import annotations

import json
from typing import Any

import boto3

from src.models import Finding, Severity

# Model IDs — cross-region inference profile prefix (us.) is required for these models
HAIKU = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
SONNET = "us.anthropic.claude-sonnet-4-20250514-v1:0"

# CIS v8 control reference (subset for mapping)
CIS_CONTROLS: dict[str, str] = {
    "CIS-1.4": "Establish and Maintain a Secure Configuration Process",
    "CIS-3.3": "Configure Data Access Control Lists",
    "CIS-3.4": "Enforce Data Retention",
    "CIS-3.11": "Encrypt Sensitive Data at Rest",
    "CIS-4.1": "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
    "CIS-4.4": "Implement and Manage a Firewall on Servers",
    "CIS-4.6": "Securely Manage Enterprise Assets and Software",
    "CIS-5.2": "Use Unique Passwords",
    "CIS-5.4": "Restrict Administrator Privileges to Dedicated Administrator Accounts",
    "CIS-6.1": "Establish an Access Granting Process",
    "CIS-6.2": "Establish an Access Revoking Process",
    "CIS-6.3": "Require MFA for Externally-Exposed Applications",
    "CIS-6.4": "Require MFA for Remote Network Access",
    "CIS-6.5": "Require MFA for Administrative Access",
    "CIS-12.1": "Ensure Network Infrastructure is Up-to-Date",
}

# NIST 800-53 control reference (subset)
NIST_CONTROLS: dict[str, str] = {
    "NIST-AC-2": "Account Management",
    "NIST-AC-3": "Access Enforcement",
    "NIST-AC-6": "Least Privilege",
    "NIST-AC-17": "Remote Access",
    "NIST-IA-2": "Identification and Authentication",
    "NIST-IA-5": "Authenticator Management",
    "NIST-SC-7": "Boundary Protection",
    "NIST-SC-8": "Transmission Confidentiality and Integrity",
    "NIST-SC-12": "Cryptographic Key Establishment and Management",
    "NIST-SC-13": "Cryptographic Protection",
    "NIST-SC-28": "Protection of Information at Rest",
    "NIST-AU-2": "Event Logging",
    "NIST-AU-3": "Content of Audit Records",
    "NIST-CM-6": "Configuration Settings",
    "NIST-CM-7": "Least Functionality",
}

# SOC 2 criteria reference
SOC2_CRITERIA: dict[str, str] = {
    "SOC2-CC6.1": "Logical and Physical Access Controls",
    "SOC2-CC6.2": "Prior to Issuing System Credentials",
    "SOC2-CC6.3": "Based on Authorization, Access is Restricted",
    "SOC2-CC6.6": "System Boundaries Security Measures",
    "SOC2-CC6.7": "Data Transmission Security",
    "SOC2-CC6.8": "Unauthorized or Malicious Software Prevention",
    "SOC2-CC7.1": "Detection and Monitoring",
    "SOC2-CC7.2": "Monitoring Activities",
    "SOC2-CC8.1": "Change Management",
}

# Tool definitions in Converse API format (toolSpec wrapper)
TOOLS: list[dict[str, Any]] = [
    {
        "toolSpec": {
            "name": "map_to_controls",
            "description": (
                "Maps a security finding to relevant compliance framework controls. "
                "Returns matching controls from CIS v8, NIST 800-53, and SOC 2."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "finding_type": {
                            "type": "string",
                            "description": "The type of finding (e.g. overpermissive, unencrypted, public_access, no_mfa, open_port)",
                        },
                        "resource_type": {
                            "type": "string",
                            "description": "The AWS resource type (e.g. iam_policy, s3_bucket, security_group)",
                        },
                    },
                    "required": ["finding_type", "resource_type"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "score_risk",
            "description": (
                "Assigns a final risk score based on finding context, blast radius, "
                "and control mappings. Returns critical, high, medium, or low."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "finding_type": {"type": "string"},
                        "resource_type": {"type": "string"},
                        "is_internet_facing": {
                            "type": "boolean",
                            "description": "Whether the resource is exposed to the internet",
                        },
                        "num_controls_violated": {
                            "type": "integer",
                            "description": "Number of compliance controls violated",
                        },
                        "has_sensitive_data": {
                            "type": "boolean",
                            "description": "Whether the resource likely contains sensitive data",
                        },
                    },
                    "required": ["finding_type", "resource_type", "is_internet_facing", "num_controls_violated"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "recommend_remediation",
            "description": "Generates a specific, actionable remediation recommendation for the finding.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "finding_type": {"type": "string"},
                        "resource_type": {"type": "string"},
                        "resource_arn": {"type": "string"},
                        "risk_score": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    },
                    "required": ["finding_type", "resource_type", "resource_arn", "risk_score"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "log_assessment",
            "description": "Logs the final assessment with all reasoning, control mappings, risk score, and remediation.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "risk_score": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                        "control_mappings": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of control IDs violated (e.g. CIS-3.11, NIST-SC-28)",
                        },
                        "remediation": {"type": "string", "description": "Specific remediation steps"},
                        "reasoning": {"type": "string", "description": "Full reasoning chain explaining the assessment"},
                    },
                    "required": ["risk_score", "control_mappings", "remediation", "reasoning"],
                }
            },
        }
    },
]


def _execute_tool(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Execute a tool call and return the result as a string."""
    if tool_name == "map_to_controls":
        return _tool_map_to_controls(tool_input)
    elif tool_name == "score_risk":
        return _tool_score_risk(tool_input)
    elif tool_name == "recommend_remediation":
        return _tool_recommend_remediation(tool_input)
    elif tool_name == "log_assessment":
        return json.dumps({"status": "logged", **tool_input})
    else:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})


def _tool_map_to_controls(inputs: dict[str, Any]) -> str:
    """Map a finding to compliance controls."""
    finding_type = inputs.get("finding_type", "")

    control_map: dict[str, dict[str, list[str]]] = {
        "wildcard_action": {
            "cis": ["CIS-5.4", "CIS-6.1"],
            "nist": ["NIST-AC-6", "NIST-AC-3"],
            "soc2": ["SOC2-CC6.1", "SOC2-CC6.3"],
        },
        "overpermissive": {
            "cis": ["CIS-5.4", "CIS-6.1", "CIS-4.6"],
            "nist": ["NIST-AC-6", "NIST-AC-2", "NIST-CM-7"],
            "soc2": ["SOC2-CC6.1", "SOC2-CC6.3"],
        },
        "no_mfa": {
            "cis": ["CIS-6.3", "CIS-6.4", "CIS-6.5"],
            "nist": ["NIST-IA-2", "NIST-IA-5"],
            "soc2": ["SOC2-CC6.1", "SOC2-CC6.2"],
        },
        "unused_access_key": {
            "cis": ["CIS-5.2", "CIS-6.2"],
            "nist": ["NIST-AC-2", "NIST-IA-5"],
            "soc2": ["SOC2-CC6.2", "SOC2-CC6.3"],
        },
        "unencrypted": {
            "cis": ["CIS-3.11"],
            "nist": ["NIST-SC-28", "NIST-SC-13"],
            "soc2": ["SOC2-CC6.7"],
        },
        "public_access": {
            "cis": ["CIS-3.3", "CIS-4.4"],
            "nist": ["NIST-AC-3", "NIST-SC-7"],
            "soc2": ["SOC2-CC6.1", "SOC2-CC6.6"],
        },
        "no_versioning": {
            "cis": ["CIS-3.4"],
            "nist": ["NIST-CM-6"],
            "soc2": ["SOC2-CC8.1"],
        },
        "no_logging": {
            "cis": ["CIS-6.1"],
            "nist": ["NIST-AU-2", "NIST-AU-3"],
            "soc2": ["SOC2-CC7.1", "SOC2-CC7.2"],
        },
        "open_port": {
            "cis": ["CIS-4.1", "CIS-4.4", "CIS-12.1"],
            "nist": ["NIST-SC-7", "NIST-AC-17", "NIST-CM-7"],
            "soc2": ["SOC2-CC6.1", "SOC2-CC6.6"],
        },
    }

    mappings = control_map.get(finding_type, {"cis": [], "nist": [], "soc2": []})
    all_controls = mappings["cis"] + mappings["nist"] + mappings["soc2"]

    descriptions: dict[str, str] = {}
    for ctrl in all_controls:
        for ref in [CIS_CONTROLS, NIST_CONTROLS, SOC2_CRITERIA]:
            if ctrl in ref:
                descriptions[ctrl] = ref[ctrl]

    return json.dumps({
        "controls": all_controls,
        "details": descriptions,
        "total_violated": len(all_controls),
    })


def _tool_score_risk(inputs: dict[str, Any]) -> str:
    """Score risk based on context."""
    is_internet_facing = inputs.get("is_internet_facing", False)
    num_controls = inputs.get("num_controls_violated", 0)
    has_sensitive_data = inputs.get("has_sensitive_data", False)

    score = 0
    if is_internet_facing:
        score += 3
    if num_controls > 4:
        score += 3
    elif num_controls > 2:
        score += 2
    else:
        score += 1
    if has_sensitive_data:
        score += 2

    if score >= 7:
        level = "critical"
    elif score >= 5:
        level = "high"
    elif score >= 3:
        level = "medium"
    else:
        level = "low"

    return json.dumps({
        "risk_score": level,
        "score_breakdown": {
            "internet_facing": is_internet_facing,
            "controls_violated": num_controls,
            "sensitive_data": has_sensitive_data,
            "raw_score": score,
        },
    })


def _tool_recommend_remediation(inputs: dict[str, Any]) -> str:
    """Generate remediation recommendation."""
    finding_type = inputs.get("finding_type", "")
    resource_arn = inputs.get("resource_arn", "")

    recommendations: dict[str, str] = {
        "wildcard_action": f"Replace Action: * with specific actions needed. Review {resource_arn} and scope down to least privilege.",
        "overpermissive": f"Restrict the trust policy or permissions for {resource_arn}. Apply least privilege by limiting Principal and Action.",
        "no_mfa": "Enable MFA for the IAM user. Use virtual MFA (authenticator app) or hardware MFA device.",
        "unused_access_key": "Rotate or delete the stale access key. If actively used, rotate immediately. If unused, delete.",
        "unencrypted": f"Enable default server-side encryption (SSE-S3 or SSE-KMS) on {resource_arn}.",
        "public_access": f"Enable S3 Block Public Access on {resource_arn}. Set all four block settings to true.",
        "no_versioning": f"Enable versioning on {resource_arn} to protect against accidental deletion.",
        "no_logging": f"Enable server access logging on {resource_arn}. Configure a target bucket for log delivery.",
        "open_port": f"Restrict inbound rules on {resource_arn}. Replace 0.0.0.0/0 with specific IP ranges or security group references.",
    }

    remediation = recommendations.get(finding_type, f"Review and remediate {resource_arn} according to security best practices.")
    return json.dumps({"remediation": remediation, "auto_remediable": finding_type in ["unencrypted", "public_access", "open_port"]})


def assess_finding(
    finding: Finding,
    session: boto3.Session | None = None,
    model_id: str = HAIKU,
) -> Finding:
    """Send a finding to Claude for assessment via Bedrock Converse API."""
    client = (session or boto3.Session()).client(
        "bedrock-runtime", region_name="us-east-1"
    )

    system_prompt = (
        "You are a security compliance analyst. Your job is to assess infrastructure "
        "findings against CIS v8, NIST 800-53, and SOC 2 controls.\n\n"
        "For each finding, you must:\n"
        "1. Call map_to_controls to identify which compliance controls are violated\n"
        "2. Call score_risk to assign a risk score based on context\n"
        "3. Call recommend_remediation to get specific fix steps\n"
        "4. Call log_assessment with your complete reasoning, the control mappings, "
        "risk score, and remediation\n\n"
        "Always call all four tools in order. Be thorough in your reasoning."
    )

    user_message = (
        f"Assess this security finding:\n\n"
        f"Title: {finding.title}\n"
        f"Description: {finding.description}\n"
        f"Resource Type: {finding.resource_type.value}\n"
        f"Resource ARN: {finding.resource_arn}\n"
        f"Finding Type: {finding.finding_type.value}\n"
        f"Initial Severity: {finding.severity.value}\n"
    )

    messages: list[dict[str, Any]] = [{"role": "user", "content": [{"text": user_message}]}]

    # Tool use loop using Converse API
    max_iterations = 10
    for _ in range(max_iterations):
        response = client.converse(
            modelId=model_id,
            system=[{"text": system_prompt}],
            messages=messages,
            toolConfig={"tools": TOOLS},
            inferenceConfig={"maxTokens": 2048},
        )

        stop_reason = response["stopReason"]
        content_blocks = response["output"]["message"]["content"]

        messages.append({"role": "assistant", "content": content_blocks})

        if stop_reason == "end_turn":
            break

        if stop_reason == "tool_use":
            tool_results: list[dict[str, Any]] = []

            for block in content_blocks:
                if "toolUse" in block:
                    tool_name = block["toolUse"]["name"]
                    tool_input = block["toolUse"]["input"]
                    tool_result = _execute_tool(tool_name, tool_input)

                    tool_results.append({
                        "toolResult": {
                            "toolUseId": block["toolUse"]["toolUseId"],
                            "content": [{"text": tool_result}],
                        }
                    })

                    if tool_name == "log_assessment":
                        assessment = tool_input
                        finding.control_mappings = assessment.get("control_mappings", [])
                        finding.claude_reasoning = assessment.get("reasoning", "")
                        finding.remediation = assessment.get("remediation", "")

                        score_str = assessment.get("risk_score", finding.severity.value)
                        try:
                            finding.severity = Severity(score_str)
                        except ValueError:
                            pass

            messages.append({"role": "user", "content": tool_results})

    return finding


def assess_findings(
    findings: list[Finding],
    session: boto3.Session | None = None,
    model_id: str = HAIKU,
) -> list[Finding]:
    """Assess a list of findings using Claude."""
    assessed: list[Finding] = []
    for i, finding in enumerate(findings):
        print(f"  [{i + 1}/{len(findings)}] Assessing: {finding.title}...")
        try:
            enriched = assess_finding(finding, session=session, model_id=model_id)
            assessed.append(enriched)
        except Exception as e:
            print(f"    ERROR: {e}")
            assessed.append(finding)
    return assessed
