#!/usr/bin/env python3
# pylint: disable=W0718, C0301
"""
LLM integration for enhanced vulnerability assessment
"""

import json
from typing import Any

import requests

from models import HostFingerprint
from config import LLM_API_ENDPOINT, LLM_TEMPERATURE, LLM_MAX_TOKENS


def llm_assess_vulnerability(fingerprint: HostFingerprint, api_key: str, model: str = "gpt-4") -> dict[str, Any] | None:
    """Use LLM to assess Y2K38 vulnerability probability"""
    # Prepare context for LLM
    context = {
        "ip": fingerprint.ip,
        "architecture": fingerprint.architecture,
        "os_type": fingerprint.os_type,
        "approx_age": fingerprint.approx_age_year,
        "embedded": fingerprint.embedded_device,
        "services": [],
        "snmp_info": fingerprint.snmp_info,
        "smb_info": fingerprint.smb_info,
    }

    # Add service summaries
    for svc in fingerprint.tcp_services[:10]:  # Limit to avoid token overflow
        svc_summary = {
            "port": svc.get("port"),
            "protocol": svc.get("protocol"),
            "banner": svc.get("banner", "")[:200],  # Limit banner length
        }
        context["services"].append(svc_summary)

    for svc in fingerprint.udp_services[:5]:
        svc_summary = {
            "port": svc.get("port"),
            "protocol": svc.get("protocol"),
            "service": svc.get("service", "unknown"),
        }
        context["services"].append(svc_summary)

    prompt = f"""You are a cybersecurity expert analyzing systems for Year 2038 (Y2K38/Epochalypse) vulnerability.

The Year 2038 problem occurs when 32-bit systems reach the maximum value of a signed 32-bit integer (2,147,483,647) representing seconds since January 1, 1970. On January 19, 2038, at 03:14:07 UTC, this will overflow.

Analyze this system and provide:
1. Vulnerability probability (0-100%)
2. Confidence level (0-100%)
3. Key risk factors
4. Recommendations

System Information:
{json.dumps(context, indent=2)}

Respond in JSON format:
{{
  "probability": <0-100>,
  "confidence": <0-100>,
  "risk_factors": ["factor1", "factor2", ...],
  "recommendations": ["rec1", "rec2", ...],
  "reasoning": "brief explanation"
}}"""

    try:
        # Support both OpenAI and compatible APIs
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert specializing in legacy system vulnerabilities."},
                {"role": "user", "content": prompt}
            ],
            "temperature": LLM_TEMPERATURE,
            "max_tokens": LLM_MAX_TOKENS,
        }

        # Try OpenAI API
        response = requests.post(
            LLM_API_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            content = result["choices"][0]["message"]["content"]

            # Try to parse JSON from response
            try:
                # Extract JSON from markdown code blocks if present
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0]

                llm_result = json.loads(content.strip())
                return llm_result
            except json.JSONDecodeError:
                return {
                    "probability": None,
                    "confidence": None,
                    "error": "Failed to parse LLM response",
                    "raw_response": content[:500]
                }
        else:
            return {
                "error": f"API request failed: {response.status_code}",
                "message": response.text[:200]
            }

    except Exception as e:
        return {
            "error": f"LLM assessment failed: {str(e)}"
        }
