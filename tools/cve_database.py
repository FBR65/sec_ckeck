import httpx
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from ..config import config
from ..models.security_models import CVEInfo, SeverityLevel


class CVEDatabase:
    def __init__(self):
        self.api_url = config.cve_api_url
        self.nvd_api_key = config.nvd_api_key
        self.client = httpx.AsyncClient(timeout=30.0)

    async def get_cve_info(self, cve_id: str) -> Dict[str, Any]:
        """Get detailed CVE information."""
        try:
            # Try CVE.circl.lu first
            response = await self.client.get(f"{self.api_url}/cve/{cve_id}")
            if response.status_code == 200:
                data = response.json()
                return self._parse_cve_data(data)

            # Fallback to NVD if available
            if self.nvd_api_key:
                return await self._get_nvd_cve(cve_id)

            return {"error": f"CVE {cve_id} not found"}

        except Exception as e:
            return {"error": f"Failed to fetch CVE data: {str(e)}"}

    async def search_by_product(
        self, product: str, version: str = None
    ) -> List[Dict[str, Any]]:
        """Search CVEs by product/vendor."""
        try:
            params = {"product": product}
            if version:
                params["version"] = version

            response = await self.client.get(f"{self.api_url}/search", params=params)
            if response.status_code == 200:
                data = response.json()
                return [self._parse_cve_data(cve) for cve in data.get("result", [])]

            return []

        except Exception as e:
            print(f"CVE search error: {e}")
            return []

    async def get_recent_cves(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get recently published CVEs."""
        try:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)

            params = {
                "time_start": start_date.strftime("%Y-%m-%d"),
                "time_end": end_date.strftime("%Y-%m-%d"),
            }

            response = await self.client.get(f"{self.api_url}/last", params=params)
            if response.status_code == 200:
                data = response.json()
                return [self._parse_cve_data(cve) for cve in data]

            return []

        except Exception as e:
            print(f"Recent CVEs fetch error: {e}")
            return []

    async def _get_nvd_cve(self, cve_id: str) -> Dict[str, Any]:
        """Get CVE from NVD database."""
        nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {}

        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        params = {"cveId": cve_id}

        response = await self.client.get(nvd_url, params=params, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data.get("vulnerabilities"):
                return self._parse_nvd_data(data["vulnerabilities"][0])

        return {"error": f"CVE {cve_id} not found in NVD"}

    def _parse_cve_data(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse CVE data from circl.lu format."""
        try:
            cve_id = cve_data.get("id", "")

            # Extract CVSS score and severity
            cvss_score = None
            severity = SeverityLevel.INFO

            if "cvss" in cve_data:
                cvss_score = float(cve_data["cvss"])
                severity = self._cvss_to_severity(cvss_score)

            return {
                "cve_id": cve_id,
                "description": cve_data.get("summary", ""),
                "severity": severity,
                "cvss_score": cvss_score,
                "published_date": cve_data.get("Published"),
                "modified_date": cve_data.get("Modified"),
                "affected_products": cve_data.get("vulnerable_product", []),
                "references": cve_data.get("references", []),
                "cwe": cve_data.get("cwe", ""),
            }

        except Exception as e:
            return {"error": f"Failed to parse CVE data: {str(e)}"}

    def _parse_nvd_data(self, nvd_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse CVE data from NVD format."""
        try:
            cve = nvd_data.get("cve", {})
            cve_id = cve.get("id", "")

            # Extract description
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CVSS metrics
            cvss_score = None
            severity = SeverityLevel.INFO

            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                severity = self._cvss_to_severity(cvss_score)
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                severity = self._cvss_to_severity(cvss_score)

            return {
                "cve_id": cve_id,
                "description": description,
                "severity": severity,
                "cvss_score": cvss_score,
                "published_date": cve.get("published"),
                "modified_date": cve.get("lastModified"),
                "affected_products": [],  # Would need to parse configurations
                "references": [ref.get("url", "") for ref in cve.get("references", [])],
                "cwe": "",  # Would need to parse weaknesses
            }

        except Exception as e:
            return {"error": f"Failed to parse NVD data: {str(e)}"}

    def _cvss_to_severity(self, cvss_score: float) -> SeverityLevel:
        """Convert CVSS score to severity level."""
        if cvss_score >= 9.0:
            return SeverityLevel.CRITICAL
        elif cvss_score >= 7.0:
            return SeverityLevel.HIGH
        elif cvss_score >= 4.0:
            return SeverityLevel.MEDIUM
        elif cvss_score > 0.0:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO

    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
