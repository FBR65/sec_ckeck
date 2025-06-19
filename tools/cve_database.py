import httpx
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import urllib.parse

from config import config
from models.security_models import CVEInfo, SeverityLevel


class CVEDatabase:
    def __init__(self):
        self.api_url = config.cve_api_url
        self.nvd_api_key = config.nvd_api_key
        self.cve_org_base = "https://www.cve.org"
        self.client = httpx.AsyncClient(timeout=30.0)

    async def get_cve_info(self, cve_id: str) -> Dict[str, Any]:
        """Get detailed CVE information."""
        try:
            # Try CVE.org first
            cve_org_result = await self._get_cve_org_record(cve_id)
            if cve_org_result and "error" not in cve_org_result:
                return cve_org_result

            # Fallback to original API
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
        """Search CVEs by product/vendor using CVE.org search."""
        try:
            print(f"Searching CVE.org for product: {product}")  # Debug output

            # First try: CVE.org search
            search_query = product
            if version:
                search_query += f" {version}"

            results = await self._search_cve_org(search_query)
            if results:
                print(f"Found {len(results)} results from CVE.org")  # Debug output
                return results

            print("No results from CVE.org, trying NVD...")  # Debug output

            # Second try: NVD API if available
            if self.nvd_api_key:
                nvd_results = await self._search_nvd_by_product(product, version)
                if nvd_results:
                    return nvd_results

            print("Trying fallback API...")  # Debug output

            # Third try: Fallback to original API
            params = {"product": product}
            if version:
                params["version"] = version

            print(f"Fallback search with params: {params}")  # Debug output

            response = await self.client.get(f"{self.api_url}/search", params=params)
            print(
                f"Fallback search response status: {response.status_code}"
            )  # Debug output

            if response.status_code == 200:
                data = response.json()
                results = [self._parse_cve_data(cve) for cve in data.get("result", [])]
                return results

            return []

        except Exception as e:
            print(f"CVE search error: {e}")
            return []

    async def _search_cve_org(self, query: str) -> List[Dict[str, Any]]:
        """Search CVEs using CVE.org search."""
        try:
            print(f"Searching CVE.org with query: {query}")  # Debug output

            # Try MITRE CVE API first
            encoded_query = urllib.parse.quote_plus(query)

            # Try different CVE.org/MITRE API endpoints
            api_endpoints = [
                f"https://cveawg.mitre.org/api/cve-search?query={encoded_query}",
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_query}",
            ]

            for endpoint in api_endpoints:
                try:
                    print(f"Trying endpoint: {endpoint}")  # Debug output
                    response = await self.client.get(endpoint)
                    print(f"Response status: {response.status_code}")  # Debug output

                    if response.status_code == 200:
                        data = response.json()
                        print(
                            f"Response data type: {type(data)}, keys: {list(data.keys()) if isinstance(data, dict) else 'N/A'}"
                        )  # Debug output

                        # Handle different response formats
                        if isinstance(data, dict):
                            if "vulnerabilities" in data:  # NVD format
                                results = []
                                for vuln in data["vulnerabilities"][
                                    :10
                                ]:  # Limit results
                                    parsed = self._parse_nvd_data(vuln)
                                    if parsed and "error" not in parsed:
                                        results.append(parsed)
                                if results:
                                    return results
                            elif "cves" in data:  # CVE.org format
                                return [
                                    self._parse_cve_org_data(cve)
                                    for cve in data["cves"][:10]
                                ]
                            elif "result" in data:  # Generic result format
                                return [
                                    self._parse_cve_data(cve)
                                    for cve in data["result"][:10]
                                ]

                except Exception as e:
                    print(f"Error with endpoint {endpoint}: {e}")
                    continue

            # If API fails, try web scraping as last resort
            print("API search failed, trying web scraping...")  # Debug output
            return await self._scrape_cve_org_search(query)

        except Exception as e:
            print(f"CVE.org search error: {e}")
            return []

    async def _search_nvd_by_product(
        self, product: str, version: str = None
    ) -> List[Dict[str, Any]]:
        """Search NVD API by product."""
        try:
            nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            headers = {}

            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key

            # Build search query
            keyword = product
            if version:
                keyword += f" {version}"

            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 20,
            }

            print(f"Searching NVD with params: {params}")  # Debug output

            response = await self.client.get(nvd_url, params=params, headers=headers)
            print(f"NVD response status: {response.status_code}")  # Debug output

            if response.status_code == 200:
                data = response.json()
                if data.get("vulnerabilities"):
                    results = []
                    for vuln in data["vulnerabilities"]:
                        parsed = self._parse_nvd_data(vuln)
                        if parsed and "error" not in parsed:
                            results.append(parsed)
                    return results

            return []

        except Exception as e:
            print(f"NVD search error: {e}")
            return []

    async def _scrape_cve_org_search(self, query: str) -> List[Dict[str, Any]]:
        """Scrape CVE.org search results as fallback."""
        try:
            encoded_query = urllib.parse.quote_plus(query)
            search_url = (
                f"https://www.cve.org/CVERecord/SearchResults?query={encoded_query}"
            )

            print(f"Scraping search URL: {search_url}")  # Debug output

            response = await self.client.get(search_url)
            print(f"Scraping response status: {response.status_code}")  # Debug output

            if response.status_code == 200:
                return await self._parse_cve_org_search_results(response.text)

            return []

        except Exception as e:
            print(f"Web scraping error: {e}")
            return []

    async def search_by_keyword(self, keyword: str) -> List[Dict[str, Any]]:
        """Search CVEs by keyword in various fields."""
        try:
            print(f"Keyword search for: {keyword}")  # Debug output

            # Try CVE.org first
            results = await self._search_cve_org(keyword)
            if results:
                return results

            # Try NVD
            if self.nvd_api_key:
                nvd_results = await self._search_nvd_by_product(keyword)
                if nvd_results:
                    return nvd_results

            # Fallback to original API
            endpoints_to_try = [
                f"{self.api_url}/search",
                f"{self.api_url}/query",
                f"{self.api_url}/cve",
            ]

            for endpoint in endpoints_to_try:
                try:
                    params = {"q": keyword}
                    response = await self.client.get(endpoint, params=params)
                    print(
                        f"Keyword search at {endpoint}: {response.status_code}"
                    )  # Debug output

                    if response.status_code == 200:
                        data = response.json()
                        if isinstance(data, list):
                            return [self._parse_cve_data(cve) for cve in data[:10]]
                        elif isinstance(data, dict) and "result" in data:
                            return [
                                self._parse_cve_data(cve) for cve in data["result"][:10]
                            ]

                except Exception as e:
                    print(f"Error with endpoint {endpoint}: {e}")
                    continue

            return []
        except Exception as e:
            print(f"Keyword search error: {e}")
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

    async def _get_cve_org_record(self, cve_id: str) -> Dict[str, Any]:
        """Get CVE record from CVE.org."""
        try:
            # CVE.org API endpoint (they might have a JSON API)
            # First try their potential JSON API
            json_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

            response = await self.client.get(json_url)
            if response.status_code == 200:
                try:
                    data = response.json()
                    return self._parse_cve_org_data(data)
                except:
                    pass

            # If JSON API doesn't work, scrape the web page
            web_url = f"https://www.cve.org/CVERecord?id={cve_id}"
            response = await self.client.get(web_url)

            if response.status_code == 200:
                return await self._parse_cve_org_web_page(response.text, cve_id)

            return {"error": f"CVE {cve_id} not found on CVE.org"}

        except Exception as e:
            return {"error": f"Failed to fetch from CVE.org: {str(e)}"}

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

    def _parse_cve_org_data(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse CVE data from CVE.org JSON format."""
        try:
            cve_id = cve_data.get("cveMetadata", {}).get("cveId", "")

            # Extract description
            descriptions = (
                cve_data.get("containers", {}).get("cna", {}).get("descriptions", [])
            )
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CVSS metrics
            cvss_score = None
            severity = SeverityLevel.INFO

            metrics = cve_data.get("containers", {}).get("cna", {}).get("metrics", [])
            for metric in metrics:
                if "cvssV3_1" in metric:
                    cvss_score = metric["cvssV3_1"].get("baseScore")
                elif "cvssV2_0" in metric:
                    cvss_score = metric["cvssV2_0"].get("baseScore")

                if cvss_score:
                    severity = self._cvss_to_severity(cvss_score)
                    break

            # Extract affected products
            affected = cve_data.get("containers", {}).get("cna", {}).get("affected", [])
            affected_products = []
            for item in affected:
                vendor = item.get("vendor", "")
                product = item.get("product", "")
                if vendor and product:
                    affected_products.append(f"{vendor} {product}")

            return {
                "cve_id": cve_id,
                "description": description,
                "severity": severity,
                "cvss_score": cvss_score,
                "published_date": cve_data.get("cveMetadata", {}).get("datePublished"),
                "modified_date": cve_data.get("cveMetadata", {}).get("dateUpdated"),
                "affected_products": affected_products,
                "references": [
                    ref.get("url", "")
                    for ref in cve_data.get("containers", {})
                    .get("cna", {})
                    .get("references", [])
                ],
                "source": "CVE.org",
            }

        except Exception as e:
            return {"error": f"Failed to parse CVE.org data: {str(e)}"}

    async def _parse_cve_org_web_page(
        self, html_content: str, cve_id: str
    ) -> Dict[str, Any]:
        """Parse CVE information from CVE.org web page (basic scraping)."""
        try:
            # Basic HTML parsing - in production, use BeautifulSoup
            description = ""
            cvss_score = None

            # Look for description in HTML
            if "Description" in html_content:
                # Simple regex-like extraction (improve with proper HTML parser)
                import re

                desc_match = re.search(
                    r"Description.*?<[^>]*>(.*?)</[^>]*>",
                    html_content,
                    re.DOTALL | re.IGNORECASE,
                )
                if desc_match:
                    description = desc_match.group(1).strip()

            # Look for CVSS score
            cvss_match = re.search(r"CVSS.*?(\d+\.\d+)", html_content)
            if cvss_match:
                cvss_score = float(cvss_match.group(1))

            severity = (
                self._cvss_to_severity(cvss_score) if cvss_score else SeverityLevel.INFO
            )

            return {
                "cve_id": cve_id,
                "description": description,
                "severity": severity,
                "cvss_score": cvss_score,
                "source": "CVE.org (web scraping)",
                "web_url": f"https://www.cve.org/CVERecord?id={cve_id}",
            }

        except Exception as e:
            return {"error": f"Failed to parse CVE.org web page: {str(e)}"}

    async def _parse_cve_org_search_results(
        self, html_content: str
    ) -> List[Dict[str, Any]]:
        """Parse search results from CVE.org search page."""
        try:
            import re

            results = []

            # Look for CVE IDs in search results
            cve_pattern = r"CVE-\d{4}-\d{4,}"
            cve_matches = re.findall(cve_pattern, html_content)

            # For each found CVE, try to get basic info
            for cve_id in set(cve_matches):  # Remove duplicates
                # Try to get full info for each CVE
                cve_info = await self._get_cve_org_record(cve_id)
                if cve_info and "error" not in cve_info:
                    results.append(cve_info)
                else:
                    # Add basic info if detailed fetch fails
                    results.append(
                        {
                            "cve_id": cve_id,
                            "description": f"CVE found in search results for query",
                            "severity": SeverityLevel.INFO,
                            "source": "CVE.org search",
                        }
                    )

            return results[:20]  # Limit results

        except Exception as e:
            print(f"Error parsing search results: {e}")
            return []

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
