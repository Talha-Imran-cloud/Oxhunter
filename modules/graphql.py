"""
GraphQL Security Testing Module
Tests for GraphQL introspection, injection, and misconfigurations
"""

import asyncio
import re
from urllib.parse import urlparse
from typing import List, Optional, Dict, Set
from dataclasses import dataclass

import httpx

from core.rate_limiter import RateLimiter
from utils.logger import setup_logger


@dataclass
class GraphQLFinding:
    """Represents a GraphQL security finding"""
    url: str
    type: str        # 'introspection', 'injection', 'dos', 'auth_bypass', 'info_disclosure', 'batch_attack'
    severity: str
    confidence: str
    query_used: str
    response_preview: str
    evidence: str
    remediation: str


class GraphQLScanner:
    """
    GraphQL Security Testing Module
    Tests for:
    - Introspection enabled (schema disclosure)
    - SQL/NoSQL injection via GraphQL arguments
    - Batch query attacks (DoS)
    - Field suggestion exploitation
    - Authentication bypass
    - Deeply nested query DoS
    - Alias-based query flooding
    - CSRF via GraphQL
    - Information disclosure via errors
    """

    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        self.logger = setup_logger("GraphQL")
        self.findings: List[GraphQLFinding] = []
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = httpx.Timeout(20.0, connect=10.0)
        self.graphql_endpoints: Set[str] = set()

        # Common GraphQL endpoint paths
        self.common_endpoints = [
            "/graphql", "/graphql/", "/api/graphql", "/api/graphql/",
            "/v1/graphql", "/v2/graphql", "/query", "/gql",
            "/graphiql", "/playground", "/api/query",
            "/graphql/console", "/graph", "/api/graph",
        ]

    # ── Queries ───────────────────────────────────────────────────────────────

    def _introspection_query(self) -> Dict:
        return {
            "query": """
            {
              __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                  name
                  kind
                  fields {
                    name
                    type { name kind }
                    args { name type { name kind } }
                  }
                }
              }
            }
            """
        }

    def _type_introspection(self) -> Dict:
        return {
            "query": "{ __typename }"
        }

    def _field_suggestion_query(self) -> Dict:
        """Trigger field suggestions to confirm GraphQL"""
        return {
            "query": "{ __typenameXXXX }"
        }

    def _batch_query(self, count: int = 50) -> List[Dict]:
        """Batch attack — send many queries at once"""
        return [{"query": "{ __typename }"} for _ in range(count)]

    def _deep_nested_query(self, depth: int = 10) -> Dict:
        """Deep nested query for DoS testing"""
        query = "{ user { " + "friends { " * depth + "name" + " }" * depth + " } }"
        return {"query": query}

    def _alias_flood_query(self, count: int = 100) -> Dict:
        """Alias-based query flooding"""
        aliases = "\n".join([f"q{i}: __typename" for i in range(count)])
        return {"query": "{ " + aliases + " }"}

    def _sqli_payloads(self) -> List[tuple]:
        """SQL injection payloads for GraphQL arguments"""
        return [
            ('{ user(id: "1 OR 1=1") { id name email } }',          "sqli_or"),
            ('{ user(id: "1; DROP TABLE users--") { id name } }',    "sqli_drop"),
            ('{ user(id: "1\' OR \'1\'=\'1") { id name } }',         "sqli_quote"),
            ('{ users(filter: "1=1") { id name email } }',           "sqli_filter"),
            ('{ user(id: "1 UNION SELECT 1,2,3--") { id } }',        "sqli_union"),
        ]

    def _nosqli_payloads(self) -> List[tuple]:
        """NoSQL injection payloads"""
        return [
            ('{ user(id: {"$gt": ""}) { id name email } }',          "nosqli_gt"),
            ('{ user(username: {"$regex": ".*"}) { id name } }',     "nosqli_regex"),
            ('{ user(id: {"$ne": null}) { id name email } }',        "nosqli_ne"),
            ('{ login(username: {"$gt": ""} password: "x") { token } }', "nosqli_login"),
        ]

    # ── HTTP Helpers ──────────────────────────────────────────────────────────

    async def _post_graphql(self, url: str, payload,
                             extra_headers: Optional[Dict] = None) -> Optional[httpx.Response]:
        """Send GraphQL POST request"""
        try:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            }
            if extra_headers:
                headers.update(extra_headers)

            async def _do_request():
                return await self.client.post(
                    url,
                    json=payload,
                    headers=headers,
                    follow_redirects=True
                )
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.debug(f"GraphQL request failed {url}: {e}")
            return None

    async def _get_graphql(self, url: str, query: str) -> Optional[httpx.Response]:
        """Send GraphQL GET request"""
        try:
            async def _do_request():
                return await self.client.get(
                    url,
                    params={"query": query},
                    follow_redirects=True
                )
            return await self.rate_limiter.execute_with_retry(_do_request)
        except Exception as e:
            self.logger.debug(f"GraphQL GET failed {url}: {e}")
            return None

    def _is_graphql_response(self, response: httpx.Response) -> bool:
        """Check if response looks like GraphQL"""
        if not response:
            return False
        ct = response.headers.get('content-type', '')
        if 'json' not in ct:
            return False
        try:
            data = response.json()
            return 'data' in data or 'errors' in data
        except Exception:
            return False

    def _has_error(self, response: httpx.Response) -> Optional[str]:
        """Extract error message from GraphQL response"""
        try:
            data = response.json()
            errors = data.get('errors', [])
            if errors:
                return errors[0].get('message', '')[:200]
        except Exception:
            pass
        return None

    # ── Test Methods ──────────────────────────────────────────────────────────

    async def find_graphql_endpoints(self, base_url: str) -> Set[str]:
        """Discover GraphQL endpoints on a target"""
        found = set()
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        tasks = []
        for path in self.common_endpoints:
            url = base + path
            tasks.append(self._check_endpoint(url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for url, is_gql in zip([base + p for p in self.common_endpoints], results):
            if is_gql is True:
                found.add(url)
                self.logger.info(f"GraphQL endpoint found: {url}")

        return found

    async def _check_endpoint(self, url: str) -> bool:
        """Check if URL is a GraphQL endpoint"""
        response = await self._post_graphql(url, self._type_introspection())
        if response and self._is_graphql_response(response):
            return True
        response = await self._get_graphql(url, "{ __typename }")
        return bool(response and self._is_graphql_response(response))

    async def test_introspection(self, url: str) -> Optional[GraphQLFinding]:
        """Test if introspection is enabled"""
        response = await self._post_graphql(url, self._introspection_query())
        if not response:
            return None

        try:
            data = response.json()
            schema = data.get('data', {}).get('__schema', {})
            if schema:
                types = schema.get('types', [])
                type_names = [t['name'] for t in types if not t['name'].startswith('__')]
                preview = f"Exposed types: {', '.join(type_names[:10])}"
                if len(type_names) > 10:
                    preview += f" ... (+{len(type_names)-10} more)"

                return GraphQLFinding(
                    url=url,
                    type="introspection",
                    severity="high",
                    confidence="high",
                    query_used="__schema introspection",
                    response_preview=preview,
                    evidence=(
                        "GraphQL introspection is ENABLED. Full schema exposed with "
                        f"{len(type_names)} types, including queries, mutations, and field names."
                    ),
                    remediation=(
                        "1. Disable introspection in production.\n"
                        "2. Apollo Server: introspection: false in ApolloServer config.\n"
                        "3. GraphQL Yoga: disableIntrospection plugin.\n"
                        "4. Use query depth limiting and query complexity analysis.\n"
                        "5. Allow introspection only for authenticated/admin users."
                    )
                )
        except Exception:
            pass
        return None

    async def test_batch_attack(self, url: str) -> Optional[GraphQLFinding]:
        """Test for batch query attack (DoS/rate limit bypass)"""
        batch = self._batch_query(count=50)
        response = await self._post_graphql(url, batch)
        if not response:
            return None

        if response.status_code == 200:
            try:
                data = response.json()
                if isinstance(data, list) and len(data) > 1:
                    return GraphQLFinding(
                        url=url,
                        type="batch_attack",
                        severity="medium",
                        confidence="high",
                        query_used=f"Batch of {len(batch)} queries",
                        response_preview=f"Server returned {len(data)} responses",
                        evidence=(
                            f"GraphQL batch queries accepted — sent {len(batch)} queries, "
                            f"received {len(data)} responses. "
                            "Attacker can bypass rate limits and cause DoS."
                        ),
                        remediation=(
                            "1. Disable or limit batch queries.\n"
                            "2. Implement query rate limiting per user/IP.\n"
                            "3. Set maximum batch size (e.g., max 5 operations).\n"
                            "4. Use query cost analysis to prevent expensive batches."
                        )
                    )
            except Exception:
                pass
        return None

    async def test_deep_nested_dos(self, url: str) -> Optional[GraphQLFinding]:
        """Test for deeply nested query DoS"""
        query = self._deep_nested_query(depth=15)
        import time
        start = time.monotonic()
        response = await self._post_graphql(url, query)
        elapsed = time.monotonic() - start

        if response and elapsed > 5:
            return GraphQLFinding(
                url=url,
                type="dos",
                severity="medium",
                confidence="medium",
                query_used="Deep nested query (15 levels)",
                response_preview=f"Response time: {elapsed:.1f}s",
                evidence=(
                    f"Deeply nested GraphQL query took {elapsed:.1f}s. "
                    "No query depth limit detected — server vulnerable to DoS via deep nesting."
                ),
                remediation=(
                    "1. Implement query depth limiting (max depth: 5-10).\n"
                    "2. Use graphql-depth-limit package (Node.js).\n"
                    "3. Implement query complexity analysis.\n"
                    "4. Set execution timeout for GraphQL queries."
                )
            )
        return None

    async def test_alias_flood(self, url: str) -> Optional[GraphQLFinding]:
        """Test alias-based query flooding"""
        query = self._alias_flood_query(count=100)
        import time
        start = time.monotonic()
        response = await self._post_graphql(url, query)
        elapsed = time.monotonic() - start

        if response and response.status_code == 200 and elapsed > 3:
            return GraphQLFinding(
                url=url,
                type="dos",
                severity="medium",
                confidence="medium",
                query_used="100-alias flood query",
                response_preview=f"Response time: {elapsed:.1f}s",
                evidence=(
                    f"Alias flood with 100 aliases took {elapsed:.1f}s. "
                    "No alias limit detected — server may be vulnerable to alias-based DoS."
                ),
                remediation=(
                    "1. Limit the number of aliases per query.\n"
                    "2. Implement query complexity scoring.\n"
                    "3. Use graphql-cost-analysis to restrict expensive queries."
                )
            )
        return None

    async def test_injection(self, url: str) -> List[GraphQLFinding]:
        """Test for SQL/NoSQL injection via GraphQL"""
        findings = []
        error_indicators = [
            r"sql", r"syntax error", r"mysql", r"postgresql", r"sqlite",
            r"ORA-", r"Warning.*mysql", r"unclosed quotation",
            r"MongoError", r"BSONTypeError", r"CastError",
        ]

        all_payloads = self._sqli_payloads() + self._nosqli_payloads()

        for query_str, technique in all_payloads:
            response = await self._post_graphql(url, {"query": query_str})
            if not response:
                continue

            error = self._has_error(response)
            if error:
                for indicator in error_indicators:
                    if re.search(indicator, error, re.IGNORECASE):
                        inj_type = "sqli" if "nosql" not in technique else "nosqli"
                        findings.append(GraphQLFinding(
                            url=url,
                            type="injection",
                            severity="critical",
                            confidence="high",
                            query_used=query_str[:100],
                            response_preview=error[:200],
                            evidence=(
                                f"{'SQL' if inj_type == 'sqli' else 'NoSQL'} injection indicator "
                                f"in GraphQL error: '{error[:100]}' | Technique: {technique}"
                            ),
                            remediation=(
                                "1. Use parameterized queries/prepared statements.\n"
                                "2. Validate and sanitize all GraphQL input arguments.\n"
                                "3. Use an ORM with safe query building.\n"
                                "4. Implement input type validation in GraphQL schema.\n"
                                "5. Never interpolate user input into raw queries."
                            )
                        ))
                        break

        return findings

    async def test_info_disclosure(self, url: str) -> Optional[GraphQLFinding]:
        """Test for information disclosure via GraphQL errors"""
        # Send intentionally broken query
        bad_query = {"query": "{ INVALID_FIELD_THAT_DOES_NOT_EXIST_12345 }"}
        response = await self._post_graphql(url, bad_query)
        if not response:
            return None

        error = self._has_error(response)
        if not error:
            return None

        # Check for field suggestions (info disclosure)
        if re.search(r'Did you mean|suggestions?|similar fields?', error, re.IGNORECASE):
            return GraphQLFinding(
                url=url,
                type="info_disclosure",
                severity="medium",
                confidence="high",
                query_used='{ INVALID_FIELD_THAT_DOES_NOT_EXIST_12345 }',
                response_preview=error[:200],
                evidence=(
                    "GraphQL field suggestions enabled — error reveals valid field names: "
                    f"'{error[:150]}'"
                ),
                remediation=(
                    "1. Disable field suggestions in production.\n"
                    "2. Apollo Server: fieldSuggestions: false.\n"
                    "3. Return generic error messages without revealing schema details."
                )
            )

        # Check for stack traces or internal details
        sensitive_patterns = [
            r"at\s+\w+\s+\(.*\.js:\d+",      # JS stack trace
            r"at\s+\w+\.java:\d+",             # Java stack trace
            r"Traceback\s+\(most recent",       # Python traceback
            r"Exception in thread",             # Java exception
            r"/home/|/var/www/|/app/",          # File paths
        ]
        for pattern in sensitive_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return GraphQLFinding(
                    url=url,
                    type="info_disclosure",
                    severity="high",
                    confidence="high",
                    query_used='{ INVALID_FIELD }',
                    response_preview=response.text[:200],
                    evidence="GraphQL errors expose stack traces or internal file paths",
                    remediation=(
                        "1. Disable detailed error messages in production.\n"
                        "2. Use a custom error formatter to sanitize errors.\n"
                        "3. Log detailed errors server-side only, return generic messages to client."
                    )
                )

        return None

    async def test_csrf(self, url: str) -> Optional[GraphQLFinding]:
        """Test if GraphQL accepts GET requests for mutations (CSRF risk)"""
        mutation = "mutation { __typename }"
        response = await self._get_graphql(url, mutation)
        if not response:
            return None

        if response.status_code == 200 and self._is_graphql_response(response):
            return GraphQLFinding(
                url=url,
                type="csrf",
                severity="medium",
                confidence="medium",
                query_used=f"GET /graphql?query={mutation}",
                response_preview=response.text[:200],
                evidence=(
                    "GraphQL accepts mutations via GET requests — CSRF attack possible. "
                    "Attacker can craft malicious links that trigger mutations."
                ),
                remediation=(
                    "1. Only allow POST requests for GraphQL mutations.\n"
                    "2. Implement CSRF tokens for GraphQL endpoints.\n"
                    "3. Validate Content-Type header (must be application/json).\n"
                    "4. Use SameSite=Strict cookies."
                )
            )
        return None

    async def scan(self, target_urls: List[str], forms: List = None) -> List[GraphQLFinding]:  # BUG-003 FIX
        """Main GraphQL security scan"""
        forms = forms or []  # BUG-003 FIX: avoid mutable default argument
        self.logger.info(f"Starting GraphQL scan on {len(target_urls)} URLs")

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, */*',
        }

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            self.client = client

            # Step 1: Find GraphQL endpoints
            seen_bases = set()
            for url in target_urls:
                parsed = urlparse(url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                if base not in seen_bases:
                    seen_bases.add(base)
                    endpoints = await self.find_graphql_endpoints(url)
                    self.graphql_endpoints.update(endpoints)

                # Check if URL itself is GraphQL
                if any(kw in url.lower() for kw in ['graphql', 'graphiql', 'gql', '/query']):
                    is_gql = await self._check_endpoint(url)
                    if is_gql:
                        self.graphql_endpoints.add(url)

            if not self.graphql_endpoints:
                self.logger.info("No GraphQL endpoints found")
                return []

            self.logger.info(f"Testing {len(self.graphql_endpoints)} GraphQL endpoint(s)")

            # Step 2: Run all tests on each endpoint
            for endpoint in self.graphql_endpoints:
                tasks = [
                    self.test_introspection(endpoint),
                    self.test_batch_attack(endpoint),
                    self.test_deep_nested_dos(endpoint),
                    self.test_alias_flood(endpoint),
                    self.test_injection(endpoint),
                    self.test_info_disclosure(endpoint),
                    self.test_csrf(endpoint),
                ]

                results = await asyncio.gather(*tasks, return_exceptions=True)

                seen = set()
                for result in results:
                    if isinstance(result, Exception):
                        self.logger.debug(f"GraphQL test error: {result}")
                        continue
                    items = result if isinstance(result, list) else ([result] if result else [])
                    for finding in items:
                        if finding:
                            key = f"{finding.url}:{finding.type}"
                            if key not in seen:
                                seen.add(key)
                                self.findings.append(finding)
                                self.logger.warning(
                                    f"GraphQL [{finding.severity.upper()}]: {finding.url} | "
                                    f"Type: {finding.type}"
                                )

        self.logger.info(f"GraphQL scan complete. Found {len(self.findings)} issues")
        return self.findings
