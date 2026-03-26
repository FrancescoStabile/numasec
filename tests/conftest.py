"""
security-mcp — Test Configuration

Shared fixtures for all tests.
"""

import json

import pytest

# ═══════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture
def target_profile():
    """Fresh TargetProfile."""
    from security_mcp.models.target import TargetProfile
    return TargetProfile()


@pytest.fixture
def populated_profile():
    """TargetProfile with realistic data."""
    from security_mcp.models.target import (
        Credential,
        Endpoint,
        Port,
        TargetProfile,
        Technology,
        VulnHypothesis,
    )

    profile = TargetProfile()
    profile.target = "http://10.10.10.1:8080"
    profile.os_guess = "Linux"

    profile.add_port(Port(number=22, protocol="tcp", service="ssh", version="OpenSSH 8.2p1"))
    profile.add_port(Port(number=80, protocol="tcp", service="http", version="Apache 2.4.41"))
    profile.add_port(Port(number=3306, protocol="tcp", service="mysql", version="MySQL 5.7"))

    profile.add_endpoint(Endpoint(url="/", method="GET", status_code=200))
    profile.add_endpoint(Endpoint(url="/admin", method="GET", status_code=403))
    profile.add_endpoint(Endpoint(url="/api/users", method="GET", status_code=200))
    profile.add_endpoint(Endpoint(url="/login", method="POST", status_code=302))

    profile.add_technology(Technology(name="Apache", version="2.4.41", category="web_server"))
    profile.add_technology(Technology(name="PHP", version="7.4", category="language"))
    profile.add_technology(Technology(name="WordPress", version="5.9", category="cms"))

    hyp = VulnHypothesis(
        vuln_type="sqli", location="/api/users?id=1",
        confidence=0.95, evidence="Error-based SQLi in id parameter",
    )
    hyp.tested = True
    hyp.confirmed = True
    profile.hypotheses.append(hyp)

    profile.hypotheses.append(
        VulnHypothesis(
            vuln_type="xss", location="/search?q=",
            confidence=0.6, evidence="Reflected XSS in search param",
        )
    )

    profile.credentials.append(
        Credential(username="admin", password="admin123", source="default_creds")
    )

    return profile


@pytest.fixture
def session_state():
    """Fresh SessionState."""
    from security_mcp.core.state import SessionState
    return SessionState()


@pytest.fixture
def populated_state(populated_profile):
    """SessionState with findings and profile data."""
    from security_mcp.core.state import SessionState
    from security_mcp.models.finding import Finding

    s = SessionState()
    s.profile = populated_profile
    s.target = populated_profile.target

    s.add_finding(Finding(
        title="SQL Injection in /api/users",
        severity="critical",
        description="Error-based SQL injection in the id parameter of /api/users endpoint.",
        evidence="GET /api/users?id=1' AND 1=1-- → 200 OK with different response",
        url="/api/users",
        method="GET",
        parameter="id",
    ))
    s.add_finding(Finding(
        title="Default credentials on admin panel",
        severity="high",
        description="The admin panel at /admin accepts default credentials admin:admin123.",
        evidence="POST /login with admin:admin123 → 302 redirect to /admin/dashboard",
        url="/login",
        method="POST",
    ))
    s.add_finding(Finding(
        title="Server version disclosure",
        severity="low",
        description="Apache version is disclosed in HTTP headers.",
        evidence="Server: Apache/2.4.41 (Ubuntu)",
        url="/",
        method="GET",
    ))

    return s


@pytest.fixture
def attack_plan(populated_profile):
    """Generated attack plan."""
    from security_mcp.core.planner import DeterministicPlanner
    planner = DeterministicPlanner()
    return planner.create_plan(populated_profile, scope="standard")


@pytest.fixture
def nmap_output():
    """Realistic nmap JSON output."""
    return json.dumps({
        "hosts": [{
            "ip": "10.10.10.1",
            "ports": [
                {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "8.2p1"},
                {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd", "version": "2.4.41"},
                {"port": 3306, "protocol": "tcp", "service": "mysql", "product": "MySQL", "version": "5.7.38"},
            ],
            "os": "Ubuntu",
        }]
    })


@pytest.fixture
def http_output():
    """Realistic HTTP tool output."""
    return json.dumps({
        "status_code": 200,
        "url": "http://10.10.10.1:8080/",
        "headers": {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3",
            "Content-Type": "text/html; charset=UTF-8",
            "Set-Cookie": "PHPSESSID=abc123; path=/",
        },
        "body": "<html><head><title>Test Site</title></head><body>Welcome to WordPress</body></html>",
    })


@pytest.fixture
def nuclei_output():
    """Realistic nuclei JSON output."""
    return json.dumps({
        "findings": [
            {"template": "CVE-2021-44228", "name": "Log4Shell RCE", "severity": "critical",
             "matched_at": "http://10.10.10.1:8080/api/logs"},
            {"template": "wordpress-login", "name": "WordPress Login Page", "severity": "info",
             "matched_at": "http://10.10.10.1:8080/wp-login.php"},
            {"template": "apache-detect", "name": "Apache Detection", "severity": "info",
             "matched_at": "http://10.10.10.1:8080/"},
        ]
    })


@pytest.fixture
def ffuf_output():
    """Realistic ffuf JSON output."""
    return json.dumps({
        "results": [
            {"input": {"FUZZ": "admin"}, "status": 200, "length": 4523,
             "url": "http://10.10.10.1:8080/admin"},
            {"input": {"FUZZ": "api"}, "status": 301, "length": 0,
             "url": "http://10.10.10.1:8080/api"},
            {"input": {"FUZZ": "backup"}, "status": 403, "length": 277,
             "url": "http://10.10.10.1:8080/backup"},
        ]
    })


@pytest.fixture
def sample_finding():
    """Single sample Finding for testing."""
    from security_mcp.models.finding import Finding
    return Finding(
        title="Test SQL Injection",
        severity="high",
        description="SQL injection vulnerability found",
        url="http://target/api",
        method="GET",
        parameter="id",
        cwe_id="CWE-89",
    )
