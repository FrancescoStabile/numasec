"""
NumaSec — Attack Graph (Multi-Stage Reasoning)

Directed graph of exploitation paths. When a finding is registered,
the graph activates downstream escalation paths. The agent reads
the graph to decide what to exploit next.

This is THE differentiator vs Shannon/PentestGPT — they find
individual vulns; NumaSec chains them into multi-step attacks.

Architecture:
  Nodes = capabilities (e.g. "sqli", "file_write", "rce")
  Edges = exploitation steps connecting capabilities
  When a capability is confirmed, downstream edges become available.

Example:
  SQLi (confirmed) → DB Dump → Credential Extraction → Admin Access → RCE
  LFI (confirmed) → Log Poisoning → RCE
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("numasec.attack_graph")


# ═══════════════════════════════════════════════════════════════════════════
# Node & Edge Types
# ═══════════════════════════════════════════════════════════════════════════

class NodeState(str, Enum):
    """State of an attack graph node."""
    UNKNOWN = "unknown"         # Not yet tested
    SUSPECTED = "suspected"     # Hypothesis, not confirmed
    CONFIRMED = "confirmed"     # Confirmed via testing
    EXPLOITED = "exploited"     # Successfully exploited
    FAILED = "failed"           # Tested and not present


@dataclass
class AttackNode:
    """A capability or vulnerability in the attack graph."""
    id: str                                      # "sqli_login", "lfi_config"
    capability: str                               # "sqli", "lfi", "rce"
    label: str                                    # Human-readable label
    state: NodeState = NodeState.UNKNOWN
    finding_title: str = ""                       # Link to Finding
    location: str = ""                            # URL/path where found
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, AttackNode):
            return self.id == other.id
        return False


@dataclass
class AttackEdge:
    """An exploitation step connecting two capabilities."""
    source: str                     # Source node ID
    target: str                     # Target node ID
    technique: str                  # "log_poisoning", "db_dump", etc.
    description: str                # Human-readable step description
    tool_hint: str = ""             # Suggested tool to use
    knowledge_ref: str = ""         # Knowledge base reference
    priority: int = 5               # 1 = highest priority
    requires_all: list[str] = field(default_factory=list)  # All required nodes

    def __hash__(self):
        return hash((self.source, self.target, self.technique))


@dataclass
class ExploitationPath:
    """A sequence of edges forming a complete exploitation chain."""
    name: str
    edges: list[AttackEdge]
    impact: str                     # "critical", "high", "medium"
    description: str

    @property
    def steps(self) -> int:
        return len(self.edges)


# ═══════════════════════════════════════════════════════════════════════════
# Attack Graph
# ═══════════════════════════════════════════════════════════════════════════

class AttackGraph:
    """Directed graph of exploitation paths.

    Core API:
      - mark_discovered(capability, finding) — register a confirmed capability
      - get_next_steps() — return highest-impact unexplored paths
      - to_prompt_context() — generate prompt text for LLM context injection

    The graph is populated with pre-built chains at construction.
    New chains can be registered dynamically.
    """

    def __init__(self):
        self.nodes: dict[str, AttackNode] = {}
        self.edges: list[AttackEdge] = []
        self._paths: list[ExploitationPath] = []

        # Populate with prebuild chains
        self._build_default_graph()

    def _build_default_graph(self) -> None:
        """Build the default attack graph with 10+ exploitation chains."""

        # ── Nodes: All possible capabilities ──
        capabilities = [
            ("sqli", "SQL Injection"),
            ("sqli_blind", "Blind SQL Injection"),
            ("xss_stored", "Stored XSS"),
            ("xss_reflected", "Reflected XSS"),
            ("lfi", "Local File Inclusion"),
            ("rfi", "Remote File Inclusion"),
            ("ssrf", "Server-Side Request Forgery"),
            ("ssti", "Server-Side Template Injection"),
            ("cmdi", "Command Injection"),
            ("file_upload", "Unrestricted File Upload"),
            ("file_write", "Arbitrary File Write"),
            ("auth_bypass", "Authentication Bypass"),
            ("idor", "Insecure Direct Object Reference"),
            ("default_creds", "Default Credentials"),
            ("db_access", "Database Access"),
            ("credential_dump", "Credential Extraction"),
            ("admin_access", "Admin Panel Access"),
            ("rce", "Remote Code Execution"),
            ("session_hijack", "Session Hijacking"),
            ("account_takeover", "Account Takeover"),
            ("data_exfil", "Data Exfiltration"),
            ("internal_access", "Internal Network Access"),
            ("log_poisoning", "Log Poisoning"),
            ("webshell", "Web Shell"),
            ("token_forgery", "Token Forgery"),
            ("jwt_vuln", "JWT Vulnerability"),
            ("dir_listing", "Directory Listing"),
            ("config_exposure", "Config/Env Exposure"),
            ("info_disclosure", "Information Disclosure"),
            ("pii_leak", "PII Data Leak"),
            ("secrets_found", "Secrets/Keys Found"),
        ]

        for cap_id, label in capabilities:
            self.nodes[cap_id] = AttackNode(id=cap_id, capability=cap_id, label=label)

        # ── Chain 1: SQLi → DB Dump → Credential Extraction ──
        self.edges.extend([
            AttackEdge(
                source="sqli", target="db_access",
                technique="db_dump",
                description="Use SQL injection to dump database contents",
                tool_hint="sqlmap --dump",
                knowledge_ref="attack-chains/sqli-to-rce",
                priority=1,
            ),
            AttackEdge(
                source="db_access", target="credential_dump",
                technique="credential_extraction",
                description="Extract user credentials from database dump",
                tool_hint="http",
                priority=2,
            ),
            AttackEdge(
                source="credential_dump", target="admin_access",
                technique="credential_reuse",
                description="Use extracted credentials to access admin panel",
                tool_hint="browser_fill",
                priority=2,
            ),
            AttackEdge(
                source="sqli", target="rce",
                technique="sqli_to_rce",
                description="Escalate SQLi to RCE via INTO OUTFILE or xp_cmdshell",
                tool_hint="sqlmap --os-shell",
                knowledge_ref="attack-chains/sqli-to-rce",
                priority=1,
            ),
        ])

        # ── Chain 2: LFI → Log Poisoning → RCE ──
        self.edges.extend([
            AttackEdge(
                source="lfi", target="log_poisoning",
                technique="log_inject",
                description="Inject PHP/Python code into access log via User-Agent",
                tool_hint="http",
                knowledge_ref="attack-chains/lfi-to-rce",
                priority=2,
            ),
            AttackEdge(
                source="log_poisoning", target="rce",
                technique="log_execution",
                description="Include poisoned log file via LFI to achieve RCE",
                tool_hint="http",
                priority=1,
            ),
            AttackEdge(
                source="lfi", target="config_exposure",
                technique="config_read",
                description="Read configuration files via LFI (/etc/passwd, .env, config.php)",
                tool_hint="http",
                priority=2,
            ),
            AttackEdge(
                source="config_exposure", target="credential_dump",
                technique="config_creds",
                description="Extract credentials from configuration files",
                priority=3,
            ),
        ])

        # ── Chain 3: SSRF → Internal Service → Data Access ──
        self.edges.extend([
            AttackEdge(
                source="ssrf", target="internal_access",
                technique="internal_scan",
                description="Use SSRF to scan internal services (metadata, redis, etc.)",
                tool_hint="http",
                knowledge_ref="web-cheatsheet",
                priority=2,
            ),
            AttackEdge(
                source="internal_access", target="data_exfil",
                technique="internal_data",
                description="Access internal data via SSRF (cloud metadata, databases)",
                tool_hint="http",
                priority=2,
            ),
        ])

        # ── Chain 4: File Upload → Webshell → RCE ──
        self.edges.extend([
            AttackEdge(
                source="file_upload", target="webshell",
                technique="shell_upload",
                description="Upload PHP/Python webshell through file upload",
                tool_hint="http",
                knowledge_ref="attack-chains/upload-to-rce",
                priority=1,
            ),
            AttackEdge(
                source="webshell", target="rce",
                technique="shell_exec",
                description="Execute commands through uploaded webshell",
                tool_hint="http",
                priority=1,
            ),
        ])

        # ── Chain 5: XSS → Session Hijack → Account Takeover ──
        self.edges.extend([
            AttackEdge(
                source="xss_stored", target="session_hijack",
                technique="cookie_theft",
                description="Steal session cookies via stored XSS",
                tool_hint="browser_navigate",
                priority=3,
            ),
            AttackEdge(
                source="session_hijack", target="account_takeover",
                technique="session_replay",
                description="Use stolen session to take over user account",
                tool_hint="http",
                priority=2,
            ),
        ])

        # ── Chain 6: IDOR → Data Exposure → PII Leak ──
        self.edges.extend([
            AttackEdge(
                source="idor", target="data_exfil",
                technique="data_enum",
                description="Enumerate objects via IDOR to extract user data",
                tool_hint="http",
                priority=3,
            ),
            AttackEdge(
                source="data_exfil", target="pii_leak",
                technique="pii_extraction",
                description="Extract PII data from enumerated objects",
                priority=4,
            ),
        ])

        # ── Chain 7: Default Creds → Admin Panel → Config Dump ──
        self.edges.extend([
            AttackEdge(
                source="default_creds", target="admin_access",
                technique="default_login",
                description="Login with default/guessable credentials",
                tool_hint="browser_fill",
                priority=1,
            ),
            AttackEdge(
                source="admin_access", target="config_exposure",
                technique="admin_config",
                description="Access configuration/settings through admin panel",
                tool_hint="browser_navigate",
                priority=3,
            ),
            AttackEdge(
                source="admin_access", target="rce",
                technique="admin_rce",
                description="Escalate admin access to RCE (plugin upload, code exec feature)",
                tool_hint="http",
                priority=2,
            ),
        ])

        # ── Chain 8: Info Disclosure → Version → Known CVE ──
        self.edges.extend([
            AttackEdge(
                source="info_disclosure", target="secrets_found",
                technique="secret_discovery",
                description="Extract secrets, API keys, or version info from disclosed data",
                tool_hint="http",
                priority=4,
            ),
        ])

        # ── Chain 9: Directory Listing → Sensitive Files → Secrets ──
        self.edges.extend([
            AttackEdge(
                source="dir_listing", target="config_exposure",
                technique="sensitive_file_access",
                description="Access sensitive files found in directory listing",
                tool_hint="http",
                priority=3,
            ),
        ])

        # ── Chain 10: JWT Weakness → Token Forgery → Auth Bypass ──
        self.edges.extend([
            AttackEdge(
                source="jwt_vuln", target="token_forgery",
                technique="jwt_forge",
                description="Forge JWT token using none algorithm or weak secret",
                tool_hint="http",
                knowledge_ref="web-cheatsheet",
                priority=1,
            ),
            AttackEdge(
                source="token_forgery", target="auth_bypass",
                technique="token_auth_bypass",
                description="Use forged token to bypass authentication",
                tool_hint="http",
                priority=1,
            ),
            AttackEdge(
                source="auth_bypass", target="admin_access",
                technique="auth_to_admin",
                description="Access admin functionality via authentication bypass",
                tool_hint="http",
                priority=2,
            ),
        ])

        # ── Chain 11: SSTI → RCE ──
        self.edges.extend([
            AttackEdge(
                source="ssti", target="rce",
                technique="ssti_rce",
                description="Escalate SSTI to RCE via template engine primitives",
                tool_hint="http",
                knowledge_ref="attack-chains/ssti-to-rce",
                priority=1,
            ),
        ])

        # ── Chain 12: Command Injection → RCE ──
        self.edges.extend([
            AttackEdge(
                source="cmdi", target="rce",
                technique="direct_rce",
                description="Command injection provides direct RCE",
                tool_hint="http",
                priority=1,
            ),
        ])

        # Build exploitation paths
        self._build_paths()

    def _build_paths(self) -> None:
        """Pre-compute named exploitation paths from edge chains."""
        path_defs = [
            ("SQLi → DB Dump → Credentials → Admin",
             ["sqli", "db_access", "credential_dump", "admin_access"],
             "critical",
             "Chain SQL injection through database dump to credential extraction and admin access"),
            ("SQLi → RCE",
             ["sqli", "rce"],
             "critical",
             "Direct SQLi to remote code execution via INTO OUTFILE or xp_cmdshell"),
            ("LFI → Log Poisoning → RCE",
             ["lfi", "log_poisoning", "rce"],
             "critical",
             "Chain local file inclusion through log poisoning to remote code execution"),
            ("SSRF → Internal → Data Exfil",
             ["ssrf", "internal_access", "data_exfil"],
             "critical",
             "Chain SSRF through internal network access to data exfiltration"),
            ("File Upload → Webshell → RCE",
             ["file_upload", "webshell", "rce"],
             "critical",
             "Upload malicious file then execute for RCE"),
            ("Stored XSS → Session Hijack → Account Takeover",
             ["xss_stored", "session_hijack", "account_takeover"],
             "high",
             "Chain stored XSS through session theft to full account takeover"),
            ("IDOR → Data Exfil → PII Leak",
             ["idor", "data_exfil", "pii_leak"],
             "high",
             "Enumerate insecure direct object references to extract PII data"),
            ("Default Creds → Admin → RCE",
             ["default_creds", "admin_access", "rce"],
             "critical",
             "Login with default credentials, escalate to RCE via admin features"),
            ("JWT Vuln → Token Forgery → Auth Bypass → Admin",
             ["jwt_vuln", "token_forgery", "auth_bypass", "admin_access"],
             "critical",
             "Forge JWT tokens to bypass authentication and access admin"),
            ("SSTI → RCE",
             ["ssti", "rce"],
             "critical",
             "Escalate template injection to remote code execution"),
        ]

        for name, node_ids, impact, desc in path_defs:
            edges = []
            for i in range(len(node_ids) - 1):
                src, tgt = node_ids[i], node_ids[i + 1]
                for edge in self.edges:
                    if edge.source == src and edge.target == tgt:
                        edges.append(edge)
                        break
            if edges:
                self._paths.append(ExploitationPath(
                    name=name, edges=edges, impact=impact, description=desc,
                ))

    # ═══════════════════════════════════════════════════════════════════
    # Core API
    # ═══════════════════════════════════════════════════════════════════

    def mark_discovered(
        self,
        capability: str,
        finding_title: str = "",
        location: str = "",
        state: NodeState = NodeState.CONFIRMED,
    ) -> list[ExploitationPath]:
        """Register a confirmed capability, activate downstream paths.

        Args:
            capability: Capability ID (e.g. "sqli", "lfi", "xss_stored")
            finding_title: Title of the finding that confirmed this
            location: URL/path where the capability was found
            state: Node state (default: CONFIRMED)

        Returns:
            List of newly available exploitation paths
        """
        # Fuzzy match: try exact first, then prefix, then alias lookup
        node = self.nodes.get(capability)
        if not node:
            cap_lower = capability.lower()

            # 1. Exact node ID match
            if cap_lower in self.nodes:
                node = self.nodes[cap_lower]

            # 2. Prefix match ("sqli" matches "sqli" but not "sqli_blind" unless exact)
            if not node:
                for nid, n in self.nodes.items():
                    if nid.lower() == cap_lower:
                        node = n
                        break

            # 3. Keyword-based alias lookup (preferred over greedy substring)
            if not node:
                _ALIASES = {
                    "sql injection": "sqli", "sql": "sqli",
                    "cross-site scripting": "xss_reflected", "cross site scripting": "xss_reflected",
                    "stored xss": "xss_stored", "reflected xss": "xss_reflected",
                    "xss": "xss_reflected",
                    "file inclusion": "lfi", "local file": "lfi",
                    "server-side request forgery": "ssrf", "server side request": "ssrf",
                    "template injection": "ssti",
                    "command injection": "cmdi", "os command": "cmdi",
                    "file upload": "file_upload",
                    "remote code execution": "rce",
                    "directory listing": "dir_listing", "directory traversal": "lfi",
                    "path traversal": "lfi",
                    "default credential": "default_creds", "default password": "default_creds",
                    "insecure direct object": "idor",
                    "authentication bypass": "auth_bypass",
                    "jwt": "jwt_vuln", "json web token": "jwt_vuln",
                    "xxe": "xxe", "xml external": "xxe",
                    "information disclosure": "info_disclosure",
                    "info disclosure": "info_disclosure",
                }
                for alias, nid in _ALIASES.items():
                    if alias in cap_lower and nid in self.nodes:
                        node = self.nodes[nid]
                        break

            # 4. Label exact match (not substring)
            if not node:
                for nid, n in self.nodes.items():
                    if n.label.lower() == cap_lower:
                        node = n
                        break

            # 5. Conservative substring: only if capability is long enough (>4 chars)
            #    to avoid "info" matching "info_disclosure" etc.
            if not node and len(cap_lower) > 4:
                for nid, n in self.nodes.items():
                    if cap_lower == nid.lower() or nid.lower().startswith(cap_lower):
                        node = n
                        break

        if not node:
            logger.debug(f"Unknown capability: {capability}")
            return []

        node.state = state
        node.finding_title = finding_title
        node.location = location

        logger.info(f"Attack graph: {capability} marked as {state.value}")

        return self.get_available_paths()

    def get_available_paths(self) -> list[ExploitationPath]:
        """Return exploitation paths that have at least one confirmed source node.

        Returns paths where the first node is confirmed but later nodes
        are still unknown/suspected — these are actionable next steps.
        """
        available = []

        for path in self._paths:
            if not path.edges:
                continue

            # First node must be confirmed/exploited
            first_source = path.edges[0].source
            first_node = self.nodes.get(first_source)
            if not first_node or first_node.state not in (NodeState.CONFIRMED, NodeState.EXPLOITED):
                continue

            # At least one later node must be unexplored
            has_unexplored = False
            for edge in path.edges:
                target_node = self.nodes.get(edge.target)
                if target_node and target_node.state in (NodeState.UNKNOWN, NodeState.SUSPECTED):
                    has_unexplored = True
                    break

            if has_unexplored:
                available.append(path)

        # Sort by impact (critical first) then by fewest steps
        impact_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        available.sort(key=lambda p: (impact_order.get(p.impact, 99), p.steps))

        return available

    def get_next_steps(self, limit: int = 5) -> list[AttackEdge]:
        """Return the highest-priority next exploitation steps.

        These are edges whose source node is confirmed but whose
        target node has not been tested yet.

        Args:
            limit: Maximum number of steps to return

        Returns:
            List of AttackEdge representing next actions
        """
        next_edges: list[AttackEdge] = []

        for edge in self.edges:
            source_node = self.nodes.get(edge.source)
            target_node = self.nodes.get(edge.target)

            if not source_node or not target_node:
                continue

            # Source must be confirmed/exploited
            if source_node.state not in (NodeState.CONFIRMED, NodeState.EXPLOITED):
                continue

            # Target must be unexplored
            if target_node.state not in (NodeState.UNKNOWN, NodeState.SUSPECTED):
                continue

            next_edges.append(edge)

        # Sort by priority (lower = higher priority)
        next_edges.sort(key=lambda e: e.priority)

        return next_edges[:limit]

    def get_confirmed_nodes(self) -> list[AttackNode]:
        """Return all confirmed/exploited nodes."""
        return [
            n for n in self.nodes.values()
            if n.state in (NodeState.CONFIRMED, NodeState.EXPLOITED)
        ]

    def to_prompt_context(self) -> str:
        """Generate prompt context for LLM injection.

        Returns a structured summary of:
          1. What capabilities are confirmed
          2. What escalation paths are now available
          3. Suggested next steps

        This is injected into the agent prompt to guide next-step reasoning.
        """
        confirmed = self.get_confirmed_nodes()
        if not confirmed:
            return ""

        lines = [
            "## Attack Graph — Confirmed Capabilities & Escalation Paths",
            "",
            "### Confirmed Capabilities",
        ]

        for node in confirmed:
            loc = f" at {node.location}" if node.location else ""
            lines.append(f"- ✅ **{node.label}**{loc}")
            if node.finding_title:
                lines.append(f"  (Finding: {node.finding_title})")

        # Available paths
        paths = self.get_available_paths()
        if paths:
            lines.append("")
            lines.append("### Available Escalation Paths")
            lines.append("")

            for path in paths[:5]:
                lines.append(f"**{path.name}** ({path.impact} impact, {path.steps} steps)")
                for i, edge in enumerate(path.edges, 1):
                    source = self.nodes.get(edge.source)
                    target = self.nodes.get(edge.target)
                    source_state = source.state.value if source else "?"
                    target_state = target.state.value if target else "?"

                    state_icon = "✅" if source_state in ("confirmed", "exploited") else "⬜"
                    lines.append(
                        f"  {i}. {state_icon} {edge.description}"
                    )
                    if edge.tool_hint:
                        lines.append(f"     → Tool: `{edge.tool_hint}`")
                    if edge.knowledge_ref:
                        lines.append(f"     → Knowledge: `numasec://kb/{edge.knowledge_ref}`")
                lines.append("")

        # Next steps
        next_steps = self.get_next_steps(limit=3)
        if next_steps:
            lines.append("### Suggested Next Actions")
            lines.append("")
            for step in next_steps:
                lines.append(f"1. **{step.description}**")
                if step.tool_hint:
                    lines.append(f"   Use: `{step.tool_hint}`")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph state for session persistence."""
        return {
            "nodes": {
                nid: {
                    "state": node.state.value,
                    "finding_title": node.finding_title,
                    "location": node.location,
                }
                for nid, node in self.nodes.items()
                if node.state != NodeState.UNKNOWN
            },
        }

    def from_dict(self, data: dict[str, Any]) -> None:
        """Restore graph state from serialized data."""
        for nid, node_data in data.get("nodes", {}).items():
            if nid in self.nodes:
                self.nodes[nid].state = NodeState(node_data.get("state", "unknown"))
                self.nodes[nid].finding_title = node_data.get("finding_title", "")
                self.nodes[nid].location = node_data.get("location", "")
