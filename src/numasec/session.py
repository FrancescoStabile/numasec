"""
Session Persistence System for NumaSec v3

Auto-save sessions, resume work, never lose progress.
Storage: ~/.numasec/sessions/ as JSON files.
Now includes TargetProfile + AttackPlan for smart resume.
"""

import json
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from numasec.state import State, Finding
from numasec.target_profile import TargetProfile
from numasec.planner import AttackPlan


@dataclass
class Session:
    """Persistent session data."""
    id: str
    timestamp: str
    target: Optional[str]
    messages: list[dict]
    findings: list[dict]
    cost: float
    tokens_in: int
    tokens_out: int
    status: str  # "active", "paused", "complete"
    # New in v3
    target_profile: dict | None = None
    attack_plan: dict | None = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        """Create from dictionary."""
        # Handle new fields that may not exist in old sessions
        known_fields = {
            'id', 'timestamp', 'target', 'messages', 'findings',
            'cost', 'tokens_in', 'tokens_out', 'status',
            'target_profile', 'attack_plan',
        }
        filtered = {k: v for k, v in data.items() if k in known_fields}
        # Set defaults for new fields
        filtered.setdefault('target_profile', None)
        filtered.setdefault('attack_plan', None)
        return cls(**filtered)


class SessionManager:
    """
    Manage persistent sessions.
    
    Features:
    - Auto-save after every finding
    - Resume interrupted sessions
    - List all sessions
    - Export session history
    """
    
    def __init__(self, sessions_dir: Optional[Path] = None):
        self.sessions_dir = sessions_dir or Path.home() / ".numasec" / "sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.current_session: Optional[Session] = None
    
    def create_session(self, target: Optional[str] = None) -> Session:
        """Create new session."""
        session = Session(
            id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            target=target,
            messages=[],
            findings=[],
            cost=0.0,
            tokens_in=0,
            tokens_out=0,
            status="active",
        )
        self.current_session = session
        self._save(session)
        return session
    
    def save_state(self, state: State, cost: float = 0.0, tokens_in: int = 0, tokens_out: int = 0):
        """Save current agent state to session."""
        if not self.current_session:
            self.create_session(state.target)
        
        # Update session data
        self.current_session.target = state.target
        self.current_session.messages = [
            {"role": m["role"], "content": self._serialize_content(m["content"])}
            for m in state.messages
        ]
        self.current_session.findings = [
            {
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
            }
            for f in state.findings
        ]
        self.current_session.cost = cost
        self.current_session.tokens_in = tokens_in
        self.current_session.tokens_out = tokens_out
        
        # Save TargetProfile and AttackPlan (v3)
        if state.profile:
            self.current_session.target_profile = state.profile.to_dict()
        if state.plan and state.plan.objective:
            self.current_session.attack_plan = state.plan.to_dict()
        
        self._save(self.current_session)
    
    def _serialize_content(self, content) -> str | list:
        """Serialize message content (handle strings and tool calls)."""
        if isinstance(content, str):
            return content
        elif isinstance(content, list):
            # Tool calls or complex content
            return [
                {k: v for k, v in item.items() if k in ["type", "id", "name", "input", "tool_call_id", "content"]}
                for item in content
            ]
        else:
            return str(content)
    
    def resume_session(self, session_id: str) -> Optional[Session]:
        """Resume a previous session."""
        session_file = self.sessions_dir / f"{session_id}.json"
        if not session_file.exists():
            return None
        
        data = json.loads(session_file.read_text())
        self.current_session = Session.from_dict(data)
        return self.current_session
    
    def list_sessions(self, limit: int = 10) -> list[Session]:
        """List recent sessions."""
        sessions = []
        for file in sorted(self.sessions_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]:
            try:
                data = json.loads(file.read_text())
                sessions.append(Session.from_dict(data))
            except Exception:
                continue
        return sessions
    
    def get_last_session(self) -> Optional[Session]:
        """Get most recent session."""
        sessions = self.list_sessions(limit=1)
        return sessions[0] if sessions else None
    
    def mark_complete(self):
        """Mark current session as complete."""
        if self.current_session:
            self.current_session.status = "complete"
            self._save(self.current_session)
    
    def mark_paused(self):
        """Mark current session as paused."""
        if self.current_session:
            self.current_session.status = "paused"
            self._save(self.current_session)
    
    def delete_session(self, session_id: str):
        """Delete a session."""
        session_file = self.sessions_dir / f"{session_id}.json"
        if session_file.exists():
            session_file.unlink()
    
    def _save(self, session: Session):
        """Save session to disk."""
        session_file = self.sessions_dir / f"{session.id}.json"
        session_file.write_text(json.dumps(session.to_dict(), indent=2))
    
    def export_session(self, session_id: str, format: str = "md") -> str:
        """Export session in various formats."""
        session = self.resume_session(session_id)
        if not session:
            return ""
        
        if format == "md":
            return self._export_markdown(session)
        elif format == "json":
            return json.dumps(session.to_dict(), indent=2)
        elif format == "html":
            return self._export_html(session)
        else:
            return ""
    
    def _export_markdown(self, session: Session) -> str:
        """Export session as Markdown."""
        md = f"# NumaSec Session Report\n\n"
        md += f"**Session ID**: {session.id}\n"
        md += f"**Date**: {session.timestamp}\n"
        md += f"**Target**: {session.target or 'N/A'}\n"
        md += f"**Status**: {session.status}\n"
        md += f"**Cost**: ${session.cost:.4f}\n"
        md += f"**Tokens**: {session.tokens_in:,} in / {session.tokens_out:,} out\n\n"
        
        md += f"## Findings ({len(session.findings)})\n\n"
        
        for i, finding in enumerate(session.findings, 1):
            md += f"### {i}. [{finding['severity'].upper()}] {finding['title']}\n\n"
            md += f"**Description**: {finding['description']}\n\n"
            if finding.get('evidence'):
                md += f"**Evidence**:\n```\n{finding['evidence']}\n```\n\n"
            md += "---\n\n"
        
        return md
    
    @staticmethod
    def _escape(text: str) -> str:
        """Escape HTML special characters to prevent XSS."""
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )

    def _export_html(self, session: Session) -> str:
        """Export session as HTML."""
        esc = self._escape
        target = esc(session.target or 'N/A')
        sid = esc(session.id)
        ts = esc(str(session.timestamp))

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>NumaSec Report - {target}</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #000; color: #00ff41; padding: 20px; }}
        .header {{ border-bottom: 2px solid #00ff41; padding-bottom: 10px; margin-bottom: 20px; }}
        .finding {{ border: 1px solid #00ff41; padding: 15px; margin: 10px 0; }}
        .critical {{ border-color: #ff0051; color: #ff0051; }}
        .high {{ border-color: #ff6b35; color: #ff6b35; }}
        .medium {{ border-color: #ffd700; color: #ffd700; }}
        .severity {{ font-weight: bold; font-size: 1.2em; }}
        pre {{ background: #111; padding: 10px; border-left: 3px solid #00ff41; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>NumaSec Session Report</h1>
        <p><strong>Session ID:</strong> {sid}</p>
        <p><strong>Date:</strong> {ts}</p>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Cost:</strong> ${session.cost:.4f}</p>
    </div>
    <h2>Findings ({len(session.findings)})</h2>
"""
        
        for i, finding in enumerate(session.findings, 1):
            severity_class = esc(finding['severity'].lower())
            title = esc(finding['title'])
            desc = esc(finding['description'])
            sev_label = esc(finding['severity'].upper())
            html += f"""
    <div class="finding {severity_class}">
        <div class="severity">[{sev_label}]</div>
        <h3>{i}. {title}</h3>
        <p><strong>Description:</strong> {desc}</p>
"""
            if finding.get('evidence'):
                html += f"<p><strong>Evidence:</strong></p><pre>{esc(finding['evidence'])}</pre>"
            html += "    </div>\n"
        
        html += """
</body>
</html>"""
        return html
