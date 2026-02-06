"""
Tests for Session — persistence layer.
"""

import json
import pytest
import tempfile
from pathlib import Path
from numasec.session import SessionManager, Session


class TestSessionManager:
    @pytest.fixture
    def session_manager(self, tmp_path):
        """SessionManager with temp directory."""
        return SessionManager(sessions_dir=tmp_path / "sessions")

    def test_create_session(self, session_manager):
        session = session_manager.create_session(target="http://10.10.10.1")
        assert session.id
        assert session.target == "http://10.10.10.1"
        assert session.status == "active"

    def test_list_sessions(self, session_manager):
        session_manager.create_session(target="target1")
        session_manager.create_session(target="target2")

        sessions = session_manager.list_sessions()
        assert len(sessions) >= 2

    def test_mark_paused(self, session_manager):
        session = session_manager.create_session(target="test")
        session_manager.mark_paused()
        # Reload
        loaded = session_manager.resume_session(session.id)
        assert loaded is not None

    def test_mark_complete(self, session_manager):
        session = session_manager.create_session(target="test")
        session_manager.mark_complete()


class TestSession:
    def test_from_dict_basic(self):
        data = {
            "id": "test-123",
            "timestamp": "2024-01-15T10:00:00",
            "target": "http://example.com",
            "status": "active",
            "messages": [],
            "findings": [],
            "cost": 0.05,
            "tokens_in": 1000,
            "tokens_out": 500,
        }
        session = Session.from_dict(data)
        assert session.id == "test-123"
        assert session.target == "http://example.com"
        assert session.cost == 0.05

    def test_from_dict_backward_compatible(self):
        """Old sessions without target_profile/attack_plan fields."""
        data = {
            "id": "old-session",
            "timestamp": "2023-12-01T10:00:00",
            "target": "http://legacy.com",
            "status": "complete",
            "messages": [],
            "findings": [],
            "cost": 0.10,
            "tokens_in": 2000,
            "tokens_out": 1000,
        }
        session = Session.from_dict(data)
        assert session.id == "old-session"
        # New fields should be None (backward compatible)
        assert session.target_profile is None
        assert session.attack_plan is None

    def test_from_dict_with_new_fields(self):
        """Session with v3 target_profile and attack_plan."""
        data = {
            "id": "new-session",
            "timestamp": "2024-01-15T10:00:00",
            "target": "http://new.com",
            "status": "active",
            "messages": [],
            "findings": [],
            "cost": 0.0,
            "tokens_in": 0,
            "tokens_out": 0,
            "target_profile": {"target": "http://new.com", "ports": []},
            "attack_plan": {"objective": "Test", "phases": []},
        }
        session = Session.from_dict(data)
        assert session.target_profile is not None
        assert session.target_profile["target"] == "http://new.com"
        assert session.attack_plan is not None
