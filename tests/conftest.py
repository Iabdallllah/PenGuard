"""Shared fixtures: repo-root imports, API key header, ledger snapshot/restore."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient

import api_server


@pytest.fixture()
def client():
    return TestClient(api_server.app)


@pytest.fixture()
def auth_headers():
    return {"X-API-Key": api_server.API_KEY}


@pytest.fixture()
def clean_ledger():
    """Snapshot the episode ledger (memory + JSON + sqlite rows) and restore after."""
    before_ids = {e.get("id") for e in api_server.episodes_db}
    snapshot = [dict(e) for e in api_server.episodes_db]
    yield api_server.episodes_db
    # restore memory + JSON file
    api_server.episodes_db[:] = snapshot
    api_server._save_episodes()
    api_server._run_in_progress = None
    # drop sqlite rows created during the test
    try:
        from database import SessionLocal, Episode as DBEpisode

        try:
            from database import SealedReport as DBSeal
        except Exception:
            DBSeal = None

        if api_server._use_db and SessionLocal and DBEpisode:
            db = SessionLocal()
            for row in db.query(DBEpisode).all():
                if row.id not in before_ids:
                    db.delete(row)
            if DBSeal is not None:
                for row in db.query(DBSeal).all():
                    db.delete(row)
            db.commit()
            db.close()
    except Exception:
        pass
