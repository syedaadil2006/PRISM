"""PostgreSQL storage and accounts. Skipped unless a test database is given:

    docker run -d --name prism-pg-test -e POSTGRES_USER=prism -e POSTGRES_PASSWORD=<pw> \\
        -e POSTGRES_DB=prism -p 127.0.0.1:55432:5432 postgres:16-alpine
    set PRISM_TEST_POSTGRES_URL=postgresql://prism:<pw>@127.0.0.1:55432/prism
    pip install -r backend/requirements-postgres.txt

Every test starts from empty tables in that database.
"""

from __future__ import annotations

import os

import pytest

URL = os.environ.get("PRISM_TEST_POSTGRES_URL", "")
pytestmark = pytest.mark.skipif(not URL, reason="set PRISM_TEST_POSTGRES_URL to run the PostgreSQL tests")


@pytest.fixture(autouse=True)
def empty_database():
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(URL, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS events, investigations, meta, users, sessions, audit")
    yield


def test_storage_round_trip():
    from app.core.config import Settings, StorageSettings
    from app.services.soc_state import SocState
    from app.services.storage import Store

    store = Store(StorageSettings(enabled=True, url=URL))
    assert store.engine == "postgres"
    state = SocState(Settings(dataset="live"))
    events, _ = state.live.parse([{"ts": 1790761620.0 + i, "query": f"h{i}.example.org"} for i in range(300)],
                                 "pg", state.inventory)
    store.save_events(events, "live", "s")
    store.save_events(events[:10], "live", "s")
    assert store.event_count("s") == 300
    assert store.load_events(50, "s")[-1].event_id == events[-1].event_id
    store.trim_events(100, "s")
    assert store.event_count("s") == 100
    store.set_meta("k", "1")
    store.set_meta("k", "2")
    assert store.get_meta("k") == "2"
    store.save_investigation("old", "2001-01-01T00:00:00+00:00", "{}")
    store.save_investigation("new", "2030-01-01T00:00:00+00:00", "{}")
    assert store.purge_older_than("2020-01-01T00:00:00+00:00") == (0, 1)
    assert "@" in str(store.describe("s")["path"]) and ":" not in str(store.describe("s")["path"]).split("@")[0][13:]
    store.close()


def test_accounts_sessions_and_audit_chain():
    import psycopg

    from app.core.config import AuthSettings
    from app.core.security_store import SecurityStore

    settings = AuthSettings(db_url=URL, default_admin_enabled=True)  # the suite switches it off
    store = SecurityStore(settings)
    SecurityStore(settings).close()  # restarting must not break the schema
    assert store.ensure_default_admin() and not store.ensure_default_admin()
    assert store.authenticate("Admin", "Admin@123").must_change_password
    store.create_user("asha", "correct horse battery", "analyst")
    cookie = store.create_session("asha", "127.0.0.1")
    assert store.session_principal(cookie).role == "analyst"
    store.update_user("asha", role="viewer")
    assert store.session_principal(cookie) is None
    for i in range(10):
        store.audit("asha", f"action {i}")
    assert store.verify_audit()["ok"]
    with psycopg.connect(URL, autocommit=True) as conn:
        conn.execute("UPDATE audit SET actor = 'mallory' WHERE seq = 3")
    assert store.verify_audit()["first_broken"] == 3
    store.close()
