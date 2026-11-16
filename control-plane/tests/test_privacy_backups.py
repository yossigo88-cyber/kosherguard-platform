"""Real disposable PostgreSQL pg_dump/restore: no activity copies restored."""
import os, subprocess
from pathlib import Path
from datetime import datetime, timezone
from sqlalchemy import text
from app.db import session_scope
from app.models import Tenant, FilterDecision
ROOT=Path(__file__).resolve().parents[2]


def test_backup_excludes_and_old_restore_strips_activity(engine, tmp_path, monkeypatch):
    import pgserver
    binaries=Path(pgserver.__file__).parent / "pginstall/bin"
    monkeypatch.setenv("PATH", str(binaries)+os.pathsep+os.environ["PATH"])
    url=engine.url.render_as_string(hide_password=False).replace('postgresql+psycopg://','postgresql://',1)
    with session_scope(engine) as s:
        t=Tenant(name='backup');s.add(t);s.flush()
        s.add(FilterDecision(tenant_id=t.id,source='dns',domain='private.example',action='block'))
    folder=tmp_path/'archives'
    backup=subprocess.run(['bash',str(ROOT/'deploy/pg_backup.sh'),url,str(folder)],capture_output=True,text=True)
    assert backup.returncode == 0, backup.stderr
    dump=next(folder.glob('*.dump'))
    listed=subprocess.check_output(['pg_restore','--list',str(dump)],text=True)
    assert 'TABLE DATA public filter_decisions ' not in listed
    # Make an intentionally legacy archive with history, then restore through
    # the supported script. This is our disposable fixture DB only.
    old=tmp_path/'legacy.dump'
    subprocess.run(['pg_dump','--format=custom','--no-owner','--no-privileges','--file',str(old),url],check=True)
    assert 'TABLE DATA public filter_decisions ' in subprocess.check_output(['pg_restore','--list',str(old)],text=True)
    engine.dispose()
    subprocess.run(['bash',str(ROOT/'deploy/pg_restore.sh'),str(old),url,'--service-stopped'],check=True,capture_output=True,text=True)
    with engine.connect() as c:
        assert c.scalar(text('SELECT count(*) FROM filter_decisions'))==0
        assert c.scalar(text('SELECT count(*) FROM tenants'))==1
