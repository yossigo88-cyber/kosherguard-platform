"""Real PostgreSQL migrations: existing sessions/history sanitize on upgrade."""
import os,sys,uuid
from pathlib import Path
sys.path.insert(0,os.path.dirname(__file__))
import pgserver
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine,text,inspect
ROOT=Path(__file__).resolve().parents[1]


def test_postgres_upgrade_and_clean_install(monkeypatch):
    engines=[]
    def cfg(label):
        server=pgserver.get_server('/tmp/kg-security-migrations-'+uuid.uuid4().hex[:8])
        url=server.get_uri().replace('postgresql://','postgresql+psycopg://',1)
        monkeypatch.setenv('KG_DATABASE_URL',url)
        c=Config(str(ROOT/'alembic.ini'));c.set_main_option('script_location',str(ROOT/'alembic'))
        e=create_engine(url);engines.append(e)
        return c,e
    c,a=cfg('upgrade');command.upgrade(c,'0010')
    with a.begin() as con:
        con.execute(text("INSERT INTO tenants(id,name,created_at) VALUES(1,'synthetic',CURRENT_TIMESTAMP)"))
        con.execute(text("INSERT INTO filter_decisions(tenant_id,source,domain,action,rule,reason,received_at) VALUES(1,'dns','old-allowed.example','allow','','',CURRENT_TIMESTAMP),(1,'dns','old-blocked.example','block','','',CURRENT_TIMESTAMP-INTERVAL '8 days'),(1,'dns','recent.example','block','private path','sensitive',CURRENT_TIMESTAMP)"))
    command.upgrade(c,'head')
    with a.connect() as con:
        assert con.execute(text('SELECT domain,rule,reason FROM filter_decisions')).all()==[('recent.example','blocked','policy blocked domain')]
        assert con.scalar(text('SELECT blocked_log_retention_days FROM tenants'))==7
    c,b=cfg('clean');command.upgrade(c,'head')
    ia,ib=inspect(a),inspect(b)
    assert set(ia.get_table_names())==set(ib.get_table_names())
    for table in ia.get_table_names():
        assert {(v['name'],str(v['type'])) for v in ia.get_columns(table)}=={(v['name'],str(v['type'])) for v in ib.get_columns(table)}
        assert {v['name'] for v in ia.get_indexes(table)}=={v['name'] for v in ib.get_indexes(table)}
    for e in engines:e.dispose()
