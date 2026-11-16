"""Private file and runtime input validation, no production credentials."""
import os,sys,importlib.util
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('proxy_runtime',ROOT/'runtime.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)


def test_private_file_rejects_public_and_symlink(tmp_path):
    p=tmp_path/'synthetic-key';p.write_text('synthetic-fixture-only');p.chmod(0o600)
    assert runtime.private_file(str(p))==b'synthetic-fixture-only'
    p.chmod(0o644)
    with pytest.raises(ValueError):runtime.private_file(str(p))
    q=tmp_path/'link';q.symlink_to(p)
    with pytest.raises(OSError):runtime.private_file(str(q))


def test_missing_runtime_configuration_refused():
    with pytest.raises(ValueError):runtime.build_runtime({})


def test_actual_process_serves_authenticated_block_and_stops(tmp_path):
    import json,hashlib,subprocess,socket,time,signal
    import server
    root=tmp_path/'published';g=root/'generations/1';g.mkdir(parents=True)
    policy=json.dumps({'default_policy':'block','allowlist':[],'blocklist':[],'category_rules':{'allow':[],'block':[]}}).encode()
    cats=b'{"domains":{}}'
    (g/'policy.json').write_bytes(policy);(g/'categories.json').write_bytes(cats)
    (g/'manifest.json').write_text(json.dumps({'revision':1,'generation':'1','tenant_id':1,'policy_sha256':hashlib.sha256(policy).hexdigest(),'categories_sha256':hashlib.sha256(cats).hexdigest(),'files':['policy.json','categories.json']}))
    (root/'current').symlink_to('generations/1')
    key=tmp_path/'key';key.write_bytes(b'local-process-synthetic-test-key');key.chmod(0o600)
    with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
    env=dict(os.environ,KG_TENANT_PUBLICATIONS_ROOT=str(root),KG_DEVICE_TOKEN_KEY_FILE=str(key),KG_PROXY_PORT=str(port),KG_POLICY_REFRESH_SECONDS='.05')
    process=subprocess.Popen([sys.executable,str(ROOT/'runtime.py')],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    token=server.device_auth.issue_token(key.read_bytes(),'1','1',scope='proxy',policy_id=1)
    try:
        end=time.monotonic()+4
        while True:
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.2) as sock:
                    sock.sendall(('CONNECT synthetic.example:443 HTTP/1.1\r\nProxy-Authorization: Bearer '+token+'\r\n\r\n').encode())
                    assert b'403' in sock.recv(1024).split(b'\r\n')[0]
                break
            except ConnectionRefusedError:
                assert time.monotonic()<end and process.poll() is None
                time.sleep(.02)
    finally:
        process.send_signal(signal.SIGTERM)
        out,err=process.communicate(timeout=6)
    assert process.returncode==0,err.decode()
    assert b'synthetic.example' not in out+err
