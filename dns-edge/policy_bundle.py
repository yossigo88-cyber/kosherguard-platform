"""Atomic scheduled policy bundles from control-plane generations.

Legacy two-file generations still use the reviewed loader. Supplemental
assigned-policy documents are pinned to one directory descriptor and
hash-checked before building any engines. No query-time file access.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
from dataclasses import dataclass
from types import MappingProxyType

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "filtering-engine", "src")))
import engine_set
import category_db
from generation_io import open_generation_dir_nofollow, read_file_under
from schedules import ScheduledPolicyEngine
from policy_engine import PolicyEngine, Decision


@dataclass(frozen=True)
class ExceptionOverlay:
    """Time-windowed per-device exceptions over the scheduled engine."""
    engine: object
    entries: tuple
    now: object

    def decide(self, domain):
        from datetime import datetime, timezone
        now = self.now() if callable(self.now) else self.now
        if now is None:
            now = datetime.now(timezone.utc)
        for entry in self.entries:
            starts = datetime.fromisoformat(entry['starts_at'])
            expires = datetime.fromisoformat(entry['expires_at'])
            if not (starts <= now < expires):
                continue
            if entry['kind'] == 'disable_policy':
                return Decision(
                    action='allow', rule='exception_disable_policy',
                    reason=f"exception {entry['exception_id']}", category=None)
            for suffix in entry['domains']:
                if domain == suffix or domain.endswith('.' + suffix):
                    return Decision(
                        action='allow', rule='exception_allow_domains',
                        reason=f"exception {entry['exception_id']}",
                        category=None)
        return self.engine.decide(domain)


@dataclass(frozen=True)
class PolicyBundle:
    engines: object
    devices: object
    revision: int
    tenant_id: int | None = None
    exceptions: object = None
    now: object = None

    def for_device(self, device_id):
        policy_id = self.devices.get(str(device_id))
        if policy_id is None:
            engine = self.engines.default
        else:
            engine = self.engines.per_policy[policy_id]
        entries = (self.exceptions or {}).get(str(device_id))
        if entries:
            return ExceptionOverlay(engine, tuple(entries), self.now)
        return engine


def load_bundle(root, now=None):
    current = os.path.join(root, 'current')
    fd, real = open_generation_dir_nofollow(current, 'policy generation')
    try:
        raw = lambda name: read_file_under(fd, name, 'policy generation file')
        manifest = json.loads(raw('manifest.json'))
        revision = manifest['revision']
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise ValueError('invalid revision')
        if manifest.get('generation') != str(revision) or os.path.basename(real) != str(revision):
            raise ValueError('generation identity mismatch')
        pb, cb = raw('policy.json'), raw('categories.json')
        for name, value in [('policy', pb), ('categories', cb)]:
            if hashlib.sha256(value).hexdigest() != manifest.get(name+'_sha256'):
                raise ValueError('generation hash mismatch')
        extras = {}
        overlay = {}
        hashes = manifest.get('extra_sha256', {})
        if not isinstance(hashes, dict):
            raise ValueError('invalid supplemental manifest')
        for name, digest in hashes.items():
            if not re.fullmatch(r'(?:device-map|exceptions|assigned-policy-[1-9][0-9]*)\.json', name):
                raise ValueError('invalid supplemental path')
            value = raw(name)
            if hashlib.sha256(value).hexdigest() != digest:
                raise ValueError('supplemental hash mismatch')
            if name == 'exceptions.json':
                overlay = json.loads(value)
            else:
                extras[name] = json.loads(value)
        expected = {'manifest.json', 'policy.json', 'categories.json', *hashes}
        if set(os.listdir(fd)) != expected:
            raise ValueError('unmanifested or missing generation file')
        cats = json.loads(cb)
        db = category_db.CategoryDB(cats['domains'], meta=cats.get('_meta', {}))
        PolicyEngine(json.loads(pb), db)  # validate before activation
        default = ScheduledPolicyEngine(json.loads(pb), db, now=now)
        mapping, engines, default_id = {}, {}, None
        if extras:
            device_map = extras.pop('device-map.json')
            if set(device_map) != {'default_policy_id', 'devices'}:
                raise ValueError('invalid device map schema')
            default_id = device_map['default_policy_id']
            if isinstance(default_id, bool) or not isinstance(default_id, int) or default_id < 1:
                raise ValueError('invalid default policy identity')
            engines[default_id] = default
            referenced = set()
            for device_id, entry in device_map['devices'].items():
                if not device_id.isdigit() or str(int(device_id)) != device_id or int(device_id) < 1:
                    raise ValueError('invalid device identity')
                pid = entry.get('policy_id')
                if isinstance(pid, bool) or not isinstance(pid, int) or pid < 1:
                    raise ValueError('invalid assigned policy identity')
                name = f'assigned-policy-{pid}.json'
                if entry.get('policy') != name or name not in extras:
                    raise ValueError('unresolved assigned policy')
                referenced.add(name)
                PolicyEngine(extras[name], db)
                assigned = ScheduledPolicyEngine(extras[name], db, now=now)
                if pid == default_id and extras[name] != json.loads(pb):
                    raise ValueError('conflicting default policy document')
                engines[pid] = assigned
                mapping[device_id] = pid
            if referenced != set(extras):
                raise ValueError('unreferenced assigned policy')
        return PolicyBundle(engine_set.EngineSet(
            default, per_policy=engines, default_policy_id=default_id),
            MappingProxyType(mapping), revision, manifest.get("tenant_id"),
            exceptions=MappingProxyType({k: tuple(v) for k, v in overlay.items()}),
            now=now)
    finally:
        os.close(fd)
