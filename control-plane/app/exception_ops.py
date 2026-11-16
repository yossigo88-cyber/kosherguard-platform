"""Scoped time-limited exceptions: validation and publication export.

Every exception has a reason, an approving user, a device/group scope
and a start/expiration window; creation and revocation are audited.
Owners may grant any kind; guardians need the explicit "exceptions"
delegation and are limited to short allow-domains exceptions. Global
baseline changes and protection removal stay owner-only: the
"disable_policy" kind and durations over 24h are refused for guardians.
"""
from datetime import datetime, timedelta, timezone
import json, re
from sqlalchemy import select
from .models import Device, DeviceGroup, GroupMembership, PolicyException
from .policy_ops import PolicyError

GUARDIAN_MAX_DURATION = timedelta(hours=24)
OWNER_MAX_DURATION = timedelta(days=30)
KINDS = ('allow_domains', 'disable_policy')
OWNER_ONLY_KINDS = ('disable_policy',)
DOMAIN_RE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')


def now_utc():
    return datetime.now(timezone.utc)


def validate_domains(domains):
    if (not isinstance(domains, list) or not domains or len(domains) > 100
            or any(not isinstance(d, str) or not DOMAIN_RE.match(d)
                   for d in domains)):
        raise PolicyError('allow_domains needs 1-100 valid domains', 400)


Every exception has a reason, an approving user, a device/group scope
and a start/expiration window; creation and revocation are audited.
Owners may grant any kind; guardians need the explicit "exceptions"
delegation and are limited to short allow-domains exceptions. Global
baseline changes and protection removal stay owner-only: the
"disable_policy" kind and durations over 24h are refused for guardians.
"""
from datetime import datetime, timedelta, timezone
import json, re
from sqlalchemy import select
from .models import Device, DeviceGroup, GroupMembership, PolicyException
from .policy_ops import PolicyError

GUARDIAN_MAX_DURATION = timedelta(hours=24)
OWNER_MAX_DURATION = timedelta(days=30)
KINDS = ('allow_domains', 'disable_policy')
OWNER_ONLY_KINDS = ('disable_policy',)
DOMAIN_RE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')


def now_utc():
    return datetime.now(timezone.utc)


def validate_domains(domains):
    if (not isinstance(domains, list) or not domains or len(domains) > 100
            or any(not isinstance(d, str) or not DOMAIN_RE.match(d)
                   for d in domains)):
        raise PolicyError('allow_domains needs 1-100 valid domains', 400)


def active_exceptions(session, tenant_id, now=None):
    """Non-revoked exceptions whose window is open or still upcoming."""
    now = now or now_utc()
    rows = session.scalars(select(PolicyException).where(
        PolicyException.tenant_id == tenant_id,
        PolicyException.revoked_at.is_(None),
        PolicyException.expires_at > now)).all()
    return [r for r in rows if _aware(r.expires_at) > now]


def exception_devices(session, tenant_id, row):
    """Resolve the scope to concrete devices; group membership is pinned
    at publication time so later moves do not extend the exception."""
    if row.scope_type == 'device':
        device = session.get(Device, row.device_id)
        if device is None or device.tenant_id != tenant_id:
            raise PolicyError('exception device missing', 409)
        return [device.id]
    members = session.scalars(select(GroupMembership.device_id).where(
        GroupMembership.tenant_id == tenant_id,
        GroupMembership.group_id == row.group_id)).all()
    return sorted(members)


def export_exceptions(session, tenant_id, now=None):
    """Per-device exception overlay for the atomic generation."""
    now = now or now_utc()
    overlay = {}
    for row in active_exceptions(session, tenant_id, now):
        for device_id in exception_devices(session, tenant_id, row):
            overlay.setdefault(str(device_id), []).append({
                'kind': row.kind,
                'domains': sorted(json.loads(row.domains)),
                'starts_at': _aware(row.starts_at).isoformat(),
                'expires_at': _aware(row.expires_at).isoformat(),
                'exception_id': row.id})
    return overlay


def _aware(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def validate_new(session, tenant_id, user, body):
    kind = body.get('kind')
    if kind not in KINDS:
        raise PolicyError('unknown exception kind', 400)
    scope_type = body.get('scope_type')
    if scope_type not in ('device', 'group'):
        raise PolicyError('scope must be a device or a group', 400)
    if scope_type == 'device':
        device = session.get(Device, body.get('device_id') or 0)
        if device is None or device.tenant_id != tenant_id:
            raise PolicyError('device not found', 404)
        group_id = None
        device_id = device.id
    else:
        group = session.get(DeviceGroup, body.get('group_id') or 0)
        if group is None or group.tenant_id != tenant_id:
            raise PolicyError('group not found', 404)
        group_id = group.id
        device_id = None
    reason = (body.get('reason') or '').strip()
    if not reason or len(reason) > 500:
        raise PolicyError('a reason is required (max 500 chars)', 400)
    starts = _parse_time(body.get('starts_at')) or now_utc()
    expires = _parse_time(body.get('expires_at'))
    if expires is None:
        raise PolicyError('an expiration time is required', 400)
    if expires <= starts:
        raise PolicyError('expiration must be after the start', 400)
    domains = body.get('domains') or []
    if kind == 'allow_domains':
        validate_domains(domains)
    else:
        domains = []
    if user.role.value == 'guardian':
        if kind in OWNER_ONLY_KINDS:
            raise PolicyError(
                'protection removal requires the owner/security administrator',
                403)
        if expires - starts > GUARDIAN_MAX_DURATION:
            raise PolicyError(
                'delegated exceptions are limited to 24 hours', 403)
    if expires - starts > OWNER_MAX_DURATION:
        raise PolicyError('exceptions are limited to 30 days', 400)
    return kind, scope_type, device_id, group_id, domains, reason, starts, expires


def _parse_time(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        raise PolicyError('invalid timestamp', 400)
    return _aware(parsed)


def exception_json(row):
    return {'id': row.id, 'kind': row.kind, 'scope_type': row.scope_type,
            'device_id': row.device_id, 'group_id': row.group_id,
            'domains': json.loads(row.domains), 'reason': row.reason,
            'approver_user_id': row.approver_user_id,
            'starts_at': _aware(row.starts_at).isoformat(),
            'expires_at': _aware(row.expires_at).isoformat(),
            'revoked_at': _aware(row.revoked_at).isoformat() if row.revoked_at else None,
            'active': row.revoked_at is None and _aware(row.expires_at) > now_utc()}
