"""Explicit single-group membership; direct device policy has precedence.

No group can weaken the selected default. This does not add bypasses,
exceptions or change authority over the protected baseline.
"""
from sqlalchemy import select
from .models import Device, DeviceGroup, GroupMembership, Policy, DeviceAssignment
from .policy_ops import PolicyError, enforce_on_new_assignment


def scoped_group(session, tenant_id, group_id):
    row=session.get(DeviceGroup,group_id)
    if row is None or row.tenant_id != tenant_id:
        raise PolicyError('group not found',404)
    return row


def checked_policy(session,tenant_id,policy_id):
    if policy_id is None:return None
    policy=session.get(Policy,policy_id)
    if policy is None or policy.tenant_id != tenant_id:
        raise PolicyError('policy not found',404)
    if not policy.enabled:raise PolicyError('disabled policy cannot be assigned',409)
    enforce_on_new_assignment(session,tenant_id,policy)
    return policy


def group_json(session,row):
    members=list(session.scalars(select(GroupMembership.device_id).where(
        GroupMembership.tenant_id==row.tenant_id,GroupMembership.group_id==row.id).order_by(GroupMembership.device_id)))
    return {'id':row.id,'name':row.name,'policy_id':row.policy_id,'device_ids':members,
            'precedence':'direct device assignment > group policy > tenant default'}


def effective_assignments(session,tenant_id):
    """Resolve and validate every active override, no ambiguous fallbacks."""
    result={}
    for member in session.scalars(select(GroupMembership).where(GroupMembership.tenant_id==tenant_id)):
        group=scoped_group(session,tenant_id,member.group_id)
        device=session.get(Device,member.device_id)
        if device is None or device.tenant_id != tenant_id:
            raise PolicyError('invalid group member',409)
        if group.policy_id is not None:
            checked_policy(session,tenant_id,group.policy_id)
            result[device.id]=group.policy_id
    seen=set()
    for direct in session.scalars(select(DeviceAssignment).where(
            DeviceAssignment.tenant_id==tenant_id,DeviceAssignment.active.is_(True))):
        if direct.device_id in seen:
            raise PolicyError('ambiguous active device assignments',409)
        seen.add(direct.device_id)
        result[direct.device_id]=direct.policy_id
    return result
