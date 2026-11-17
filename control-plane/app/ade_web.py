"""Attended reusable ADE web enrollment. No unattended CMS-only key delivery.

A stable configuration_web_url opens a fresh login ceremony. Apple CMS gives
inventory data but cannot issue a profile. A fresh guardian MFA session,
current assignment, pre-approved inventory and explicit restart confirmation
create a short-lived attempt, whose private profile is delivered ONLY to that
same authenticated browser session and ceremony. This is attended recovery,
not hardware-freshness attestation or automatic unattended recovery.
"""
from datetime import timedelta
import base64
import json
import secrets

from sqlalchemy import select, text, func

from . import native_mdm as n
from .db import lock_tenant, ScopedSession
from .models import (MDMAppleInventory, MDMWebActivation, MDMWebCeremony, AuthSession,
                     MDMEnrollment, Device, utcnow)


def begin(session,runtime, envelope):
    if runtime is None or runtime.ade_verifier is None or not envelope or len(envelope)>65536:
        raise n.TransportError("attended ADE is not configured or invalid request",503)
    info,signer=runtime.ade_verifier.inspect(envelope)
    if not 1<=len(info["SERIAL"])<=120 or not 8<=len(info["UDID"])<=120:
        raise n.TransportError("invalid device inventory",400)
    ceremony=secrets.token_urlsafe(32)
    state=runtime.fernet.encrypt(json.dumps({"ceremony":ceremony,"started_at":utcnow().isoformat(),
        "envelope":base64.b64encode(envelope).decode(),"serial":info["SERIAL"],"udid":info["UDID"],"signer":signer}).encode()).decode()
    # Cookie carries only opaque nonce, not a CMS chain larger than browser
    # cookie limits. Bound anonymous DB rows under a PostgreSQL advisory lock.
    if session.bind.dialect.name != "postgresql":
        raise n.TransportError("ADE web service requires PostgreSQL",503)
    session.execute(text("SELECT pg_advisory_xact_lock(7102315)"))
    session.query(MDMWebCeremony).filter(MDMWebCeremony.expires_at<=utcnow()).delete()
    if session.scalar(select(func.count()).select_from(MDMWebCeremony))>=1000:
        raise n.TransportError("ADE web enrollment capacity reached",429)
    token=secrets.token_urlsafe(32)
    session.add(MDMWebCeremony(token_hash=n.digest(token),encrypted_state=state,expires_at=utcnow()+timedelta(minutes=10)))
    session.flush()
    return token


def _ceremony(session,runtime,state):
    from datetime import datetime
    try:
        row=session.scalar(select(MDMWebCeremony).where(MDMWebCeremony.token_hash==n.digest(state),MDMWebCeremony.expires_at>utcnow()))
        if row is None:raise ValueError("unknown ceremony")
        data=json.loads(runtime.fernet.decrypt(row.encrypted_state.encode(),ttl=600))
        data["started_at"]=datetime.fromisoformat(data["started_at"])
        return data
    except Exception as exc:
        raise n.TransportError("expired or invalid ADE browser ceremony",410) from exc


def _fresh_session(session,token,user_id,started_at):
    if not token:
        raise n.TransportError("fresh guardian sign-in required",401)
    row=session.scalar(select(AuthSession).where(AuthSession.token_hash==n.digest(token),AuthSession.user_id==user_id))
    if (row is None or not row.mfa_verified or n.aware(row.expires_at)<=utcnow()
            or n.aware(row.created_at)<started_at or utcnow()-n.aware(row.created_at)>timedelta(minutes=5)):
        raise n.TransportError("sign in again with MFA after starting ADE",403)
    return row.token_hash


def approve_inventory(session,*,tenant_id,device_id,serial,udid,actor_user_id):
    if not isinstance(serial,str) or not 1<=len(serial)<=120 or not isinstance(udid,str) or not 8<=len(udid)<=120:
        raise n.TransportError("invalid inventory identifiers",400)
    lock_tenant(session,tenant_id)
    device=session.scalar(select(Device).where(Device.id==device_id,Device.tenant_id==tenant_id).with_for_update())
    if not device or device.state!="active":
        raise n.TransportError("active tenant device required",404)
    if session.scalar(select(MDMAppleInventory.id).where(MDMAppleInventory.device_id==device_id)):
        raise n.TransportError("inventory already approved; use guarded same-device inventory correction",409)
    row=MDMAppleInventory(tenant_id=tenant_id,device_id=device_id,serial=serial,udid=udid,approved_by=actor_user_id)
    session.add(row);session.flush()
    ScopedSession(session,tenant_id).audit("mdm.ade.inventory_approved",f"device {device_id}; operator-verified inventory, not hardware attestation",actor_user_id)
    return row


def authorize(session,runtime,*,state,session_token,user,device_id,restart):
    data=_ceremony(session,runtime,state)
    session_hash=_fresh_session(session,session_token,user.id,data["started_at"])
    lock_tenant(session,user.tenant_id)
    inv=session.scalar(select(MDMAppleInventory).where(MDMAppleInventory.tenant_id==user.tenant_id,MDMAppleInventory.device_id==device_id))
    if inv is None or inv.serial!=data["serial"] or inv.udid!=data["udid"]:
        raise n.TransportError("CMS device does not match approved tenant inventory")
    verifier=runtime.ade_verifier
    # Fresh guardian approval binds the actual CMS signer to existing approved
    # inventory for THIS attempt only, no silent global/permanent trust upgrade.
    try:
        assignment=verifier.lookup(user.tenant_id,inv.serial)
    except Exception as exc:
        raise n.TransportError("current Apple assignment could not be verified",503) from exc
    if (not isinstance(assignment,dict) or assignment.get("assigned") is not True
            or assignment.get("udid")!=inv.udid):
        raise n.TransportError("device is not currently assigned to tenant/server")
    device=session.scalar(select(Device).where(Device.id==device_id).with_for_update().execution_options(populate_existing=True))
    current=list(session.scalars(select(MDMEnrollment).where(MDMEnrollment.device_id==device_id,MDMEnrollment.tenant_id==user.tenant_id,MDMEnrollment.state.in_(["pending","enrolled"]))))
    if current and restart is not True:
        raise n.TransportError("explicit guardian restart confirmation required",409)
    for old in current:
        # An attended erase/recovery attempt must not impersonate remote
        # removal: this local action only disables previous server identity.
        n.cleanup_enrollment(session,tenant_id=user.tenant_id,enrollment_pk=old.id,reason="revoked")
        old.state="offboarded"
    session.flush()
    # Isolated per-attempt verifier copy, not global mutation across tenants.
    from mdm.ade_identity import ADEIdentityVerifier
    local=ADEIdentityVerifier(apple_root_file=verifier.apple_root_file,assigned_device_lookup=verifier.lookup,
                             signer_pins={(user.tenant_id,inv.serial):data["signer"]})
    import copy
    scoped=copy.copy(runtime);scoped.ade_verifier=local
    token,pk=n.issue(session,scoped,tenant_id=user.tenant_id,device_id=device_id,udid=inv.udid,serial=inv.serial,mode="ade",actor_user_id=user.id)
    nonce=secrets.token_urlsafe(32)
    attempt=MDMWebActivation(tenant_id=user.tenant_id,enrollment_pk=pk,nonce_hash=n.digest(nonce),
        session_hash=session_hash,ceremony_hash=n.digest(data["ceremony"]),
        encrypted_attempt=runtime.fernet.encrypt(json.dumps({"token":token,"envelope":data["envelope"],"signer":data["signer"],"serial":inv.serial}).encode()).decode(),
        expires_at=utcnow()+timedelta(minutes=5))
    session.add(attempt);session.flush()
    ScopedSession(session,user.tenant_id).audit("mdm.ade.attended_authorized",f"enrollment {pk}; current guardian authorization, not physical activation proof",user.id)
    return nonce


def deliver(session,runtime,*,state,session_token,user,nonce):
    data=_ceremony(session,runtime,state)
    session_hash=_fresh_session(session,session_token,user.id,data["started_at"])
    lock_tenant(session,user.tenant_id)
    attempt=session.scalar(select(MDMWebActivation).where(MDMWebActivation.nonce_hash==n.digest(nonce),MDMWebActivation.tenant_id==user.tenant_id).with_for_update())
    if (attempt is None or attempt.used_at is not None or n.aware(attempt.expires_at)<=utcnow()
            or attempt.session_hash!=session_hash or attempt.ceremony_hash!=n.digest(data["ceremony"])):
        raise n.TransportError("profile attempt is expired/used or belongs to another browser session",409)
    secret=json.loads(runtime.fernet.decrypt(attempt.encrypted_attempt.encode()))
    from mdm.ade_identity import ADEIdentityVerifier
    import copy
    scoped=copy.copy(runtime)
    scoped.ade_verifier=ADEIdentityVerifier(apple_root_file=runtime.ade_verifier.apple_root_file,
        assigned_device_lookup=runtime.ade_verifier.lookup,signer_pins={(user.tenant_id,secret["serial"]):secret["signer"]})
    profile=n.download_profile(session,scoped,secret["token"],machineinfo=base64.b64decode(secret["envelope"],validate=True),attended_context=attempt.nonce_hash)
    attempt.used_at=utcnow();attempt.encrypted_attempt="{}"
    return profile


def correct_inventory(session,*,tenant_id,device_id,serial,udid,actor_user_id):
    """Audited same-device correction ONLY with no current enrollment.

    Never rewrites an installed identity or silently moves inventory between
    tenants/devices. Tenant transfer still requires explicit offboarding.
    """
    lock_tenant(session,tenant_id)
    device=session.scalar(select(Device).where(Device.id==device_id,Device.tenant_id==tenant_id).with_for_update())
    if device is None or device.state!="active":
        raise n.TransportError("active tenant device required",404)
    if session.scalar(select(MDMEnrollment.id).where(MDMEnrollment.device_id==device_id,MDMEnrollment.state.in_(["pending","enrolled"]))):
        raise n.TransportError("revoke/complete current enrollment before correcting inventory",409)
    row=session.scalar(select(MDMAppleInventory).where(MDMAppleInventory.tenant_id==tenant_id,MDMAppleInventory.device_id==device_id).with_for_update())
    if row is None:raise n.TransportError("approved inventory not found",404)
    if not isinstance(serial,str) or not 1<=len(serial)<=120 or not isinstance(udid,str) or not 8<=len(udid)<=120:
        raise n.TransportError("invalid inventory identifiers",400)
    row.serial,row.udid,row.approved_by=serial,udid,actor_user_id
    session.flush()
    ScopedSession(session,tenant_id).audit("mdm.ade.inventory_corrected",f"device {device_id}; no active enrollment; new operator inventory approval",actor_user_id)
    return row


def release_inventory(session,*,tenant_id,device_id,actor_user_id):
    """Local inventory release only after completed offboarding, never Apple."""
    lock_tenant(session,tenant_id)
    device=session.scalar(select(Device).where(Device.id==device_id,Device.tenant_id==tenant_id).with_for_update())
    if device is None:raise n.TransportError("device not found",404)
    if device.state!="offboarded" or session.scalar(select(MDMEnrollment.id).where(MDMEnrollment.device_id==device_id,MDMEnrollment.state.in_(["pending","enrolled"]))):
        raise n.TransportError("complete device offboarding before releasing local inventory",409)
    row=session.scalar(select(MDMAppleInventory).where(MDMAppleInventory.tenant_id==tenant_id,MDMAppleInventory.device_id==device_id).with_for_update())
    if row is None:raise n.TransportError("approved inventory not found",404)
    session.delete(row);session.flush()
    ScopedSession(session,tenant_id).audit("mdm.ade.inventory_released",f"device {device_id}; local inventory only, no Apple release performed",actor_user_id)
