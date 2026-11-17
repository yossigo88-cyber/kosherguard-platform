"""Native MDM transport operations over the existing control-plane database.

These are real PKCS#12/CMS and Apple plist protocol implementations, tested
with synthetic TLS peers only. No Apple service/device validation claimed.
Only the dedicated TLS listener calls device_message with getpeercert DER.
No request header or client-supplied certificate field is trusted as mTLS.
"""
from __future__ import annotations

import hashlib
import json
import plistlib
import secrets
import uuid
import base64
from datetime import timedelta, timezone

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from sqlalchemy import select, or_

from mdm.identity import ProvisioningError, valid_cert, verify_signed_profile
from mdm.profiles import (ManualSupervisionDeclaration, _check_declaration,
                          build_provisioned_profile)
from .db import lock_tenant, ScopedSession
from .models import (Device, MDMEnrollment, MDMProvision, MDMCommand, utcnow)


class TransportError(RuntimeError):
    def __init__(self, message, status=403):
        super().__init__(message)
        self.status = status


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def aware(value):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class EnrollmentRuntime:
    """Explicitly configured issuer/signer, NEVER an insecure default.

    allowed_topics binds customer-specific APNs topic to a tenant. The
    encryption key protects stored push tokens at rest, separately from DB.
    Legal/business permission is an operator gate, not inferred from a cert.
    """
    def __init__(self, *, issuer, signer, signer_trust_file, base_url,
                 organization, allowed_topics, token_encryption_key,
                 authorization_reference, ade_verifier=None):
        from mdm.identity import https_url
        self.base_url = https_url(base_url)
        if not authorization_reference or not organization:
            raise ProvisioningError("documented authorization and organization required")
        if not allowed_topics or any(type(k) is not int or k < 1 or not isinstance(v, str) or not v.startswith("com.apple.mgmt.") for k, v in allowed_topics.items()):
            raise ProvisioningError("explicit tenant APNs topics required")
        if len(set(allowed_topics.values())) != len(allowed_topics):
            raise ProvisioningError("APNs topic must not be shared across customers")
        self.issuer, self.signer = issuer, signer
        self.signer_trust_file = signer_trust_file
        self.organization, self.topics = organization, dict(allowed_topics)
        self.fernet = Fernet(token_encryption_key)
        self.authorization_reference = authorization_reference
        self.ade_verifier = ade_verifier


def issue(session, runtime, *, tenant_id, device_id, udid, serial,
          mode="ordinary", declaration=None, actor_user_id=None):
    """Authenticated control-plane call, return raw download token ONCE.

    The UDID/serial are preregistered operator claims, not hardware proof.
    No device key is generated until the profile is actually downloaded.
    """
    if runtime is None:
        raise TransportError("native enrollment is not configured", 503)
    if mode not in {"ordinary", "manual_supervised", "ade"}:
        raise TransportError("invalid strategy", 400)
    if tenant_id not in runtime.topics:
        raise TransportError("tenant has no authorized APNs topic", 409)
    if not isinstance(udid, str) or not 8 <= len(udid) <= 120 or not isinstance(serial, str) or not 1 <= len(serial) <= 120:
        raise TransportError("pre-registered UDID and serial required", 400)
    if mode == "ade":
        if runtime.ade_verifier is None:
            raise TransportError("ADE assignment/Apple identity verifier not configured", 409)
        runtime.ade_verifier.check_assignment(tenant_id, serial, udid)
    if mode == "manual_supervised":
        try:
            _check_declaration(declaration, serial, None)
        except ValueError as exc:
            raise TransportError("invalid manual-supervision declaration", 400) from exc
    elif declaration is not None:
        raise TransportError("removal declaration is manual-only", 400)
    lock_tenant(session, tenant_id)
    device = session.scalar(select(Device).where(Device.id == device_id, Device.tenant_id == tenant_id).with_for_update())
    if not device:
        raise TransportError("device not found", 404)
    if device.state != "active":
        raise TransportError("device is not active", 409)
    current = session.scalar(select(MDMEnrollment.id).where(MDMEnrollment.device_id == device_id, MDMEnrollment.state.in_(["pending", "enrolled"])))
    if current:
        raise TransportError("device already has a current enrollment", 409)
    if session.scalar(select(MDMProvision.id).where(MDMProvision.udid == udid, MDMProvision.revoked_at.is_(None))):
        raise TransportError("device identity already reserved", 409)
    row = MDMEnrollment(tenant_id=tenant_id, device_id=device_id,
                        enrollment_id="native-" + secrets.token_hex(16),
                        device_udid=udid, state="pending",
                        supervision_requested=mode == "manual_supervised")
    session.add(row)
    session.flush()
    token = secrets.token_urlsafe(32)
    decl = {} if declaration is None else dict(
        serial_number=declaration.serial_number, supervised=declaration.supervised,
        recorded_by=declaration.recorded_by, recorded_at=declaration.recorded_at.isoformat(),
        evidence=sorted(declaration.evidence))
    provision = MDMProvision(tenant_id=tenant_id, enrollment_pk=row.id,
            udid=udid, serial=serial, mode=mode, topic=runtime.topics[tenant_id],
            stage="issued", declaration_json=json.dumps(decl),
            ticket_hash=digest(token), ticket_expires_at=utcnow()+timedelta(minutes=10))
    session.add(provision)
    session.flush()
    ScopedSession(session, tenant_id).audit("mdm.native.issue", f"enrollment {row.id} strategy {mode}", actor_user_id)
    return token, row.id


def _locked_provision(session, predicate):
    tenant = session.scalar(select(MDMProvision.tenant_id).where(predicate))
    if tenant is None:
        raise TransportError("unknown enrollment")
    lock_tenant(session, tenant)
    # Align with offboarding: tenant -> device -> provision -> enrollment.
    # Refresh after lock wait; cached ORM state must not resurrect offboarding.
    enrollment_pk = session.scalar(select(MDMProvision.enrollment_pk).where(predicate))
    device_id = session.scalar(select(MDMEnrollment.device_id).where(MDMEnrollment.id == enrollment_pk))
    device = session.scalar(select(Device).where(Device.id == device_id).with_for_update().execution_options(populate_existing=True))
    row = session.scalar(select(MDMProvision).where(predicate).with_for_update().execution_options(populate_existing=True))
    if row is None:
        raise TransportError("unknown enrollment")
    enrollment = session.scalar(select(MDMEnrollment).where(MDMEnrollment.id == row.enrollment_pk).with_for_update().execution_options(populate_existing=True))
    if (row.revoked_at is not None or enrollment.state not in {"pending", "enrolled"}
            or device is None or device.tenant_id != tenant or device.state != "active"
            or enrollment.tenant_id != tenant or enrollment.device_udid != row.udid):
        raise TransportError("enrollment is inactive", 410)
    return row, enrollment, device


def download_profile(session, runtime, token, machineinfo=None, attended_context=None):
    if runtime is None:
        raise TransportError("native enrollment is not configured", 503)
    if not isinstance(token, str) or not 30 <= len(token) <= 100:
        raise TransportError("invalid enrollment token")
    p, enrollment, device = _locked_provision(session, MDMProvision.ticket_hash == digest(token))
    if p.served_at is not None or p.stage != "issued":
        raise TransportError("enrollment token already used", 409)
    if aware(p.ticket_expires_at) <= utcnow():
        raise TransportError("enrollment token expired", 410)
    if runtime.topics.get(p.tenant_id) != p.topic:
        raise TransportError("tenant topic changed", 409)
    if p.mode == "ade":
        if runtime.ade_verifier is None or not machineinfo:
            raise TransportError("signed Apple MachineInfo required")
        # A fresh authenticated attended ceremony may authorize a reused CMS
        # inventory envelope, but never by possession of that envelope alone.
        # Its one-use session-bound attempt supplies a distinct replay scope.
        scope = attended_context.encode() if attended_context is not None else b""
        sha = hashlib.sha256(machineinfo+scope).hexdigest()
        if session.scalar(select(MDMProvision.id).where(MDMProvision.machineinfo_sha256 == sha)):
            raise TransportError("MachineInfo envelope already used", 409)
        runtime.ade_verifier.verify(p.tenant_id, p.serial, p.udid, machineinfo)
        p.machineinfo_sha256 = sha
    elif machineinfo is not None:
        raise TransportError("MachineInfo is only accepted for ADE", 400)
    declaration = None
    if p.mode == "manual_supervised":
        from datetime import datetime
        d = json.loads(p.declaration_json)
        d["recorded_at"] = datetime.fromisoformat(d["recorded_at"])
        d["evidence"] = frozenset(d["evidence"])
        declaration = ManualSupervisionDeclaration(**d)
    identity = runtime.issuer.issue(p.tenant_id, p.udid)
    raw = build_provisioned_profile(identity=identity, mode=p.mode,
        identity_uuid=str(uuid.uuid5(uuid.NAMESPACE_URL, "kosherguard:"+enrollment.enrollment_id)).upper(),
        server_url=runtime.base_url+"/mdm", checkin_url=runtime.base_url+"/checkin",
        topic=p.topic, organization=runtime.organization, device_name=device.name,
        removal_protection=declaration, device_serial=p.serial)
    signed = runtime.signer.sign(raw)
    if verify_signed_profile(signed, runtime.signer_trust_file) != raw:
        raise ProvisioningError("signed profile differs from generated profile")
    p.cert_der, p.cert_expires_at = identity.certificate_der, identity.expires_at
    p.cert_sha256 = hashlib.sha256(identity.certificate_der).hexdigest()
    p.served_at, p.stage, p.identity_health = utcnow(), "profile_served", "healthy"
    enrollment.identity_cert_sha256 = p.cert_sha256
    enrollment.identity_cert_status = "issued_native"
    ScopedSession(session, p.tenant_id).audit("mdm.native.profile_served", f"enrollment {enrollment.id}")
    return signed


def parse_message(data):
    if not data or len(data) > 1024*1024 or b"<!ENTITY" in data.upper():
        raise TransportError("invalid plist size or entities", 400)
    try:
        result = plistlib.loads(data)
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except Exception as exc:
        raise TransportError("invalid plist", 400) from exc


def device_message(session, runtime, peer_der, path, data):
    """peer_der MUST come from validated TLS socket, never HTTP input.

    Pin exact issued certificate in addition to listener's CA/EKU verification;
    check DB revocation and parent lifecycle on EVERY message. Authenticate
    does not claim hardware serial/supervision cryptographically established.
    """
    if runtime is None:
        raise TransportError("native enrollment is not configured", 503)
    if not peer_der:
        raise TransportError("client TLS certificate required")
    try:
        cert = x509.load_der_x509_certificate(peer_der)
        valid_cert(cert)
    except Exception as exc:
        raise TransportError("invalid client identity") from exc
    sha = cert.fingerprint(hashes.SHA256()).hex()
    p, enrollment, device = _locked_provision(session, or_(MDMProvision.cert_sha256 == sha, MDMProvision.pending_cert_sha256 == sha))
    is_pending = p.pending_cert_sha256 == sha
    pinned_der = p.pending_cert_der if is_pending else p.cert_der
    expiry = p.pending_cert_expires_at if is_pending else p.cert_expires_at
    if pinned_der != peer_der or expiry is None or aware(expiry) <= utcnow():
        raise TransportError("identity is expired or not pinned")
    if runtime.topics.get(p.tenant_id) != p.topic:
        raise TransportError("tenant topic changed", 409)
    message = parse_message(data)
    if message.get("UDID") != p.udid or "UserID" in message or "EnrollmentID" in message:
        raise TransportError("device/channel identity mismatch")
    if path == "/checkin":
        kind = message.get("MessageType")
        if kind == "Authenticate":
            if p.stage not in {"profile_served", "authenticated"} and not (is_pending and p.stage == "enrolled"):
                raise TransportError("unexpected Authenticate", 409)
            if message.get("Topic") != p.topic or message.get("SerialNumber") != p.serial:
                raise TransportError("topic/serial mismatch")
            if not is_pending:
                p.stage = "authenticated"
        elif kind == "TokenUpdate":
            if p.stage not in {"authenticated", "enrolled", "push_invalid"}:
                raise TransportError("TokenUpdate before Authenticate", 409)
            token, magic = message.get("Token"), message.get("PushMagic")
            if (message.get("Topic") != p.topic or not isinstance(token, bytes)
                    or not 16 <= len(token) <= 256 or not isinstance(magic, str)
                    or not 1 <= len(magic) <= 1024):
                raise TransportError("invalid push registration", 400)
            # UnlockToken is optional and retained when omitted. Never logged.
            previous = json.loads(runtime.fernet.decrypt(p.push_ciphertext.encode())) if p.push_ciphertext else {}
            previous.update(token=token.hex(), push_magic=magic)
            if "UnlockToken" in message:
                unlock = message["UnlockToken"]
                if not isinstance(unlock, bytes) or len(unlock) > 65536:
                    raise TransportError("invalid unlock token", 400)
                previous["unlock_token"] = unlock.hex()
            p.push_ciphertext = runtime.fernet.encrypt(json.dumps(previous).encode()).decode()
            p.stage, enrollment.state = "enrolled", "enrolled"
            p.push_state, p.push_attempts, p.push_next_at = "idle", 0, None
            schedule_push(session, tenant_id=p.tenant_id, enrollment_pk=enrollment.id)
            if is_pending:
                # Promote only on valid new-identity TokenUpdate, not CMS
                # signing, HTTP download, queued InstallProfile or old ACK.
                p.cert_der, p.cert_sha256, p.cert_expires_at = p.pending_cert_der, p.pending_cert_sha256, p.pending_cert_expires_at
                p.pending_cert_der = p.pending_cert_sha256 = p.pending_cert_expires_at = None
                enrollment.identity_cert_sha256 = p.cert_sha256
                for command in session.scalars(select(MDMCommand).where(MDMCommand.tenant_id==p.tenant_id,MDMCommand.enrollment_pk==enrollment.id,MDMCommand.command=="InstallProfile")):
                    payload=json.loads(command.payload)
                    if isinstance(payload,dict) and set(payload)=={"_native_encrypted_profile"}:
                        command.payload="{}"  # No historical replacement private-key retention.
                ScopedSession(session, p.tenant_id).audit("mdm.native.identity_rotated", f"enrollment {enrollment.id}")
        elif kind == "CheckOut":
            if p.stage not in {"authenticated", "enrolled", "push_invalid"}:
                raise TransportError("unexpected checkout", 409)
            cleanup_enrollment(session, tenant_id=p.tenant_id, enrollment_pk=enrollment.id, reason="checked_out")
            enrollment.state = "unenrolled"
        else:
            raise TransportError("unsupported check-in", 400)
        enrollment.last_seen_at = utcnow()
        ScopedSession(session, p.tenant_id).audit("mdm.native."+kind.lower(), f"enrollment {enrollment.id}")
        return b""
    if path != "/mdm" or p.stage != "enrolled" or enrollment.state != "enrolled":
        raise TransportError("device is not enrolled", 409)
    p.push_state, p.push_attempts, p.push_next_at = "idle", 0, None
    status = message.get("Status")
    if status not in {"Idle", "Acknowledged", "Error", "CommandFormatError", "NotNow"}:
        raise TransportError("invalid command status", 400)
    if status != "Idle":
        command_uuid = message.get("CommandUUID")
        if not isinstance(command_uuid, str) or not command_uuid.isdigit() or len(command_uuid) > 18:
            raise TransportError("unknown command", 409)
        command = session.scalar(select(MDMCommand).where(MDMCommand.id == int(command_uuid), MDMCommand.enrollment_pk == enrollment.id, MDMCommand.tenant_id == p.tenant_id).with_for_update())
        response_digest = hashlib.sha256(data).hexdigest()
        duplicate = command is not None and command.result_detail == "native response sha256:" + response_digest
        if command is None or (command.status != "delivered" and not duplicate):
            raise TransportError("command response is unknown or conflicting", 409)
        command.status = {"Acknowledged": "acknowledged", "NotNow": "not_now"}.get(status, "error")
        # Retain only a body digest, not sensitive query values/error chains.
        # Exact duplicate authenticated replies are idempotent when a prior
        # HTTP response was lost. Conflicting/reused UUID replies reject.
        command.result_detail = "native response sha256:" + response_digest
        if status == "NotNow":
            # Apple handling-notnow-status-responses: stop this session so
            # device polls when conditions change. Re-send same UUID on its
            # next poll; don't strand or silently overtake deferred policy.
            enrollment.last_seen_at = utcnow()
            return b""
        # Acknowledged is not independently verified applied filtering.
        command.applied = False
        if command.command == "DeviceInformation" and status == "Acknowledged":
            response = message.get("QueryResponses", {})
            if not isinstance(response, dict):
                raise TransportError("invalid DeviceInformation response", 400)
            if response.get("UDID", p.udid) != p.udid or response.get("SerialNumber", p.serial) != p.serial:
                raise TransportError("device information identity mismatch")
            enrollment.supervision_verified = response.get("IsSupervised") is True
    enrollment.last_seen_at = utcnow()
    # One in-flight command per enrollment. A duplicate Idle re-delivers the
    # SAME UUID; never advances the queue while an answer is outstanding.
    pending = session.scalar(select(MDMCommand).where(MDMCommand.enrollment_pk == enrollment.id, MDMCommand.tenant_id == p.tenant_id, MDMCommand.status == "delivered").order_by(MDMCommand.id).limit(1))
    if pending is None:
        pending = session.scalar(select(MDMCommand).where(MDMCommand.enrollment_pk == enrollment.id, MDMCommand.tenant_id == p.tenant_id, MDMCommand.status.in_(["queued", "not_now"])).order_by(MDMCommand.id).limit(1))
    if pending is None:
        return b""
    from mdm.command_codec import encode_command
    try:
        payload = json.loads(pending.payload)
        if pending.command == "InstallProfile" and isinstance(payload, dict) and set(payload) == {"_native_encrypted_profile"}:
            envelope = json.loads(runtime.fernet.decrypt(payload["_native_encrypted_profile"].encode()))
            if envelope.get("enrollment_pk") != enrollment.id or envelope.get("tenant_id") != p.tenant_id:
                raise ProvisioningError("encrypted profile scope mismatch")
            payload = {"Payload": envelope["cms_base64"]}
        wire = encode_command(pending.command, payload)
    except (ProvisioningError, ValueError) as exc:
        raise TransportError("invalid or unsupported queued command", 409) from exc
    pending.status = "delivered"
    return plistlib.dumps({"CommandUUID": str(pending.id), "Command": wire})


def revoke(session, *, tenant_id, enrollment_pk, actor_user_id=None):
    """Local disable: not device removal, ABM release or remote erase."""
    p, enrollment, _ = _locked_provision(session, (MDMProvision.tenant_id == tenant_id) & (MDMProvision.enrollment_pk == enrollment_pk))
    cleanup_enrollment(session, tenant_id=tenant_id, enrollment_pk=enrollment_pk, reason="revoked")
    enrollment.state = "offboarded"
    ScopedSession(session, tenant_id).audit("mdm.native.revoke", f"enrollment {enrollment_pk}", actor_user_id)


def customer_push(session, runtime, transport, *, tenant_id, enrollment_pk):
    """Invoke ONLY within customer's instance; never transfer the APNs key.

    The caller controls transaction/retry schedule. A successful APNs HTTP
    response is only acceptance, never delivery/acknowledgment. Latest device
    registration and parent offboarding are rechecked under tenant lock.
    """
    p, enrollment, _ = _locked_provision(session, (MDMProvision.tenant_id == tenant_id) & (MDMProvision.enrollment_pk == enrollment_pk))
    if p.stage not in {"enrolled", "push_invalid"} or not p.push_ciphertext or runtime.topics.get(tenant_id) != p.topic:
        raise TransportError("push registration unavailable", 409)
    secret = json.loads(runtime.fernet.decrypt(p.push_ciphertext.encode()))
    result = transport.push(topic=p.topic, token=secret["token"], push_magic=secret["push_magic"])
    if result.get("classification") == "bad_token":
        p.push_ciphertext = None
        p.stage = "push_invalid"
    ScopedSession(session, tenant_id).audit("mdm.native.push", f"enrollment {enrollment_pk} accepted {result.get('accepted') is True}")
    return result


def renew_identity(session, runtime, *, tenant_id, enrollment_pk, actor_user_id=None, declaration=None):
    """Queue same-identifier MDM profile replacement before expiry.

    Supported mechanism, local protocol/crypto-tested only. Hardware behavior
    and rollback recovery must be proved before using on a fleet. Old pin is
    kept until new-identity TokenUpdate, then old identity is disabled.
    """
    if runtime is None:
        raise TransportError("native enrollment not configured", 503)
    p, enrollment, device = _locked_provision(session, (MDMProvision.tenant_id == tenant_id) & (MDMProvision.enrollment_pk == enrollment_pk))
    if (p.stage != "enrolled" or p.pending_cert_sha256 is not None
            or p.cert_expires_at is None or aware(p.cert_expires_at) <= utcnow()+timedelta(hours=24)):
        raise TransportError("renew while enrolled and >24h before expiry with no pending rotation", 409)
    if runtime.topics.get(tenant_id) != p.topic:
        raise TransportError("tenant topic mismatch", 409)
    if p.mode == "manual_supervised":
        try:
            _check_declaration(declaration, p.serial, None)
        except ValueError as exc:
            raise TransportError("fresh manual-supervision declaration required", 400) from exc
    elif declaration is not None:
        raise TransportError("declaration is manual-only", 400)
    if declaration is not None:
        p.declaration_json = json.dumps(dict(serial_number=declaration.serial_number,
            supervised=declaration.supervised, recorded_by=declaration.recorded_by,
            recorded_at=declaration.recorded_at.isoformat(), evidence=sorted(declaration.evidence)))
    identity = runtime.issuer.issue(tenant_id, p.udid)
    raw = build_provisioned_profile(identity=identity, mode=p.mode,
        identity_uuid=str(uuid.uuid5(uuid.NAMESPACE_URL, "kosherguard:"+enrollment.enrollment_id)).upper(),
        server_url=runtime.base_url+"/mdm", checkin_url=runtime.base_url+"/checkin",
        topic=p.topic, organization=runtime.organization, device_name=device.name,
        removal_protection=declaration, device_serial=p.serial)
    signed = runtime.signer.sign(raw)
    if verify_signed_profile(signed, runtime.signer_trust_file) != raw:
        raise ProvisioningError("renewal CMS mismatch")
    envelope = json.dumps({"tenant_id":tenant_id,"enrollment_pk":enrollment_pk,
                           "cms_base64":base64.b64encode(signed).decode()})
    command = MDMCommand(tenant_id=tenant_id, enrollment_pk=enrollment_pk,
        command="InstallProfile", payload=json.dumps({"_native_encrypted_profile":runtime.fernet.encrypt(envelope.encode()).decode()}),
        status="queued", actor_user_id=actor_user_id)
    session.add(command)
    p.pending_cert_der, p.pending_cert_sha256 = identity.certificate_der, hashlib.sha256(identity.certificate_der).hexdigest()
    p.pending_cert_expires_at = identity.expires_at
    session.flush()
    schedule_push(session, tenant_id=tenant_id, enrollment_pk=enrollment_pk)
    ScopedSession(session, tenant_id).audit("mdm.native.identity_renewal_queued", f"enrollment {enrollment_pk} command {command.id}", actor_user_id)
    return command.id


def cleanup_enrollment(session, *, tenant_id, enrollment_pk, reason):
    """Common native cleanup while caller holds tenant/device lifecycle locks."""
    if reason not in {"revoked", "offboarded", "checked_out"}:
        raise ValueError("invalid cleanup reason")
    p = session.scalar(select(MDMProvision).where(MDMProvision.tenant_id == tenant_id, MDMProvision.enrollment_pk == enrollment_pk).with_for_update())
    if p is not None:
        p.revoked_at, p.stage, p.push_ciphertext = utcnow(), reason, None
        p.push_state, p.push_next_at = "disabled", None
        p.pending_cert_der = p.pending_cert_sha256 = p.pending_cert_expires_at = None
    for command in session.scalars(select(MDMCommand).where(MDMCommand.enrollment_pk == enrollment_pk, MDMCommand.tenant_id == tenant_id, MDMCommand.status.in_(["queued", "delivered", "not_now"]))):
        command.status, command.result_detail = "error", "enrollment " + reason
        payload=json.loads(command.payload)
        if isinstance(payload,dict) and set(payload)=={"_native_encrypted_profile"}:
            command.payload="{}"


def schedule_push(session, *, tenant_id, enrollment_pk):
    p = session.scalar(select(MDMProvision).where(MDMProvision.tenant_id == tenant_id, MDMProvision.enrollment_pk == enrollment_pk))
    if p is None or p.revoked_at is not None:
        return
    queued = session.scalar(select(MDMCommand.id).where(MDMCommand.tenant_id == tenant_id, MDMCommand.enrollment_pk == enrollment_pk, MDMCommand.status == "queued").limit(1))
    if queued and p.stage == "enrolled" and p.push_ciphertext and p.push_state in {"idle", "exhausted"}:
        p.push_state, p.push_attempts, p.push_next_at = "due", 0, utcnow()


def dispatch_customer_pushes(session, runtime, transport, *, tenant_id, limit=20, now=None):
    """Bounded durable outbox polling within customer's owned worker instance.

    Registry is tenant->topic in runtime plus a single customer transport.
    This worker may only dispatch that transport's matching tenant topic.
    Cert keys never cross to vendor. Backoff is persisted across restarts.
    """
    if runtime.topics.get(tenant_id) != transport.topic or not 1 <= limit <= 100:
        raise TransportError("customer transport registry mismatch")
    now = now or utcnow()
    lock_tenant(session, tenant_id)
    jobs = list(session.scalars(select(MDMProvision).where(MDMProvision.tenant_id == tenant_id, MDMProvision.revoked_at.is_(None), MDMProvision.push_next_at <= now).order_by(MDMProvision.push_next_at).limit(limit)))
    results = []
    for p in jobs:
        try:
            result = customer_push(session, runtime, transport, tenant_id=tenant_id, enrollment_pk=p.enrollment_pk)
        except TransportError:
            p.push_state, p.push_next_at = "disabled", None
            continue
        except Exception:
            result = {"accepted":False,"classification":"retryable"}
        p.push_attempts += 1
        classification = result.get("classification")
        if classification in {"bad_token", "cert_problem"}:
            p.push_state, p.push_next_at = classification, None
        elif p.push_attempts >= 8:
            p.push_state, p.push_next_at = "exhausted", None
        else:
            p.push_state = "awaiting_device" if result.get("accepted") else "backoff"
            delay = 300 if result.get("accepted") else min(3600, 15 * 2**(p.push_attempts-1))
            p.push_next_at = now + timedelta(seconds=delay)
        results.append({"enrollment_pk":p.enrollment_pk,"state":p.push_state})
    return results


def scan_identity_expiry(session, *, tenant_id, now=None):
    """State/audit only, no unsolicited messages or automatic Apple actions."""
    now = now or utcnow()
    lock_tenant(session, tenant_id)
    changed = []
    for p in session.scalars(select(MDMProvision).where(MDMProvision.tenant_id == tenant_id, MDMProvision.revoked_at.is_(None), MDMProvision.cert_expires_at.is_not(None))):
        remaining = aware(p.cert_expires_at)-now
        health = "expired" if remaining <= timedelta(0) else "renewal_due" if remaining <= timedelta(days=7) else "healthy"
        if p.identity_health != health:
            p.identity_health = health
            ScopedSession(session,tenant_id).audit("mdm.native.identity_health", f"enrollment {p.enrollment_pk} {health}")
            changed.append({"enrollment_pk":p.enrollment_pk,"health":health})
    return changed


def cancel_undelivered_renewal(session, runtime, *, tenant_id, enrollment_pk, actor_user_id=None):
    """Safe cancellation only while replacement is definitely not delivered.

    A delivered/failed update may already have changed device state. Never
    remove that pending pin on a guess; physical/device verification needed.
    """
    p,enrollment,_ = _locked_provision(session, (MDMProvision.tenant_id == tenant_id) & (MDMProvision.enrollment_pk == enrollment_pk))
    if p.pending_cert_sha256 is None:
        raise TransportError("no identity replacement pending",409)
    rows=list(session.scalars(select(MDMCommand).where(MDMCommand.tenant_id == tenant_id, MDMCommand.enrollment_pk == enrollment_pk, MDMCommand.command == "InstallProfile").order_by(MDMCommand.id.desc())))
    for command in rows:
        payload=json.loads(command.payload)
        if not isinstance(payload,dict) or set(payload)!={"_native_encrypted_profile"}:
            continue
        envelope=json.loads(runtime.fernet.decrypt(payload["_native_encrypted_profile"].encode()))
        if envelope.get("enrollment_pk")!=enrollment_pk or envelope.get("tenant_id")!=tenant_id:
            raise TransportError("replacement scope mismatch")
        if command.status!="queued":
            raise TransportError("replacement may have reached device; do not discard pending identity without verification",409)
        command.status,command.result_detail,command.payload="error","undelivered renewal canceled","{}"
        p.pending_cert_der=p.pending_cert_sha256=p.pending_cert_expires_at=None
        ScopedSession(session,tenant_id).audit("mdm.native.identity_renewal_canceled",f"enrollment {enrollment_pk}",actor_user_id)
        return
    raise TransportError("matching undelivered renewal not found",409)
