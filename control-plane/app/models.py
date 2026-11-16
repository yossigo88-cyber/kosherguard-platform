"""Control-plane data model.

The family is the tenant. Every scoped table carries tenant_id and the
data layer refuses cross-tenant access. Users are guardians of a tenant
with a role. Sessions store only token hashes. Audit events are
append-only.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Role(str, enum.Enum):
    owner = "owner"        # full control, manages other guardians
    guardian = "guardian"  # manages policies and devices
    viewer = "viewer"      # read-only


class StaffRole(str, enum.Enum):
    """Platform staff roles (Answer 29). A user with staff_role set is a
    staff account and must enroll MFA; the tenant Role still governs
    their home tenant. Customer/parent administrator is the tenant-side
    Role.owner/guardian - it is not a staff role."""
    owner = "owner"                          # full platform control; manages staff
    security_admin = "security_admin"        # security policy, categories, sensitive-op approvals
    support_admin = "support_admin"          # limited troubleshooting only
    read_only = "read_only"                  # viewing authorized information only


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    blocked_log_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=7, server_default="7")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role), nullable=False)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    delegated_settings: Mapped[str] = mapped_column(Text, nullable=False, default="[]", server_default="[]")
    is_platform_admin: Mapped[bool] = mapped_column(
        nullable=False, default=False)
    # Platform staff role (Answer 29). NULL for ordinary tenant users.
    # Legacy is_platform_admin rows are migrated to staff_role='owner'
    # by alembic 0017; new code reads staff_role only.
    staff_role: Mapped[str | None] = mapped_column(String(30), nullable=True)
    tenant: Mapped[Tenant] = relationship()
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True)
    mfa_verified: Mapped[bool] = mapped_column(nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class LoginAttempt(Base):
    """Persisted login-rate-limit state; restarts do not reset lockouts."""
    __tablename__ = "login_attempts"
    key: Mapped[str] = mapped_column(String(400), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_failure_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow)


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    engine_doc: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class PolicyVersion(Base):
    __tablename__ = "policy_versions"
    __table_args__ = (UniqueConstraint("policy_id", "version"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_id: Mapped[int] = mapped_column(
        ForeignKey("policies.id"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    engine_doc: Mapped[str] = mapped_column(Text, nullable=False)
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False,
                                       default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class DeviceAssignment(Base):
    __tablename__ = "device_assignments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id"), nullable=False)
    policy_id: Mapped[int] = mapped_column(
        ForeignKey("policies.id"), nullable=False)
    active: Mapped[bool] = mapped_column(nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class PublicationState(Base):
    __tablename__ = "publication_states"
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), primary_key=True)
    selected_policy_id: Mapped[int | None] = mapped_column(
        ForeignKey("policies.id"), nullable=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class MDMEnrollment(Base):
    """One device's MDM enrollment under a tenant.

    enrollment_id is the NanoMDM enrollment identifier once a real
    enrollment exists; until then it is a locally generated placeholder
    and the record carries state 'pending'.
    """
    __tablename__ = "mdm_enrollments"
    __table_args__ = (UniqueConstraint("tenant_id", "enrollment_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id"), nullable=False, index=True)
    enrollment_id: Mapped[str] = mapped_column(String(120), nullable=False)
    # The device UDID expected at enrollment (recorded when the
    # enrollment is created, from the device record / operator input,
    # NOT from any later caller claim). NanoMDM's device-channel
    # enrollment ID IS the UDID, so this is the association key that
    # lets the first authenticated DDM contact bind a pending record
    # to the real NanoMDM ID.
    device_udid: Mapped[str | None] = mapped_column(
        String(120), nullable=True)
    enrollment_ticket_id: Mapped[int | None] = mapped_column(
        ForeignKey("enrollment_tickets.id"), nullable=True)
    # Device identity certificate fingerprint presented at ticket
    # redemption, plus how far it could be verified (Answer 28).
    identity_cert_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True)
    identity_cert_status: Mapped[str | None] = mapped_column(
        String(30), nullable=True)
    state: Mapped[str] = mapped_column(String(20), nullable=False,
                                       default="pending")
    # Requested vs verified supervision are different facts. A guardian
    # requests supervision; only device-reported check-in data can verify
    # it. A pending, never-contacted enrollment can never show verified.
    supervision_requested: Mapped[bool] = mapped_column(
        nullable=False, default=False)
    supervision_verified: Mapped[bool] = mapped_column(
        nullable=False, default=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class DeviceAppPolicy(Base):
    """Per-device application allow/block policy (spec Part 10:
    Applications). Stored intent; applying it queues an InstallProfile
    command carrying a com.apple.applicationaccess payload through the
    normal MDM command lifecycle. Device behavior of that payload is
    BUILT-UNVERIFIED until the spec Part 17 device-testing phase.
    """
    __tablename__ = "device_app_policies"
    __table_args__ = (UniqueConstraint("tenant_id", "device_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id"), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), nullable=False,
                                      default="blocklist")
    bundle_ids: Mapped[str] = mapped_column(Text, nullable=False,
                                            default="[]")
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow,
        nullable=False)


class DDMStatusReport(Base):
    """A verbatim DDM status report from a device, received on the
    /api/ddm/status endpoint NanoMDM forwards (spec Part 10). RECEIPT
    ONLY: a stored report proves the enrollment sent a well-formed
    report, not that any declaration applied. Application evidence
    lives in declaration_states, extracted per the verified
    management.declarations shape (identifier + server-token + active
    + valid); it must be matched against what was actually served."""
    __tablename__ = "ddm_status_reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    enrollment_id: Mapped[str] = mapped_column(String(120), nullable=False,
                                               index=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    declaration_states: Mapped[str] = mapped_column(Text, nullable=False,
                                                    default="{}")
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class MDMCommand(Base):
    """One MDM command sent to one enrollment, with its full lifecycle.

    status moves queued -> delivered -> acknowledged | error | not_now.
    applied is set only from a positive device Acknowledged status plus,
    where verifiable, a confirming query - never from a successful send.
    """
    __tablename__ = "mdm_commands"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    enrollment_pk: Mapped[int] = mapped_column(
        ForeignKey("mdm_enrollments.id"), nullable=False, index=True)
    command: Mapped[str] = mapped_column(String(60), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    status: Mapped[str] = mapped_column(String(20), nullable=False,
                                        default="queued")
    applied: Mapped[bool] = mapped_column(nullable=False, default=False)
    result_detail: Mapped[str] = mapped_column(Text, nullable=False,
                                               default="")
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow,
        nullable=False)


class FilterDecision(Base):
    """One filtering decision reported by an edge service (proxy-edge
    today). Written only through POST /api/filter-logs with a valid
    scoped device credential; the tenant comes from the token, never
    from the request body. This is the real decision trail the
    Filtering panel shows - if no edge is connected, the table and the
    panel are simply empty, and the panel says so.
    """
    __tablename__ = "filter_decisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id"), nullable=True)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(10), nullable=False)
    rule: Mapped[str] = mapped_column(String(120), nullable=False,
                                      default="")
    reason: Mapped[str] = mapped_column(String(300), nullable=False,
                                        default="")
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class CategoryRule(Base):
    """Platform-wide domain -> category assignment (seed dataset).

    Provenance is recorded per row: who added it, from what source,
    when. A rule is never hard-deleted; deactivating keeps the audit
    trail. Platform-admin only via the /api/admin/categories routes;
    tenant guardians never see other tenants' data because these rows
    are not tenant data at all - they are the shared filter dataset.
    """
    __tablename__ = "category_rules"
    __table_args__ = (UniqueConstraint("domain"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    category: Mapped[str] = mapped_column(String(120), nullable=False)
    verdict: Mapped[str] = mapped_column(
        String(16), nullable=False, default="block")
    source: Mapped[str] = mapped_column(
        String(400), nullable=False, default="manual-review")
    added_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True)
    active: Mapped[bool] = mapped_column(nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)
    deactivated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


class PendingMfaEnrollment(Base):
    """Server-bound pending TOTP enrollment: the secret is generated
    and stored server-side, bound to exactly one user, single-use, and
    expires. Replaces the earlier stateless design in which the client
    supplied the secret at confirm time."""
    __tablename__ = "pending_mfa_enrollments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False, unique=True, index=True)
    secret: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class InviteToken(Base):
    """Guardian invitation. Stores only the token hash; the raw token
    is shown once to the inviting owner to deliver out of band."""
    __tablename__ = "invite_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role), nullable=False)
    token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True)
    invited_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True)
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class CredentialArtifact(Base):
    """One uploaded credential artifact's METADATA (APNs key, MDM push
    certificate, ADE token, entitlement file, ...). The secret bytes
    live only on the server's filesystem under the configured
    credentials root (mode 0600, outside Git); this row holds the
    fingerprint, size, storage path and lifecycle state. Content is
    never returned by the API. environment stamps the build the upload
    came from ("development" during this build: fixture credentials
    only - the UI says so on screen)."""
    __tablename__ = "credential_artifacts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(500), nullable=False)
    environment: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="active")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    uploaded_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


class IssuedCredential(Base):
    """Issuance registry for scoped device tokens. Stores the token's
    jti (never the token itself) so outstanding credentials can be
    revoked before their natural expiry: the revoke route marks rows,
    the revocation feed lists revoked jtis, and edge verifiers
    (proxy-edge, url-filter-server) refuse listed tokens."""
    __tablename__ = "issued_credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id"), nullable=False, index=True)
    jti: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True)
    scope: Mapped[str] = mapped_column(String(24), nullable=False)
    policy_id: Mapped[int | None] = mapped_column(
        Integer, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class PublicationJob(Base):
    """Durable tenant-scoped request to publish the then-current policy.

    Workers select only queued, due rows. Idempotency keys are scoped to
    the tenant so a different customer cannot collide with a request.
    """
    __tablename__ = "publication_jobs"
    __table_args__ = (UniqueConstraint("tenant_id", "request_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), index=True)
    actor_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    actor_email: Mapped[str] = mapped_column(String(320))
    request_key: Mapped[str] = mapped_column(String(100))
    # Server-set only, never from the jobs API: marks a narrow
    # server-initiated cleanup publication (e.g. "exception-revoke").
    system_action: Mapped[str | None] = mapped_column(String(40), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(200), nullable=True)


class DeviceGroup(Base):
    """One optional group policy per device; direct assignment wins."""
    __tablename__ = 'device_groups'
    __table_args__ = (UniqueConstraint('tenant_id', 'name'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey('tenants.id'), index=True)
    name: Mapped[str] = mapped_column(String(120))
    policy_id: Mapped[int | None] = mapped_column(ForeignKey('policies.id'), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PolicyException(Base):
    """Time-limited scoped exception: reason, approver, scope, window, audit."""
    __tablename__ = 'policy_exceptions'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey('tenants.id'), index=True)
    kind: Mapped[str] = mapped_column(String(30))
    scope_type: Mapped[str] = mapped_column(String(10))
    device_id: Mapped[int | None] = mapped_column(ForeignKey('devices.id'), nullable=True)
    group_id: Mapped[int | None] = mapped_column(ForeignKey('device_groups.id'), nullable=True)
    domains: Mapped[str] = mapped_column(Text, default="[]", server_default="[]")
    reason: Mapped[str] = mapped_column(Text)
    approver_user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GroupMembership(Base):
    __tablename__ = 'group_memberships'
    __table_args__ = (UniqueConstraint('device_id'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey('tenants.id'), index=True)
    group_id: Mapped[int] = mapped_column(ForeignKey('device_groups.id'))
    device_id: Mapped[int] = mapped_column(ForeignKey('devices.id'))


class SensitiveCommandApproval(Base):
    """Two-person approval for especially destructive operations
    (Answer 25): remote erase, ABM release, removal of protection,
    sensitive certificate operations. The requester and the approver
    must be two DIFFERENT privileged users, each passing fresh TOTP
    verification and an explicit confirmation. Nothing executes at
    request time; expiry is short so a stale pending request cannot be
    approved later."""
    __tablename__ = "sensitive_command_approvals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    enrollment_pk: Mapped[int | None] = mapped_column(
        ForeignKey("mdm_enrollments.id"), nullable=True)
    operation: Mapped[str] = mapped_column(String(60), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending")
    requested_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False)
    decided_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True)
    decision_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class CategorySource(Base):
    """A registered category-data source (Answer 22): name, license
    and attribution on record - an open-source repository license is
    NOT assumed to make the dataset commercially usable, so both
    fields are required. Imports arrive as reviewed updates."""
    __tablename__ = "category_sources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False,
                                      unique=True, index=True)
    license_name: Mapped[str] = mapped_column(String(300), nullable=False)
    attribution: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False,
                                        default="active")
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class CategorySourceUpdate(Base):
    """One imported dataset version for a source: version + SHA-256,
    category mapping, validation results, and its review state.
    Updates start pending_review and become active only through
    explicit staff review with fresh MFA; rollback reactivates a
    superseded update (one active per source at a time)."""
    __tablename__ = "category_source_updates"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(
        ForeignKey("category_sources.id"), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(120), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    category_mapping: Mapped[str] = mapped_column(Text, nullable=False,
                                                  default="{}")
    validation_results: Mapped[str] = mapped_column(Text, nullable=False,
                                                    default="{}")
    # pending_review | active | rejected | superseded | rolled_back
    status: Mapped[str] = mapped_column(String(20), nullable=False,
                                        default="pending_review")
    imported_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)
    reviewed_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    review_notes: Mapped[str] = mapped_column(Text, nullable=False,
                                              default="")


class OffboardingCase(Base):
    """Documented, verified offboarding (Answer 24). A case records the
    manual, verified process: initiator, ownership verification,
    per-kind attestation steps, data-retention date, completion. Cases
    NEVER trigger MDM commands, erasure, locks or Apple Business
    releases by themselves - nonpayment must never permanently lock a
    device and nothing auto-erases or auto-releases; every
    device-affecting step stays a separate, already gated action
    (two-person approval for destructive commands)."""
    __tablename__ = "offboarding_cases"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("devices.id"), nullable=True, index=True)
    # cancellation | transfer | loss_of_authority | dispute
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    # open | verified | completed | canceled
    status: Mapped[str] = mapped_column(String(20), nullable=False,
                                        default="open")
    created_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False)
    verified_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    # Recorded attestations of MANUAL steps done outside the platform
    # (Activation Lock cleared on the device, Apple Business release
    # performed in ABM). Never executed by this build.
    activation_lock_attested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    abm_release_attested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    data_retention_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


class EnrollmentTicket(Base):
    """Short-lived, single-use enrollment ticket (Answer 28). The raw
    token is shown once at issue and only its hash is stored. A ticket
    binds one tenant + one device record: redeeming it is the
    authenticated assignment proof - a serial number alone never is.
    used_at + a FOR UPDATE redemption make it single-use under
    concurrent redeems; expires_at + revoked_at bound its life."""
    __tablename__ = "enrollment_tickets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True)
    created_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)
