"""NanoDEP / ADE sync shell.

NanoDEP (MIT, Go) talks to Apple's Device Enrollment Program API: token
sync, device fetch, enrollment-profile assignment. KosherGuard's Apple
Business organization is currently "Not Qualified" with an unresolved
account conflict (docs/MDM_ENROLLMENT_AND_PUSH.md prerequisite 3), so
NO live ADE path exists and this module deliberately contains no
working Apple API client.

What exists here, so the integration shape is settled and testable:
- ADESyncPlan: the declarative record of what a sync WOULD do
  (assign profile P to serials S) that a future NanoDEP sidecar
  executes. Building a plan requires no credentials and performs no
  network calls.
- Validation of the plan against our own enrollment records, with
  tenant scoping: a plan may only reference device serials registered
  to the same tenant.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class ADEError(RuntimeError):
    pass


@dataclass
class ADESyncPlan:
    tenant_id: int
    profile_name: str
    serials: list[str] = field(default_factory=list)

    def validate_against(self, known_serials: set[str]) -> None:
        """Every serial in the plan must be a known device of the same
        tenant. Unknown serials are rejected rather than silently
        skipped: a typo'd serial that assigns the wrong device is a
        security event, not a no-op."""
        unknown = [s for s in self.serials if s not in known_serials]
        if unknown:
            raise ADEError(
                f"unknown device serials for tenant {self.tenant_id}: "
                + ", ".join(sorted(unknown)))


def build_sync_plan(tenant_id: int, profile_name: str,
                    serials: list[str],
                    known_serials: set[str]) -> ADESyncPlan:
    """Build and validate a sync plan. No network, no credentials."""
    if not profile_name:
        raise ADEError("profile_name is required")
    plan = ADESyncPlan(tenant_id=tenant_id, profile_name=profile_name,
                       serials=list(serials))
    plan.validate_against(known_serials)
    return plan
