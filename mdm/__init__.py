"""KosherGuard MDM adapter package (Milestone 4).

See docs/evaluations/MDM_ADE_EVALUATION.md. NanoMDM (MIT, Go) is the MDM
protocol server; this package is the narrow interface our control plane
uses to enqueue commands and reconcile device status. Nothing here holds
or needs Apple credentials; live APNs/enrollment paths are blocked until
the Stage 6 prerequisites land.
"""

from .adapter import (  # noqa: F401
    CommandResult,
    MDMAdapter,
    MDMAdapterError,
    NanoMDMAdapter,
    SimulatedMDMAdapter,
    SUPPORTED_COMMANDS,
)
