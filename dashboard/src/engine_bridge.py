"""Bridge to the existing KosherGuard filtering engine (Stage 3).

The dashboard reuses the filtering engine's policy validation, policy
evaluation, domain/category validation, and category-database code
instead of duplicating any of it. This module puts filtering-engine/src
on sys.path and re-exports exactly the pieces the dashboard uses, so
every dashboard module imports engine code from one place and the
integration surface is easy to audit.

If the filtering engine moves, only this file changes.
"""

import sys
from pathlib import Path

_ENGINE_SRC = Path(__file__).resolve().parents[2] / "filtering-engine" / "src"
if not _ENGINE_SRC.is_dir():
    raise RuntimeError(
        f"filtering-engine sources not found at {_ENGINE_SRC}; "
        "the dashboard must live in the same repository as filtering-engine/"
    )
if str(_ENGINE_SRC) not in sys.path:
    sys.path.insert(0, str(_ENGINE_SRC))

from category_db import (  # noqa: E402,F401  (re-exported intentionally)
    CategoryDB,
    CategoryDBError,
    validate_category,
    validate_domain,
)
from policy_engine import (  # noqa: E402,F401  (re-exported intentionally)
    CATEGORY_RE,
    DOMAIN_RE,
    VALID_ACTIONS,
    Decision,
    PolicyConfigError,
    PolicyEngine,
    domain_matches,
    normalize_domain,
    validate_policy,
)
from address_canonicalization import (  # noqa: E402,F401  (Stage 11A)
    BINDING_KINDS,
    BindingValidationError,
    canonicalize_binding,
    canonicalize_ipv4,
    canonicalize_ipv6_prefix,
    identity_class_for_kind,
)
from policy_comparison import (  # noqa: E402,F401  (Stage 11A)
    ComparisonResult,
    at_least_as_restrictive,
)
