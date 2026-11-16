"""Policy previews use the same scheduled engine as enforcement.

Templates are examples, not approved religious/content standards.
No user-provided URL paths or query strings are persisted.
"""
from __future__ import annotations
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'dns-edge')))
from schedules import ScheduledPolicyEngine
import category_db

TEMPLATES = {
    'strict-review': {
        'label': 'Strict: unknown domains blocked pending review',
        'description': 'Example starting point; owner approval required for actual categories.',
        'rules': {'default_policy': 'block', 'allowlist': [], 'blocklist': [],
                  'category_allow': [], 'category_block': []}},
    'category-mode': {
        'label': 'Category mode: explicit unknown-domain policy',
        'description': 'No categories are endorsed or preselected.',
        'rules': {'default_policy': 'allow', 'allowlist': [], 'blocklist': [],
                  'category_allow': [], 'category_block': []}},
}


def preview(document, domain, categories_path=None, moment=None):
    if not isinstance(domain, str) or not domain or len(domain) > 253:
        raise ValueError('domain must contain 1-253 characters')
    # Deliberately accept domain names only. Never collect a full URL.
    if any(c in domain for c in '/?#:@'):
        raise ValueError('preview accepts a domain, not a URL')
    from policy_engine import normalize_domain, validate_policy, DOMAIN_RE
    normalized = normalize_domain(domain)
    if not normalized or '.' not in normalized or not DOMAIN_RE.fullmatch(normalized):
        raise ValueError('a qualified domain is required')
    validate_policy(document)
    if categories_path:
        db = category_db.CategoryDB.load(categories_path)
    else:
        db = category_db.CategoryDB({})
    moment = moment or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise ValueError('preview time requires a timezone offset')
    engine = ScheduledPolicyEngine(document, db, now=lambda: moment)
    verdict = engine.decide(normalized)
    return {'domain': normalized, 'action': verdict.action,
            'rule': verdict.rule, 'category': verdict.category,
            'reason': verdict.reason,
            'at': moment.isoformat(),
            'scope': 'server-side policy preview only; not verified device behavior',
            'category_dataset_configured': bool(categories_path)}
