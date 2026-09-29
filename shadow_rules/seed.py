"""Preset rules, requests and a demo batch covering both diff categories."""
from __future__ import annotations

import json

from . import engine
from .redact import DEFAULT_SECRET_FIELDS, sanitize
from .rules import digest_rule, digest_text, normalize

RULE_BASELINE = {
    "op": "and",
    "args": [
        {"op": "ge", "left": {"field": "age"}, "right": 18},
        {"op": "fallback", "args": [
            {"op": "le", "left": {"field": "score"}, "right": 700},
            False,
        ]},
    ],
}

RULE_CANDIDATE = {
    "op": "and",
    "args": [
        {"op": "gt", "left": {"field": "age"}, "right": 18},
        {"op": "or", "args": [
            {"op": "le", "left": {"field": "score"}, "right": 700},
            {"op": "not", "arg": {"op": "exists", "field": "score"}},
        ]},
    ],
}

SEED_REQUESTS = [
    # age 18: baseline passes (ge), candidate rejects (gt) -> outcome diff
    {"id": "req-001", "body": {"age": 18, "score": 500,
                               "ssn": "123-45-6789"}},
    # both reject, but via different paths/field accesses -> path diff
    {"id": "req-002", "body": {"age": 20, "score": 800}},
    # explicit null score: baseline falls back, candidate errors on null
    {"id": "req-003", "body": {"age": 25, "score": None}},
]

SEED_BATCH_KEY = "seed:baseline-vs-candidate"


def seed(store, clock, secret_fields=None):
    if store.list_rules():
        return
    secret_fields = secret_fields or DEFAULT_SECRET_FIELDS
    baseline_text = json.dumps(RULE_BASELINE, ensure_ascii=False, indent=2)
    candidate_text = json.dumps(RULE_CANDIDATE, ensure_ascii=False, indent=2)
    rule_a = store.add_rule("baseline-v1", baseline_text,
                            digest_text(baseline_text), normalize(RULE_BASELINE),
                            digest_rule(RULE_BASELINE), None, clock)
    rule_b = store.add_rule("candidate-v2", candidate_text,
                            digest_text(candidate_text),
                            normalize(RULE_CANDIDATE),
                            digest_rule(RULE_CANDIDATE), rule_a["id"], clock)
    request_ids = []
    for item in SEED_REQUESTS:
        clean = sanitize(item["body"], secret_fields)
        store.add_request(item["id"], clean,
                          digest_text(json.dumps(clean, sort_keys=True)),
                          clock)
        request_ids.append(item["id"])
    engine.create_batch(store, SEED_BATCH_KEY, rule_a["id"], rule_b["id"],
                        request_ids, clock)
