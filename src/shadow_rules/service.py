"""领域服务：规则上传、批次演算、决议与导出。

可注入时钟，便于测试例外到期与恢复时序。
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from .clock import Clock, is_active, parse_stamp
from .engine import (
    STATUS_LABELS,
    RuleError,
    canonical,
    compile_rule,
    evaluate,
)
from .redaction import redact
from .store import connect, dumps, init_db, loads, transaction


def new_id() -> str:
    return uuid.uuid4().hex


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def payload_digest(rule_ids: tuple[str, str], secret_paths: list[str],
                   requests: list[Any]) -> str:
    material = {
        "current": rule_ids[0],
        "candidate": rule_ids[1],
        "secret_paths": sorted(secret_paths),
        "requests": requests,
    }
    return sha256_text(dumps(material))


def request_digest(redacted: Any) -> str:
    return sha256_text(dumps(redacted))


class ConflictError(Exception):
    def __init__(self, message: str, payload: dict[str, Any]):
        super().__init__(message)
        self.payload = payload


class NotFoundError(LookupError):
    pass


class ValidationError(ValueError):
    pass


def _explain(label: str, outcome: dict[str, Any]) -> str:
    if outcome["status"] != "ok":
        return f"{label}：{STATUS_LABELS.get(outcome['status'], outcome['status'])}（{outcome['error']}）"
    decision = "通过" if outcome["value"] else "拒绝"
    return f"{label}：{decision}"


def classify_diff(current: dict[str, Any], candidate: dict[str, Any]) -> str:
    if current["status"] != candidate["status"]:
        return "status_difference"
    if current["status"] != "ok":
        return "status_detail_difference"
    if current["value"] != candidate["value"]:
        return "decision_difference"
    if current["accessed"] != candidate["accessed"]:
        return "access_trace_difference"
    if current["short_circuits"] != candidate["short_circuits"]:
        return "short_circuit_difference"
    return "identical"


DIFF_LABELS = {
    "identical": "完全一致",
    "short_circuit_difference": "同结果不同短路路径",
    "access_trace_difference": "同结果不同字段轨迹",
    "decision_difference": "决策结果不同",
    "status_detail_difference": "异常类别相同但细节不同",
    "status_difference": "正常/异常状态不同",
}


class Service:
    def __init__(self, db_path: str, clock: Clock | None = None):
        self.conn = connect(db_path)
        init_db(self.conn)
        self.clock = clock or Clock()

    def close(self) -> None:
        self.conn.close()

    # ---- 规则版本 ----

    def upload_rule(self, name: str, rule: Any, parent_id: str | None) -> dict[str, Any]:
        try:
            normalized = compile_rule(rule)
        except RuleError as exc:
            raise ValidationError(str(exc)) from exc
        raw_text = rule if isinstance(rule, str) else dumps(rule)
        parent = None
        if parent_id is not None:
            row = self.conn.execute(
                "SELECT id FROM rule_versions WHERE id = ?", (parent_id,)
            ).fetchone()
            if row is None:
                raise ValidationError(f"父版本不存在: {parent_id}")
            parent = row["id"]
        rid = new_id()
        digest = sha256_text(canonical(normalized))
        with transaction(self.conn):
            self.conn.execute(
                """INSERT INTO rule_versions
                   (id, name, raw_text, raw_sha256, normalized, digest, parent_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (rid, name, raw_text, sha256_text(raw_text), dumps(normalized),
                 digest, parent, self.clock.stamp()),
            )
        return self.get_rule(rid)

    def get_rule(self, rid: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM rule_versions WHERE id = ?", (rid,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"规则版本不存在: {rid}")
        return {
            "id": row["id"],
            "name": row["name"],
            "raw_sha256": row["raw_sha256"],
            "normalized": loads(row["normalized"]),
            "digest": row["digest"],
            "parent_id": row["parent_id"],
            "created_at": row["created_at"],
        }

    def list_rules(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT id, name, digest, parent_id, created_at "
            "FROM rule_versions ORDER BY created_at, rowid"
        ).fetchall()
        return [dict(r) for r in rows]

    def _rule_expr(self, rid: str) -> Any:
        row = self.conn.execute(
            "SELECT normalized FROM rule_versions WHERE id = ?", (rid,)
        ).fetchone()
        if row is None:
            raise ValidationError(f"规则版本不存在: {rid}")
        return loads(row["normalized"])

    # ---- 批次 ----

    def _evaluate_side(self, expr: Any, request: Any, secret_paths: list[str]) -> dict[str, Any]:
        return evaluate(expr, request, secret_paths).as_dict()

    def _run_requests(self, batch_id: str, expr_cur: Any, expr_cand: Any,
                      secret_paths: list[str]) -> None:
        """逐条幂等写入结果；崩溃后重跑只补缺行，不重复追加。"""
        rows = self.conn.execute(
            "SELECT id, position, redacted_json FROM batch_requests "
            "WHERE batch_id = ? ORDER BY position",
            (batch_id,),
        ).fetchall()
        for row in rows:
            exists = self.conn.execute(
                "SELECT 1 FROM request_results WHERE request_id = ?", (row["id"],)
            ).fetchone()
            if exists is not None:
                continue
            request = loads(row["redacted_json"])
            cur = self._evaluate_side(expr_cur, request, secret_paths)
            cand = self._evaluate_side(expr_cand, request, secret_paths)
            category = classify_diff(cur, cand)
            explanations = {
                "current": _explain("当前版本", cur),
                "candidate": _explain("候选版本", cand),
            }
            self.conn.execute(
                """INSERT OR IGNORE INTO request_results
                   (request_id, current_json, candidate_json, diff_category, explanations_json)
                   VALUES (?, ?, ?, ?, ?)""",
                (row["id"], dumps(cur), dumps(cand), category, dumps(explanations)),
            )
            # 每行立即落盘：进程中途退出后已算结果不会丢，也不会重算追加。
            self.conn.commit()

    def create_batch(self, idempotency_key: str | None, current_rule_id: str,
                     candidate_rule_id: str, secret_paths: list[str],
                     requests: list[Any]) -> dict[str, Any]:
        expr_cur = self._rule_expr(current_rule_id)
        expr_cand = self._rule_expr(candidate_rule_id)
        digest = payload_digest(
            (current_rule_id, candidate_rule_id), secret_paths, requests
        )
        if idempotency_key:
            prior = self.conn.execute(
                "SELECT id, input_digest FROM batches WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if prior is not None:
                if prior["input_digest"] != digest:
                    raise ConflictError(
                        "幂等键相同但输入摘要不同",
                        {
                            "code": "idempotency_input_mismatch",
                            "existing_batch_id": prior["id"],
                            "existing_input_digest": prior["input_digest"],
                            "submitted_input_digest": digest,
                        },
                    )
                return self.get_batch(prior["id"], reused=True)

        batch_id = new_id()
        with transaction(self.conn):
            self.conn.execute(
                """INSERT INTO batches
                   (id, idempotency_key, input_digest, current_rule_id, candidate_rule_id,
                    revision, status, secret_schema, created_at)
                   VALUES (?, ?, ?, ?, ?, 1, 'pending', ?, ?)""",
                (batch_id, idempotency_key, digest, current_rule_id,
                 candidate_rule_id, dumps(sorted(secret_paths)), self.clock.stamp()),
            )
            for position, item in enumerate(requests):
                request = item["request"] if isinstance(item, dict) and "request" in item else item
                redacted = redact(request, secret_paths)
                self.conn.execute(
                    """INSERT INTO batch_requests (id, batch_id, position, redacted_json, digest)
                       VALUES (?, ?, ?, ?, ?)""",
                    (new_id(), batch_id, position, dumps(redacted),
                     request_digest(redacted)),
                )
        self._run_requests(batch_id, expr_cur, expr_cand, secret_paths)
        self.finalize_batch(batch_id)
        return self.get_batch(batch_id)

    def finalize_batch(self, batch_id: str) -> bool:
        """仅在全部结果就绪、尚未汇总时写一次汇总。返回本次是否完成。"""
        with transaction(self.conn):
            row = self.conn.execute(
                "SELECT status, secret_schema, current_rule_id, candidate_rule_id "
                "FROM batches WHERE id = ?",
                (batch_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"批次不存在: {batch_id}")
            if row["status"] == "done":
                return False
            missing = self.conn.execute(
                """SELECT 1 FROM batch_requests br
                   LEFT JOIN request_results rr ON rr.request_id = br.id
                   WHERE br.batch_id = ? AND rr.request_id IS NULL
                   LIMIT 1""",
                (batch_id,),
            ).fetchone()
            if missing is not None:
                return False
            counts: dict[str, int] = {}
            for r in self.conn.execute(
                """SELECT rr.diff_category AS c, COUNT(*) AS n
                   FROM request_results rr
                   JOIN batch_requests br ON br.id = rr.request_id
                   WHERE br.batch_id = ? GROUP BY rr.diff_category""",
                (batch_id,),
            ):
                counts[r["c"]] = r["n"]
            summary = {
                "total": sum(counts.values()),
                "by_category": counts,
                "identical": counts.get("identical", 0),
                "differences": sum(v for k, v in counts.items() if k != "identical"),
            }
            self.conn.execute(
                "UPDATE batches SET status = 'done', summary = ?, finalized_at = ? "
                "WHERE id = ? AND status = 'pending'",
                (dumps(summary), self.clock.stamp(), batch_id),
            )
        return True

    def recover_pending(self) -> list[str]:
        """重启后：只补缺失结果与汇总，已存在的结果不会重复追加。"""
        recovered: list[str] = []
        rows = self.conn.execute(
            "SELECT id, current_rule_id, candidate_rule_id, secret_schema "
            "FROM batches WHERE status = 'pending'"
        ).fetchall()
        for row in rows:
            secret_paths = loads(row["secret_schema"])
            expr_cur = self._rule_expr(row["current_rule_id"])
            expr_cand = self._rule_expr(row["candidate_rule_id"])
            self._run_requests(row["id"], expr_cur, expr_cand, secret_paths)
            if self.finalize_batch(row["id"]):
                recovered.append(row["id"])
        return recovered

    # ---- 查询 ----

    def _decision_view(self, row: Any) -> dict[str, Any]:
        active = is_active(row["expires_at"], self.clock)
        return {
            "id": row["id"],
            "request_id": row["request_id"],
            "batch_revision": row["batch_revision"],
            "version": row["version"],
            "verdict": row["verdict"],
            "reason": row["reason"],
            "expires_at": row["expires_at"],
            "decided_at": row["decided_at"],
            "active": active,
        }

    def get_batch(self, batch_id: str, reused: bool = False) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM batches WHERE id = ?", (batch_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(f"批次不存在: {batch_id}")
        secret_paths = loads(row["secret_schema"])
        requests_out: list[dict[str, Any]] = []
        for br in self.conn.execute(
            "SELECT * FROM batch_requests WHERE batch_id = ? ORDER BY position",
            (batch_id,),
        ):
            rr = self.conn.execute(
                "SELECT * FROM request_results WHERE request_id = ?", (br["id"],)
            ).fetchone()
            decision_row = self.conn.execute(
                "SELECT * FROM decisions WHERE batch_id = ? AND request_id = ?",
                (batch_id, br["id"]),
            ).fetchone()
            item = {
                "request_id": br["id"],
                "position": br["position"],
                "redacted_request": loads(br["redacted_json"]),
                "request_digest": br["digest"],
            }
            if rr is not None:
                item.update(
                    {
                        "current": loads(rr["current_json"]),
                        "candidate": loads(rr["candidate_json"]),
                        "diff_category": rr["diff_category"],
                        "diff_label": DIFF_LABELS.get(rr["diff_category"], rr["diff_category"]),
                        "explanations": loads(rr["explanations_json"]),
                    }
                )
            if decision_row is not None:
                item["decision"] = self._decision_view(decision_row)
            requests_out.append(item)
        return {
            "id": row["id"],
            "idempotency_key": row["idempotency_key"],
            "input_digest": row["input_digest"],
            "current_rule_id": row["current_rule_id"],
            "candidate_rule_id": row["candidate_rule_id"],
            "revision": row["revision"],
            "status": row["status"],
            "secret_paths": secret_paths,
            "summary": loads(row["summary"]),
            "created_at": row["created_at"],
            "finalized_at": row["finalized_at"],
            "reused": reused,
            "requests": requests_out,
        }

    def list_batches(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT id, idempotency_key, status, revision, summary, created_at, "
            "current_rule_id, candidate_rule_id FROM batches ORDER BY rowid DESC"
        ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["summary"] = loads(row["summary"])
            out.append(item)
        return out

    # ---- 决议 ----

    def put_decision(self, batch_id: str, request_id: str, verdict: str,
                     reason: str, expires_at: str | None, version: int) -> dict[str, Any]:
        if verdict not in ("accept", "block", "exception"):
            raise ValidationError("verdict 只能是 accept / block / exception")
        batch = self.conn.execute(
            "SELECT revision FROM batches WHERE id = ?", (batch_id,)
        ).fetchone()
        if batch is None:
            raise NotFoundError(f"批次不存在: {batch_id}")
        req = self.conn.execute(
            "SELECT 1 FROM batch_requests WHERE id = ? AND batch_id = ?",
            (request_id, batch_id),
        ).fetchone()
        if req is None:
            raise NotFoundError(f"请求不在该批次中: {request_id}")
        if verdict == "exception" and expires_at is None:
            raise ValidationError("限时例外必须提供 expires_at")
        if expires_at is not None:
            try:
                expiry = parse_stamp(expires_at)
            except ValueError as exc:
                raise ValidationError(f"expires_at 时间格式非法: {exc}") from exc
            if expiry <= self.clock.now():
                raise ValidationError("expires_at 必须晚于当前时间")

        current = self.conn.execute(
            "SELECT * FROM decisions WHERE batch_id = ? AND request_id = ?",
            (batch_id, request_id),
        ).fetchone()
        # 乐观锁：无决议时期望版本为 0，每次成功决议后版本号 +1。
        expected = current["version"] if current is not None else 0
        if version != expected:
            other = self._decision_view(current) if current is not None else None
            raise ConflictError(
                f"决议版本冲突：需要 {expected}，收到 {version}",
                {
                    "code": "decision_version_conflict",
                    "required_version": expected,
                    "submitted_version": version,
                    "existing_decision": other,
                    "submitted_reason": reason,
                    "submitted_verdict": verdict,
                },
            )
        if current is None:
            did = new_id()
            with transaction(self.conn):
                self.conn.execute(
                    """INSERT INTO decisions
                       (id, batch_id, request_id, batch_revision, version, verdict,
                        reason, expires_at, decided_at)
                       VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)""",
                    (did, batch_id, request_id, batch["revision"], verdict, reason,
                     expires_at, self.clock.stamp()),
                )
        else:
            did = current["id"]
            with transaction(self.conn):
                self.conn.execute(
                    """UPDATE decisions SET verdict = ?, reason = ?, expires_at = ?,
                       decided_at = ?, version = version + 1 WHERE id = ?""",
                    (verdict, reason, expires_at, self.clock.stamp(), did),
                )
        row = self.conn.execute("SELECT * FROM decisions WHERE id = ?", (did,)).fetchone()
        return self._decision_view(row)

    # ---- 导出（保证不含秘密）----

    def export_batch(self, batch_id: str) -> dict[str, Any]:
        batch = self.get_batch(batch_id)
        rule_cur = self._rule_summary(batch["current_rule_id"])
        rule_cand = self._rule_summary(batch["candidate_rule_id"])
        differences = []
        for item in batch["requests"]:
            if item.get("diff_category") in (None, "identical"):
                continue
            differences.append(
                {
                    "request_digest": item["request_digest"],
                    "diff_category": item["diff_category"],
                    "diff_label": item["diff_label"],
                    "current": item["current"],
                    "candidate": item["candidate"],
                    "explanations": item["explanations"],
                    "decision": item.get("decision"),
                }
            )
        return {
            "batch_id": batch["id"],
            "batch_revision": batch["revision"],
            "status": batch["status"],
            "exported_at": self.clock.stamp(),
            "rules": {"current": rule_cur, "candidate": rule_cand},
            "input": {
                "input_digest": batch["input_digest"],
                "secret_paths": batch["secret_paths"],
                "request_digests": [r["request_digest"] for r in batch["requests"]],
            },
            "summary": batch["summary"],
            "differences": differences,
        }

    def _rule_summary(self, rid: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT id, name, digest, raw_sha256, parent_id, created_at "
            "FROM rule_versions WHERE id = ?",
            (rid,),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"规则版本不存在: {rid}")
        return dict(row)
