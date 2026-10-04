import json
import sqlite3
from datetime import datetime, timezone

from .audit import audit_hash, canonical_json
from .domain import ConflictError, NotFoundError, DomainError
from .rules import assess


def now_iso():
    return datetime.now(timezone.utc).isoformat()


class Repository:
    def __init__(self, path):
        self.path = path

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self):
        conn = self.connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    stable_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    payload TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(entity_type, stable_key)
                );
                CREATE TABLE IF NOT EXISTS sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    source_type TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, source_type, external_id),
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER,
                    event_type TEXT NOT NULL,
                    actor TEXT,
                    role TEXT,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pipeline_id TEXT NOT NULL,
                    segment_id TEXT NOT NULL,
                    valve_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(pipeline_id, segment_id, valve_id)
                );
                CREATE TABLE IF NOT EXISTS topology_meta (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    version INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS valves (
                    valve_id TEXT PRIMARY KEY,
                    position TEXT NOT NULL DEFAULT 'unknown',
                    occupied_by INTEGER,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS isolation_plans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    pipeline_id TEXT NOT NULL,
                    segment_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    severity_score REAL NOT NULL,
                    valves TEXT NOT NULL,
                    closed_valves TEXT NOT NULL DEFAULT '[]',
                    occupied_valves TEXT NOT NULL DEFAULT '[]',
                    failed_valve TEXT,
                    topology_version INTEGER NOT NULL,
                    topology_drifted INTEGER NOT NULL DEFAULT 0,
                    conflict TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_plans_active
                    ON isolation_plans(item_id)
                    WHERE status NOT IN ('completed','invalidated');
                CREATE TABLE IF NOT EXISTS valve_receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plan_id INTEGER NOT NULL,
                    valve_id TEXT NOT NULL,
                    result TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 1,
                    observed_at TEXT,
                    source TEXT,
                    created_at TEXT NOT NULL,
                    last_observed_at TEXT,
                    UNIQUE(plan_id, valve_id)
                );
                """
            )
        finally:
            conn.close()

    def _row_to_item(self, row):
        if row is None:
            return None
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def _last_hash(self, conn, item_id):
        row = conn.execute(
            "SELECT event_hash FROM audit_events WHERE item_id IS ? ORDER BY id DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        return row["event_hash"] if row else "GENESIS"

    def append_audit(self, conn, item_id, event_type, actor, role, payload):
        previous = self._last_hash(conn, item_id)
        event = {
            "item_id": item_id,
            "event_type": event_type,
            "actor": actor,
            "role": role,
            "payload": payload,
            "created_at": now_iso(),
        }
        event_hash = audit_hash(previous, event)
        conn.execute(
            "INSERT INTO audit_events(item_id,event_type,actor,role,payload,previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (item_id, event_type, actor, role, canonical_json(payload), previous, event_hash, event["created_at"]),
        )

    def create_item(self, entity_type, stable_key, initial_status, payload, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT INTO items(entity_type,stable_key,status,version,payload,created_by,created_role,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        entity_type,
                        stable_key,
                        initial_status,
                        1,
                        canonical_json(payload),
                        actor,
                        role,
                        now_iso(),
                        now_iso(),
                    ),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_item", "同一业务实体已经存在")
            item_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(conn, item_id, "created", actor, role, {"stable_key": stable_key})
            conn.execute("COMMIT")
            return self.get_item(item_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def get_item(self, item_id):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            return self._row_to_item(row)
        finally:
            conn.close()

    def list_items(self, status=None):
        conn = self.connect()
        try:
            if status:
                rows = conn.execute("SELECT * FROM items WHERE status=? ORDER BY id DESC", (status,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM items ORDER BY id DESC").fetchall()
            return [self._row_to_item(row) for row in rows]
        finally:
            conn.close()

    def add_source(self, item_id, source_type, external_id, payload, observed_at, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            item = conn.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            try:
                conn.execute(
                    "INSERT INTO sources(item_id,source_type,external_id,payload,observed_at,created_at) VALUES(?,?,?,?,?,?)",
                    (item_id, source_type, external_id, canonical_json(payload), observed_at, now_iso()),
                )
            except sqlite3.IntegrityError:
                raise ConflictError("duplicate_source", "同一来源记录已经提交")
            source_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self.append_audit(
                conn,
                item_id,
                "source_recorded",
                actor,
                role,
                {"source_id": source_id, "source_type": source_type, "external_id": external_id},
            )
            conn.execute("COMMIT")
            return {"id": source_id, "item_id": item_id, "source_type": source_type, "external_id": external_id, "payload": payload, "observed_at": observed_at}
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def list_sources(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM sources WHERE item_id=? ORDER BY id DESC", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def apply_action(self, item_id, action, actor, role, new_status, new_payload, event_payload, expected_version=None):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            if expected_version is not None and int(expected_version) != int(row["version"]):
                raise ConflictError("version_conflict", "记录已被其他操作更新，请重新读取")
            version = int(row["version"]) + 1
            conn.execute(
                "UPDATE items SET status=?,version=?,payload=?,updated_at=? WHERE id=?",
                (new_status, version, canonical_json(new_payload), now_iso(), item_id),
            )
            conn.execute(
                "INSERT INTO actions(item_id,action,actor,role,payload,created_at) VALUES(?,?,?,?,?,?)",
                (item_id, action, actor, role, canonical_json(event_payload), now_iso()),
            )
            self.append_audit(conn, item_id, action, actor, role, event_payload)
            conn.execute("COMMIT")
            return self.get_item(item_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def audit_trail(self, item_id):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM audit_events WHERE item_id=? ORDER BY id", (item_id,)).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value["payload"])
                result.append(value)
            return result
        finally:
            conn.close()

    def state_summary(self):
        conn = self.connect()
        try:
            counts = {}
            for row in conn.execute("SELECT status, COUNT(*) AS total FROM items GROUP BY status").fetchall():
                counts[row["status"]] = row["total"]
            return {"counts": counts, "items": self.list_items()}
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # 隔离账：连接关系（拓扑）
    # ------------------------------------------------------------------

    def _topology_version(self, conn):
        row = conn.execute("SELECT version FROM topology_meta WHERE id=1").fetchone()
        return row["version"] if row else 0

    def set_segment_valves(self, pipeline_id, segment_id, valves, actor, role):
        """更新某管段的边界阀门（连接关系），并按规则作废/重算隔离方案。"""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            now = now_iso()
            version = self._topology_version(conn) + 1
            conn.execute(
                "INSERT INTO topology_meta(id,version,updated_at) VALUES(1,?,?) "
                "ON CONFLICT(id) DO UPDATE SET version=?,updated_at=?",
                (version, now, version, now),
            )
            conn.execute(
                "DELETE FROM connections WHERE pipeline_id=? AND segment_id=?",
                (pipeline_id, segment_id),
            )
            for valve_id in valves:
                conn.execute(
                    "INSERT INTO connections(pipeline_id,segment_id,valve_id,created_at) VALUES(?,?,?,?)",
                    (pipeline_id, segment_id, valve_id, now),
                )
            seg_key = "%s|%s" % (pipeline_id, segment_id)
            plans = self._load_active_plans(conn)
            seg_plans = [p for p in plans if p["segment_key"] == seg_key]
            from . import ledger

            invalidated, drifted = ledger.topology_update_effects(seg_plans, seg_key, valves, version)
            for plan in invalidated + drifted:
                self._persist_plan(conn, plan)
            # 作废的未执行方案按新拓扑重算，生成替代方案
            replacements = []
            for plan in invalidated:
                replacement = self._create_plan_row(
                    conn, plan["item_id"], pipeline_id, segment_id,
                    plan["severity"], plan["severity_score"], valves, version, now,
                )
                replacements.append(replacement)
            # 重新分配阀门（新方案可能立即开始）
            all_plans = self._load_active_plans(conn)
            valve_map = self._load_valves(conn)
            started = ledger.allocate(all_plans, valve_map)
            for plan in all_plans:
                self._persist_plan(conn, plan)
            self._persist_valves(conn, valve_map)
            self.append_audit(
                conn, None, "topology_updated", actor, role,
                {"pipeline_id": pipeline_id, "segment_id": segment_id, "valves": valves, "version": version},
            )
            for plan in invalidated:
                self.append_audit(conn, plan["item_id"], "plan_invalidated", actor, role, {"plan_id": plan["id"], "reason": "topology_changed"})
            for plan in drifted:
                self.append_audit(conn, plan["item_id"], "plan_topology_drifted", actor, role, {"plan_id": plan["id"]})
            for plan in started:
                self.append_audit(conn, plan["item_id"], "isolation_started", actor, role, {"plan_id": plan["id"]})
            conn.execute("COMMIT")
            return {
                "version": version,
                "valves": valves,
                "invalidated": [p["id"] for p in invalidated],
                "drifted": [p["id"] for p in drifted],
                "replacements": [p["id"] for p in replacements],
            }
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def get_segment_valves(self, pipeline_id, segment_id):
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT valve_id FROM connections WHERE pipeline_id=? AND segment_id=? ORDER BY valve_id",
                (pipeline_id, segment_id),
            ).fetchall()
            return [row["valve_id"] for row in rows]
        finally:
            conn.close()

    def list_valves(self):
        conn = self.connect()
        try:
            rows = conn.execute("SELECT * FROM valves ORDER BY valve_id").fetchall()
            result = {
                r["valve_id"]: {
                    "valve_id": r["valve_id"], "position": r["position"],
                    "occupied_by": r["occupied_by"], "updated_at": r["updated_at"],
                }
                for r in rows
            }
            # 连接关系中出现过、但从未被占用或上报的阀门也要列出
            for row in conn.execute("SELECT DISTINCT valve_id FROM connections").fetchall():
                result.setdefault(row["valve_id"], {
                    "valve_id": row["valve_id"], "position": "unknown",
                    "occupied_by": None, "updated_at": None,
                })
            return [result[key] for key in sorted(result)]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # 隔离账：方案
    # ------------------------------------------------------------------

    def _create_plan_row(self, conn, item_id, pipeline_id, segment_id, severity, score, valves, version, now):
        cur = conn.execute(
            "INSERT INTO isolation_plans(item_id,pipeline_id,segment_id,status,severity,severity_score,"
            "valves,closed_valves,occupied_valves,failed_valve,topology_version,topology_drifted,conflict,"
            "created_at,updated_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                item_id, pipeline_id, segment_id, "queued", severity, score,
                json.dumps(list(valves)), "[]", "[]", None, version, 0, None, now, now, None,
            ),
        )
        return {
            "id": cur.lastrowid,
            "item_id": item_id,
            "pipeline_id": pipeline_id,
            "segment_id": segment_id,
            "segment_key": "%s|%s" % (pipeline_id, segment_id),
            "status": "queued",
            "severity": severity,
            "severity_score": score,
            "valves": list(valves),
            "closed_valves": [],
            "occupied_valves": [],
            "failed_valve": None,
            "topology_version": version,
            "topology_drifted": False,
            "conflict": None,
            "receipts": [],
            "created_at": now,
            "updated_at": now,
            "completed_at": None,
        }

    def _row_to_plan(self, row):
        d = dict(row)
        d["segment_key"] = "%s|%s" % (d["pipeline_id"], d["segment_id"])
        d["valves"] = json.loads(d["valves"])
        d["closed_valves"] = json.loads(d["closed_valves"])
        d["occupied_valves"] = json.loads(d["occupied_valves"])
        d["topology_drifted"] = bool(d["topology_drifted"])
        d["conflict"] = json.loads(d["conflict"]) if d["conflict"] else None
        d.setdefault("receipts", [])
        return d

    def _persist_plan(self, conn, plan):
        conn.execute(
            "UPDATE isolation_plans SET status=?,valves=?,closed_valves=?,occupied_valves=?,failed_valve=?,"
            "topology_version=?,topology_drifted=?,conflict=?,updated_at=?,completed_at=? WHERE id=?",
            (
                plan["status"],
                json.dumps(plan["valves"]),
                json.dumps(plan.get("closed_valves", [])),
                json.dumps(plan.get("occupied_valves", [])),
                plan.get("failed_valve"),
                plan.get("topology_version", 0),
                1 if plan.get("topology_drifted") else 0,
                json.dumps(plan["conflict"]) if plan.get("conflict") else None,
                now_iso(),
                plan.get("completed_at"),
                plan["id"],
            ),
        )

    def _load_active_plans(self, conn):
        rows = conn.execute(
            "SELECT * FROM isolation_plans WHERE status IN ('queued','in_progress','partially_closed') ORDER BY id"
        ).fetchall()
        return [self._row_to_plan(r) for r in rows]

    def _get_active_plan_row(self, conn, item_id):
        row = conn.execute(
            "SELECT * FROM isolation_plans WHERE item_id=? AND status NOT IN ('completed','invalidated') "
            "ORDER BY id DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        if row is None:
            return None
        plan = self._row_to_plan(row)
        plan["receipts"] = self._list_receipts(conn, plan["id"])
        return plan

    def get_active_plan(self, item_id):
        conn = self.connect()
        try:
            return self._get_active_plan_row(conn, item_id)
        finally:
            conn.close()

    def _get_latest_plan_row(self, conn, item_id):
        row = conn.execute(
            "SELECT * FROM isolation_plans WHERE item_id=? ORDER BY id DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        if row is None:
            return None
        plan = self._row_to_plan(row)
        plan["receipts"] = self._list_receipts(conn, plan["id"])
        return plan

    def get_latest_plan(self, item_id):
        conn = self.connect()
        try:
            return self._get_latest_plan_row(conn, item_id)
        finally:
            conn.close()

    def submit_isolation(self, item_id, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if item is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            payload = json.loads(item["payload"])
            pipeline_id = payload.get("pipeline_id")
            segment_id = payload.get("segment_id")
            # 旧数据缺连接关系：只读兼容，拒绝建立隔离账
            rows = conn.execute(
                "SELECT valve_id FROM connections WHERE pipeline_id=? AND segment_id=? ORDER BY valve_id",
                (pipeline_id, segment_id),
            ).fetchall()
            if not rows:
                raise DomainError("topology_required", "该管段缺少连接关系，仅支持只读访问，不能建立隔离账", 409)
            valves = [r["valve_id"] for r in rows]
            existing = conn.execute(
                "SELECT id FROM isolation_plans WHERE item_id=? AND status NOT IN ('completed','invalidated')",
                (item_id,),
            ).fetchone()
            if existing:
                raise ConflictError("isolation_plan_exists", "该事件已有进行中的隔离方案")
            from . import ledger

            severity = ledger.severity_of(payload)
            version = self._topology_version(conn)
            now = now_iso()
            plan = self._create_plan_row(
                conn, item_id, pipeline_id, segment_id, severity,
                assess(payload)["score"], valves, version, now,
            )
            all_plans = self._load_active_plans(conn)
            valve_map = self._load_valves(conn)
            started = ledger.allocate(all_plans, valve_map)
            for p in all_plans:
                self._persist_plan(conn, p)
            self._persist_valves(conn, valve_map)
            self.append_audit(
                conn, item_id, "isolation_submitted", actor, role,
                {"plan_id": plan["id"], "severity": plan["severity"], "valves": plan["valves"]},
            )
            for p in started:
                self.append_audit(conn, p["item_id"], "isolation_started", actor, role, {"plan_id": p["id"]})
            conn.execute("COMMIT")
            return self.get_active_plan(item_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # 隔离账：阀门互斥与回执
    # ------------------------------------------------------------------

    def _load_valves(self, conn):
        rows = conn.execute("SELECT * FROM valves").fetchall()
        result = {}
        for r in rows:
            result[r["valve_id"]] = {
                "valve_id": r["valve_id"],
                "position": r["position"],
                "occupied_by": r["occupied_by"],
            }
        return result

    def _persist_valves(self, conn, valve_map):
        now = now_iso()
        for state in valve_map.values():
            conn.execute(
                "INSERT INTO valves(valve_id,position,occupied_by,updated_at) VALUES(?,?,?,?) "
                "ON CONFLICT(valve_id) DO UPDATE SET position=?,occupied_by=?,updated_at=?",
                (
                    state["valve_id"], state.get("position", "unknown"), state.get("occupied_by"), now,
                    state.get("position", "unknown"), state.get("occupied_by"), now,
                ),
            )

    def _row_to_receipt(self, row):
        if row is None:
            return None
        return dict(row)

    def _list_receipts(self, conn, plan_id):
        rows = conn.execute("SELECT * FROM valve_receipts WHERE plan_id=? ORDER BY id", (plan_id,)).fetchall()
        return [self._row_to_receipt(r) for r in rows]

    def _get_receipt(self, conn, plan_id, valve_id):
        row = conn.execute(
            "SELECT * FROM valve_receipts WHERE plan_id=? AND valve_id=?",
            (plan_id, valve_id),
        ).fetchone()
        return self._row_to_receipt(row)

    def _upsert_receipt(self, conn, plan_id, receipt, result):
        valve_id = receipt["valve_id"].strip()
        observed_at = receipt.get("observed_at")
        source = receipt.get("source")
        existing = conn.execute(
            "SELECT * FROM valve_receipts WHERE plan_id=? AND valve_id=?",
            (plan_id, valve_id),
        ).fetchone()
        now = now_iso()
        if existing is None:
            conn.execute(
                "INSERT INTO valve_receipts(plan_id,valve_id,result,attempts,observed_at,source,created_at,last_observed_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (plan_id, valve_id, result, 1, observed_at, source, now, observed_at),
            )
        else:
            # 结果变化（失败→关闭）：更新为最新结果，尝试次数 +1；
            # 完全相同的重复回执不进入此分支（幂等）。
            conn.execute(
                "UPDATE valve_receipts SET result=?, attempts=attempts+1, last_observed_at=?, source=? "
                "WHERE plan_id=? AND valve_id=?",
                (result, observed_at, source, plan_id, valve_id),
            )

    def submit_receipt(self, item_id, receipt, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            plan = self._get_active_plan_row(conn, item_id)
            if plan is None:
                raise NotFoundError("isolation_plan_not_found", "该事件没有进行中的隔离方案")
            from . import ledger

            valve_map = self._load_valves(conn)
            outcome, events = ledger.apply_receipt(plan, receipt, valve_map)
            if outcome == "duplicate":
                # 重复回执：只记一次，不重复计数、不推进断点
                existing = self._get_receipt(conn, plan["id"], receipt["valve_id"].strip())
                conn.execute("COMMIT")
                return {"outcome": "duplicate", "receipt": existing, "plan": self.get_latest_plan(item_id)}
            if outcome == "conflict":
                ledger.suspend_plan(
                    plan,
                    {"reason": "valve_status_conflict", "valve_id": receipt["valve_id"].strip(), "reported": "failed"},
                    valve_map,
                )
                self._persist_plan(conn, plan)
                self._persist_valves(conn, valve_map)
                self.append_audit(conn, item_id, "plan_suspended", actor, role, {"plan_id": plan["id"], "conflict": plan["conflict"]})
                conn.execute("COMMIT")
                return {"outcome": "conflict", "receipt": None, "plan": self.get_latest_plan(item_id)}
            self._upsert_receipt(conn, plan["id"], receipt, outcome)
            self._persist_plan(conn, plan)
            self._persist_valves(conn, valve_map)
            for event in events:
                self.append_audit(conn, item_id, event["type"], actor, role, {"plan_id": plan["id"], "valve_id": event.get("valve_id")})
            if plan["status"] == "completed":
                all_plans = self._load_active_plans(conn)
                started = ledger.allocate(all_plans, valve_map)
                for p in all_plans:
                    self._persist_plan(conn, p)
                self._persist_valves(conn, valve_map)
                for p in started:
                    self.append_audit(conn, p["item_id"], "isolation_started", actor, role, {"plan_id": p["id"]})
            conn.execute("COMMIT")
            return {
                "outcome": outcome,
                "receipt": self._get_receipt(conn, plan["id"], receipt["valve_id"].strip()),
                "plan": self.get_latest_plan(item_id),
            }
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def resume_isolation(self, item_id, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            plan = self._get_active_plan_row(conn, item_id)
            if plan is None:
                raise NotFoundError("isolation_plan_not_found", "该事件没有进行中的隔离方案")
            if plan["status"] == "suspended":
                raise DomainError("plan_suspended", "方案已挂起，请先人工裁决", 409)
            rows = conn.execute(
                "SELECT valve_id FROM connections WHERE pipeline_id=? AND segment_id=? ORDER BY valve_id",
                (plan["pipeline_id"], plan["segment_id"]),
            ).fetchall()
            topology_valves = [r["valve_id"] for r in rows]
            from . import ledger

            valve_map = self._load_valves(conn)
            ledger.resume_plan(plan, valve_map, topology_valves)
            self._persist_plan(conn, plan)
            self._persist_valves(conn, valve_map)
            self.append_audit(conn, item_id, "isolation_resumed", actor, role, {"plan_id": plan["id"], "valves": plan["valves"]})
            conn.execute("COMMIT")
            return self.get_active_plan(item_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # 隔离账：断网阀位合并与冲突挂起
    # ------------------------------------------------------------------

    def merge_valve_positions(self, reports, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            from . import ledger

            valve_map = self._load_valves(conn)
            plans = self._load_active_plans(conn)
            result = ledger.merge_positions(reports, valve_map, plans)
            # 挂起释放阀门后，让排队中的方案按严重度接续占用
            started = ledger.allocate(plans, valve_map)
            self._persist_valves(conn, valve_map)
            for plan in plans:
                self._persist_plan(conn, plan)
            for plan in started:
                self.append_audit(conn, plan["item_id"], "isolation_started", actor, role, {"plan_id": plan["id"]})
            self.append_audit(
                conn, None, "valve_positions_merged", actor, role,
                {"merged_count": len(result["merged"]), "suspended": [s["plan_id"] for s in result["suspended"]]},
            )
            for suspended in result["suspended"]:
                self.append_audit(conn, suspended["item_id"], "plan_suspended", actor, role, suspended["conflict"])
            conn.execute("COMMIT")
            return result
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def resolve_isolation(self, item_id, resolution, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            plan = self._get_active_plan_row(conn, item_id)
            if plan is None:
                raise NotFoundError("isolation_plan_not_found", "该事件没有进行中的隔离方案")
            if plan["status"] != "suspended":
                raise DomainError("plan_not_suspended", "方案未挂起，无需裁决", 409)
            from . import ledger

            valve_map = self._load_valves(conn)
            if resolution == "proceed":
                ledger.requeue_plan(plan, valve_map)
                self._persist_plan(conn, plan)  # 先落库 queued，再重新加载分配
                all_plans = self._load_active_plans(conn)
                started = ledger.allocate(all_plans, valve_map)
                for p in all_plans:
                    self._persist_plan(conn, p)
                for p in started:
                    self.append_audit(conn, p["item_id"], "isolation_started", actor, role, {"plan_id": p["id"]})
            elif resolution == "abort":
                plan["status"] = "invalidated"
                plan["conflict"] = {"reason": "manual_abort"}
                ledger.release_plan_valves(plan, valve_map)
                self._persist_plan(conn, plan)
            else:
                raise DomainError("invalid_resolution", "裁决必须是 proceed 或 abort", 400)
            self._persist_valves(conn, valve_map)
            self.append_audit(
                conn, item_id, "plan_resolved", actor, role,
                {"plan_id": plan["id"], "resolution": resolution},
            )
            conn.execute("COMMIT")
            return self.get_active_plan(item_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()
