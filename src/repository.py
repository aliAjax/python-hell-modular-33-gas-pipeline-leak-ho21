import json
import sqlite3
from datetime import datetime, timezone

from .audit import audit_hash, canonical_json
from .domain import ConflictError, NotFoundError, DomainError
from .isolation import (
    JOB_QUEUED,
    JOB_ACTIVE,
    JOB_BLOCKED,
    JOB_ISOLATED,
    JOB_SUSPENDED,
    JOB_VOIDED,
    LIVE_STATUSES,
    LEASE_HELD,
    LEASE_CLOSED,
    LEASE_RELEASED,
    RESULT_CLOSED,
    RESULT_FAILED,
    DEVICE_CLOSED,
    DEVICE_OPEN,
    boundary_valves,
    expected_valve,
    revision_effect,
    merge_decision,
)
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
                -- 隔离账：管段 / 阀门 / 连接关系
                CREATE TABLE IF NOT EXISTS segments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    segment_id TEXT NOT NULL UNIQUE,
                    note TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS valves (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    valve_id TEXT NOT NULL UNIQUE,
                    online INTEGER NOT NULL DEFAULT 1,
                    last_remote_state TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    valve_id TEXT NOT NULL,
                    segment_a TEXT NOT NULL,
                    segment_b TEXT,
                    revision INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    UNIQUE(valve_id, segment_a, segment_b)
                );
                CREATE TABLE IF NOT EXISTS topology_revisions (
                    revision INTEGER PRIMARY KEY,
                    note TEXT NOT NULL DEFAULT '',
                    actor TEXT,
                    role TEXT,
                    created_at TEXT NOT NULL
                );
                -- 隔离方案（作业）
                CREATE TABLE IF NOT EXISTS isolation_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL,
                    segment_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    required_valves TEXT NOT NULL,
                    closed_valves TEXT NOT NULL DEFAULT '[]',
                    failed_valve TEXT,
                    suspended_valve TEXT,
                    priority_score REAL NOT NULL,
                    priority_level TEXT NOT NULL,
                    topology_revision INTEGER NOT NULL,
                    supersedes_job INTEGER,
                    void_reason TEXT,
                    created_by TEXT NOT NULL,
                    created_role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(item_id) REFERENCES items(id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_one_live_per_item
                    ON isolation_jobs(item_id) WHERE status IN ('queued','active','blocked','suspended');
                -- 阀门占用账：同一时刻一个阀门只归一组作业
                CREATE TABLE IF NOT EXISTS valve_leases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    valve_id TEXT NOT NULL,
                    job_id INTEGER,
                    item_id INTEGER,
                    state TEXT NOT NULL,
                    acquired_at TEXT NOT NULL,
                    released_at TEXT,
                    note TEXT NOT NULL DEFAULT ''
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_leases_one_active
                    ON valve_leases(valve_id) WHERE state IN ('held','closed');
                -- 关阀回执：同一回执只记一次（幂等）
                CREATE TABLE IF NOT EXISTS valve_receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id INTEGER NOT NULL,
                    valve_id TEXT NOT NULL,
                    receipt_id TEXT NOT NULL,
                    result TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(job_id, receipt_id)
                );
                -- 断网/现场阀位上报
                CREATE TABLE IF NOT EXISTS valve_state_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    valve_id TEXT NOT NULL,
                    online INTEGER NOT NULL,
                    device_state TEXT,
                    decision TEXT,
                    actor TEXT,
                    role TEXT,
                    created_at TEXT NOT NULL
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
    # 隔离账：拓扑注册与查询
    # ------------------------------------------------------------------

    def _ensure_segment(self, conn, segment_id, note=""):
        conn.execute(
            "INSERT OR IGNORE INTO segments(segment_id,note,created_at) VALUES(?,?,?)",
            (segment_id, note, now_iso()),
        )

    def _ensure_valve(self, conn, valve_id):
        conn.execute(
            "INSERT OR IGNORE INTO valves(valve_id,online,created_at) VALUES(?,1,?)",
            (valve_id, now_iso()),
        )

    def register_valve(self, valve_id, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT INTO valves(valve_id,online,created_at) VALUES(?,1,?)",
                    (valve_id, now_iso()),
                )
            except sqlite3.IntegrityError:
                conn.execute("ROLLBACK")
                raise ConflictError("valve_exists", "阀门已经登记：%s" % valve_id)
            self.append_audit(conn, None, "valve_registered", actor, role, {"valve_id": valve_id})
            conn.execute("COMMIT")
            return {"valve_id": valve_id, "online": True, "last_remote_state": None}
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def _current_revision(self, conn):
        row = conn.execute("SELECT MAX(revision) AS rev FROM topology_revisions").fetchone()
        return int(row["rev"] or 0)

    def _edges(self, conn):
        return [
            {"valve_id": r["valve_id"], "segment_a": r["segment_a"], "segment_b": r["segment_b"]}
            for r in conn.execute("SELECT valve_id,segment_a,segment_b FROM connections").fetchall()
        ]

    def topology(self):
        conn = self.connect()
        try:
            revision = self._current_revision(conn)
            edges = self._edges(conn)
            valves = [
                {"valve_id": r["valve_id"], "online": bool(r["online"]), "last_remote_state": r["last_remote_state"]}
                for r in conn.execute("SELECT valve_id,online,last_remote_state FROM valves ORDER BY valve_id").fetchall()
            ]
            segments = [r["segment_id"] for r in conn.execute("SELECT segment_id FROM segments ORDER BY segment_id").fetchall()]
            return {"revision": revision, "segments": segments, "valves": valves, "connections": edges}
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # 隔离账：排队调度（严重度优先 + 全有或全无，天然无死锁）
    # ------------------------------------------------------------------

    def _valves_held_by(self, conn, valve_ids):
        """返回 {valve_id: job_id}：当前被任一活作业占用（held/closed）的阀门。"""
        if not valve_ids:
            return {}
        placeholders = ",".join("?" for _ in valve_ids)
        rows = conn.execute(
            "SELECT valve_id,job_id FROM valve_leases WHERE state IN ('held','closed') AND valve_id IN (%s)" % placeholders,
            list(valve_ids),
        ).fetchall()
        return {r["valve_id"]: r["job_id"] for r in rows}

    def _schedule(self, conn):
        """按严重度降序、先到先得扫描活作业：所需阀门全空闲才整组占用。

        分组同时申请、共用阀门时，严重度高的组先拿全套阀门；另一组保持排队，
        任何一组都不会“占一半等对方”，因此不会互相锁死。
        """
        jobs = conn.execute(
            "SELECT * FROM isolation_jobs WHERE status IN ('queued','active','blocked') "
            "ORDER BY priority_score DESC, id ASC"
        ).fetchall()
        for row in jobs:
            required = json.loads(row["required_valves"])
            held = self._valves_held_by(conn, required)
            blockers = {v: j for v, j in held.items() if j != row["id"]}
            if blockers:
                continue  # 有任一边界阀被其他组占用：整组等待，不部分占用
            # 本组所需阀门全部可用（或已归本组）：补齐缺失占用
            missing = [v for v in required if v not in held]
            for valve_id in missing:
                self._ensure_valve(conn, valve_id)
                conn.execute(
                    "INSERT INTO valve_leases(valve_id,job_id,item_id,state,acquired_at) VALUES(?,?,?,'held',?)",
                    (valve_id, row["id"], row["item_id"], now_iso()),
                )
            if row["status"] == JOB_QUEUED:
                conn.execute(
                    "UPDATE isolation_jobs SET status='active',updated_at=? WHERE id=?",
                    (now_iso(), row["id"]),
                )

    def create_isolation_job(self, item_id, segment_id, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            item_row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            if item_row is None:
                raise NotFoundError("item_not_found", "业务实体不存在")
            item = self._row_to_item(item_row)
            if item["status"] not in ("verified", "isolated", "repaired", "tested"):
                raise DomainError("isolation_not_ready", "泄漏事件需先核验才能提交隔离申请", 409)
            live = conn.execute(
                "SELECT id FROM isolation_jobs WHERE item_id=? AND status IN ('queued','active','blocked','suspended')",
                (item_id,),
            ).fetchone()
            if live is not None:
                raise ConflictError("isolation_job_exists", "该泄漏事件已有进行中的隔离方案")
            revision = self._current_revision(conn)
            edges = self._edges(conn)
            valves = boundary_valves(edges, segment_id)
            if not valves:
                # 旧数据缺连接关系：只读兼容，不允许走账本隔离
                raise DomainError("topology_unavailable", "缺少管段连接关系，无法生成隔离方案（旧数据只读）", 409)
            self._ensure_segment(conn, segment_id)
            assessment = assess(json.loads(item_row["payload"]))
            now = now_iso()
            conn.execute(
                "INSERT INTO isolation_jobs(item_id,segment_id,status,required_valves,closed_valves,"
                "priority_score,priority_level,topology_revision,created_by,created_role,created_at,updated_at) "
                "VALUES(?,?,'queued',?,'[]',?,?,?,?,?,?,?)",
                (
                    item_id, segment_id, canonical_json(valves),
                    assessment["score"], assessment["level"], revision, actor, role, now, now,
                ),
            )
            job_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            self._schedule(conn)
            self.append_audit(conn, item_id, "isolation_job_created", actor, role,
                              {"job_id": job_id, "valves": valves, "priority": assessment})
            conn.execute("COMMIT")
            return self.get_job(job_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def _job_from_row(self, conn, row):
        job = dict(row)
        for key in ("required_valves", "closed_valves"):
            job[key] = json.loads(job[key])
        required = set(job["required_valves"])
        closed = set(job["closed_valves"])
        job["pending_valves"] = [v for v in job["required_valves"] if v not in closed]
        job["next_valve"] = expected_valve(job["required_valves"], job["closed_valves"])
        held = self._valves_held_by(conn, job["required_valves"])
        job["blocking_valves"] = {v: j for v, j in held.items() if j != job["id"] and v in required}
        return job

    def get_job(self, job_id):
        conn = self.connect()
        try:
            row = conn.execute("SELECT * FROM isolation_jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise NotFoundError("job_not_found", "隔离方案不存在")
            return self._job_from_row(conn, row)
        finally:
            conn.close()

    def list_jobs(self, status=None):
        conn = self.connect()
        try:
            if status:
                rows = conn.execute(
                    "SELECT * FROM isolation_jobs WHERE status=? ORDER BY priority_score DESC, id DESC",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM isolation_jobs ORDER BY priority_score DESC, id DESC"
                ).fetchall()
            return [self._job_from_row(conn, row) for row in rows]
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # 隔离账：关阀回执（断点续做 + 幂等）
    # ------------------------------------------------------------------

    def add_valve_receipt(self, job_id, valve_id, receipt_id, result, observed_at, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM isolation_jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise NotFoundError("job_not_found", "隔离方案不存在")
            job = self._job_from_row(conn, row)

            # 重复回执：只记一次，直接回原结果（幂等优先于方案状态检查）
            duplicate = conn.execute(
                "SELECT * FROM valve_receipts WHERE job_id=? AND receipt_id=?", (job_id, receipt_id)
            ).fetchone()
            if duplicate is not None:
                conn.execute("COMMIT")
                return {
                    "job_id": job_id,
                    "receipt_id": receipt_id,
                    "duplicate": True,
                    "valve_id": duplicate["valve_id"],
                    "result": duplicate["result"],
                    "job_status": job["status"],
                }

            if job["status"] in (JOB_ISOLATED, JOB_VOIDED):
                raise DomainError("job_not_open", "隔离方案已 %s，不再接收回执" % job["status"], 409)

            required = set(job["required_valves"])
            closed = set(job["closed_valves"])
            held = self._valves_held_by(conn, [valve_id])
            if valve_id not in required:
                raise DomainError("valve_not_in_plan", "阀门 %s 不属于当前隔离方案" % valve_id, 409)
            if held.get(valve_id) not in (job_id, None):
                raise ConflictError("valve_held_by_other", "阀门 %s 已被其他作业占用" % valve_id)
            if valve_id in closed:
                # 阀门已关、回执号却不同：按重复结果处理并拒绝重复入账
                raise ConflictError("valve_already_closed", "阀门 %s 已关闭，请勿重复关阀" % valve_id)
            if job["status"] == JOB_SUSPENDED:
                raise DomainError("job_suspended", "方案因阀位冲突挂起，需先裁决恢复", 409)

            nxt = expected_valve(job["required_valves"], closed)
            if nxt != valve_id:
                raise DomainError(
                    "out_of_sequence",
                    "当前断点为阀门 %s，请先完成该阀门" % nxt,
                    409,
                )

            now = now_iso()
            conn.execute(
                "INSERT INTO valve_receipts(job_id,valve_id,receipt_id,result,observed_at,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (job_id, valve_id, receipt_id, result, observed_at, now),
            )
            response_result = result
            if result == RESULT_CLOSED:
                # 关阀成功：占用转为已关（物理结果留账）
                conn.execute(
                    "UPDATE valve_leases SET state='closed' WHERE valve_id=? AND job_id=? AND state='held'",
                    (valve_id, job_id),
                )
                closed.add(valve_id)
                new_closed = sorted(closed)
                new_required = job["required_valves"]
                if all(v in closed for v in new_required):
                    self._complete_isolation(conn, row, new_closed, valve_id, actor, role)
                else:
                    conn.execute(
                        "UPDATE isolation_jobs SET closed_valves=?,failed_valve=NULL,"
                        "status=CASE WHEN status='blocked' THEN 'active' ELSE status END,updated_at=? WHERE id=?",
                        (canonical_json(new_closed), now, job_id),
                    )
                    self.append_audit(conn, row["item_id"], "valve_closed", actor, role,
                                      {"job_id": job_id, "valve_id": valve_id, "receipt_id": receipt_id})
            else:
                # 关阀失败：停在断点；已关阀不回滚，重试从该阀门继续
                conn.execute(
                    "UPDATE isolation_jobs SET failed_valve=?,status='blocked',updated_at=? WHERE id=?",
                    (valve_id, now, job_id),
                )
                self.append_audit(conn, row["item_id"], "valve_close_failed", actor, role,
                                  {"job_id": job_id, "valve_id": valve_id, "receipt_id": receipt_id,
                                   "resume_from": valve_id})
            conn.execute("COMMIT")
            refreshed = self.get_job(job_id)
            return {
                "job_id": job_id,
                "receipt_id": receipt_id,
                "duplicate": False,
                "valve_id": valve_id,
                "result": response_result,
                "job_status": refreshed["status"],
                "next_valve": refreshed["next_valve"],
                "resume_from": refreshed["failed_valve"],
            }
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def _complete_isolation(self, conn, row, closed_valves, last_valve, actor, role):
        """边界阀全部关闭：方案完成，泄漏事件流转 isolated。"""
        job_id = row["id"]
        now = now_iso()
        conn.execute(
            "UPDATE isolation_jobs SET status='isolated',closed_valves=?,failed_valve=NULL,updated_at=? WHERE id=?",
            (canonical_json(closed_valves), now, job_id),
        )
        payload = json.loads(self._get_payload(conn, row["item_id"]))
        payload["valve_sequence"] = closed_valves
        self._patch_item_row(conn, row["item_id"], "isolated", payload, now)
        conn.execute(
            "INSERT INTO actions(item_id,action,actor,role,payload,created_at) VALUES(?,?,?,?,?,?)",
            (row["item_id"], "isolate", actor, role,
             canonical_json({"valve_sequence": closed_valves, "job_id": job_id}), now),
        )
        self.append_audit(conn, row["item_id"], "valve_closed", actor, role,
                          {"job_id": job_id, "valve_id": last_valve, "receipt_id": None, "isolated": True})

    def _get_payload(self, conn, item_id):
        return conn.execute("SELECT payload FROM items WHERE id=?", (item_id,)).fetchone()["payload"]

    def _patch_item_row(self, conn, item_id, status, payload, now):
        version_row = conn.execute("SELECT version FROM items WHERE id=?", (item_id,)).fetchone()
        version = int(version_row["version"]) + 1
        conn.execute(
            "UPDATE items SET status=?,version=?,payload=?,updated_at=? WHERE id=?",
            (status, version, canonical_json(payload), now, item_id),
        )

    # ------------------------------------------------------------------
    # 隔离账：断网恢复后的阀位合并与冲突挂起
    # ------------------------------------------------------------------

    def sync_valve(self, valve_id, online, device_state, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._ensure_valve(conn, valve_id)
            conn.execute(
                "UPDATE valves SET online=?,last_remote_state=COALESCE(?,last_remote_state) WHERE valve_id=?",
                (1 if online else 0, device_state, valve_id),
            )
            lease = conn.execute(
                "SELECT * FROM valve_leases WHERE valve_id=? AND state IN ('held','closed')",
                (valve_id,),
            ).fetchone()
            decision = "unknown"
            suspended_job = None
            lease_state = lease["state"] if lease else None
            if lease is not None:
                decision = merge_decision(online, lease_state, device_state)
                if decision == "conflict":
                    self._suspend_job(
                        conn, lease["job_id"], valve_id, actor, role,
                        reason={
                            "valve_id": valve_id,
                            "ledger_state": lease_state,
                            "remote_state": device_state,
                        },
                        event="valve_state_conflict",
                    )
                    suspended_job = lease["job_id"]
                elif decision == "consistent":
                    # 冲突项现场复归一致：自动恢复挂起
                    self._resume_if_matches(conn, lease["job_id"], valve_id, actor, role)
            conn.execute(
                "INSERT INTO valve_state_events(valve_id,online,device_state,decision,actor,role,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (valve_id, 1 if online else 0, device_state, decision, actor, role, now_iso()),
            )
            conn.execute("COMMIT")
            result = {"valve_id": valve_id, "online": online, "device_state": device_state,
                      "ledger_state": lease_state, "decision": decision}
            if suspended_job is not None:
                result["suspended_job"] = suspended_job
            return result
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def _suspend_job(self, conn, job_id, valve_id, actor, role, reason, event):
        row = conn.execute("SELECT * FROM isolation_jobs WHERE id=?", (job_id,)).fetchone()
        if row is None or row["status"] == JOB_ISOLATED or row["status"] == JOB_VOIDED:
            return
        conn.execute(
            "UPDATE isolation_jobs SET status='suspended',suspended_valve=?,updated_at=? WHERE id=?",
            (valve_id, now_iso(), job_id),
        )
        self.append_audit(conn, row["item_id"], event, actor, role,
                          {"job_id": job_id, "suspended_valve": valve_id, **reason})

    def _resume_if_matches(self, conn, job_id, valve_id, actor, role):
        row = conn.execute("SELECT * FROM isolation_jobs WHERE id=?", (job_id,)).fetchone()
        if row is None or row["status"] != JOB_SUSPENDED or row["suspended_valve"] != valve_id:
            return
        target = "blocked" if row["failed_valve"] else "active"
        conn.execute(
            "UPDATE isolation_jobs SET status=?,suspended_valve=NULL,updated_at=? WHERE id=?",
            (target, now_iso(), job_id),
        )
        self.append_audit(conn, row["item_id"], "isolation_resumed", actor, role,
                          {"job_id": job_id, "valve_id": valve_id, "status": target, "auto": True})

    def resolve_job(self, job_id, resolution, actor, role):
        """裁决挂起项：adopt_device=以现场阀位为准；trust_ledger=以账本为准继续执行。"""
        if resolution not in ("adopt_device", "trust_ledger"):
            raise DomainError("invalid_resolution", "resolution 只能是 adopt_device 或 trust_ledger")
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM isolation_jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise NotFoundError("job_not_found", "隔离方案不存在")
            if row["status"] != JOB_SUSPENDED:
                raise DomainError("job_not_suspended", "该方案未挂起，无需裁决", 409)
            valve_id = row["suspended_valve"]
            valve_row = conn.execute("SELECT * FROM valves WHERE valve_id=?", (valve_id,)).fetchone()
            remote = valve_row["last_remote_state"] if valve_row else None
            if resolution == "adopt_device":
                if remote == DEVICE_CLOSED:
                    # 现场确已关：接受物理结果，补齐关闭账
                    conn.execute(
                        "UPDATE valve_leases SET state='closed' WHERE valve_id=? AND job_id=? AND state='held'",
                        (valve_id, job_id),
                    )
                    closed = set(json.loads(row["closed_valves"]))
                    closed.add(valve_id)
                    new_closed = sorted(closed)
                    conn.execute(
                        "UPDATE isolation_jobs SET closed_valves=?,suspended_valve=NULL,updated_at=? WHERE id=?",
                        (canonical_json(new_closed), now_iso(), job_id),
                    )
                    self.append_audit(conn, row["item_id"], "valve_conflict_resolved", actor, role,
                                      {"job_id": job_id, "valve_id": valve_id, "resolution": resolution})
                    required_now = json.loads(row["required_valves"])
                    if all(v in set(new_closed) for v in required_now):
                        self._complete_isolation(
                            conn,
                            self._job_lite(conn, job_id),
                            new_closed,
                            valve_id,
                            actor,
                            role,
                        )
                        conn.execute("COMMIT")
                        return self.get_job(job_id)
                elif remote == DEVICE_OPEN:
                    # 现场仍开：关阀动作作废，回到该阀门断点重试
                    conn.execute(
                        "UPDATE isolation_jobs SET failed_valve=?,suspended_valve=NULL,status='blocked',updated_at=? WHERE id=?",
                        (valve_id, now_iso(), job_id),
                    )
                    self.append_audit(conn, row["item_id"], "valve_conflict_resolved", actor, role,
                                      {"job_id": job_id, "valve_id": valve_id, "resolution": resolution})
            # trust_ledger：维持账本结论，挂起解除，继续排队/执行
            target = "blocked" if row["failed_valve"] else "active"
            conn.execute(
                "UPDATE isolation_jobs SET status=?,suspended_valve=NULL,updated_at=? WHERE id=?",
                (target, now_iso(), job_id),
            )
            self.append_audit(conn, row["item_id"], "valve_conflict_resolved", actor, role,
                              {"job_id": job_id, "valve_id": valve_id, "resolution": resolution})
            self._schedule(conn)
            conn.execute("COMMIT")
            return self.get_job(job_id)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def _job_lite(self, conn, job_id):
        return conn.execute("SELECT * FROM isolation_jobs WHERE id=?", (job_id,)).fetchone()

    def release_item_valves(self, item_id, actor, role):
        """恢复供气后统一释放本事件占用（含已关）阀门。"""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT id,valve_id FROM valve_leases WHERE item_id=? AND state IN ('held','closed')",
                (item_id,),
            ).fetchall()
            released = []
            now = now_iso()
            for r in rows:
                conn.execute(
                    "UPDATE valve_leases SET state='released',released_at=?,note='restored' WHERE id=?",
                    (now, r["id"]),
                )
                conn.execute(
                    "UPDATE valves SET last_remote_state='open' WHERE valve_id=?", (r["valve_id"],)
                )
                released.append(r["valve_id"])
            self.append_audit(conn, item_id, "valves_released", actor, role, {"valves": released})
            self._schedule(conn)  # 释放后让排队组继续
            conn.execute("COMMIT")
            return {"item_id": item_id, "released_valves": released}
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def cancel_open_jobs(self, item_id, reason, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT * FROM isolation_jobs WHERE item_id=? AND status IN ('queued','active','blocked','suspended')",
                (item_id,),
            ).fetchall()
            voided = []
            for r in rows:
                conn.execute(
                    "UPDATE isolation_jobs SET status='voided',void_reason=?,updated_at=? WHERE id=?",
                    (reason, now_iso(), r["id"]),
                )
                if r["status"] == JOB_QUEUED:
                    # 排队方案未执行，没有实际占用
                    pass
                else:
                    # 已执行方案：已关阀保留，未关的 held 释放
                    conn.execute(
                        "UPDATE valve_leases SET state='released',released_at=?,note='job_voided' "
                        "WHERE job_id=? AND state='held'",
                        (now_iso(), r["id"]),
                    )
                voided.append(r["id"])
                self.append_audit(conn, item_id, "isolation_job_voided", actor, role,
                                  {"job_id": r["id"], "reason": reason})
            self._schedule(conn)
            conn.execute("COMMIT")
            return voided
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def has_live_job(self, item_id):
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT id FROM isolation_jobs WHERE item_id=? AND status IN ('queued','active','blocked','suspended')",
                (item_id,),
            ).fetchone()
            return row["id"] if row else None
        finally:
            conn.close()

    def occupy_manual_valves(self, item_id, valve_ids, actor, role):
        """手工 isolate（旧路径）：序列中已登记阀门按账本口径关阀留账，未登记阀门不管。"""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            managed = []
            for valve_id in valve_ids:
                exists = conn.execute("SELECT 1 FROM valves WHERE valve_id=?", (valve_id,)).fetchone()
                if not exists:
                    continue
                held = self._valves_held_by(conn, [valve_id])
                if held.get(valve_id) not in (None,):
                    raise ConflictError("valve_held_by_other", "阀门 %s 已被隔离作业占用" % valve_id)
                conn.execute(
                    "INSERT INTO valve_leases(valve_id,job_id,item_id,state,acquired_at,note) "
                    "VALUES(?,?,?,?,'closed',?,'manual')",
                    (valve_id, None, item_id, now_iso()),
                )
                managed.append(valve_id)
            conn.execute("COMMIT")
            return managed
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # 隔离账：连接关系修订（未执行作废重算，已关阀保留）
    # ------------------------------------------------------------------

    def commit_revision(self, new_edges, note, actor, role):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            normalized = []
            seen = set()
            for edge in new_edges:
                key = (edge["valve_id"], edge["segment_a"], edge.get("segment_b"))
                if key in seen:
                    raise DomainError("duplicate_edge", "连接关系中存在重复阀门边：%s" % edge["valve_id"])
                seen.add(key)
                if edge.get("segment_b") == edge["segment_a"]:
                    raise DomainError("invalid_edge", "连接两端不能是同一管段")
                normalized.append(edge)
                self._ensure_valve(conn, edge["valve_id"])
                self._ensure_segment(conn, edge["segment_a"])
                if edge.get("segment_b"):
                    self._ensure_segment(conn, edge["segment_b"])

            revision = self._current_revision(conn) + 1
            conn.execute("DELETE FROM connections")
            now = now_iso()
            for edge in normalized:
                conn.execute(
                    "INSERT INTO connections(valve_id,segment_a,segment_b,revision,created_at) VALUES(?,?,?,?,?)",
                    (edge["valve_id"], edge["segment_a"], edge.get("segment_b"), revision, now),
                )
            conn.execute(
                "INSERT INTO topology_revisions(revision,note,actor,role,created_at) VALUES(?,?,?,?,?)",
                (revision, note, actor, role, now),
            )
            self.append_audit(conn, None, "topology_revised", actor, role,
                              {"revision": revision, "edges": normalized, "note": note})
            replacements = self._reconcile_jobs(conn, normalized, revision, actor, role)
            conn.execute("COMMIT")
            return {"revision": revision, "connections": normalized, "replacements": replacements}
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def _reconcile_jobs(self, conn, edges, revision, actor, role):
        """连接关系更新后：未执行方案作废重算；执行中的保留已关阀、未执行部分按新关系重算。"""
        jobs = conn.execute(
            "SELECT * FROM isolation_jobs WHERE status IN ('queued','active','blocked','suspended')"
        ).fetchall()
        replacements = []
        now = now_iso()
        for row in jobs:
            old_required = json.loads(row["required_valves"])
            closed = json.loads(row["closed_valves"])
            new_required = boundary_valves(edges, row["segment_id"])

            if row["status"] == JOB_QUEUED:
                # 未执行：整份作废，按新连接关系重算并排队
                conn.execute(
                    "UPDATE isolation_jobs SET status='voided',void_reason=?,updated_at=? WHERE id=?",
                    ("topology_revision:%d" % revision, now, row["id"]),
                )
                self.append_audit(conn, row["item_id"], "isolation_plan_voided", actor, role,
                                  {"job_id": row["id"], "revision": revision, "stage": "queued"})
                if new_required:
                    new_id = self._spawn_replacement(conn, row, new_required, revision, actor, role)
                    replacements.append({"voided_job": row["id"], "new_job": new_id})
                else:
                    replacements.append({"voided_job": row["id"], "new_job": None,
                                         "reason": "segment_disconnected"})
                continue

            if row["status"] == JOB_SUSPENDED:
                # 冲突挂起项不因拓扑修订自动重算，挂起待裁决
                continue

            # active / blocked：已关阀保留，只重算未执行部分
            lease_rows = conn.execute(
                "SELECT valve_id,state FROM valve_leases WHERE job_id=? AND state IN ('held','closed')",
                (row["id"],),
            ).fetchall()
            leased = {r["valve_id"] for r in lease_rows}
            effect = revision_effect(old_required, closed, leased, new_required)

            for valve_id in effect["release"]:
                conn.execute(
                    "UPDATE valve_leases SET state='released',released_at=?,note='topology_revision' "
                    "WHERE job_id=? AND valve_id=? AND state='held'",
                    (now, row["id"], valve_id),
                )
            conn.execute(
                "UPDATE isolation_jobs SET required_valves=?,topology_revision=?,updated_at=? WHERE id=?",
                (canonical_json(effect["plan"]), revision, now, row["id"]),
            )
            self.append_audit(conn, row["item_id"], "isolation_plan_recomputed", actor, role,
                              {"job_id": row["id"], "revision": revision,
                               "retain_closed": effect["retain_closed"],
                               "release": effect["release"], "acquire": effect["acquire"]})
            replacements.append({"job_id": row["id"], "recomputed": True,
                                 "retain_closed": effect["retain_closed"],
                                 "acquire": effect["acquire"], "release": effect["release"]})
        self._schedule(conn)
        return replacements

    def _spawn_replacement(self, conn, old_row, required_valves, revision, actor, role):
        item_row = conn.execute("SELECT payload FROM items WHERE id=?", (old_row["item_id"],)).fetchone()
        assessment = assess(json.loads(item_row["payload"]))
        now = now_iso()
        conn.execute(
            "INSERT INTO isolation_jobs(item_id,segment_id,status,required_valves,closed_valves,"
            "priority_score,priority_level,topology_revision,supersedes_job,created_by,created_role,created_at,updated_at) "
            "VALUES(?,?,'queued',?,'[]',?,?,?,?,?,?,?,?)",
            (
                old_row["item_id"], old_row["segment_id"], canonical_json(required_valves),
                assessment["score"], assessment["level"], revision, old_row["id"],
                old_row["created_by"], old_row["created_role"], now, now,
            ),
        )
        new_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        self.append_audit(conn, old_row["item_id"], "isolation_job_replaced", actor, role,
                          {"old_job": old_row["id"], "new_job": new_id, "valves": required_valves})
        return new_id

