import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.repository import Repository
from src.service import Service
from src.domain import ConflictError, DomainError
from src.isolation import (
    boundary_valves,
    expected_valve,
    revision_effect,
    merge_decision,
)


EDGES = [
    {"valve_id": "V-1", "segment_a": "S-1", "segment_b": "S-2"},
    {"valve_id": "V-2", "segment_a": "S-2", "segment_b": "S-3"},
]
# S-1 边界：V-1；S-2 边界：V-1、V-2；S-3 边界：V-2


class IsolationLedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)
        self.service.revise_topology(
            {"connections": EDGES, "note": "initial"}, "sup-1", "supervisor"
        )

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _leak(self, segment, pressure=60, ppm=400, odor=4, reporter="d"):
        item = self.service.create_item({
            "pipeline_id": "P-1",
            "segment_id": segment,
            "reported_at": "2026-10-04T08:00:00+00:00",
            "pressure_drop_kpa": pressure,
            "sensor_value_ppm": ppm,
            "odor_reports": odor,
            "reporter": reporter,
        }, reporter, "dispatcher")
        return self.service.act(item["id"], "verify", {"field_confirmed": True},
                                "r", "responder", item["version"])

    def test_plan_is_boundary_valves_and_receipt_flow(self):
        item = self._leak("S-2")
        job = self.service.create_isolation_job(item["id"], {}, "sup-1", "supervisor")
        self.assertEqual(job["status"], "active")
        self.assertEqual(job["required_valves"], ["V-1", "V-2"])
        self.assertEqual(job["next_valve"], "V-1")
        r1 = self.service.submit_receipt(job["id"], {
            "valve_id": "V-1", "receipt_id": "RC-1", "result": "closed",
            "observed_at": "2026-10-04T08:10:00+00:00",
        }, "resp-1", "responder")
        self.assertFalse(r1["duplicate"])
        self.assertEqual(r1["next_valve"], "V-2")
        # 必须按断点顺序
        with self.assertRaises(DomainError) as ctx:
            self.service.submit_receipt(job["id"], {
                "valve_id": "V-1", "receipt_id": "RC-X", "result": "closed",
                "observed_at": "2026-10-04T08:11:00+00:00",
            }, "resp-1", "responder")
        self.assertEqual(ctx.exception.code, "valve_already_closed")
        self.service.submit_receipt(job["id"], {
            "valve_id": "V-2", "receipt_id": "RC-2", "result": "closed",
            "observed_at": "2026-10-04T08:12:00+00:00",
        }, "resp-1", "responder")
        done = self.service.get_job(job["id"])
        self.assertEqual(done["status"], "isolated")
        item = self.service.get_item(item["id"])
        self.assertEqual(item["status"], "isolated")
        self.assertEqual(set(item["payload"]["valve_sequence"]), {"V-1", "V-2"})

    def test_duplicate_receipt_recorded_once(self):
        item = self._leak("S-1")
        job = self.service.create_isolation_job(item["id"], {}, "sup-1", "supervisor")
        payload = {
            "valve_id": "V-1", "receipt_id": "DUP-1", "result": "closed",
            "observed_at": "2026-10-04T08:10:00+00:00",
        }
        first = self.service.submit_receipt(job["id"], payload, "resp-1", "responder")
        second = self.service.submit_receipt(job["id"], dict(payload), "resp-1", "responder")
        self.assertFalse(first["duplicate"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(second["result"], "closed")
        conn = self.repo.connect()
        try:
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM valve_receipts WHERE receipt_id='DUP-1'"
            ).fetchone()["n"]
        finally:
            conn.close()
        self.assertEqual(count, 1)

    def test_failed_valve_resumes_from_breakpoint(self):
        item = self._leak("S-2")
        job = self.service.create_isolation_job(item["id"], {}, "sup-1", "supervisor")
        self.service.submit_receipt(job["id"], {
            "valve_id": "V-1", "receipt_id": "RC-1", "result": "closed",
            "observed_at": "2026-10-04T08:10:00+00:00",
        }, "resp-1", "responder")
        failed = self.service.submit_receipt(job["id"], {
            "valve_id": "V-2", "receipt_id": "RC-F", "result": "failed",
            "observed_at": "2026-10-04T08:11:00+00:00",
        }, "resp-1", "responder")
        self.assertEqual(failed["job_status"], "blocked")
        self.assertEqual(failed["resume_from"], "V-2")
        job = self.service.get_job(job["id"])
        self.assertEqual(job["closed_valves"], ["V-1"])  # 已关阀不回滚
        # 重试断点阀门
        self.service.submit_receipt(job["id"], {
            "valve_id": "V-2", "receipt_id": "RC-2", "result": "closed",
            "observed_at": "2026-10-04T08:20:00+00:00",
        }, "tech-1", "technician")
        self.assertEqual(self.service.get_job(job["id"])["status"], "isolated")

    def test_severity_queue_wins_shared_valves_no_deadlock(self):
        # S-2（高危，要 V-1,V-2）与 S-1（低危，要 V-1）同时申请
        hi = self._leak("S-2", pressure=60, ppm=400, odor=4)
        lo = self._leak("S-1", pressure=1, ppm=2, odor=0, reporter="d2")
        hi_job = self.service.create_isolation_job(hi["id"], {}, "sup-1", "supervisor")
        lo_job = self.service.create_isolation_job(lo["id"], {}, "sup-2", "supervisor")
        self.assertEqual(hi_job["status"], "active")
        self.assertEqual(lo_job["status"], "queued")
        self.assertEqual(lo_job["blocking_valves"], {"V-1": hi_job["id"]})
        # 低危组此时不能关 V-1：阀门不归它
        with self.assertRaises(ConflictError) as ctx:
            self.service.submit_receipt(lo_job["id"], {
                "valve_id": "V-1", "receipt_id": "LO-1", "result": "closed",
                "observed_at": "2026-10-04T08:10:00+00:00",
            }, "resp-2", "responder")
        self.assertEqual(ctx.exception.code, "valve_held_by_other")
        # 高危组完成 -> 恢复流程释放阀门 -> 低危组自动获得
        for idx, valve in enumerate(["V-1", "V-2"], start=1):
            self.service.submit_receipt(hi_job["id"], {
                "valve_id": valve, "receipt_id": "HI-%d" % idx, "result": "closed",
                "observed_at": "2026-10-04T08:%02d:00+00:00" % (10 + idx),
            }, "resp-1", "responder")
        hi = self.service.get_item(hi["id"])
        self.service.act(hi["id"], "repair", {"work_order": "WO"}, "t", "technician", hi["version"])
        hi = self.service.get_item(hi["id"])
        self.service.act(hi["id"], "pressure_test",
                         {"test_passed": True, "pressure_kpa": 150}, "t", "technician", hi["version"])
        hi = self.service.get_item(hi["id"])
        self.service.act(hi["id"], "restore", {"hazards_clear": True},
                         "sup-1", "supervisor", hi["version"])
        self.assertEqual(self.service.get_job(lo_job["id"])["status"], "active")

    def test_concurrent_submissions_do_not_deadlock(self):
        # S-2 与 S-3 共用 V-2，两个线程同时提交
        a = self._leak("S-2", pressure=30, ppm=300, odor=2)
        b = self._leak("S-3", pressure=20, ppm=100, odor=1, reporter="d3")
        ids = {}

        def submit(item_id, key):
            try:
                job = self.service.create_isolation_job(item_id, {}, "sup-%s" % key, "supervisor")
                ids[key] = job["status"]
            except DomainError as exc:
                ids[key] = exc.code

        t1 = threading.Thread(target=submit, args=(a["id"], "a"))
        t2 = threading.Thread(target=submit, args=(b["id"], "b"))
        t1.start(); t2.start(); t1.join(); t2.join()
        statuses = sorted(ids.values())
        # 一个 active 一个 queued，且没有重复键/死锁异常
        self.assertEqual(statuses, ["active", "queued"])

    def test_topology_revision_voids_queued_and_rekeeps_closed(self):
        # 独立拓扑：S-9 = {VA: S-9-S-10, VB: S-9-S-11, VC: S-10-S-11}
        self.service.revise_topology({"connections": [
            {"valve_id": "VA", "segment_a": "S-9", "segment_b": "S-10"},
            {"valve_id": "VB", "segment_a": "S-9", "segment_b": "S-11"},
            {"valve_id": "VC", "segment_a": "S-10", "segment_b": "S-11"},
        ], "note": "branch"}, "sup-1", "supervisor")
        item = self._leak("S-9")
        job = self.service.create_isolation_job(item["id"], {}, "sup-1", "supervisor")
        self.assertEqual(job["required_valves"], ["VA", "VB"])
        self.service.submit_receipt(job["id"], {
            "valve_id": "VA", "receipt_id": "R-A", "result": "closed",
            "observed_at": "2026-10-04T09:00:00+00:00",
        }, "resp-1", "responder")
        # 修订：VA 边删除，VB 保留，VD 新增为 S-9 边界（已关 VA 保留，未执行部分重算）
        result = self.service.revise_topology({"connections": [
            {"valve_id": "VB", "segment_a": "S-9", "segment_b": "S-11"},
            {"valve_id": "VC", "segment_a": "S-10", "segment_b": "S-11"},
            {"valve_id": "VD", "segment_a": "S-9", "segment_b": "S-12"},
        ], "note": "late change"}, "sup-1", "supervisor")
        self.assertEqual(result["revision"], 3)
        job = self.service.get_job(job["id"])
        # 已执行方案：VA 已关但不在新方案（保留 closed 租约），未执行部分重算为 VB,VD
        self.assertEqual(job["status"], "active")
        self.assertEqual(job["required_valves"], ["VB", "VD"])
        self.assertEqual(job["closed_valves"], ["VA"])
        self.assertEqual(job["next_valve"], "VB")
        self.service.submit_receipt(job["id"], {
            "valve_id": "VB", "receipt_id": "R-B", "result": "closed",
            "observed_at": "2026-10-04T09:05:00+00:00",
        }, "resp-1", "responder")
        self.service.submit_receipt(job["id"], {
            "valve_id": "VD", "receipt_id": "R-D", "result": "closed",
            "observed_at": "2026-10-04T09:06:00+00:00",
        }, "resp-1", "responder")
        self.assertEqual(self.service.get_job(job["id"])["status"], "isolated")
        # VA 物理结果仍在账上（closed，未被释放）
        conn = self.repo.connect()
        try:
            state = conn.execute(
                "SELECT state FROM valve_leases WHERE valve_id='VA' AND job_id=? ORDER BY id DESC LIMIT 1",
                (job["id"],),
            ).fetchone()["state"]
        finally:
            conn.close()
        self.assertEqual(state, "closed")

    def test_queued_plan_voided_and_recomputed_on_revision(self):
        # S-3 排队（边界 V-2，被 S-2 占住），修订后 S-3 边界变为 V-2,V-9
        hi = self._leak("S-2")
        lo = self._leak("S-3", pressure=1, ppm=2, odor=0, reporter="d4")
        hi_job = self.service.create_isolation_job(hi["id"], {}, "sup-1", "supervisor")
        lo_job = self.service.create_isolation_job(lo["id"], {}, "sup-2", "supervisor")
        self.assertEqual(lo_job["status"], "queued")
        result = self.service.revise_topology({"connections": [
            {"valve_id": "V-1", "segment_a": "S-1", "segment_b": "S-2"},
            {"valve_id": "V-2", "segment_a": "S-2", "segment_b": "S-3"},
            {"valve_id": "V-9", "segment_a": "S-3", "segment_b": "S-4"},
        ], "note": "extend"}, "sup-1", "supervisor")
        queued_replacements = [r for r in result["replacements"] if "voided_job" in r]
        recomputed = [r for r in result["replacements"] if r.get("recomputed")]
        self.assertEqual(len(queued_replacements), 1)
        self.assertEqual(queued_replacements[0]["voided_job"], lo_job["id"])
        # 进行中的 S-2 方案也按新连接关系重算（V-1,V-2 仍在，无新增/释放）
        self.assertEqual(len(recomputed), 1)
        new_id = queued_replacements[0]["new_job"]
        new_job = self.service.get_job(new_id)
        self.assertEqual(new_job["required_valves"], ["V-2", "V-9"])
        self.assertEqual(new_job["status"], "queued")
        self.assertEqual(new_job["supersedes_job"], lo_job["id"])
        self.assertEqual(self.service.get_job(lo_job["id"])["status"], "voided")

    def test_offline_valve_merge_conflict_suspends_and_resolves(self):
        item = self._leak("S-2")
        job_id = self.service.create_isolation_job(item["id"], {}, "sup-1", "supervisor")["id"]
        # 设备离线：不裁决
        offline = self.service.sync_valve("V-1", {"online": False}, "gw", "sensor")
        self.assertEqual(offline["decision"], "unknown")
        # 恢复后上报与账本一致（held 期望 open）
        ok = self.service.sync_valve("V-1", {"online": True, "device_state": "open"}, "gw", "sensor")
        self.assertEqual(ok["decision"], "consistent")
        # 关掉第一个边界阀（方案仍 active，还有 V-2）
        self.service.submit_receipt(job_id, {
            "valve_id": "V-1", "receipt_id": "R-1", "result": "closed",
            "observed_at": "2026-10-04T09:00:00+00:00",
        }, "resp-1", "responder")
        # 断网恢复后现场却报 open -> 合并冲突，作业挂起
        conflict = self.service.sync_valve(
            "V-1", {"online": True, "device_state": "open"}, "gw", "sensor")
        self.assertEqual(conflict["decision"], "conflict")
        self.assertEqual(self.service.get_job(job_id)["status"], "suspended")
        # 挂起期间回执被拒
        with self.assertRaises(DomainError) as ctx:
            self.service.submit_receipt(job_id, {
                "valve_id": "V-2", "receipt_id": "R-2", "result": "closed",
                "observed_at": "2026-10-04T09:05:00+00:00",
            }, "resp-1", "responder")
        self.assertEqual(ctx.exception.code, "job_suspended")
        # 现场复归一致 -> 自动恢复（回 active，V-2 尚未关）
        self.service.sync_valve("V-1", {"online": True, "device_state": "closed"}, "gw", "sensor")
        job = self.service.get_job(job_id)
        self.assertEqual(job["status"], "active")
        self.assertEqual(job["next_valve"], "V-2")

    def test_conflict_resolution_adopt_remote_closed(self):
        item = self._leak("S-1")
        job_id = self.service.create_isolation_job(item["id"], {}, "sup-1", "supervisor")["id"]
        # 账本认为 held(现场应 open)，现场却报 closed：冲突挂起
        conflict = self.service.sync_valve(
            "V-1", {"online": True, "device_state": "closed"}, "gw", "sensor")
        self.assertEqual(conflict["decision"], "conflict")
        # 监督岗裁决以现场为准：直接接受物理关阀结果，方案完成
        resolved = self.service.resolve_job(job_id, {"resolution": "adopt_device"},
                                            "sup-1", "supervisor")
        self.assertEqual(resolved["status"], "isolated")

    def test_legacy_data_without_topology_is_read_only_compatible(self):
        # 无连接关系的旧事件：可读、可走原有手工流程；账本隔离明确拒绝
        self.service.revise_topology({"connections": [
            {"valve_id": "V-1", "segment_a": "S-1", "segment_b": "S-2"},
        ], "note": "minimal"}, "sup-1", "supervisor")
        item = self.service.create_item({
            "pipeline_id": "P-9",
            "segment_id": "SEG-OLD",
            "reported_at": "2026-10-04T10:00:00+00:00",
            "pressure_drop_kpa": 5,
            "sensor_value_ppm": 5,
            "odor_reports": 0,
            "reporter": "legacy",
        }, "legacy", "dispatcher")
        fetched = self.service.get_item(item["id"])  # 只读不报错
        self.assertEqual(fetched["payload"]["segment_id"], "SEG-OLD")
        item = self.service.act(item["id"], "verify", {"field_confirmed": True},
                                "r", "responder", item["version"])
        with self.assertRaises(DomainError) as ctx:
            self.service.create_isolation_job(item["id"], {}, "sup-1", "supervisor")
        self.assertEqual(ctx.exception.code, "topology_unavailable")
        # 手工流程仍可用（旧阀 VX 未登记，不管账）
        item = self.service.act(item["id"], "isolate",
                                {"valve_sequence": ["VX-1", "VX-2"]},
                                "sup-1", "supervisor", item["version"])
        self.assertEqual(item["status"], "isolated")

    def test_cancel_voids_queued_plan(self):
        hi = self._leak("S-2")
        lo = self._leak("S-1", pressure=1, ppm=2, odor=0, reporter="d5")
        self.service.create_isolation_job(hi["id"], {}, "sup-1", "supervisor")
        lo_job = self.service.create_isolation_job(lo["id"], {}, "sup-2", "supervisor")
        self.assertEqual(lo_job["status"], "queued")
        self.service.act(lo["id"], "cancel", {"reason": "false alarm"},
                         "sup-2", "supervisor", lo["version"])
        self.assertEqual(self.service.get_job(lo_job["id"])["status"], "voided")


class PureLogicTest(unittest.TestCase):
    def test_boundary_and_breakpoint(self):
        edges = [
            {"valve_id": "VA", "segment_a": "S1", "segment_b": "S2"},
            {"valve_id": "VB", "segment_a": "S2", "segment_b": "S3"},
        ]
        self.assertEqual(boundary_valves(edges, "S2"), ["VA", "VB"])
        self.assertEqual(boundary_valves(edges, "SX"), [])
        self.assertEqual(expected_valve(["VA", "VB"], ["VA"]), "VB")
        self.assertIsNone(expected_valve(["VA"], ["VA"]))

    def test_revision_effect_rekeeps_closed(self):
        effect = revision_effect(
            required=["VA", "VB", "VX"],
            closed=["VA"],
            leased=["VA", "VB", "VX"],
            new_required=["VB", "VC"],
        )
        # VX 未关且不再需要 -> 释放；VB 仍在新方案 -> 保留；VA 已关 -> 物理结果保留
        self.assertEqual(effect["release"], ["VX"])
        self.assertEqual(effect["acquire"], ["VC"])
        self.assertEqual(effect["retain_closed"], ["VA"])

    def test_merge_decision(self):
        self.assertEqual(merge_decision(False, "held", None), "unknown")
        self.assertEqual(merge_decision(True, "held", "open"), "consistent")
        self.assertEqual(merge_decision(True, "closed", "closed"), "consistent")
        self.assertEqual(merge_decision(True, "closed", "open"), "conflict")


if __name__ == "__main__":
    unittest.main()
