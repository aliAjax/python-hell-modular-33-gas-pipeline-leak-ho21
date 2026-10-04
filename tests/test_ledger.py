import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.repository import Repository
from src.service import Service
from src.domain import ConflictError, DomainError
from src import ledger


class LedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.repo = Repository(self.tmp.name)
        self.repo.initialize()
        self.service = Service(self.repo)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def _item(self, pipeline_id, segment_id, pressure=30, ppm=120, odor=3, reported_at="2026-09-27T08:00:00+00:00"):
        return self.service.create_item(
            {
                "pipeline_id": pipeline_id,
                "segment_id": segment_id,
                "reported_at": reported_at,
                "pressure_drop_kpa": pressure,
                "sensor_value_ppm": ppm,
                "odor_reports": odor,
                "reporter": "dispatch",
            },
            "dispatch",
            "dispatcher",
        )

    def _topology(self, pipeline_id, segment_id, valves):
        return self.service.set_topology(
            {"pipeline_id": pipeline_id, "segment_id": segment_id, "valves": valves},
            "eng",
            "dispatcher",
        )

    # 1) 按严重度排队占用阀门；阀门同一时刻只归一组作业；无死锁
    def test_severity_queue_and_valve_mutex(self):
        self._topology("P-1", "S-1", ["V-1", "V-2"])
        self._topology("P-1", "S-2", ["V-2", "V-3"])
        critical = self._item("P-1", "S-1", pressure=30, ppm=120, odor=3)  # 87 critical
        high = self._item("P-1", "S-2", pressure=20, ppm=150, odor=2)      # 65 high

        plan_a = self.service.submit_isolation(critical["id"], "sup", "supervisor")
        plan_b = self.service.submit_isolation(high["id"], "sup", "supervisor")

        self.assertEqual(plan_a["status"], "in_progress")
        self.assertEqual(plan_b["status"], "queued")
        # V-2 同时被两组需要，但只归高严重度的 A
        valves = {v["valve_id"]: v for v in self.service.list_valves()["valves"]}
        self.assertEqual(valves["V-2"]["occupied_by"], plan_a["id"])
        self.assertIsNone(valves["V-3"]["occupied_by"])

        # A 关完 V-1、V-2 后释放，B 不再死锁，自动开始
        self.service.submit_receipt(critical["id"], {"valve_id": "V-1", "result": "closed"}, "r", "responder")
        done = self.service.submit_receipt(critical["id"], {"valve_id": "V-2", "result": "closed"}, "r", "responder")
        self.assertEqual(done["plan"]["status"], "completed")
        plan_b = self.service.get_isolation(high["id"])["plan"]
        self.assertEqual(plan_b["status"], "in_progress")

    # 2) 关阀失败后从断点恢复，已关阀门不重复关
    def test_resume_from_breakpoint(self):
        self._topology("P-1", "S-1", ["V-1", "V-2", "V-3"])
        item = self._item("P-1", "S-1")
        self.service.submit_isolation(item["id"], "sup", "supervisor")

        r1 = self.service.submit_receipt(item["id"], {"valve_id": "V-1", "result": "closed"}, "r", "responder")
        self.assertEqual(r1["outcome"], "closed")
        r2 = self.service.submit_receipt(item["id"], {"valve_id": "V-2", "result": "failed"}, "r", "responder")
        self.assertEqual(r2["outcome"], "failed")
        self.assertEqual(r2["plan"]["status"], "partially_closed")
        self.assertEqual(r2["plan"]["failed_valve"], "V-2")

        resumed = self.service.resume_isolation(item["id"], "r", "responder")
        self.assertEqual(resumed["status"], "in_progress")
        self.assertIsNone(resumed["failed_valve"])

        self.service.submit_receipt(item["id"], {"valve_id": "V-2", "result": "closed"}, "r", "responder")
        done = self.service.submit_receipt(item["id"], {"valve_id": "V-3", "result": "closed"}, "r", "responder")
        self.assertEqual(done["plan"]["status"], "completed")

        receipts = {r["valve_id"]: r for r in done["plan"]["receipts"]}
        self.assertEqual(receipts["V-1"]["attempts"], 1)
        self.assertEqual(receipts["V-2"]["attempts"], 2)  # 失败后重试成功
        self.assertEqual(receipts["V-3"]["attempts"], 1)
        self.assertEqual(len(done["plan"]["receipts"]), 3)

    # 3) 重复回执只记一次
    def test_duplicate_receipt_recorded_once(self):
        self._topology("P-1", "S-1", ["V-1", "V-2"])
        item = self._item("P-1", "S-1")
        self.service.submit_isolation(item["id"], "sup", "supervisor")

        first = self.service.submit_receipt(item["id"], {"valve_id": "V-1", "result": "closed"}, "r", "responder")
        self.assertEqual(first["outcome"], "closed")
        second = self.service.submit_receipt(item["id"], {"valve_id": "V-1", "result": "closed"}, "r", "responder")
        self.assertEqual(second["outcome"], "duplicate")

        plan = self.service.get_isolation(item["id"])["plan"]
        self.assertEqual(plan["closed_valves"], ["V-1"])  # 不重复计数
        self.assertEqual(len(plan["receipts"]), 1)
        self.assertEqual(plan["receipts"][0]["attempts"], 1)

    # 4) 连接关系更新：未执行方案作废重算，已关阀门留结果
    def test_topology_update_invalidates_and_keeps_closed(self):
        self._topology("P-1", "S-1", ["V-1", "V-2"])
        item_a = self._item("P-1", "S-1")
        plan_a = self.service.submit_isolation(item_a["id"], "sup", "supervisor")
        self.service.submit_receipt(item_a["id"], {"valve_id": "V-1", "result": "closed"}, "r", "responder")

        item_b = self._item("P-1", "S-1", pressure=20, ppm=150, odor=2, reported_at="2026-09-27T09:00:00+00:00")
        plan_b = self.service.submit_isolation(item_b["id"], "sup", "supervisor")
        self.assertEqual(plan_b["status"], "queued")

        summary = self._topology("P-1", "S-1", ["V-1", "V-5"])
        self.assertIn(plan_b["id"], summary["invalidated"])
        self.assertIn(plan_a["id"], summary["drifted"])
        self.assertEqual(len(summary["replacements"]), 1)

        plan_a = self.service.get_isolation(item_a["id"])["plan"]
        self.assertTrue(plan_a["topology_drifted"])
        self.assertEqual(plan_a["closed_valves"], ["V-1"])  # 已关阀门留结果

        replacement = self.repo.get_active_plan(item_b["id"])
        self.assertEqual(replacement["valves"], ["V-1", "V-5"])  # 作废重算
        self.assertNotEqual(replacement["id"], plan_b["id"])

    # 5) 断网阀位恢复后合并，冲突项挂起
    def test_position_merge_suspends_conflict(self):
        self._topology("P-1", "S-1", ["V-1", "V-2"])
        item = self._item("P-1", "S-1")
        plan = self.service.submit_isolation(item["id"], "sup", "supervisor")
        self.service.submit_receipt(item["id"], {"valve_id": "V-1", "result": "closed"}, "r", "responder")

        # 不矛盾的上报：V-2 尚未关闭，报 open 与台账一致
        ok = self.service.merge_positions(
            {"reports": [{"valve_id": "V-2", "position": "open", "observed_at": "2026-09-27T10:00:00+00:00"}]},
            "eng",
            "dispatcher",
        )
        self.assertEqual(ok["suspended"], [])

        # 矛盾上报：台账显示 V-1 已关，实际上报 open -> 挂起
        conflict = self.service.merge_positions(
            {"reports": [{"valve_id": "V-1", "position": "open", "observed_at": "2026-09-27T11:00:00+00:00"}]},
            "eng",
            "dispatcher",
        )
        self.assertEqual(len(conflict["suspended"]), 1)
        plan = self.service.get_isolation(item["id"])["plan"]
        self.assertEqual(plan["status"], "suspended")
        self.assertEqual(plan["conflict"]["reason"], "valve_position_conflict")
        valves = {v["valve_id"]: v for v in self.service.list_valves()["valves"]}
        self.assertIsNone(valves["V-1"]["occupied_by"])  # 挂起后释放预留

        # 挂起后不能直接恢复，需人工裁决
        with self.assertRaises(DomainError) as ctx:
            self.service.resume_isolation(item["id"], "r", "responder")
        self.assertEqual(ctx.exception.code, "plan_suspended")

        # 裁决 proceed 后重新排队
        resolved = self.service.resolve_isolation(item["id"], {"resolution": "proceed"}, "sup", "supervisor")
        self.assertEqual(resolved["status"], "in_progress")

    # 6) 旧数据缺连接关系：只读兼容
    def test_legacy_data_read_only(self):
        item = self._item("P-9", "S-9")  # 未维护连接关系
        # 读取正常
        read = self.service.get_item(item["id"])
        self.assertIn("assessment", read)
        self.assertEqual(read["status"], "reported")
        self.service.list_items()
        self.service.state()
        # 写入隔离账被拒绝（只读兼容）
        with self.assertRaises(DomainError) as ctx:
            self.service.submit_isolation(item["id"], "sup", "supervisor")
        self.assertEqual(ctx.exception.code, "topology_required")
        self.assertEqual(ctx.exception.status, 409)

    # 7) 严重度排序纯逻辑
    def test_severity_ordering(self):
        plans = [
            {"id": 1, "severity": "low"},
            {"id": 2, "severity": "critical"},
            {"id": 3, "severity": "high"},
            {"id": 4, "severity": "critical"},
        ]
        ordered = ledger.sort_plans(plans)
        self.assertEqual([p["id"] for p in ordered], [2, 4, 3, 1])

    # 8) 越权与参数校验
    def test_permission_and_validation(self):
        self._topology("P-1", "S-1", ["V-1", "V-2"])
        item = self._item("P-1", "S-1")
        with self.assertRaises(DomainError) as ctx:
            self.service.submit_isolation(item["id"], "x", "technician")
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(DomainError) as ctx:
            self.service.set_topology({"pipeline_id": "P", "segment_id": "S", "valves": []}, "eng", "dispatcher")
        self.assertEqual(ctx.exception.code, "valves_required")


if __name__ == "__main__":
    unittest.main()
