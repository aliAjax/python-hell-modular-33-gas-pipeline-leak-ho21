"""隔离账纯逻辑：方案计算、严重度排队、断点、阀位合并、拓扑修订效应。

本模块不碰数据库，所有函数均可单测：
- boundary_valves：按管段连接关系计算隔离边界阀
- revision_effect：连接关系修订后，未执行部分作废、已关阀保留
- expected_valve：关阀断点（下一个待操作阀门）
- merge_decision：断网恢复后远端阀位与账本的合并判定
"""

from .domain import DomainError

# 作业生命周期
JOB_QUEUED = "queued"          # 排队等待分配阀门
JOB_ACTIVE = "active"          # 阀门已分到本组，正在关阀
JOB_BLOCKED = "blocked"        # 关阀失败，停在断点
JOB_ISOLATED = "isolated"      # 边界阀全部关闭，隔离完成
JOB_SUSPENDED = "suspended"    # 阀位冲突，挂起待裁决
JOB_VOIDED = "voided"          # 方案作废（拓扑修订后重算 / 事件取消）

ACTIVE_STATUSES = (JOB_QUEUED, JOB_ACTIVE, JOB_BLOCKED, JOB_SUSPENDED)
LIVE_STATUSES = (JOB_QUEUED, JOB_ACTIVE, JOB_BLOCKED, JOB_SUSPENDED)

# 阀门租约状态
LEASE_HELD = "held"            # 已占用、尚未关闭
LEASE_CLOSED = "closed"        # 已关闭（物理结果，留账）
LEASE_RELEASED = "released"

RESULT_CLOSED = "closed"
RESULT_FAILED = "failed"
VALID_RESULTS = (RESULT_CLOSED, RESULT_FAILED)

DEVICE_OPEN = "open"
DEVICE_CLOSED = "closed"
VALID_DEVICE_STATES = (DEVICE_OPEN, DEVICE_CLOSED)


def boundary_valves(edges, segment_id):
    """一个管段的隔离边界 = 所有与该管段相接的连接上的阀门（最小切割集）。

    edges: [{"valve_id", "segment_a", "segment_b"(可空)}]
    相邻管段共用阀门时，该阀门自然同时出现在两侧方案里，由排队/互斥层裁决。
    """
    valves = set()
    for edge in edges:
        if edge.get("segment_a") == segment_id or edge.get("segment_b") == segment_id:
            valves.add(edge["valve_id"])
    return sorted(valves)


def expected_valve(required, closed):
    """返回当前断点：方案中第一个尚未关闭的阀门；全部关闭返回 None。"""
    closed_set = set(closed)
    for valve_id in required:
        if valve_id not in closed_set:
            return valve_id
    return None


def revision_effect(required, closed, leased, new_required):
    """连接关系修订对一份在执行方案的影响（全集合入参，排序后返回）。

    - 新方案不再需要、且还没关的阀门：立即释放（作废未执行部分）
    - 已经关闭的阀门：无论是否仍在新方案中，物理结果保留（继续占用到统一释放）
    - 新方案新增、当前未占用的阀门：需要重新申请
    """
    required = set(required)
    closed = set(closed)
    leased = set(leased)
    new_required = set(new_required)

    release = sorted(v for v in leased if v not in new_required and v not in closed)
    retain_closed = sorted(closed)
    acquire = sorted(v for v in new_required if v not in leased)
    new_plan = sorted(new_required)
    return {
        "plan": new_plan,
        "acquire": acquire,
        "release": release,
        "retain_closed": retain_closed,
    }


def merge_decision(online, lease_state, device_state):
    """断网恢复后合并远端阀位。

    - 设备仍离线 / 未带阀位：unknown，不裁决
    - 租约 closed 期望现场 closed；held 期望现场 open
    - 一致 => consistent（冲突挂起项可自动恢复），不一致 => conflict（挂起）
    """
    if not online or not device_state:
        return "unknown"
    expected = DEVICE_CLOSED if lease_state == LEASE_CLOSED else DEVICE_OPEN
    return "consistent" if device_state == expected else "conflict"


def normalize_receipt(payload):
    from .domain import require_text, parse_timestamp

    valve_id = require_text(payload, "valve_id")
    receipt_id = require_text(payload, "receipt_id")
    result = require_text(payload, "result")
    if result not in VALID_RESULTS:
        raise DomainError("invalid_result", "result 只能是 closed 或 failed")
    observed_at = parse_timestamp(payload, "observed_at")
    return {
        "valve_id": valve_id,
        "receipt_id": receipt_id,
        "result": result,
        "observed_at": observed_at,
    }


def normalize_edge(payload):
    from .domain import require_text

    valve_id = require_text(payload, "valve_id")
    segment_a = require_text(payload, "segment_a")
    segment_b = payload.get("segment_b")
    if segment_b is not None:
        if not isinstance(segment_b, str) or not segment_b.strip():
            raise DomainError("field_required", "segment_b 为空时应省略")
        segment_b = segment_b.strip()
    return {"valve_id": valve_id, "segment_a": segment_a, "segment_b": segment_b}
