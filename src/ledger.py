"""隔离账纯逻辑：严重度排队、阀门互斥、断点恢复、回执幂等、拓扑作废与冲突挂起。

本模块不接触数据库，只操作普通 dict/list，便于单测。持久化与事务
由 repository 层负责，service 层负责角色与编排。

核心不变量：
- 阀门同一时刻只归一组作业（occupied_by 互斥）。
- 方案按严重度排队；同一阀门被占用时，等待方按严重度排序，
  高严重度方案优先获得阀门，且不会出现“互相锁死”（占用为
  all-or-nothing：方案一次性占用全部所需阀门，否则继续等待）。
- 关阀必须按顺序逐阀进行；失败后记录断点，恢复时从断点继续，
  已关阀门不重复关闭。
- 重复回执只记一次（同方案同阀门同结果的重复提交幂等）。
"""

from .domain import DomainError
from .rules import assess

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

ACTIVE_STATUSES = ("queued", "in_progress", "partially_closed")
HELD_STATUSES = ("in_progress", "partially_closed")


def severity_of(payload):
    """从泄漏事件 payload 取严重度（critical/high/medium/low）。"""
    return assess(payload)["level"]


def sort_plans(plans):
    """按严重度（高→低）、同严重度按 id（先到先得）排序。"""
    return sorted(plans, key=lambda p: (SEVERITY_ORDER.get(p["severity"], 99), p["id"]))


def active_plans(plans):
    return [p for p in plans if p["status"] in ACTIVE_STATUSES]


def held_valves(plan):
    """方案当前已占用（预留）的阀门。"""
    return list(plan.get("occupied_valves", plan.get("valves", [])))


def closed_valves(plan):
    return list(plan.get("closed_valves", []))


def remaining_valves(plan):
    """尚未关闭的阀门（按方案顺序）。"""
    closed = set(closed_valves(plan))
    return [v for v in plan["valves"] if v not in closed]


def next_expected_valve(plan):
    """下一个应关闭的阀门；全部关闭返回 None。"""
    remaining = remaining_valves(plan)
    return remaining[0] if remaining else None


def _is_held_by_other(valve_id, plan, valves):
    state = valves.get(valve_id)
    if state is None:
        return False
    holder = state.get("occupied_by")
    return holder is not None and holder != plan["id"]


def _higher_severity_waiting(valve_id, plan, plans):
    """是否有更高严重度且仍在排队（尚未占用）的方案也需要该阀门。"""
    for other in plans:
        if other["id"] == plan["id"]:
            continue
        if other["status"] != "queued":
            continue
        if SEVERITY_ORDER.get(other["severity"], 99) >= SEVERITY_ORDER.get(plan["severity"], 99):
            continue
        if valve_id in other["valves"]:
            return True
    return False


def can_occupy(plan, plans, valves):
    """方案能否一次性占用全部所需阀门（all-or-nothing）。

    条件：每个阀门都未被其他方案占用，且没有更高严重度的排队方案
    需要其中任何一个阀门。
    """
    for valve_id in plan["valves"]:
        if _is_held_by_other(valve_id, plan, valves):
            return False
        if _higher_severity_waiting(valve_id, plan, plans):
            return False
    return True


def allocate(plans, valves):
    """按严重度顺序，让排队中的方案占用阀门。

    返回新开始（queued→in_progress）的方案列表。原地修改 plans/valves。
    """
    started = []
    for plan in sort_plans([p for p in plans if p["status"] == "queued"]):
        if not can_occupy(plan, plans, valves):
            continue
        for valve_id in plan["valves"]:
            state = valves.get(valve_id)
            if state is None:
                state = {"valve_id": valve_id, "position": "unknown", "occupied_by": None}
                valves[valve_id] = state
            state["occupied_by"] = plan["id"]
        plan["status"] = "in_progress"
        plan["occupied_valves"] = list(plan["valves"])
        started.append(plan)
    return started


def release_plan_valves(plan, valves):
    """释放方案占用的全部阀门（已关阀门的物理位置保留，仅解除预留）。"""
    for valve_id in held_valves(plan):
        state = valves.get(valve_id)
        if state is not None and state.get("occupied_by") == plan["id"]:
            state["occupied_by"] = None
    plan["occupied_valves"] = []


def apply_receipt(plan, receipt, valves):
    """处理一条关阀回执，返回 (outcome, events)。

    outcome: "closed" | "failed" | "duplicate"
    - 必须按顺序关阀（下一个应关阀门）。
    - 同方案同阀门同结果的重复回执幂等，不重复计数。
    - 关阀失败：方案置 partially_closed，记录断点，等待 resume。
    - 全部关完：方案 completed，释放阀门。
    """
    if plan["status"] not in HELD_STATUSES:
        raise DomainError("plan_not_active", "方案不在执行状态，不能提交关阀回执", 409)
    valve_id = receipt.get("valve_id")
    result = receipt.get("result")
    if not isinstance(valve_id, str) or not valve_id.strip():
        raise DomainError("valve_required", "回执必须指明阀门", 400)
    valve_id = valve_id.strip()
    if result not in ("closed", "failed"):
        raise DomainError("invalid_receipt_result", "回执结果必须是 closed 或 failed", 400)
    if valve_id not in plan["valves"]:
        raise DomainError("valve_not_in_plan", "阀门 %s 不在该方案的隔离范围内" % valve_id, 400)

    expected = next_expected_valve(plan)
    already_closed = valve_id in closed_valves(plan)

    if result == "closed" and already_closed:
        return "duplicate", []
    if result == "failed" and already_closed:
        # 台账显示已关，回执却报失败——矛盾，走冲突挂起。
        return "conflict", [{"type": "valve_status_conflict", "valve_id": valve_id}]

    if valve_id != expected:
        raise DomainError(
            "valve_sequence_violation",
            "必须按顺序关阀，当前应关闭 %s" % expected,
            409,
        )

    events = []
    if result == "closed":
        plan["closed_valves"].append(valve_id)
        plan["failed_valve"] = None
        events.append({"type": "valve_closed", "valve_id": valve_id})
        if all(v in plan["closed_valves"] for v in plan["valves"]):
            plan["status"] = "completed"
            plan["completed_at"] = receipt.get("observed_at")
            release_plan_valves(plan, valves)
            events.append({"type": "isolation_completed"})
        else:
            plan["status"] = "in_progress"
    else:  # failed
        plan["status"] = "partially_closed"
        plan["failed_valve"] = valve_id
        events.append({"type": "valve_close_failed", "valve_id": valve_id})
    return result, events


def resume_plan(plan, valves, topology_valves):
    """从断点恢复关阀。

    - 仅 partially_closed 可恢复。
    - 若期间连接关系更新（topology_drifted），按新连接关系重算剩余
      阀门（已关阀门保留），再继续。
    - 恢复后状态回到 in_progress，从下一个未关阀门继续。
    返回 (resumed_valves, events)。
    """
    if plan["status"] != "partially_closed":
        raise DomainError("nothing_to_resume", "没有需要从断点恢复的失败关阀", 409)
    events = []
    if plan.get("topology_drifted"):
        new_valves = recompute_valves(plan, topology_valves)
        plan["valves"] = new_valves
        plan["topology_drifted"] = False
        events.append({"type": "plan_recomputed", "valves": list(new_valves)})
    # 确保剩余阀门仍被本方案预留
    for valve_id in plan["valves"]:
        if valve_id in closed_valves(plan):
            continue
        state = valves.get(valve_id)
        if state is None:
            state = {"valve_id": valve_id, "position": "unknown", "occupied_by": None}
            valves[valve_id] = state
        if state.get("occupied_by") in (None, plan["id"]):
            state["occupied_by"] = plan["id"]
    plan["occupied_valves"] = [v for v in plan["valves"] if v not in closed_valves(plan)]
    plan["status"] = "in_progress"
    plan["failed_valve"] = None
    events.append({"type": "isolation_resumed"})
    return plan["valves"], events


def recompute_valves(plan, topology_valves):
    """按新连接关系重算方案所需阀门：新拓扑阀门减去已关阀门。"""
    closed = set(closed_valves(plan))
    return [v for v in topology_valves if v not in closed]


def suspend_plan(plan, conflict, valves):
    """冲突挂起：释放预留阀门，记录冲突，等待人工裁决。"""
    plan["status"] = "suspended"
    plan["conflict"] = conflict
    release_plan_valves(plan, valves)


def requeue_plan(plan, valves):
    """人工裁决后重新排队（释放预留、回到 queued，等待 allocate）。"""
    plan["status"] = "queued"
    plan["conflict"] = None
    plan["failed_valve"] = None
    release_plan_valves(plan, valves)


def topology_update_effects(plans, segment_key, new_valves, new_version):
    """连接关系更新对方案的影响。

    - queued（未执行）方案：作废（invalidated），随后由调用方按新拓扑
      重算并创建替代方案。
    - in_progress/partially_closed（已开始）方案：标记 topology_drifted，
      已关阀门保留，恢复时按新拓扑重算剩余阀门。
    返回 (invalidated, drifted) 两个方案列表。
    """
    invalidated = []
    drifted = []
    for plan in plans:
        if plan["segment_key"] != segment_key:
            continue
        if plan["status"] == "queued":
            plan["status"] = "invalidated"
            plan["conflict"] = {"reason": "topology_changed", "topology_version": new_version}
            invalidated.append(plan)
        elif plan["status"] in HELD_STATUSES:
            plan["topology_drifted"] = True
            drifted.append(plan)
    return invalidated, drifted


def merge_positions(reports, valves, plans):
    """合并断网期间上报的阀位。

    对每条上报：更新阀位；若与台账矛盾（台账显示已关但上报为 open），
    挂起占用该阀门的方案。返回 {"merged": [...], "suspended": [...]}。
    """
    suspended = []
    merged = []
    for report in reports:
        valve_id = report.get("valve_id")
        position = report.get("position")
        if not isinstance(valve_id, str) or not valve_id.strip():
            raise DomainError("valve_required", "阀位上报必须指明阀门", 400)
        valve_id = valve_id.strip()
        if position not in ("open", "closed", "unknown"):
            raise DomainError("invalid_position", "阀位必须是 open/closed/unknown", 400)
        observed_at = report.get("observed_at")
        state = valves.get(valve_id)
        if state is None:
            state = {"valve_id": valve_id, "position": "unknown", "occupied_by": None}
            valves[valve_id] = state
        state["position"] = position
        merged.append({"valve_id": valve_id, "position": position, "observed_at": observed_at})
        if position != "open":
            continue
        # 矛盾：台账显示该阀门已被某方案关闭，但实际上报为 open。
        for plan in active_plans(plans):
            if valve_id not in plan["valves"]:
                continue
            if valve_id not in closed_valves(plan):
                continue
            conflict = {
                "reason": "valve_position_conflict",
                "valve_id": valve_id,
                "expected": "closed",
                "reported": "open",
                "observed_at": observed_at,
            }
            suspend_plan(plan, conflict, valves)
            suspended.append({"plan_id": plan["id"], "item_id": plan["item_id"], "conflict": conflict})
    return {"merged": merged, "suspended": suspended}
