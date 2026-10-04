"""管段连接关系（拓扑）校验与查询。

连接关系描述“某条管段的边界阀门有哪些”。相邻管段共用阀门，
因此同一阀门会出现在多条管段的连接关系中——这正是隔离账排队
与互斥的依据。
"""

from .domain import DomainError


def segment_key(pipeline_id, segment_id):
    return "%s|%s" % (pipeline_id, segment_id)


def normalize_valves(payload):
    """从请求体解析阀门列表，去重、保序、去空白。"""
    valves = payload.get("valves")
    if not isinstance(valves, list) or not valves:
        raise DomainError("valves_required", "必须提供该管段的边界阀门列表")
    result = []
    seen = set()
    for value in valves:
        if not isinstance(value, str):
            raise DomainError("invalid_valve", "阀门编号必须是字符串")
        valve = value.strip()
        if not valve:
            raise DomainError("invalid_valve", "阀门编号不能为空")
        if valve not in seen:
            seen.add(valve)
            result.append(valve)
    if not result:
        raise DomainError("valves_required", "阀门列表不能为空")
    return result


def normalize_connection(payload):
    pipeline_id = payload.get("pipeline_id")
    segment_id = payload.get("segment_id")
    if not isinstance(pipeline_id, str) or not pipeline_id.strip():
        raise DomainError("field_required", "pipeline_id 不能为空")
    if not isinstance(segment_id, str) or not segment_id.strip():
        raise DomainError("field_required", "segment_id 不能为空")
    return {
        "pipeline_id": pipeline_id.strip(),
        "segment_id": segment_id.strip(),
        "valves": normalize_valves(payload),
    }


def segment_valves(rows):
    """把一组 (pipeline_id, segment_id, valve_id) 行整理成 {segment_key: [valves]}。"""
    result = {}
    for row in rows:
        key = segment_key(row["pipeline_id"], row["segment_id"])
        result.setdefault(key, [])
        if row["valve_id"] not in result[key]:
            result[key].append(row["valve_id"])
    for valves in result.values():
        valves.sort()
    return result
