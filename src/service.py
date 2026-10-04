from . import domain, rules, isolation
from .domain import DomainError, ConflictError

ISOLATION_ROLES = {"supervisor", "responder"}
RECEIPT_ROLES = {"supervisor", "responder", "technician"}
TOPOLOGY_ROLES = {"supervisor"}
SYNC_ROLES = {"dispatcher", "sensor", "supervisor", "responder", "patrol"}


class Service:
    def __init__(self, repository):
        self.repository = repository

    def create_item(self, payload, actor, role, region=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.CREATE_ROLES:
            raise DomainError("forbidden", "当前角色不能创建此类业务记录", 403)
        normalized = domain.normalize_create(payload)
        stable_key = normalized.pop("_stable_key")
        return self.repository.create_item(
            rules.ENTITY_TYPE, stable_key, rules.INITIAL_STATUS, normalized, actor, role
        )

    def add_source(self, item_id, payload, actor, role, region=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.SOURCE_ROLES:
            raise DomainError("forbidden", "当前角色不能提交来源记录", 403)
        item = self.repository.get_item(item_id)
        normalized = domain.normalize_source(payload)
        if region and rules.ENFORCE_REGION and role != "regulator" and normalized.get("region") and normalized["region"] != region:
            raise DomainError("region_mismatch", "来源记录不属于当前管辖区域", 403)
        result = self.repository.add_source(
            item_id,
            normalized.pop("source_type"),
            normalized.pop("external_id"),
            normalized,
            normalized.pop("observed_at"),
            actor,
            role,
        )
        return result

    def act(self, item_id, action, payload, actor, role, expected_version=None, region=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        item = self.repository.get_item(item_id)
        allowed = rules.ACTION_ROLES.get(action, set())
        if role not in allowed:
            raise DomainError("forbidden", "当前角色不能执行该操作", 403)
        if rules.ENFORCE_REGION and action in rules.REGION_SENSITIVE_ACTIONS and region and role != "regulator":
            if item["payload"].get("region") != region:
                raise DomainError("region_mismatch", "不能处理其他区域的记录", 403)
        if action in rules.ACTION_REQUIRES_VERSION and expected_version is None:
            raise DomainError("expected_version_required", "该操作需要 expected_version", 400)
        # 账本隔离方案进行中时，手工 isolate 与账本互斥，防止同一阀门两套结论
        if action == "isolate" and self.repository.has_live_job(item_id):
            raise ConflictError("isolation_job_in_progress", "该事件已有隔离账方案，请通过回执推进")
        new_status, new_payload, event_payload = rules.apply_action(item, action, payload, actor, role)
        self.repository.apply_action(
            item_id, action, actor, role, new_status, new_payload, event_payload, expected_version
        )
        if action == "isolate":
            # 旧路径兼容：手工序列里已登记进拓扑的阀门按账本口径关阀留账
            self.repository.occupy_manual_valves(item_id, event_payload.get("valve_sequence", []), actor, role)
        if action == "restore":
            # 恢复供气后统一释放占用（含已关）阀门，让排队中的隔离组继续
            self.repository.release_item_valves(item_id, actor, role)
        if action == "cancel":
            # 未执行方案作废；已关阀结果保留
            self.repository.cancel_open_jobs(item_id, event_payload.get("reason", "cancelled"), actor, role)
        return self.get_item(item_id)

    # ------------------------------------------------------------------
    # 隔离账
    # ------------------------------------------------------------------

    def topology(self):
        return self.repository.topology()

    def register_valve(self, payload, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in TOPOLOGY_ROLES:
            raise DomainError("forbidden", "只有监督岗能登记阀门", 403)
        valve_id = domain.require_text(payload, "valve_id")
        return self.repository.register_valve(valve_id, actor, role)

    def revise_topology(self, payload, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in TOPOLOGY_ROLES:
            raise DomainError("forbidden", "只有监督岗能修订连接关系", 403)
        raw_edges = payload.get("connections")
        if not isinstance(raw_edges, list) or not raw_edges:
            raise DomainError("connections_required", "需要提交完整的连接关系列表")
        edges = [isolation.normalize_edge(edge) for edge in raw_edges]
        note = str(payload.get("note", ""))
        return self.repository.commit_revision(edges, note, actor, role)

    def create_isolation_job(self, item_id, payload, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in ISOLATION_ROLES:
            raise DomainError("forbidden", "当前角色不能提交隔离申请", 403)
        item = self.repository.get_item(item_id)
        segment_id = payload.get("segment_id") if isinstance(payload, dict) else None
        if not isinstance(segment_id, str) or not segment_id.strip():
            segment_id = item["payload"].get("segment_id")
        if not segment_id:
            raise DomainError("segment_required", "缺少管段标识")
        return self.repository.create_isolation_job(item_id, segment_id.strip(), actor, role)

    def list_jobs(self, status=None):
        return self.repository.list_jobs(status)

    def get_job(self, job_id):
        return self.repository.get_job(job_id)

    def submit_receipt(self, job_id, payload, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in RECEIPT_ROLES:
            raise DomainError("forbidden", "当前角色不能提交关阀回执", 403)
        normalized = isolation.normalize_receipt(payload)
        return self.repository.add_valve_receipt(
            job_id,
            normalized["valve_id"],
            normalized["receipt_id"],
            normalized["result"],
            normalized["observed_at"],
            actor,
            role,
        )

    def sync_valve(self, valve_id, payload, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in SYNC_ROLES:
            raise DomainError("forbidden", "当前角色不能上报阀位", 403)
        online = bool(payload.get("online", True))
        device_state = payload.get("device_state")
        if device_state is not None and device_state not in isolation.VALID_DEVICE_STATES:
            raise DomainError("invalid_device_state", "device_state 只能是 open 或 closed")
        return self.repository.sync_valve(valve_id, online, device_state, actor, role)

    def resolve_job(self, job_id, payload, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in TOPOLOGY_ROLES:
            raise DomainError("forbidden", "只有监督岗能裁决阀位冲突", 403)
        resolution = domain.require_text(payload, "resolution")
        return self.repository.resolve_job(job_id, resolution, actor, role)

    def get_item(self, item_id):
        item = self.repository.get_item(item_id)
        item["sources"] = self.repository.list_sources(item_id)
        item["audit"] = self.repository.audit_trail(item_id)
        item["assessment"] = rules.assess(item["payload"])
        item["isolation_jobs"] = [
            job for job in self.repository.list_jobs() if job["item_id"] == item_id
        ]
        return item

    def list_items(self, status=None):
        return self.repository.list_items(status)

    def state(self):
        summary = self.repository.state_summary()
        jobs = self.repository.list_jobs()
        job_counts = {}
        for job in jobs:
            job_counts[job["status"]] = job_counts.get(job["status"], 0) + 1
        summary["isolation"] = {"job_counts": job_counts, "jobs": jobs}
        summary["topology_revision"] = self.repository.topology()["revision"]
        return summary
