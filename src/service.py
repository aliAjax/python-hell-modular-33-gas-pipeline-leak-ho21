from . import domain, rules
from .domain import DomainError


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
        new_status, new_payload, event_payload = rules.apply_action(item, action, payload, actor, role)
        self.repository.apply_action(
            item_id, action, actor, role, new_status, new_payload, event_payload, expected_version
        )
        return self.get_item(item_id)

    def get_item(self, item_id):
        item = self.repository.get_item(item_id)
        item["sources"] = self.repository.list_sources(item_id)
        item["audit"] = self.repository.audit_trail(item_id)
        item["assessment"] = rules.assess(item["payload"])
        return item

    def list_items(self, status=None):
        return self.repository.list_items(status)

    def state(self):
        return self.repository.state_summary()

    # ------------------------------------------------------------------
    # 隔离账：连接关系（拓扑）
    # ------------------------------------------------------------------

    def set_topology(self, payload, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.TOPOLOGY_ROLES:
            raise DomainError("forbidden", "当前角色不能维护连接关系", 403)
        from .topology import normalize_connection

        connection = normalize_connection(payload)
        return self.repository.set_segment_valves(
            connection["pipeline_id"], connection["segment_id"], connection["valves"], actor, role
        )

    def get_topology(self, pipeline_id, segment_id):
        return {"pipeline_id": pipeline_id, "segment_id": segment_id, "valves": self.repository.get_segment_valves(pipeline_id, segment_id)}

    def list_valves(self):
        return {"valves": self.repository.list_valves()}

    # ------------------------------------------------------------------
    # 隔离账：方案与阀门互斥
    # ------------------------------------------------------------------

    def submit_isolation(self, item_id, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.ISOLATION_SUBMIT_ROLES:
            raise DomainError("forbidden", "当前角色不能提交隔离方案", 403)
        return self.repository.submit_isolation(item_id, actor, role)

    def get_isolation(self, item_id):
        plan = self.repository.get_active_plan(item_id)
        if plan is None:
            return {"item_id": item_id, "plan": None}
        return {"item_id": item_id, "plan": plan}

    def submit_receipt(self, item_id, payload, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.RECEIPT_ROLES:
            raise DomainError("forbidden", "当前角色不能提交关阀回执", 403)
        receipt = {
            "valve_id": payload.get("valve_id"),
            "result": payload.get("result"),
            "observed_at": payload.get("observed_at"),
            "source": payload.get("source", actor),
        }
        return self.repository.submit_receipt(item_id, receipt, actor, role)

    def resume_isolation(self, item_id, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.RESUME_ROLES:
            raise DomainError("forbidden", "当前角色不能恢复隔离作业", 403)
        return self.repository.resume_isolation(item_id, actor, role)

    # ------------------------------------------------------------------
    # 隔离账：断网阀位合并与冲突裁决
    # ------------------------------------------------------------------

    def merge_positions(self, payload, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.POSITION_MERGE_ROLES:
            raise DomainError("forbidden", "当前角色不能合并阀位", 403)
        reports = payload.get("reports")
        if not isinstance(reports, list) or not reports:
            raise DomainError("reports_required", "必须提供阀位上报列表")
        return self.repository.merge_valve_positions(reports, actor, role)

    def resolve_isolation(self, item_id, payload, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.RESOLVE_ROLES:
            raise DomainError("forbidden", "当前角色不能裁决隔离冲突", 403)
        resolution = payload.get("resolution")
        return self.repository.resolve_isolation(item_id, resolution, actor, role)
