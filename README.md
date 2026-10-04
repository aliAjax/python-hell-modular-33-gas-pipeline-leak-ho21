# 燃气管线泄漏检测与隔离协调

模块化纯 Python 3.9.6+ 标准库项目，默认端口 `8333`。

- `app.py`：参数、依赖和服务生命周期。
- `src/domain.py`：管段、传感值和来源记录校验。
- `src/rules.py`：泄漏评分、阀门顺序、修复、试压、恢复状态机。
- `src/repository.py`：SQLite、重复保护、乐观版本和审计链。
- `src/isolation.py`：隔离账纯逻辑（边界阀、严重度排队、断点、阀位合并、拓扑修订效应）。
- `src/service.py`：角色权限和业务编排。
- `src/http_api.py`：JSON 接口与首页。
- `src/audit.py`：可校验的审计事件。

## 隔离账

把管段连接、阀门和泄漏事件接成一本隔离账：

- **按严重度排队占用阀门**：核验后的泄漏事件提交隔离申请，方案 = 管段全部相接阀门（最小切割集）。调度器按严重度评分降序、先到先得扫描；一组所需阀门**全部空闲才整组占用**（全有或全无），相邻管段共用阀门、两组同时申请时不会互相锁死，低严重度组保持 `queued` 并带 `blocking_valves`。
- **阀门同一时刻只归一组**：`valve_leases` 部分唯一索引保证 `held/closed` 占用互斥；关阀成功转为 `closed`，恢复供气后统一释放，排队组自动接上。
- **关阀失败从断点恢复**：失败阀门标记 `failed_valve`，作业进入 `blocked`，已关阀不回滚；重试回执从断点阀门继续，成功后回 `active`。
- **重复回执只记一次**：`(job_id, receipt_id)` 唯一，重复提交返回 `duplicate: true` 与原结果，不重复入账。
- **连接关系修订**：`POST /api/topology` 全量提交新连接。未执行（`queued`）方案整份作废并按新关系重算排队（`supersedes_job` 串起新旧方案）；执行中的方案保留已关阀物理结果，仅释放“不再需要且未关”的占用，其余按新边界重算。
- **断网阀位合并**：`POST /api/valves/<id>/sync` 上报在线状态与现场阀位。离线不裁决；恢复后与账本一致为 `consistent`（挂起项自动恢复），不一致为 `conflict` 并挂起作业；监督岗可用 `POST /api/jobs/<id>/resolve` 选择以现场为准（`adopt_device`）或以账本为准（`trust_ledger`）。
- **旧数据只读兼容**：没有连接关系的管段，事件仍可读取、仍可走原有手工隔离流程；仅账本隔离申请返回 `topology_unavailable`。

新增接口：

```
GET  /api/topology
POST /api/topology                       # 修订连接关系（supervisor）
POST /api/valves                         # 登记阀门（supervisor）
POST /api/valves/<id>/sync               # 断网恢复/阀位上报
POST /api/items/<id>/isolation-jobs      # 提交隔离申请（supervisor/responder）
GET  /api/jobs[?status=...]              # 隔离方案队列
GET  /api/jobs/<id>
POST /api/jobs/<id>/receipts             # 关阀回执（幂等）
POST /api/jobs/<id>/resolve              # 裁决阀位冲突（supervisor）
```

作业状态：`queued → active → isolated`，旁路 `blocked`（关阀失败断点）、`suspended`（阀位冲突挂起）、`voided`（方案作废）。


```bash
python3 app.py --init --db ./data.db
python3 app.py --db ./data.db --port 8333
python3 -m unittest discover -s tests -v
```

接口包括 `GET /health`、`GET /api/state`、`POST /api/items`、`POST /api/items/<id>/sources`、`POST /api/items/<id>/actions` 和审计查询。测试覆盖完整抢修流程、重复事件、阀门顺序、试压阈值、现场危险条件、权限和版本冲突。模型不替代 SCADA、管网水力计算或正式应急预案。
