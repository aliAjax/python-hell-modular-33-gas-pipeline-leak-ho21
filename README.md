# 燃气管线泄漏检测与隔离协调

模块化纯 Python 3.9.6+ 标准库项目，默认端口 `8333`。

- `app.py`：参数、依赖和服务生命周期。
- `src/domain.py`：管段、传感值和来源记录校验。
- `src/rules.py`：泄漏评分、阀门顺序、修复、试压、恢复状态机。
- `src/repository.py`：SQLite、重复保护、乐观版本和审计链。
- `src/service.py`：角色权限和业务编排。
- `src/http_api.py`：JSON 接口与首页。
- `src/audit.py`：可校验的审计事件。

```bash
python3 app.py --init --db ./data.db
python3 app.py --db ./data.db --port 8333
python3 -m unittest discover -s tests -v
```

接口包括 `GET /health`、`GET /api/state`、`POST /api/items`、`POST /api/items/<id>/sources`、`POST /api/items/<id>/actions` 和审计查询。测试覆盖完整抢修流程、重复事件、阀门顺序、试压阈值、现场危险条件、权限和版本冲突。模型不替代 SCADA、管网水力计算或正式应急预案。

隔离账（管段连接 + 阀门 + 泄漏事件）接口：

- `POST /api/topology/connections`：维护管段边界阀门（连接关系），按 `pipeline_id`+`segment_id` 全量替换。
- `GET /api/topology/connections?pipeline_id=..&segment_id=..`：读取管段连接关系。
- `GET /api/topology/valves`：阀门台账（阀位、占用方）。
- `POST /api/items/<id>/isolation`：按严重度排队提交隔离方案（阀门互斥，同一时刻只归一组作业）。
- `GET /api/items/<id>/isolation`：读取该事件的隔离方案与回执。
- `POST /api/items/<id>/isolation/receipts`：提交关阀回执（按顺序逐阀；失败记断点；重复回执只记一次）。
- `POST /api/items/<id>/isolation/resume`：从断点恢复关阀。
- `POST /api/items/<id>/isolation/resolve`：人工裁决挂起方案（`proceed`/`abort`）。
- `POST /api/topology/positions/merge`：合并断网期间上报的阀位，矛盾项挂起。

连接关系更新后，未执行的隔离方案作废并按新拓扑重算，已关阀门保留结果；旧数据缺连接关系时只读兼容（读取正常，建立隔离账返回 `topology_required`）。
