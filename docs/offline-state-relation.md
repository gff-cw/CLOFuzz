# 离线双状态关联记录

`tools/offline_state_relation.py` 读取已有观测，只汇总显式对齐的证据。不推导状态转换、不修改 StateAFL 状态 ID，也不从旧数组下标补造对应关系。理论依据见[双状态观测模型](dual-state-observation-model.md)。

输入为 UTF-8 JSON，根对象固定为 `{"format":"stateafl.offline-observations","version":1,"events":[...]}`。命令行只读文件并向标准输出返回 JSON：

```bash
python3 tools/offline_state_relation.py --input path/to/existing-observations.json
```

Python API 为 `analyze(document)`。CLI 成功处理记录返回 0，格式错误返回 2。0 不表示协议符合性或执行成功；零条可关联观测也是合法报告。该格式不是当前 C runtime 的直接输出，旧共享状态数组不能被按序号补写成同步观测。

## 事件身份

事件必含以下字段：

| 字段 | 规则 |
| --- | --- |
| `run_id` | 独立运行身份 |
| `session_id` | 生产者说明的协议会话作用域 |
| `session_epoch` | 非负整数，同一 run/session 不得倒退 |
| `event_index` | 非负整数，同一 session epoch 内严格递增 |
| `model_sha256` | 小写 SHA256，覆盖影响解释的描述与契约版本 |
| `kind` | session_start、reset、observation、timeout、partial 或 unmatched |

新的 epoch 必须以 session_start/reset 开始，同一 epoch 内不能再次 start/reset 或修改模型摘要。reset 另需 `reset_evidence: "confirmed"`，声明生产者已在指定作用域确认重置；模块不执行重置或独立验证其后置条件。

事件可含 protocol、memory、boundary；缺失或 null 表示证据缺失。未知属性会被拒绝。

## 协议记录

protocol 必含 status、states、source、correlation、complete，另可含 evidence_ref：

| status | states 与来源 |
| --- | --- |
| observed | 恰好一个状态，来源为实际匹配响应或本地观测 |
| ambiguous | 至少两个候选，整组保留 |
| predicted | 非空预测集合，source 必须为 prediction |
| unknown / unobserved | states 为空，source 为 none |
| inconsistent | states 为空，表示生产者判定模型与观测不相容，保留实际观测来源 |

source 为 matched_response、local_observation、prediction 或 none。correlation 为 confirmed、ambiguous 或 missing；它表示所需因果关联是否明确，独立于协议候选是否唯一。complete 为布尔值。除 unknown/unobserved 外均需 evidence_ref，引用生产者的原始证据位置；模块不打开或执行引用。

仅完整且 correlation=confirmed 的 observed/ambiguous 记录有资格继续关联。预测不升级为确认。timeout/partial/unmatched 不产生关系，当前可确认状态变为 unknown，历史 last_confirmed 仍保留；这不表示目标回到初始状态。last_prediction 单独保存。模块不读取状态图计算候选集合，inconsistent 也是生产者提供的解释。

## 内存与共同边界

memory 必含：

| 字段 | 含义 |
| --- | --- |
| namespace | 可追溯目标、插桩/快照/过滤配置和聚类库身份 |
| calibration_epoch | 非负整数，区分校准及距离判定配置 |
| library_revision | 本次观测使用的参考库修订 |
| state_id | 32 位无符号整数 |
| source | 取样证据位置 |
| status | snapshot_label 或 synthetic |

synthetic 和 ID 0 不建立内存关联。当前 StateAFL 的 0 可表示 dummy/不可用状态，不应当作某个已推断快照类别。

boundary 必含：

| 字段 | 含义 |
| --- | --- |
| observation_id | 同一 session epoch 内唯一的共同边界编号 |
| alignment | shared_marker 或 unaligned |
| phase | completed、quiescent 或 pending |
| synchronization | quiescent、atomic_snapshot 或 unknown |
| source | 共同标记与同步机制的证据位置 |

只有 shared_marker、完成阶段及明确同步声明同时存在才建立关系。completed 单独不足以证明内存取样与协议观测处于相同边界；atomic_snapshot 也必须把双方绑定到同一逻辑检查点，仅内存复制原子性不够。

## 输出及限制

关系按 `(model_sha256, memory namespace, calibration_epoch, library_revision, run_id, session_id, session_epoch)` 分区。每条关系包含 protocol_states、memory_state_id、certainty、计数与原始证据引用。observed 的状态数组长度为 1；ambiguous 的集合不拆成多条确定关系，计数不是概率。允许两侧出现多对多对应。

报告另含 session 的当前类别与候选、历史确认、最近预测，以及跳过原因统计。未对齐或未确认的原始声明保存在 unpaired_observations 中，避免丢失任一侧证据。不提供跨运行自动合并、状态等价判定、事务重建或在线调度接口。

CLI 文件上限 1 MiB，最多 10000 事件、65536 关系；候选至多 64 个且不重复，文本至多 256 字符。重复 JSON key、非有限数、布尔冒充整数及未知字段被拒绝。

marker、digest、关联与同步声明均来自生产者。模块只检查内部契约，不验证报文发生、目标身份、线程静止或重置完成。相同字符串不能制造真实因果证据；报告保留这一限制。多线程/异步事务的观测充分性和 scope 划分仍需上游证据。

按用户要求，本轮没有运行工具或测试，只完成实现、文档和静态审阅。
