# 版本化指标与证据口径

当前源码状态见 [2026-11-02 修复记录](repair-status-20261102.md)。本页定义计数含义，不是本轮执行结果。统计版本、候选版本、manifest 版本与共享内存 ABI 是独立协议，不能用一个版本号推断其他版本。

## 候选到反馈

| 指标 | 实际含义 | 合理分母及限制 |
| --- | --- | --- |
| `candidate_attempts` | 宿主进入 `protocol_prepare` 的结构化构造尝试 | 构造尝试数；不是目标执行数 |
| `construction_success` / runtime `structured_success` | 引擎成功构造输出 | 各自尝试数；宿主随后仍可能拒绝 |
| `changed` / `unchanged` | 引擎输出与原 M2 的实际字节/记录比较 | 成功构造数；发送绑定发生在其后，不是在线发送成功率 |
| `unavailable` | 选中层没有可操作消息字段而拒绝 | 构造尝试数；与其他失败及 no-op 分开 |
| `host_accepted` | 完整 M1/M2/M3 通过支持模式的资源/模型校验 | 成功构造数；不是应用成功 |
| `structured_runs` | 宿主准备调用 `run_target` 的结构化候选次数 | 宿主接受数；不能由此证明子进程实际启动或完整处理 |
| `complete_transmissions` | 原候选 M2 结构化消息全部提交，且整个计划消息序列完整提交 | 结构化运行尝试数；尚不表示完整响应或应用接受 |
| `valid_observations` | 满足当前代码的反馈资格：完整提交、响应观察未失败或超限、fault 符合保留模式 | 完整提交数；默认正常运行与 crash-mode 要分别解释 |
| `reward_committed` | 一个候选最终反馈包含非零事件，至多一次调用奖励入口 | 事件可能包括覆盖、内存、队列或异常保留；须分事件统计，不能把总数直接除以仅记录常规保留资格的 `valid_observations` |

分母为零时标 `N/A`。不得把层被选中、输出构造成功、完整写入套接字、响应相关或方法收益混为同一成功率。`selection_policy=eligible-weighted-v1` 表示在有资格的消息中直接加权选择；没有在所有消息中盲抽后有限重试。

## 网络和响应

`planned_messages` 是本次全部计划请求；`attempted_messages` 是尝试发送数；`sent_messages` 是完整提交数；`submitted_records` 是至少提交一个字节的记录数。部分尾部包含在后者，零提交尝试不写为零长度 replay 消息。`is_transmission_complete` 要求计划非空、完整数等于计划数且无部分尾部，不能只看已尝试消息。

`is_response_complete` 仅表示网络观察未因错误、截断或预算失败而不完整；正常 idle 可以结束观察。它不保证协议已响应、pending 已完成或未来没有更多数据。`response_budget_exceeded`、truncated datagram、系统错误以及有未读数据的 deadline 不能给有效观察资格。达到字节预算但没有实际新增字节可以正常结束。

统计 JSON 当前声明 `stats_version=2`、`metrics_version=1`：

| 字段 | 含义 |
| --- | --- |
| `responses` | 匹配已声明响应模型的帧，可能包括无 pending 的响应 |
| `completed_responses` / `expected_complete` | 匹配 pending、当前模型/状态及全部适用关联条件后完成的响应 |
| `correlated_responses` | 上述完成响应中至少检查一条显式 correlation 规则（或 BACnet invoke 关联）的响应数，不是字段比较次数；普通 copy/bind 检查不自动计为 correlation |
| `incomplete_frames` | 流解析时遇到尚缺字节的诊断次数；同一待补帧可在不同接收调用重复计数 |
| `framing_errors` | 长度/分帧约束失败的诊断次数 |
| `grammar_mismatches` | 帧未匹配声明响应模型 |
| `unrelated_responses` | 无匹配 pending 或不满足当前期望/模型上下文 |
| `correlation_mismatches` | 关联字段不满足的诊断次数 |

这些计数单位不同，不能声称它们是互斥且穷尽的请求终态分区。v1 `correlated_responses` 曾包含无字段规则的完成，分析器不能套用 v2 定义。BACnet 和 generic-wire 当前均按单 pending 使用，没有并发事务队列。

`responses_by_purpose` 使用 `coverage`、`confirmation`、`calibration`、`sync`、`state_analysis`、`hang_check`、`unknown` 分类；缺失用途保持未知，不默认归为 coverage。跨用途总数不作为独立变异效果的分母。

## 身份、保存及恢复

候选 sidecar 当前 `format_version=3`。必须以 `(run_id, segment_id, candidate_id, exec_id)` 关联原 coverage 提交记录与反馈；confirmation/calibration/state-analysis 不是新的独立候选。原执行 ID 在任何重放前冻结，未执行的拒绝候选以 exec ID 0 明确表示未执行。部分提交 replay 是诊断，不能用于合法完整候选的编辑证据。`execution_identity_verified=false` 保留现有进程映像证明限制；本地文件摘要不是正在运行映像的认证。

实际输入保存使用所属执行持有的 wire 副本，不读取重放遗留的全局计数或长期 mdata。确认与跨 forkserver 状态归因默认要求逐记录实际 wire 精确相等；不隐式掩码 session token。消息边界映射、可信状态、完整传输与响应资格另行检查。

manifest 当前为 v2/config v1：记录请求配置、独立 protocol/state 内容摘要和每段配置快照；超时自动确定后补充该段 effective execution/hang 预算。请求的 `-t` 策略（含 `+`）、capture limit、层/比例/回退、调度、目标 argv、传输、选择算法、相关选项与等待预算均参与恢复一致性检查。旧版缺字段清单拒绝恢复；学习状态在新 segment 重置，非学习检查点。

capture limit 在每个 segment 内计数；文件编号跨恢复继续，二者不得共用一个上界判断。文件摘要仅用于内容身份检查，不是签名。统计/manifest 发布失败必须报告，不能把未落盘内容写成已有证据。

后续编译复核还将响应完整性及超限资格与原执行 ID 一起冻结；所有 discovery 事件使用同一资格，重放后的全局值不参与重新判断。新队列的 inline 校准另外保留原 coverage 位图作为比较基线；实际网络校准字节与原 wire 不同或不完整时记录 `calibration_rejected`，不消费该次校准的 virgin bits 或发布有效校准分数。写入测试文件本身并不能强制网络发送原字节。具体边界见[编译复核](build-review-20261103.md)。

## 方法有效性的边界

memory_events 或发现非零状态不证明该状态被选中并实际进入 M2。需要受控目标的真实边界发布、种子登记、非零选择、完整实际 wire 及唯一原反馈关联，随后才能建立重复对照。模拟单元、生产函数回归、集成正确性和方法收益是不同层级；本轮均未新增运行证据。
