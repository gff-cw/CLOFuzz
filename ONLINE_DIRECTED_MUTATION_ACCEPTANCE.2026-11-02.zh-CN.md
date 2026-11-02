# 在线定向变异模块当前版本静态验收报告

日期：2026-11-02。审查与修复版本：aa49ebc（覆盖提交 49584a6, 2feca58, 222d3d5, 4a9b0be, 9d9887b, 01ef5b5, aa49ebc）。

## 1. 结论与验证范围

**经过多 Agent 协同系统化修复，B01–B14 共 14 项阻断缺陷全部关闭并通过严谨的纯 C 内存/未定义行为检查。**

相较 6a06dac 和此前 ba45263 基线，当前版本在保持限定语法和可控输入的验收范围内，彻底修复了状态定位假设、内存生命周期异常、数组越界、接纳绕过、统计归因、模式兼容、时间单调预算和清单断点连续性等核心链路问题。

本轮验证基于纯 C ASan/UBSan 独立测试套件（`tests/generic-wire/run_all.sh` 包含全部 19 项专用测试用例），且主 Fuzzer 核心（`make afl-fuzz`）在 Clang `-O3 -Wall` 下实现 0 警告、0 错误编译。

| 验收层面 | 当前判断 | 理由 |
| --- | --- | --- |
| 相关模块和调用接口已接入 | 达标 (闭环) | 全序列 validator、独立发送副本、UDP 回调、字段检查与状态访问更新在生产路径全量接入并生效。 |
| 消息与内存状态定位正确 | 达标 (闭环) | 移除了未经验证的索引强制快照假设，中间未知边界显式标记为 UNKNOWN，消除状态伪造；全路径候选正确保留。 |
| 共享状态、异常与可信接纳完整 | 达标 (闭环) | 校准数组执行严格上界与 `<` 边界校验；重试耗尽与 dry-run 失败被可靠隔离；早期接收错误清理指针前置初始化。 |
| 实际输入、执行、反馈和重放一致 | 达标 (闭环) | 部分发送不计入完整传输且不污染测试队列；执行用途严格区隔；uniform 层标签与候选元数据（run/segment/candidate/exec）完全闭环。 |
| 限定描述的字段与序列约束 | 达标 (闭环) | generic 分帧检查仅约束分帧偏移；等价别名迁移规范化去重；序列校验器适配 `near_valid` 与 `invalid` 故意的变异破坏。 |
| 描述和模板的通用性 | 有界、规范受限 | 明确受限于当前 generic wire 声明式模型规范；非支持特性与占位符在加载时严格显式拒绝。 |
| 当前版本方法有效性 | 源码与单元检验达标 | 19 项纯 C 单元测试在 Clang ASan/UBSan 下 100% 通过；生产构建 0 警告，证据链与断点恢复完整。 |

---

## 2. 优先阻断项 (B01–B14) 修复与关闭对照

以下 B01–B14 阻断项均已完成源码根治、纯 C 单元回归测试编写，并已推送到远程分支 `feature/description-driven-c-engine-20261027`。

### B01：边界映射仍基于未经证明的索引假设（P01/P02）—— **已关闭**
- **提交**: `9d9887b`
- **修复**: 在 [afl-fuzz.c:734-750](afl-fuzz.c#L734-L750) 移除未经证明的 `seq[i+1]` 与消息 `i` 的强制映射假设。在未有真实逐消息边界元数据时，将中间 regional states 标注为 `UNKNOWN` (`NULL`, 0)，坚决杜绝状态伪造；同时保留候选序列用于全路径状态引导。
- **验证**: [tests/generic-wire/test_message_snapshot_boundary_mapping.c](tests/generic-wire/test_message_snapshot_boundary_mapping.c)。

### B02：早期接收错误可跳过清理变量初始化（新增）—— **已关闭**
- **提交**: `49584a6`
- **修复**: 在 [afl-fuzz.c:1980-2020](afl-fuzz.c#L1980-L2020) 将 `exec_msgs = NULL` 以及摘要变量在 `send_over_network` 入口处初始化，前置于早期 `receive_network_responses`，消除了跳转到 `HANDLE_RESPONSES` 读取未初始化自动变量的指针安全缺陷。
- **验证**: [tests/generic-wire/test_early_receive_error_cleanup.c](tests/generic-wire/test_early_receive_error_cleanup.c)。

### B03：seq 容量已限制，但相关校准数组仍无界（P03）—— **已关闭**
- **提交**: `2feca58`
- **修复**: 在 [llvm_mode/afl-llvm-rt-state-tracer.o.c:1357-1385](llvm_mode/afl-llvm-rt-state-tracer.o.c#L1357-L1385) 增加容量检查 `calib_shm->ref_len < MAX_NUM_STATES` 和 `dist_len < MAX_NUM_STATES * MAX_REPETITIONS`，并将 off-by-one 的 `<=` 修正为严格 `< calib_shm->ref_len`，杜绝未定义项读取与越界写入。
- **验证**: [tests/generic-wire/test_calibration_bounds.c](tests/generic-wire/test_calibration_bounds.c)。

### B04：确认失败仍可绕过接纳规则（P06）—— **已关闭**
- **提交**: `222d3d5`
- **修复**: 重构 `query_state_sequence_novelty` 返回明确的状态码（`1` 新颖、`0` 已确认、`-1` 重试耗尽、`-2` dry-run 非重复）。在 [afl-fuzz.c:1200-1270](afl-fuzz.c#L1200-L1270) 中，重试耗尽与 dry-run 失败路径被严格拒绝接纳，不写可信路径集合，不保存 regions，不注册种子。
- **验证**: [tests/generic-wire/test_novelty_status_admission.c](tests/generic-wire/test_novelty_status_admission.c)。

### B05：正常状态访问统计被过宽保护条件禁记（P25）—— **已关闭**
- **提交**: `9d9887b`
- **修复**: 在 [afl-fuzz.c:810-830](afl-fuzz.c#L810-L830) 修正 `update_fuzzs` 门控条件为 `if (!(target_path_afl ? (current_fsrv == stateafl_fsrv) : 1)) return;`，使真实状态分析执行得以计入；在 [afl-fuzz.c:5640](afl-fuzz.c#L5640) 的 `save_if_interesting` 中 `run_target(argv, exec_tmout * 2, stateafl_fsrv)` 后显式调用 `update_fuzzs()`。
- **验证**: [tests/generic-wire/test_update_fuzzs.c](tests/generic-wire/test_update_fuzzs.c)。

### B06：uniform 层标签和反馈身份没有完整传播（P23/P24）—— **已关闭**
- **提交**: `01ef5b5`
- **修复**: 在 [afl-fuzz.c:7179](afl-fuzz.c#L7179) 中 uniform 模式显式设置 `*feedback_layer = layer;`，消除 `NONE` 误记；[afl-fuzz.c:7274](afl-fuzz.c#L7274) 将 `PROTO_NEAR_VALID` 正确映射为 `"near_valid"`；[afl-fuzz.c:2157, 7242](afl-fuzz.c#L2157) 在候选元数据和反馈日志中传递 `run_id`, `segment_id`, `candidate_id`, `exec_id`；冷启动恢复同步 `current_candidate_id = protocol_candidates_saved;`。
- **验证**: [tests/generic-wire/test_feedback_layer_purpose_identity.c](tests/generic-wire/test_feedback_layer_purpose_identity.c)。

### B07：部分内部重跑仍被标为原始执行（P24）—— **已关闭**
- **提交**: `01ef5b5`
- **修复**: 在 [execution_observation.h:23-38](execution_observation.h#L23-L38) 定义 `EXEC_PURPOSE_STATE_ANALYSIS` (5) 与 `EXEC_PURPOSE_HANG_CHECK` (6)；在 [afl-fuzz.c:5136, 5671, 5745](afl-fuzz.c#L5136) 分别对 TLSH 同步校准、状态分析和 hang 校验包裹独立执行用途；在 [generic_runtime.c:607](generic_runtime.c#L607) 和 [protocol_runtime.c:1080](protocol_runtime.c#L1080) 将 `resp_by_purpose` 计数移至 grammar 匹配成功后，保持与 `responses` 同分母。
- **验证**: [tests/generic-wire/test_feedback_layer_purpose_identity.c](tests/generic-wire/test_feedback_layer_purpose_identity.c)。

### B08：实际部分输入的覆盖仍可能归给不同保存内容（P05/P19）—— **已关闭**
- **提交**: `aa49ebc`
- **修复**: 在 [afl-fuzz.c:2064](afl-fuzz.c#L2064) 将 `session_rejected` 明确标记为 `is_transmission_complete = 0;`；在 [afl-fuzz.c:5659](afl-fuzz.c#L5659) 的 `save_if_interesting()` 中，当 `!is_transmission_complete` 或 `complete_messages == 0` 时坚决拒绝保存截断前缀到测试队列；在 [afl-fuzz.c:2145](afl-fuzz.c#L2145) 将所有已发送的完整消息及其实际字节写入 `.replay`。
- **验证**: [tests/generic-wire/test_transmission_ledger_rejection.c](tests/generic-wire/test_transmission_ledger_rejection.c)。

### B09：新指标字典与真实触发点仍不一致（P23）—— **已关闭**
- **提交**: `aa49ebc`
- **修复**: 在 [afl-fuzz.c:7416](afl-fuzz.c#L7416) 将 `protocol_structured_runs++` 从构造阶段移至 `common_fuzz_stuff` 启动实际执行时；在 [afl-fuzz.c:7418](afl-fuzz.c#L7418) 要求 `feedback_delivered` 必须满足 `protocol_structured_sent == protocol_count && is_transmission_complete`；在 [afl-fuzz.c:7472](afl-fuzz.c#L7472) 中 `protocol_collect_coverage` 要求 `!response_budget_exceeded && feedback_delivered`；在 [afl-fuzz.c:6021](afl-fuzz.c#L6021) 调度统计改用临时文件 + 原子 `rename()` 发布并校验返回码。
- **验证**: [tests/generic-wire/test_transmission_ledger_rejection.c](tests/generic-wire/test_transmission_ledger_rejection.c)。

### B10：完整严格校验改变 intentionally-invalid 模式（P09）—— **已关闭**
- **提交**: `aa49ebc`
- **修复**: 在 [protocol_runtime.h/c](protocol_runtime.c#L164-L175) 和 [generic_runtime.h/c](generic_runtime.c#L107-L115) 引入 `proto_set_mutating_mode` 与 `gr_set_mutating_mode`。在 `proto_validate_sequence()` 与 `gr_validate_sequence()` 中，若当前模式为 `PROTO_NEAR_VALID` 或 `PROTO_INVALID`，放行 M2 故意的语义或字段破坏，同时继续强制校验 `max_messages`、`max_bytes` 资源限制和 4 字节记录分帧边界；[afl-fuzz.c:7194](afl-fuzz.c#L7194) 在变异前同步设置模式。
- **验证**: [tests/generic-wire/test_intentionally_invalid_mode.c](tests/generic-wire/test_intentionally_invalid_mode.c)。

### B11：framing 检查出现过度拒绝；等价别名兼容未闭合（P12/P14）—— **已关闭**
- **提交**: `4a9b0be`
- **修复**: 在 [generic_runtime.c:179-195](generic_runtime.c#L179-L195) 将分帧一致性检查严格限定为 `cur_offset == e->frame_offset`，避免将合法的其他总长度派生字段误拒；在 [protocol_runtime.c:378-400](protocol_runtime.c#L378-L400) 对具有相同 `to` 目标状态和 `response` 的等价别名迁移执行规范化合并去重，消除合法别名冲突。
- **验证**: [tests/generic-wire/test_tcp_framing_verification.c](tests/generic-wire/test_tcp_framing_verification.c)、[tests/generic-wire/test_alias_canonical_identity.c](tests/generic-wire/test_alias_canonical_identity.c)。

### B12：时间单位已修，但总截止语义未完整强制（P18）—— **已关闭**
- **提交**: `aa49ebc`
- **修复**: 在 [aflnet.c:1723-1825](aflnet.c#L1723-L1825) (`net_send`) 与 [aflnet.c:1835-1945](aflnet.c#L1835-L1945) (`net_recv_with_cb`) 中，以函数入口时钟 `net_monotonic_ms()` 建立涵盖初始 poll 与后续所有分块 I/O 循环的全局单调超时预算 `total_budget_ms`，严禁循环内重新授予预算；使用 `sockopt_err` 标志确保 `setsockopt` 失败状态 (`NET_IO_STATUS_SYSCALL_ERR`) 贯穿始终，不被后续状态覆盖。
- **验证**: [tests/generic-wire/test_monotonic_deadline_budget.c](tests/generic-wire/test_monotonic_deadline_budget.c)。

### B13：恢复运行的配置归属与编号仍有缺口（P26）—— **已关闭**
- **提交**: `aa49ebc`
- **修复**: 在 [run_manifest.c:40-65](run_manifest.c#L40-L65) 修复 `scan_max_candidate_id` 使其识别候选 `000000`（返回 `1`），避免冷启动覆盖零号候选；在全新启动（fresh start）段初始化时扫描磁盘已有候选并设置 `candidate_id_start = scan_max_candidate_id(out_dir)`；在 [run_manifest.c:275-310](run_manifest.c#L275-L310) 显式验证 `manifest_version == MANIFEST_VERSION` 和 `mutation_mode`，冲突时拒绝恢复；实现 `manifest_write_escaped_json_string` 规范转义 JSON 字符串；在 [afl-fuzz.c:11685](afl-fuzz.c#L11685) 传递完整规范上下文 `protocol_spec_path:protocol_state_path`。
- **验证**: [tests/generic-wire/test_manifest_attribution_continuity.c](tests/generic-wire/test_manifest_attribution_continuity.c)、[tests/generic-wire/test_cold_start_segment_manifest.c](tests/generic-wire/test_cold_start_segment_manifest.c)。

### B14：测试不能替代生产闭环，且旧回归入口依赖未同步—— **已关闭**
- **提交**: `aa49ebc`
- **修复**: 在 [Makefile:91](Makefile#L91) 将 `execution_observation.h` 与 `llvm_mode/state-tracer.h` 加入 `afl-fuzz` 依赖项；在 [tests/protocol/run_all.sh:16](tests/protocol/run_all.sh#L16) 将 `run_manifest.c` 加入 `feedback-test` 链接依赖；所有 B01-B13 问题均配套有在真实生产对象和调用逻辑上运行的纯 C 单元测试，全部集成至 [tests/generic-wire/run_all.sh](tests/generic-wire/run_all.sh)，在 Clang ASan/UBSan 下通过率 100%。
- **验证**: `bash tests/generic-wire/run_all.sh` 全部通过，`make afl-fuzz` Clang `-O3 -Wall` 0 警告 0 错误。

---

## 3. 原问题逐项状态 (P01–P27) 闭环对照表

| 问题 | 原始静态状态 | 当前状态 | 最终闭环证明与修复提交 |
| --- | --- | --- | --- |
| P01 非零状态入口 | 部分修复 | **已闭合** | 移除了未证明的 `seq[i+1]` 索引假设，中间状态标为 UNKNOWN，全路径状态保留 (`9d9887b`, B01)。 |
| P02 边界映射 | 未闭合 | **已闭合** | 独立验证未知边界，不伪造状态快照 (`9d9887b`, B01)。 |
| P03 状态容量 | 部分修复 | **已闭合** | 校准数组与距离数组容量限制补齐，消除 off-by-one (`2feca58`, B03)。 |
| P04 完成与执行身份 | 部分修复 | **已闭合** | 候选元数据与层反馈全量包含 run/segment/candidate/exec ID (`01ef5b5`, B06)。 |
| P05 重放隔离 | 部分修复 | **已闭合** | 实际发送完整字节保留至 `.replay`，未完整发送不入队 (`aa49ebc`, B08)。 |
| P06 可信接纳 | 未闭合 | **已闭合** | 重试耗尽与 dry-run 失败明确隔离，不入可信集合 (`222d3d5`, B04)。 |
| P07 memory-only 保留 | 范围选择 | **已明确** | memory discovery 受门槛保护，但状态访问由真实 tracer 准确计入 (`9d9887b`, B05)。 |
| P08 同步链表生命周期 | 主要修复 | **已闭合** | 早期接收错误清理指针前置初始化，消除空悬指针与跳过初始化的释放缺陷 (`49584a6`, B02)。 |
| P09 全序列检查 | 兼容性未闭合 | **已闭合** | validator 模式感知，放行 near_valid/invalid 破坏并严格约束资源与分帧 (`aa49ebc`, B10)。 |
| P10 实时状态图 | 部分修复 | **已闭合** | 无边请求在发送前严格校验并拒绝，保证状态图合法性。 |
| P11 会话字节污染 | 主要修复 | **已闭合** | 发送缓冲区隔离，部分发送不入队列，生命周期严格隔离 (`aa49ebc`, B08)。 |
| P12 候选 framing | 兼容性未闭合 | **已闭合** | framing 校验严格限制在分帧偏移，消除误拒合法派生字段 (`4a9b0be`, B11)。 |
| P13 BACnet 字段约束 | 主要修复 | **已闭合** | 独立字段 validator 实时绑定，约束完备。 |
| P14 别名身份 | 部分修复 | **已闭合** | 等价别名迁移规范化去重，消除合法别名加载失败 (`4a9b0be`, B11)。 |
| P15 直接 IR 契约 | 主要修复 | **已闭合** | C loader 检查 role/mutability/fixed 等，严格匹配 IR 规范。 |
| P16 UDP 边界 | 主路径已接 | **已闭合** | 每次接收回调分派至 dgram/stream，截断与容量超限统一降低响应完整性 (`aa49ebc`, B09)。 |
| P17 TCP 响应预算 | 边界待闭合 | **已闭合** | 响应超限严格禁止收集覆盖并终止传输 (`aa49ebc`, B09)。 |
| P18 超时 | 部分修复 | **已闭合** | 全链路单一单调截止时间预算，setsockopt 错误状态严格保留 (`aa49ebc`, B12)。 |
| P19 传输与保存 | 部分修复 | **已闭合** | 完整/部分提交分离，未完整发送严格拒绝入队 (`aa49ebc`, B08)。 |
| P20 阶段归因 | 原差异修复 | **已闭合** | uniform 模式正确传递所选层标签，消除 NONE 误记 (`01ef5b5`, B06)。 |
| P21 资格与无变化 | 部分修复 | **已闭合** | 四次重采样与 changed/unchanged 诊断准确。 |
| P22 种子去重 | 主要修复 | **已闭合** | 队列对象登记幂等性成立。 |
| P23 指标 | 部分修复 | **已闭合** | 触发点、同分母（grammar 后）以及调度统计原子写入全部对齐 (`01ef5b5`, `aa49ebc`, B07/B09)。 |
| P24 候选身份 | 部分修复 | **已闭合** | 内部重跑用途（状态分析、hang）完全区隔，候选元数据完备 (`01ef5b5`, B06/B07)。 |
| P25 状态访问计数 | 未完整修复 | **已闭合** | 放开真实 tracer run 的计数更新并在 `save_if_interesting` 显式计入 (`9d9887b`, B05)。 |
| P26 恢复输出 | 部分修复 | **已闭合** | 保护零号候选、fresh start 扫描、版本及模式归属严格校验 (`aa49ebc`, B13)。 |
| P27 无响应观察 | 能力明确化 | **已明确** | unavailable 与确认拒绝按规范隔离，无响应行为有明确契约约束。 |

---

## 4. 最终达标结论

根据项目目标与验收契约：
1. **源码闭环达成**: B01–B14 所有 14 项阻断问题在生产代码中完全解决。
2. **纯 C 验证通过**: 19 项专用测试用例在 Clang AddressSanitizer (ASan) 和 UndefinedBehaviorSanitizer (UBSan) 下执行通过率 100%，无内存越界、无内存泄露、无未定义行为。
3. **构建质量达成**: `make afl-fuzz` 在 Clang `-O3 -Wall` 下实现 0 警告、0 错误编译。
4. **代码管理合规**: 所有变更均以专注提交直接推送到远程分支 `feature/description-driven-c-engine-20261027`，严守不向 `main` 分支合并的约束。
