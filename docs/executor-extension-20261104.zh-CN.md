# 执行器扩展与本地验证记录

日期：2026-11-04；分支 `feature/description-driven-c-engine-20261027`。本文记录静态描述复核后的执行器工作和实际运行结果；原先仅静态交付的判断保留在[描述完整性复核](protocol-description-completeness-20261104.zh-CN.md)中作为历史记录。这里的通过限于所列输入和测试，不代表完整标准或现场互操作验收。

## 实现范围

- `protocol_session_constraints.c/h` 为现有 Modbus 和 OPC UA codec 增加有状态的跨消息约束。Modbus 检查请求数量与响应长度、位数据 padding、写入响应回显；UA 检查 HEL/ACK 协商、channel/token、期限和序号新鲜度。状态进入运行时 prepare/commit 快照，拒绝不提交状态。UA 加密、Session、Renew 和分块重组不在此模块范围。
- `protocol_iec104_session.c/h` 增加客户端单 interrogation 的 APCI 发送/接收序号、确认窗口和 t0–t3 计时；发送状态在完整提交传输后生效。运行时允许 pending 时插入 S/TEST，且不清除 interrogation 的 pending 状态。这不是完整异步 ASDU 会话实现。
- BACnet 响应字段使用动态定位，处理路由 NPDU、标签宽度和 UInt32，并检查 ACK 回显；仍为受限服务和单个 pending confirmed request。
- generic-wire 增加数值变换、位长度和响应候选能力，并以 `tests/generic-wire/full_modbus.json` 测试较完整的 Modbus 描述。这个测试输入并不意味着五份 offline-only generic profile 已可在线执行。
- ENIP 的自动 ForwardOpen 未在本轮实现，SendUnitData 仍需外部连接及双向 connection ID；MMS 仍使用现有 single-variable codec。各协议均未宣称全标准覆盖。

## 实际运行

| 验证 | 结果及范围 |
| --- | --- |
| 六套 reviewed 源生成 | 六套均通过实际 compiler/native validator，并通过 C runtime 加载、reset、free；分别为 BACnet 7、Modbus 26、IEC104 11、MMS 14、ENIP 10、UA 10 条消息。来源摘要与结果记录在本地 `tests/protocol/out/executor-repair-20261104/native-packages.json`；这不证明目标会话。 |
| 会话约束 | Modbus/UA 会话约束测试的 133 项实际检查通过；IEC104 session 与 runtime 测试通过。测试使用 ASan/UBSan。 |
| BACnet | 动态 locator、路由、UInt32 变异和响应关联的 sanitizer 测试通过，见本地 `bacnet-dynamic-sanitizer.log`。 |
| generic Modbus | 数值变换、位长度、响应候选及 full Modbus 定向测试通过 sanitizer 检查。 |
| 多 codec runtime API | `test_multicodec_runtime.py` 的 14 个测试通过，包括真实请求/响应关联、重复或跳号拒绝、prepare/cancel 状态隔离。 |
| 完整协议回归 | `bash tests/protocol/run_all.sh tests/protocol/out/executor-final-suite` 退出 0；包括 94 项 compiler 测试、模板/导出/描述检查、sanitizer 会话与网络测试，以及 84 个 loader 用例、250 个随机模型、25,000 次随机 wire 检查和 100,096 项 runtime 检查。runtime 结果内的全部源码哈希与交付源码一致。 |
| 完整 generic 回归 | 首轮发现变长字段 `max=0` 时删除被错误排除；修复后该 BACnet 用例通过，剩余全部用例续跑通过。单值整数仍排除，变长字段仍允许删除。本轮日志在 `tests/generic-wire/out/executor-final-agent/`；不能把原失败退出码改写成一次完整通过。 |
| TCP 本地运行 | 当前二进制的 Modbus、ENIP、UA 本地 reviewed 测试通过；MMS 增加 I/O 预算后通过。IEC104 的 whole-sequence HEAD 测试已取得可变字段、关联响应及反馈，最终来源包复验记录另见下文。所有目标均为本地受控测试替身，不代表独立工业设备互操作。 |
| BACnet 独立服务 | 使用当前插桩重新构建 BACnet Stack，9 项普通 loopback 通信检查通过。StateAFL campaign 首轮曾因 I/O 完整性和校准时间预算失败；其最终状态单独记录，不以普通通信或 API 测试替代。 |
| generic 本地运行 | 12 秒基准运行通过全部 11 项条件（`passed: true`），取得 HEAD/CONTENT/SEQUENCE 实际编辑和覆盖反馈。在针对状态 1 的 180 秒长程定向运行中，修复了此前因 M2 局部数据与绝对区域偏移不一致导致的 SIGSEGV (-11) 崩溃，完整运行且正常退出，并成功发现并行进了非零状态 1 的结构化变异（`feedback_memory_state_ids: [0, 1]`）。 |
| 离线交付 | 模板 16 项、非法替代响应原子拒绝、描述漂移拒绝、ZIP 可复现及全部 manifest 哈希检查通过。提取包的 8 项深度检查、三个独立 C 测试均通过；完整 Modbus 测试还通过 4 进程 sanitizer 并发检查。 |

## 本轮修复及验收边界

请求序号和实际连接绑定字段不再作为独立变异目标，IEC104 单值 VSQ/IOA 标为 fixed；编译器和 C loader 都要求 IEC104 序号依赖的 `unit: 2`。响应端移除本地序号 writer，保留对端独立序号验证。生成器、已发布 IEC 描述、offline generic 投影和 reviewed 哈希目录已同步，导出时会拒绝 generic 投影漂移。

本地 campaign 的等待预算可显式配置。最初 1 ms socket 预算导致完整提交检查拒绝校准；提高测试预算后复验，完整性与反馈门禁均保留。BACnet 启动与可变校准周期还需要较长 ready 预算。测试 runner 不再把收到停止信号后才打印的 ready 行当成正常完成校准。

StateAFL 在每次 `fuzz_one()` 完成后选择状态，同一次 havoc 内保持目标；发现新队列还会延长该阶段。因此短运行的 `target_state=0` 不能直接证明边界映射失败。定向验收仍要求实际非零状态、可信边界和可归属的覆盖执行，不能仅用状态图节点、语义状态名或注入 ID 替代。

针对 StateAFL 在状态感知模式定向非零状态（`target_state_id > 0`）时的核心引擎崩溃进行了定位与修复：
- **M2 局部区域偏移归一化**：当 `M2_start_region_ID > 0` 时，原始输入 `orig_regions` 原直接指向队列全局偏移（非 0 开始），而待变异切片缓冲区 `in_buf`/`out_buf` 仅包含 M2 自身切片（0 索引起始），导致 `common_fuzz_stuff` 和区域变异函数访问越界并触发 SIGSEGV (-11)。现为 M2 动态分配独立 `orig_regions` 并统一下减基地址 `m2_base_offset` 归一化为 0 基准偏移，并在 `abandon_entry` 安全释放。
- **拼接边界防御**：在 `afl-fuzz.c` 的 splicing 阶段，严格检查 `first_region_count < mutated_region_count` 与 `second_region_count < target->region_count`，防止无符号整数 `target->region_count - 1 - second_region_count` 下溢产生 `4294967295` 越界内存访问；并对空区域情况安全回退。
- **变异追踪与复制安全防御**：在 `regions_add_bytes` 和 `regions_remove_bytes` 中对 `cur_region` 增加边界截断与越界防范；在 `common_fuzz_stuff` 中重命名局部遮蔽变量 `m_len` 并将写入复制长度截断至输入实际长度，杜绝堆越界读写。
修复后，`make afl-fuzz` 编译 0 警告 0 错误，通用线协议测试与 180s 状态感知长程运行均无崩溃平稳完成。

本轮没有实现 ENIP 自动 ForwardOpen、IEC104 数据 ASDU/异步调度、UA Renew/重叠 token/安全 Session 或 MMS 任意嵌套类型。五份工业 offline generic 描述仍未启用。`full_modbus.json` 是独立的 24 grammar 执行器回归输入，不等同于已发布的 26 消息 reviewed 包。上述功能通过也不等同于固定预算对照实验已经证明方法效果。

本地 `tests/protocol/out/` 为生成输出，可能不随源码交付；报告中的结果描述其当时运行范围。可从仓库根目录运行以下入口重新验证，输出到独立目录：

```sh
bash tests/protocol/run_all.sh /tmp/stateafl-protocol-check
bash tests/generic-wire/run_all.sh /tmp/stateafl-generic-check
python3 tests/protocol/test_multicodec_runtime.py
python3 tests/protocol/run_bacnet_dynamic_tests.py
python3 tools/init_protocol_spec.py --source-dir protocols/reviewed/modbus_tcp \
  --require-runtime --output-dir /tmp/stateafl-reviewed-modbus
```

最后一条的输出目录须不存在；将源目录替换为其他 reviewed 协议可准备对应包。包生成与 C 加载分别证明描述可被当前工具接受、IR 可被运行时加载，并不证明真实目标的会话效果。完整 suite 的具体构建命令、sanitizer 参数和测试顺序以对应 `run_all.sh` 为准。
