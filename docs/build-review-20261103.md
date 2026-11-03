# 编译复核与进一步反思

> 本页固定记录 `23e0f0d`→`ef72bd1` 的编译修复。后续 U01–U09、完整回归源码只编译入口及新结果见[可用性修复](usability-repair-20261103.zh-CN.md)，不应把下文原阶段的剩余问题直接当作最新状态。

日期：UTC 2026-11-03（Phoenix 2026-11-02）。分支：`feature/description-driven-c-engine-20261027`。复核起点：`23e0f0de682bc82dbf80c81acb6509d3a0810044`。

用户本次明确授权编译。已实际编译主工具、LLVM 默认组件及选定回归源码，没有运行这些回归程序、插桩 smoke test、验收控制器或目标服务。此前“只静态”的记录属于原阶段；本页是后续结果。**默认64位构建已通过，运行正确性和方法有效性仍未验收。**

## 本次确认的问题及修复

| 问题 | 证据和影响 | 本次处理 |
| --- | --- | --- |
| 新日志函数缺声明，真实编译失败 | `protocol_runtime.c` 调用了 `nj_write_string`，没有包含 `native_json.h`；Clang 18 报 implicit function declaration。初始主构建退出2，严格运行时编译退出1。 | 补齐直接头文件依赖，重新编译主程序、运行时对象和宿主回归。这个错误说明上一轮静态复核确实漏掉了构建阻断。 |
| 没有完整的只编译入口 | 默认 `all` 会运行插桩 smoke test；仅指定 LLVM 产物又可能漏掉原先挂在测试路径上的 section isolation。 | 根目录和 LLVM Makefile 增加 `build-only`；LLVM 入口包含 runtime section rename。rename 循环错误立即失败；嵌套 CMake 构建传递 make jobserver。 |
| 网络对象缺少头文件依赖 | 修改 `aflnet.h` 时，原 implicit `aflnet.o` 规则仍认为对象最新；fuzzer 重新链接也可能复用旧网络 ABI。`make -n -W aflnet.h aflnet.o` 可检查该问题而不改动文件。 | 显式声明网络对象的公共头文件依赖；相同 dry-run 现在要求重新编译网络对象。强制主构建原已重编该对象。 |
| 发现奖励与响应资格不一致 | `protocol_collect_coverage` 检查响应完整性，最终 discovery 奖励却只检查全部请求是否提交。全部发送后接收失败，异常保留事件仍可能获得奖励。 | 在原执行结束后冻结 `feedback_eligible`，覆盖采集及全部 discovery 奖励共用它。重放后的响应全局值不能改变原资格。补充真实宿主回归源码。 |
| 传给校准的原输入文件不等于实际网络输入 | `calibrate_case` 虽写入 `use_mem`，网络仍发送 `kl_messages`，并可能根据本次连接重新绑定字段。不能因传入原 coverage bytes 就声称校准输入相同。 | 新队列 inline 校准接收原 wire 观察；实际字节不同或不完整时记录 `calibration_rejected`，保留失败标记并退出该次校准，不消费其 virgin bits 或发布校准分数。原合法覆盖队列仍保留，没有强行发送失效 session 值。 |
| 校准位图基线可被内部重放覆盖 | 原 checksum 已冻结，但 `first_trace` 仍可能复制状态分析/确认之后的全局位图，导致不同来源的比较基线。 | 新队列进入内部重放前保存原 coverage 位图，并显式传入 inline 校准；与原 wire 一起保持到校准返回。 |
| 根工具存在无用计数警告 | `afl-gotcpu.c` 的 `loop_repeats` 只自增而未使用。 | 删除无效局部计数，不改变计时和调度循环。 |

本次补充的宿主断言源码调用生产完整性和 wire 比较函数；已重新编译，未执行，不能据此声称断言通过。校准身份拒绝沿用 `FAULT_NOBITS` 兼容返回值，具体原因在 `calibration_rejected` 日志中区分，不代表目标运行故障。

## 实际编译结果

系统使用 `/usr/bin/clang`、`clang++`、`llvm-config`，均为18.1.3；没有下载替代工具链，没有安装或修改系统依赖。

| 范围 | 实际操作与结果 | 可支持的结论 |
| --- | --- | --- |
| 初始主构建 | 强制重编所有根工具，因缺少 `nj_write_string` 声明退出2 | 真实失败，不能用旧二进制冒充本次源码成功 |
| 修复后主工具 | `make -B -j2 build-only` 退出0；最终源码修改后再次 `make -j2 build-only` 退出0 | 9个标准主工具及 `afl-as` 可编译、链接；最终 `afl-fuzz` 已按修改后的源码重建 |
| LLVM 默认组件及源码依赖 | `make -C llvm_mode -B -j2 build-only` 退出0 | wrapper、LLVM Pass、原生/64位 coverage runtime、C/C++ state tracer 及 Containers/TLSH/MVPTree 源码构建成功 |
| 严格运行时编译 | 10个 runtime/codec 对象使用 C11、`-Wall -Wextra -Werror`、ASan/UBSan 编译；另编译网络对象，全部退出0 | 编译器未发现这些翻译单元的警告或错误，不表示 sanitizer 已运行 |
| 12个选定回归程序 | 编译、链接全部退出0；宿主合同在最终源码上重新编译退出0 | 这些回归源码可构建，不等于测试通过 |
| 实际插桩 C/C++ 链接 | `afl-clang-fast` 编译现有 state fixture，`afl-clang-fast++` 编译调用 `trace_message_boundary` 的最小 C++ 源，均退出0 | 新 helper 可以通过两种 wrapper 链接，不证明边界发布运行正确 |
| ABI 调试工具 | `state-debug.c` 使用 C11、`-Wall -Wextra -Werror` 编译退出0 | 更新后的调试器可构建，未执行 SHM 操作 |
| 目标对象静态检查 | `readelf` 显示两种 tracer 的 `.tracer_data/.tracer_bss`；`nm` 均显示 `trace_message_boundary` 定义 | 必要 section isolation 和符号存在，不等于运行时内存行为已验证 |
| 可选32位 coverage runtime | 构建报告跳过；单独 `clang -m32` 编译退出1，缺 `bits/libc-header-start.h` | 当前环境缺少32位 libc 开发头文件；本次不认可32位构建通过，也不宣称完整32位 StateAFL 支持 |

本次编译并链接的12个程序为：`test_generic_runtime`、`test_generic_modbus`、`test_response_completion_transaction`、`test_intentionally_invalid_mode`、`test_manifest_configuration_contract`、`test_cold_start_segment_manifest`、`test_manifest_attribution_continuity`、`test_layer_operability_accounting`、`test_state_graph_strict_execution`、`test_execution_wire_contract`、`test_transport_error_contract`、`test_production_execution_contract`。其中旧宿主/网络翻译单元沿用兼容警告选项，未将其写成全仓 `-Werror` 通过。

TLSH 上游 CMake 最低兼容版本仍产生 deprecation warning；未修改固定版本的第三方源码来隐藏警告。默认构建成功不能解释为零警告或可选目标全部通过。

## 必须继续保留的边界

- **有意损坏模式不保证完整会话发送。** 当前 intentional predicate 只在有效投影可于当前会话 prepare 时放行，并随即 cancel；实际损坏报文成功发送也不会把该投影自动提交为真实 session。若 M3 依赖该状态或响应绑定，仍可能拒绝。全序列投影通过只是名义模型检查；要改变此语义，需要另行设计和验证专门的发送事务，不能靠无条件放行 M3 或假造目标状态完成。
- **精确 wire 身份会保守拒绝不同 session 值。** 这保护归因，但可能使状态分析、确认或 inline 校准无法接纳动态绑定会话；本次没有定义 session 等价规则，也没有证明这种拒绝对方法有效性没有影响。
- **边界提供者仍是必要前提。** 编译和 C/C++ 链接不证明自然非零状态产生种子并进入 M2。无协作 provider 仍为 UNKNOWN；目前契约仅覆盖受控单进程、单线程。
- **原 wire 保存的范围不能扩大解释。** 正常 coverage 队列及 IPSM 保存使用其观察；已有 dry-run/异常诊断保存仍有逻辑列表或末次执行口径，不能把它们都解释成原 coverage 的不可变 wire 证据。本轮没有扩展异常目标验证。
- **构建与方法验收分开。** 未运行单元、目标、网络对照或效果实验；P07 独立 memory-only 保留、一般协议表达力、并发事务和方法收益仍受既有范围限制。未来应运行对应回归验证新门控和校准拒绝，而不是将构建退出0当成全部缺陷关闭。

上一轮的主要流程问题是只审阅源码就交付了范围很大的改动，新增回归也没有实际编译，因而没有发现最直接的声明依赖错误。今后若执行范围只允许静态分析，应保持“未编译”的明确状态；允许编译后，应分别确认主程序、插桩产物和回归源码，且继续单独报告运行验收。

## 本地证据与复现

原始日志及二进制放在被忽略的本地目录 [tests/protocol/out/build-review-20261103-0110](../tests/protocol/out/build-review-20261103-0110)。该目录未提交；克隆仓库不会自动得到这些日志或产物。本页记录结果与范围，不声称完整构建来源认证。

- [首轮失败](../tests/protocol/out/build-review-20261103-0110/root-build-initial.log)、[修复后强制主构建](../tests/protocol/out/build-review-20261103-0110/root-build-fixed.log)、[最终主构建](../tests/protocol/out/build-review-20261103-0110/root-build-verified.log)。
- [最终 LLVM 构建](../tests/protocol/out/build-review-20261103-0110/llvm-build-final.log)、[独立32位失败](../tests/protocol/out/build-review-20261103-0110/runtime-32-probe.log)。
- [运行时与12个回归的完整编译 argv/退出码](../tests/protocol/out/build-review-20261103-0110/contracts/commands.json)、[最终宿主编译](../tests/protocol/out/build-review-20261103-0110/contracts/test_production_execution_contract.final.compile.log)、[C/C++ wrapper 链接记录](../tests/protocol/out/build-review-20261103-0110/boundary-link-commands.json)。

只构建默认产物的入口如下；它们仍会运行编译器探针和构建工具，不执行插桩测试程序：

```sh
make -j2 build-only
make -C llvm_mode -j2 build-only
```

需要强制重编时添加 `-B`；无需为了本次检查删除工作树或既有输出。运行测试仍应遵守用户后续授权范围。
