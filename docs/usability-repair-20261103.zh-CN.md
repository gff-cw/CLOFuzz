# U01–U09 可用性问题修复与交接

日期：2026-11-03。分支：`feature/description-driven-c-engine-20261027`。修复起点为 `9578baa`，其[可用性审计](usability-review-ef72bd1.zh-CN.md)针对源码 `ef72bd1`。本页描述后续生产源码、描述包和回归入口的改进；旧审计保留为历史基线。

本轮由三个 agent 分别处理子进程等待、校准与评分、模板与语料，主 agent 合并并复核。交叉审查进一步补齐了概率选择误判、初始 pending 无重试入口、目标路径身份和条件日志清理等遗漏。**本轮只做静态检查、编译及语料文件转换，没有执行回归程序、插桩测试、目标服务或效果实验。** 下文“已修复”指源码行为已修改并接受编译检查，不表示运行断言已经通过。

| 编号与原问题 | 生产实现中的解决方式 | 回归源码与剩余验证 |
| --- | --- | --- |
| U01 清单冲突在旧输出清理后才发现 | [run_manifest](../run_manifest.c) 新增只读 `manifest_prepare_config`：严格校验旧清单、配置、描述摘要和候选编号，只在内存准备下一 segment。[宿主](../afl-fuzz.c) 在取得输出目录锁后、任何 rename/delete 之前调用，目录准备成功后才显式发布。目标检查也移至目录准备前。锁失败明确拒绝。已有 protocol 输出不得通过关闭描述绕过检查；缺少清单但已有 queue、统计或派生结果时拒绝冒认新实验。条件 tracer 日志也在检查成功后才创建，提前失败允许日志为空。 | [manifest 配置合同](../tests/generic-wire/test_manifest_configuration_contract.c) 覆盖 fresh prepare 不创建文件、成功 prepare 不发布、冲突不改旧清单；[启动合同](../tests/generic-wire/test_startup_selection_contract.c) 调用真实 `maybe_delete_out_dir`，分别检查普通复用和 resume 冲突时 queue 路径、内容及清单不变。均仅编译。 |
| U02 直接 fork 等待 PID 消失，先于本进程 waitpid 而空转 | 删除网络函数末尾 `kill(pid,0)` 循环。`run_target` 唯一负责直接子进程回收，使用 `waitpid(WNOHANG)`，处理 EINTR、ECHILD、停止和超时。forkserver request/PID/status word 通过 poll 等待，完整收齐 4 字节后才发布；请求、握手与执行共享单调 deadline，超时清理共用最多 1000ms 宽限。计时器覆盖 PID 握手，迟到的完整 PID 在已超时时仍被终止。 | [等待合同](../tests/generic-wire/test_child_wait_contract.c) 对真实 helper 注入 syscall 替身，覆盖 zombie、EINTR、ECHILD、取消、有限清理、partial/EOF 和正 PID 信号条件；未执行替身或真实子进程验证。外部 `-c` hook 的 `system()` 仍遵守既有外部命令契约，不承诺被这些 helper 限时。 |
| U03 inline 校准失败后既无有效测量又长期留在 pending | 队列明确区分待校准、已测量、终止隔离，失败最多使用 `CAL_CHANCES=3` 次完整校准尝试。`fuzz_one` 在任何 mutation 前重试；初始状态扫描先解决 pending，状态选择也给全局 pending 队列重试入口，不要求它预先登记可信状态。耗尽后保留磁盘样本和原因、移除评分引用、释放临时 bitmap，pending 只结算一次，不伪称 `was_fuzzed`。 | [队列合同](../tests/generic-wire/test_calibration_queue_contract.c) 覆盖未测量不评分、wire 重建、隔离、引用释放和一次结算；启动合同覆盖无可信状态成员资格的 pending 调度。需要运行验证瞬时失败恢复、持续 session 差异及停止分支。 |
| U04 被拒绝的状态轨迹提前改变 `unique_state_count` | 将写入移至可信接纳门控之后。完整性、确认或重试拒绝时保持原值。初始 coverage 校准保存 bitmap，可信状态分析后用该原 bitmap 重新排名；不用内部重放覆盖后的全局 trace。 | [生产执行合同](../tests/generic-wire/test_production_execution_contract.c) 增加响应不完整、预算超限、发送不完整均不改可信计数的断言，尚未运行。 |
| U05 速度×长度的比较分支不可达 | 比较顺序明确为：有效测量优先，可信 unique state 更多者优先；状态数相等时选择更小的执行时间×长度；完全相同保留 incumbent。乘法饱和，避免溢出反转。待校准与隔离项不参与 bitmap 排名；cull 重新设置初始种子的 favored。 | 队列合同直接调用生产比较及排名 helper，覆盖更多/更少/相同状态、快慢、稳定 tie、溢出、自更新引用和隔离移除。仍需运行验证。 |
| U06 最小 Modbus 模板请求 quantity 与固定响应大小不配套 | [最小模板](../protocols/templates/minimal_runnable_example/protocol_spec.yaml) 固定 quantity=1，固定角色和 mutability 同步；响应保持两个 data 字节。完整 Modbus profile 的多寄存器范围不收窄。 | [规划器回归源码](../tests/protocol/test_seed_planner.py) 检查最小模板范围；仅 AST 检查，未运行 parser 或响应闭环。 |
| U07 后续请求 fixture 缺少建链前缀 | [通用规划器](../tools/protocol_seed_planner.py) 按声明状态图、canonical aliases 和一次 expected-response 投影进行有界 BFS，无协议名对应的前缀硬编码。单包移存 `fixtures/requests`，`seeds` 只放模型可达的请求序列，manifest 记录路径、字节数、重复数、搜索限制和外部前提。生成器、导出器和测试消费者同步。六包保留 31 个原始单包，交付 31 个模型序列；其中 15 个旧 seed 增加了前缀。 | 完成纯文件转换及原单包身份、序列拼接和 LE32 数量核对。没有生成响应或运行目标；`actual_target_session_verified=false`。具体规则、六包路径与命令见[语料修复](seed-corpus-repair-20261102.md)。 |
| U08 选择参数可接受非法值，选种循环无界 | `-q/-s` 必须完整解析为 1、2、3。各选择策略跳过隔离项并响应停止。FAVOR 概率轮后补确定性扫描，不能由随机跳过推断无工作；状态偏好有界尝试后完整枚举。状态与普通队列模式耗尽可选项都明确停止。全局 pending 优先只授予校准机会，不伪造 reachability。 | 启动合同覆盖非法字符串、三种策略、只有一个可用项、全部隔离、取消及无可信登记的 pending；尚未执行。 |
| U09 相对 `-u` 路径在 `-U` 后指向不同文件 | `check_binary` 在父进程中解析为绝对可执行路径，`AFL_SKIP_BIN_CHECK` 也不跳过路径解析；主目标提前检查。`-U` 解析为绝对目录并检查可进入权限；子进程 chdir 失败发布 exec 失败标记。清单记录实际解析的主/vanilla 路径。无 forkserver 的模式明确拒绝单独的 `-u`，`-U` 要求 `-u`。 | 启动合同包含真实路径 helper 检查。相对资源参数仍按所选工作目录解释，未自动改写 argv 内资源路径。路径和磁盘摘要也不认证运行中的映像。 |

另修复了 U07 复核发现的真实 loader 问题：[protocol_runtime.c](../protocol_runtime.c) 原来在同一遍循环中判断字段模型和迁移等价，Modbus partial request 与其稍后出现的 response alias 会互相阻止归一化。现在先建立全部执行模型等价类，再验证每个 alias 与代表的双向迁移角色，最后去重转换边；不同迁移仍整包拒绝。[alias 回归源码](../tests/generic-wire/test_alias_canonical_identity.c) 增加实际 Modbus 包和逆序 message 声明的加载检查，尚未运行 loader 断言。

## 额外修复：恢复时 raw / replay 输入混淆

交付前再次检查恢复路径发现：首次 pivot 与新覆盖保留后的 `queue` 是不含 LE32 头的 raw 字节；原 `-i -` 却将 queue 移为 `_resume` 后再按 LE32 提取、再次去头。普通 `-i <旧输出>` 的 queue 自动导入也存在相同问题。不能用初始字节“看起来像长度”猜格式；`regions` 是尽力写入的调试文件，初始 basename 还与 pivot 后不同，也不能将它作为可靠的恢复契约。

生产路径新增 `queue/.state/replay/<同名ID>`：在初始 pivot 和新 raw 队列保存后，从该 raw 文件与完整连续的 region 边界写出独立的 LE32 快照，使用隐藏临时文件及 rename 发布。它不来自末次诊断执行的 `replayable-queue`。新覆盖队列的边界始终使用已提交消息列表，不再因为 sync 标志把 raw 输入当 replay 重提取。

额外快照会增加磁盘占用、保存与启动核对的 I/O；本轮没有测量其成本。方法对照应使用相同版本和相同保存策略，不能忽略这项实现开销。

锁内恢复检查逐文件比较快照各记录拼接与 raw 字节，检查长度、记录边界、清单数量与普通文件类型，再将保存整个 `.state` 的 queue 一次 rename。已有 `_resume` 只使用其自身快照，不能混用新 queue 的证据；其他 rename 错误明确失败。导入读取快照目录，pivot 只去头一次，复制后再次保存快照；deterministic 标记、自动字典与外部恢复统计仍按原 raw 队列路径读取。受管理的 `.pending-*` 中断文件另行清理，不依赖会跳过点文件的旧清理函数。

`-i <旧输出>` 或显式旧 queue 导入也在修改目的输出前验证并切换到权威快照；导入自己的输出必须使用 `-i -`。**旧产物没有这种快照、快照与 raw 不符或清单不完整时，提前拒绝并保留源目录，不自动迁移或推测边界。** 快照不恢复旧 session、intentional-invalid nonce 或学习状态，也不认证执行映像。完整 pivot 后删除 `_resume` 的过程仍无全目录事务：该清理中断可能需要人工选择已完成的新 queue，不能承诺任意崩溃点自动恢复。

新增 [恢复合同](../tests/generic-wire/test_resume_input_contract.c) 调用实际快照、核对、外部队列准备、扫描和 pivot 函数，覆盖双消息边界、同长度 raw 改写、截断快照、一次去头及隐藏临时文件清理。该源码仅编译，不执行文件恢复断言或任何目标。

## 校准策略的具体边界

重试继续使用原来的 structured/raw 准备策略；structured 路径仍经过 fresh session 的 prepare、完整提交 commit 和响应检查，并逐次比较实际 wire 与磁盘保留输入。没有关闭结构化准备来强行重发过期 session 值。重试没有当前 mutation，M2 为空，不能继承前一个 intentional-invalid 候选的豁免。无法重新证明的 invalid 样本或动态会话差异可能耗尽预算而隔离；日志明确 `strict_original_mode` 和 provenance 未恢复。

隔离并不撤销原 coverage 队列发现，也不提供 session 等价掩码或独立 memory-only 保留机制。`calibration_trace` 仅暂存每项 MAP_SIZE 位图，在成功完成所需排名或终止隔离后释放；完整 wire/响应观察没有被无限挂在队列中。每次校准内部仍可能有 8 或可变路径的 40 轮，所以“3 次尝试”不是“最多执行目标 3 次”。

只读启动检查保护配置/描述/目标拒绝之前的旧输出。它不是整个文件系统启动事务：成功检查之后的 I/O、权限竞争或布局失败没有全目录回滚；resume 的 `_resume` 仍遵循原恢复流程。新清单用原子文件发布，失败明确退出；不能把这个保证扩大为任意启动故障都保持所有派生文件原样。

## 编译与静态检查记录

新增回归入口只编译选项如下。默认入口仍会执行测试，当前轮次没有调用默认入口：

```sh
make -j2 build-only
make -C llvm_mode -j2 build-only
bash tests/generic-wire/run_all.sh --build-only tests/protocol/out/usability-repair-20261103/contracts
```

严格 runtime/codec 使用 C11、`-Wall -Wextra -Werror`、ASan/UBSan 编译；旧宿主/网络翻译单元沿用兼容警告选项。sanitizer 编译和链接不代表 sanitizer 运行。额外编译启用 `LOG_STATE_TRACER` 的宿主，以检查提前失败时日志尚未创建的条件路径。本地原始产物位于被忽略目录 [usability-repair-20261103](../tests/protocol/out/usability-repair-20261103)，不随提交发布。

| 实际操作 | 结果和范围 |
| --- | --- |
| 根目录 `make -j2 build-only` | 退出0；恢复补丁完成后再次构建退出0，`afl-fuzz` 由最终源码重新编译、链接。未变化的其他主工具按依赖复用，不声称本轮全部强制重编。最终日志为 `root-build-resume-final.log`。 |
| `make -C llvm_mode -j2 build-only` | 退出0；本轮没有修改 LLVM 源码，复用已有有效产物并执行 section rename。可选32位 runtime 仍报告跳过，不能写成32位构建成功；此前确认的 multilib 缺失见原编译复核。 |
| 完整 C 回归只编译入口 | 退出0；10个 runtime/codec 对象以严格选项重建，另编译网络对象。无 Python checker 或测试二进制执行。日志为 `contracts-build.log`，执行日志可能为空。 |
| 最后恢复补丁后的宿主回归 | `production_execution`、`calibration_queue`、`child_wait`、`startup_selection`、`resume_input` 使用最终生产源码再次编译、链接，命令循环退出0，日志 `host-contracts-final.log` 逐项标注 COMPILED ONLY。未因宿主改动重编无关独立测试。 |
| 最终回归产物集合 | 本地目录共54个不同 C 回归可执行产物，均有上述编译来源；只检查文件，不执行。这个数量不是通过的断言数量，也不代表仓库中所有其他测试已编译。 |
| 条件日志宏 | `clang -fsyntax-only -DLOG_STATE_TRACER` 在最终源码退出0，日志 `log-state-tracer.delivery.compile.log`；仅编译前端检查。 |
| 恢复补丁的首次语法检查 | 退出1，真实发现 `nj_read_file` 未直接声明；补充 `native_json.h` 后再次语法检查及实际主构建均退出0。失败日志保留为 `resume-syntax.log`，没有用旧二进制代替失败结果。 |

修改的 7 个 Python 文件仅用 `ast.parse` 检查；Bash 入口使用 `bash -n`；6 份 seed manifest 做 JSON 和字节内容核对；31 个单包 fixture 与修复前 seed 原字节相同。无测试断言执行或新方法收益证据。

## 接手后仍需完成的运行验收

取得运行授权后，先运行新增的真实 helper/API 回归，分别验证旧输出冲突保留、直接 fork 自然退出/超时/中断、forkserver 短包/EOF，以及校准恢复和耗尽。然后在受控协作目标上核对完整请求序列、现场绑定、显式消息边界、原 wire/coverage 归属、自然非零状态选种与真正进入 M2。最后按[方法验证契约](method-validation-contract.md)做相同输入和预算的重复对照。

本轮没有将五份 offline-only generic profile 改成 online，没有实现任意 YAML 到 generic-wire 的翻译器、一般并发事务或全协议解析能力。非零内存状态定位仍要求协作式消息完成边界，当前契约限定单进程、单线程。修复 U01–U09 不足以宣称所有协议可直接运行，或方法有效性已经完整达标。
