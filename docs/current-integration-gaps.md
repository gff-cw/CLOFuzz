# 当前集成问题与修正状态

2026-11-02 对分支 `feature/description-driven-c-engine-20261027`（最新提交 `aa49ebc`）的全面审查与纯 C ASan/UBSan 测试验证确认：
在线定向变异模块的 14 项阻断问题（B01–B14）及相关的 27 项协议与状态运行时问题均已完成源码修复并建立完整单元回归。
本页更新此前基于 `ba45263` 的旧记录，如实反映当前的闭环状态。
方法正确性与实验有效性的判据分别列于[方法验证契约](method-validation-contract.md)。

| 项目 | 源码依据与当前状态 |
| --- | --- |
| 非零状态变异入口 | **已修复 (闭环)。** 首 region 的零计数阻断已移除；状态访问更新在真实状态分析执行后显式计入（[afl-fuzz.c](../afl-fuzz.c#L810), `9d9887b`）。 |
| 消息与内存状态边界 | **已闭合。** 移除了未证明的 `seq[i+1]` 索引强绑假设，中间未验证快照统一设为 UNKNOWN，消除状态伪造并保留全路径候选（[afl-fuzz.c](../afl-fuzz.c#L734), `9d9887b`）。 |
| 内存新颖性门槛 | **已闭合。** 解耦新颖性状态码，确认失败与重试耗尽路径均被严格隔离，不污染可信集合与区域标注（[afl-fuzz.c](../afl-fuzz.c#L1200), `222d3d5`）。 |
| UDP 响应边界 | **已修复 (闭环)。** 每次接收回调分派至 `gr_after_dgram` 与 `gr_after_stream`；响应截断与超限统一在反馈收集阶段降低完整性（`aa49ebc`）。 |
| M3 全序列一致性 | **已修复 (闭环)。** 全序列验证器覆盖 M1/M2/M3，且支持模式感知（`near_valid` 与 `invalid` 故意的 M2 破坏不被误拒，严格执行容量与分帧约束）（[protocol_runtime.c](../protocol_runtime.c#L876), `aa49ebc`）。 |
| 确定性阶段归因 | **已修复 (闭环)。** uniform 变异模式显式传递所选反馈层标签，消除记录为 NONE 的缺陷；候选全量记录 run/segment/candidate/exec ID（[afl-fuzz.c](../afl-fuzz.c#L7179), `01ef5b5`）。 |
| 在线语法能力 | **保持规范定义范围。** 通用字段编译器支持平铺 uint/bytes、size_of 及整数相等关联；不支持的高级特性在加载阶段明确拒绝，防止静默错用。 |
| 六工业 profile | **保持受限支持范围。** 范围严格限定在已支持的 14 条核心迁移，不支持特性显式隔离。 |
| 模板与转换关系 | **说明已修正，边界已对齐。** 区分旧 YAML、被动布局和新 JSON，加载时校验分帧与样例唯一性。 |
| 样例语法歧义 | **已闭合。** 等价别名迁移规范化去重（[protocol_runtime.c](../protocol_runtime.c#L378), `4a9b0be`），加载时互斥检查已通过单元验证。 |
| 关联规则完整性 | **已闭合。** 响应匹配后且关联通过后方才计入相应用途的响应统计，同分母对齐。 |
| JSON 输入边界 | **已闭合。** 采用原生 JSON 解析器与转义写入函数（[run_manifest.c](../run_manifest.c#L50)），特殊字符与控制字符规范转义，无解析越界。 |
| TCP 样例分帧契约 | **已修复 (闭环)。** generic 分帧一致性检查严格限定为 `cur_offset == e->frame_offset`，杜绝将合法的总长度派生字段误拒（[generic_runtime.c](../generic_runtime.c#L180), `4a9b0be`）。 |
| 请求样例预算 | **已闭合。** 限制总消息数、总字节数以及 4 字节 LE 分帧，超过预算即时拒绝。 |
| 响应统计含义 | **已闭合。** 指标触发点对齐至实际执行阶段，内部重跑用途（状态分析、hang）完全区隔，调度统计临时文件原子发布（[afl-fuzz.c](../afl-fuzz.c#L6021), `01ef5b5`, `aa49ebc`）。 |
| 证据来源 | **已闭合。** 冷启动与断点恢复严格验证 `manifest_version` 和 `mutation_mode`，多文件规范链式哈希，零号候选得到完整保护（[run_manifest.c](../run_manifest.c#L40), `aa49ebc`）。 |
| 原始证据保存 | **已闭合。** 实际发送报文完整持久化至 `.replay`；未完整发送的截断会话严格禁止入队测试用例（[afl-fuzz.c](../afl-fuzz.c#L5659), `aa49ebc`）。 |
| 文档时序冲突 | **已修正。** 文档已与最新代码和提交哈希完全对齐。 |

---

### 验证依据
- **纯 C 测试套件**: `tests/generic-wire/run_all.sh` 包含 19 个独立测试程序，在 Clang `-std=c11 -O1 -Wall -Wextra -Werror -fsanitize=address,undefined` 下全部通过（退出码 0）。
- **Fuzzer 生产构建**: `make afl-fuzz` 在 Clang `-O3 -Wall` 下编译实现 0 警告、0 错误。
- **分支与代码管理**: 变更均直接推送到 `feature/description-driven-c-engine-20261027`，保持分支隔离。
