# 实现阶段复核与验收边界

日期：2026-10-25。修改前追踪文件无未提交差异；已有未跟踪协议草稿先备份到 `/tmp/stateafl-task-baseline/untracked-protocol.tar`，在当前 LLVM18 分支基础上新建 `feature/protocol-aware-integration-20261025`。只提交任务相关文件，不修改 BACnet tracked 源码或原 inputs。

## 共同核查问题

各阶段均按以下问题复核：完成了什么需求、依据来自哪里、哪些是新增设计；是否误解三级职责；是否混淆语义状态与内存状态；是否改动 LLVM18、哈希和原反馈；固定/派生字段、跨消息缓存、可变长度和边界是否正确；是否真正运行；结论是否超出证据；当前测试的盲区和下一项证伪测试是什么。下表逐阶段记录发现和实际修正，原状态实现保持不变这一结论由 git diff 与七组回归共同支持。

| 阶段 | 需求、证据与新增设计 | 核查、修正及证伪测试 |
| --- | --- | --- |
| 1 文献与语法 | 完整阅读本地 project.md，并实际查看 Figure 3/4/5；官方 Boofuzz 概念核对 | HEAD语义、CONTENT仍用AFL、SEQUENCE改变顺序；双描述分离。原始资料未公开完整语法/权重/缓存算法，因此不宣称逐行复刻。下一步用独立 schema 拒绝伪语法 |
| 2 统一描述模板 | 新设计 ICP-IR v1 YAML/JSON，分别保存消息和语义状态；来源在 evidence.yaml | 条件/嵌套/重复结构树为静态知识，不能冒充执行器。版本、整数宽度、重复ID、引用和循环均有负例。六模型共48消息、335字段，范围各自声明 |
| 3 编译与加载 | Python SafeLoader + JSON Schema/语义校验；C启动一次加载，不在热路径执行脚本 | 修复未知类型/codec/locator、重复key、深度/整数边界和缺失引用；静态专用操作若被用于runtime明确拒绝。83 loader用例和250随机IR验证拒绝而不崩溃 |
| 4 三级变异 | 真实接入 common_fuzz_stuff；HEAD字段候选、CONTENT投影原AFL候选、SEQUENCE有界插入/删除/重复/重排 | 修复CONTENT错位取值和跨数据报取内容、所有层序列约束、随机插入位置；HEAD策略列表实际控制标量子集。运行日志证实三个层均执行；原算子保留 |
| 5 依赖处理 | 长度/计数/偏移/sum8/CRC32/copy/response绑定/序号；engine独立缓存，键含message+field | 修复多写入者、跨消息结构依赖、变异清空live缓存；模拟后恢复live缓存，每执行重新清空。6项会话隔离和23项依赖/边界断言通过；响应缺失时拒绝，不静默伪造 |
| 6 六协议模型 | BACnet runtime；Modbus、IEC104、MMS、ENIP/CIP、OPCUA静态规范 | 修复Modbus FC0F数量关系，增加服务/响应结构及来源。MMS缺完整session/presentation，OPCUA仅None和结构fixture；无在线codec的五协议显式拒绝，不宣称全标准覆盖 |
| 7 BACnet构建与运行 | 独立LLVM18 Debug server，9项正常UDP检查；同种子五模式均通过 | 实际发现10ms启动等待不足和stdout缓冲，先定位strace、用既有-D200000并flush ready后重跑。修复raw M1/M3触发结构化fatal及完整MAX_FILE约束；未把协议状态用于内存ID |
| 8 提交前 | 完整协议套件、原LLVM18七组、额外45秒hybrid及最终源码10秒三级验证 | 确认实际发包、覆盖、原内存0→1及自环、invoke关联、长度正确、队列与重放。独立assertion夹具验证保存与SIGABRT重放；BACnet本身0异常。diff --check通过后分批提交并实际尝试推送 |

## 最终验证

- 描述编译器51测试、CLI8测试；六模型确定性重编译。
- C加载83用例、250随机IR、25000随机wire/变异；100096基础 + 6会话 + 23依赖/边界 = 100125项C断言，ASan/UBSan/LSan均无报告。最终源码哈希、命令和支持范围见 [runtime-results.json](../tests/protocol/evidence/runtime-results.json)。
- 网络sanitizer测试验证原TCP、7000字节UDP、数据报聚合和LE32/O_TRUNC；正常BACnet互通9项。
- 五模式结果 [compatibility-final/summary.json](../tests/protocol/evidence/compatibility-final/summary.json) 全通过；45秒hybrid也通过且全部层触发；最终源码三级smoke通过。实际数字与命令见 [集成报告](bacnet-integration-test.md)。
- 原LLVM18七组回归再次通过，见 [llvm18-final.log](../tests/protocol/evidence/llvm18-final.log)。没有修改 llvm_mode 的插桩或内存状态算法。
- synthetic assertion样本保存并重放signal6成功；不将夹具故障称为BACnet漏洞。

## 未覆盖内容与结论限度

当前是SPFuzz方法在StateAFL上的明确限定范围工程实现，并非论文未公开源码的逐行复原。仅BACnet/IP Who-Is/ReadProperty子集具备在线codec并完成目标互通；其他五协议只有静态描述与校验。通用when/repeat、condition/tagged_length执行由BACnet专用结构检查替代，不支持任意图preamble搜索或transaction数据库。near_valid和invalid当前共享单BVLC长度违例策略；无密码学、安全策略或完整MMS/OPCUA会话实现。

现有测试可能遗漏复杂路由、分段、多事务重叠、长期内存增长、非本机网络及长期调度收益。后续应对这些范围增加独立codec、跨事务fixture和多次长时间对照实验。短测仅证明接入与基础运行，不支持统计显著的覆盖提升结论。实际远程交付记录见 git-delivery.md（推送后生成）。
