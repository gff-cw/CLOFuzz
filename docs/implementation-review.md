# 实现阶段复核与验收边界

日期：2026-10-25。修改前追踪文件无未提交差异；已有未跟踪协议草稿先备份到 `/tmp/stateafl-task-baseline/untracked-protocol.tar`，在当前 LLVM18 分支基础上新建 `feature/protocol-aware-integration-20261025`。只提交任务相关文件，不修改 BACnet tracked 源码或原 inputs。

以下阶段表、首轮验收数字及 BACnet 多轮对照是历史记录，保留其原始统计。本次新增五种 TCP runtime 的实现与证据边界列在文末；历史通过结果不能替代当前源码的最终回归。

## 共同核查问题

各阶段均按以下问题复核：完成了什么需求、依据来自哪里、哪些是新增设计；是否误解三级职责；是否混淆语义状态与内存状态；是否改动 LLVM18、哈希和原反馈；固定/派生字段、跨消息缓存、可变长度和边界是否正确；是否真正运行；结论是否超出证据；当前测试的盲区和下一项证伪测试是什么。下表逐阶段记录发现和实际修正，原状态实现保持不变这一结论由 git diff 与七组回归共同支持。

| 阶段 | 需求、证据与新增设计 | 核查、修正及证伪测试 |
| --- | --- | --- |
| 1 文献与语法 | 完整阅读本地 project.md，并实际查看 Figure 3/4/5；官方 Boofuzz 概念核对 | HEAD语义、CONTENT仍用AFL、SEQUENCE改变顺序；双描述分离。原始资料未公开完整语法/权重/缓存算法，因此不宣称逐行复刻。下一步用独立 schema 拒绝伪语法 |
| 2 统一描述模板 | 新设计 ICP-IR v1 YAML/JSON，分别保存消息和语义状态；来源在 evidence.yaml | 条件/嵌套/重复结构树为静态知识，不能冒充执行器。版本、整数宽度、重复ID、引用和循环均有负例。首轮六模型共48消息、335字段（已由本轮71消息、641字段替代），范围各自声明 |
| 3 编译与加载 | Python SafeLoader + JSON Schema/语义校验；C启动一次加载，不在热路径执行脚本 | 修复未知类型/codec/locator、重复key、深度/整数边界和缺失引用；静态专用操作若被用于runtime明确拒绝。83 loader用例和250随机IR验证拒绝而不崩溃 |
| 4 三级变异 | 真实接入 common_fuzz_stuff；HEAD字段候选、CONTENT投影原AFL候选、SEQUENCE有界插入/删除/重复/重排 | 修复CONTENT错位取值和跨数据报取内容、所有层序列约束、随机插入位置；HEAD策略列表实际控制标量子集。运行日志证实三个层均执行；原算子保留 |
| 5 依赖处理 | 长度/计数/偏移/sum8/CRC32/copy/response绑定/序号；engine独立缓存，键含message+field | 修复多写入者、跨消息结构依赖、变异清空live缓存；模拟后恢复live缓存，每执行重新清空。6项会话隔离和23项依赖/边界断言通过；响应缺失时拒绝，不静默伪造 |
| 6 六协议模型 | BACnet runtime；Modbus、IEC104、MMS、ENIP/CIP、OPCUA静态规范 | 修复Modbus FC0F数量关系，增加服务/响应结构及来源。该历史阶段补齐MMS session/presentation与OPCUA服务体时，五种TCP协议仍只有静态描述并拒绝在线启用；本次新增codec另见文末，不宣称全标准覆盖 |
| 7 BACnet构建与运行 | 独立LLVM18 Debug server，9项正常UDP检查；同种子五模式均通过 | 实际发现10ms启动等待不足和stdout缓冲，先定位strace、用既有-D200000并flush ready后重跑。修复raw M1/M3触发结构化fatal及完整MAX_FILE约束；未把协议状态用于内存ID |
| 8 提交前 | 完整协议套件、原LLVM18七组、额外45秒hybrid及最终源码10秒三级验证 | 确认实际发包、覆盖、原内存0→1及自环、invoke关联、长度正确、队列与重放。独立assertion夹具验证保存与SIGABRT重放；BACnet本身0异常。diff --check通过后分批提交并实际尝试推送 |

## 历史 BACnet 阶段验证（保留原数值）

- 描述编译器51测试、CLI8测试；六模型确定性重编译。
- 当时C加载83用例、250随机IR、25000随机wire/变异；100096基础 + 6会话 + 23依赖/边界 = 100125项C断言，ASan/UBSan/LSan均无报告。[runtime-results.json](../tests/protocol/evidence/runtime-results.json) 此后已被最新离线运行更新，包含五 TCP codec 的源码哈希，不再是本段旧计数的原始快照。
- 网络sanitizer测试验证原TCP、7000字节UDP、数据报聚合和LE32/O_TRUNC；正常BACnet互通9项。
- 五模式结果 [compatibility-final/summary.json](../tests/protocol/evidence/compatibility-final/summary.json) 全通过；45秒hybrid也通过且全部层触发；最终源码三级smoke通过。实际数字与命令见 [集成报告](bacnet-integration-test.md)。
- 原LLVM18七组回归再次通过，见 [llvm18-final.log](../tests/protocol/evidence/llvm18-final.log)。没有修改 llvm_mode 的插桩或内存状态算法。
- synthetic assertion样本保存并重放signal6成功；不将夹具故障称为BACnet漏洞。

## 未覆盖内容与结论限度

当前是SPFuzz方法在StateAFL上的明确限定范围工程实现，并非论文未公开源码的逐行复原。真实工业目标互通证据仍来自 BACnet/IP Who-Is/ReadProperty 子集。本次六种参考 profile 均有有界 C runtime；五种 TCP 功能路径使用本地 C fixture double，不能作为工业产品互通证明。通用 when/repeat/conditional_presence 仍不执行；仅允许精确 Modbus data/count repeat 和 codec 管理的 MMS tagged_length。不支持任意图 preamble 搜索或完整 transaction 数据库。near_valid/invalid 共享单条对应协议长度+1策略；密码学、安全策略与完整 MMS/OPC UA 会话仍被排除。

现有测试可能遗漏复杂路由、分段、多事务重叠、长期内存增长、非本机网络及长期调度收益。后续应对这些范围增加独立codec、跨事务fixture和多次长时间对照实验。短测仅证明接入与基础运行，不支持统计显著的覆盖提升结论。实际远程交付记录见 git-delivery.md（推送后生成）。


## 用户模板流程补充复核

用户指出此前只有schema与已填模型，缺少可直接填写的模板。这一反馈成立；原交付不能据此宣称已经提供完整用户建模流程。本次补上通用协议/状态模板、六协议配置生成器和按描述目录启动入口。

新增验证覆盖：六种协议按同一模板实例化并编译；拒绝覆盖已有目录、空/非法ID、未填占位符；静态模型不得启动；每次启动从已编辑YAML重编译，配置错误不得使用旧IR。C sanitizer夹具证明 invoke_id 枚举值从33改为77后，实际HEAD结果随之改变，其他字节不变。另发现Who-Is内容编码依赖消息ID字面值，已改为APDU服务语义判断，并用重命名消息加CONTENT范围重编码测试确认修复。

模板/启动新增12项测试通过；同原编译器51项、CLI8项、runtime随机输入和网络检查共同进入 `tests/protocol/run_all.sh`。真实本机BACnet还通过新的启动入口加载自定义protocol_id的描述包；完整日志和最终统计见 `tests/protocol/evidence/template-workflow-result.json`。该次模板补充时仍未实现其他五种协议的在线 codec；这是历史范围，本次新增 runtime 另列下节，仍不以模板生成或静态通过代替工业目标验证。


## 本轮完整描述与多次对照复核

本轮明确修复模板与C执行器不一致、角色/依赖矛盾、样例仅检查外壳、状态/匹配歧义、IR预算及深依赖递归等真实问题，见 template-audit.md。六协议已扩充至71完整fixture/641字段，并新增独立深层结构检查、内部长度破坏负例和生成重现；不再把旧MMS/OPCUA片段当成完整消息。

本地BACnet采用三轮配对随机种子、五种模式轮转，完成15次各20秒有效阶段的对照。新增同步校准基线和实际发送序列保存；功能对照另外验证Invoke33/77、仅长度+1以及错误依赖启动拒绝。15次均通过接入检查，原内存状态反馈仍存在，观察到0 crash/0 hang。结构化样本符合profile比例更高，但本轮raw的覆盖位图新增位置更多，不能宣称取得覆盖提升。结果、边界和复现命令见 bacnet-controlled-results.md。

实验中曾发现功能模型把NPDU control固定为4，而既有种子为0，导致候选全被拒绝；这证明仅YAML静态通过还不够。随后从原始种子生成该固定签名并重跑，功能对照通过。失败记录保留，未将它计入五模式性能比较。该轮 BACnet 对照统计期间其他五种协议 runtime 尚未实现；此历史结果不用于证明本次新增 TCP codec 的能力或收益。


## 本次五种 TCP runtime 扩展

新增 Modbus TCP、IEC104、MMS/TCP、EtherNet/IP/CIP 与 OPC UA TCP 的有界 C codec，与原 BACnet 通过同一可选 engine 分派。71条完整 fixture、641个字段的范围保持不变；31条 request 可断言 runtime_encode，response 用于验证、关联和缓存。各协议的排除项、SendUnitData 外部 ForwardOpen 前提和 OPC UA CLO 的实现/规范措辞差异继续保留，不能据此宣称完整标准覆盖。

非 BACnet 编译器通过 `tools/native_protocol_codecs.py` 调用相同 C validate/field/same_kind，检查内部结构与实际切片，需要 C11 编译器、公共头和五个 codec 源文件；在线直接执行 C，不在每次变异运行 Python。IR 支持完整 UInt64，length/count 支持 multiply，Modbus repeat 限于既有 data/count 精确布局；MMS tagged_length 由 codec 管理，叶替换允许 BER/session 长度头及 invoke INTEGER 编码宽度变化。未支持的 opaque BER/CIP/UA 整体替换明确拒绝。

网络接收按各协议长度缓存分片、拆分合并响应，完整且满足模型及声明关联的实际响应才能写入绑定缓存。每连接/执行重置缓存；候选模拟结束恢复 live cache。已有 M1 前缀为 M2 提供语义起点，只模拟状态边，不产生 session/channel/token 等响应值，不搜索任意 preamble。未提供描述时仍由原 AFL/StateAFL 路径调度和反馈，语义状态与内存状态保持独立。

新增 [C 功能目标](../tests/protocol/fixtures/multicodec_server.c) 和 [五协议功能驱动](../tests/protocol/multicodec_integration.py) 检查真实 StateAFL/socket 路径、可变字段、响应句柄绑定与 framing；独立 codec/runtime 测试另外覆盖内层长度破坏、叶增长/缩短、字段切片和状态/依赖拒绝。这些夹具部分共享工程 codec，不是独立工业协议实现。

恢复核对时，协议离线套件与 LLVM18 回归有通过日志，runtime 证据中九个源码哈希均匹配磁盘；这不是恢复后重跑。五 TCP 夹具中四项记录通过，IEC104 进程退出码 -11；其 JSONL 的 47 次 mutation 与 structured_success=0 快照不一致，原因未证明。最新 BACnet legacy 在初始 dry run 超过1000ms主动中止，尚未 ready，其余四模式未运行。两项失败未解决，最新扩展未提交/推送，不能宣告最终集成完成。详细路径、验收边界及只读核验命令见 [任务恢复记录](task-recovery.md)。
