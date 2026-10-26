# 任务恢复与当前验收状态

本记录以 `workspace/old-session.md`、`Readme.txt`、`project/project.md` 和当前磁盘为依据。旧对话是历史证据，不作为需要逐条重新执行的命令。恢复时未读取 workspace 下的 libiec61850、lib60870、libmodbus、OpENer 四个目录，未重置或清理工作区。

## 目标、方案与验收要求

原始目标是在 LLVM 18 改进版 StateAFL 中接入 SPFuzz 风格的协议描述驱动三级变异，同时保留原 AFL 算子、覆盖率、内存状态推断、队列、状态调度与 M1/M2/M3 路径。交付包括六协议的协议/状态 YAML、标准化 IR、来源与范围声明、验证器、解释器、codec、依赖处理、测试、文档及新分支提交和远程推送。原需求强制要求实际工业实现验证的对象是 BACnet Stack 1.5.0；自建 TCP fixture 不能替代工业目标互通。

已确定的工程方案是两份 YAML 离线编译为 ICP-IR v1，C 在启动时加载，在线不执行描述中的 Python 或任意代码；新功能显式启用，默认路径保留。协议语义状态与 StateAFL 内存状态独立。外层 replay 使用 LE32 消息长度，与协议内层长度分开处理。HEAD/SEQUENCE 从原 M2 出发，CONTENT 使用 AFL 候选的内容投影，已有前后缀继续参与原执行路径。协议模型必须声明有限范围，不能据此声称覆盖完整标准。

## Git 与已落盘实现

恢复基线分支是 `feature/protocol-aware-integration-20261025`，HEAD 为 `2bdfeb1264c1b561a693481063303d05953cd016`。本地远程跟踪引用与其一致；本次未联网核验远端。远程为 `origin` / `git@github.com:gff-cw/CLOFuzz.git`。

开始恢复时有 55 个已跟踪文件修改、14 个未跟踪文件，暂存区为空。这些成果均已保留。其中包含：

- 已有 YAML/IR 编译器、schema、可填写模板、六模型、按描述目录启动流程及 BACnet 集成。
- 五个未跟踪的 `protocol_codec_*.c`、`protocol_codecs.h`、native codec 校验桥及相关 codec/runtime 测试。
- `protocol_runtime.[ch]`、`afl-fuzz.c`、Makefile、编译器/schema、六模型/IR、导出包、测试和文档的未提交修改。
- 自建 `multicodec_server.c` 与五 TCP 功能驱动。它们已写入磁盘，但最新整体集成未通过，尚未交付到该 HEAD。

最近已提交节点还包括 `d1455a1`（模板与启动流程）、`a755d53`（六个有界 profile）、`a0bb76c`（重复 BACnet 对照与描述包）、`2bdfeb1`（独立描述包核验）。不能把后续工作区修改当成已提交或已推送。

## 现有测试证据

下表是恢复时读取的既有产物，**不是本次恢复后重跑的结果**。

| 证据 | 磁盘记录 | 结论范围 |
| --- | --- | --- |
| `tests/protocol/out/multicodec-final-regression/` | 编译器 93、CLI 12、模板 14、完整性 8、Modbus/IEC codec 7、MMS 9、ENIP/OPCUA codec 6、跨 codec runtime 13、分析 10、导出 1，均有通过日志；网络日志 PASS | 各组既有离线记录；不包含五 TCP campaign 的最终验收 |
| `tests/protocol/evidence/runtime-results.json` | passed；84 loader case、250 随机 IR、25000 随机 wire；100096 基础 + 6 会话 + 29 依赖断言 | 记录的 9 个源码 SHA256 与当前磁盘匹配；不覆盖 afl-fuzz.c、fuzzer 二进制或全部集成输入 |
| `tests/protocol/out/multicodec-llvm18.log` | 七组通过终止标记 | 原 LLVM18 回归的既有结果，不替代协议集成 |
| `tests/protocol/out/multicodec-tcp-final/` | Modbus、MMS、ENIP、OPCUA 记录通过；IEC104 失败，退出码 -11 | 自建夹具结果；没有完整源码/二进制绑定，不能认证当前完整工作树 |
| `tests/protocol/out/multicodec-bacnet-regression/` | 只有 legacy 运行，退出码 1、未 ready；其余四模式没有本轮结果 | 当前 BACnet 五模式验收未完成 |
| `tests/protocol/evidence/controlled-comparison/summary.json` | 较早五模式 × 三轮，共 15 次通过 | 旧源码阶段；不能覆盖最新失败。该实验没有证明覆盖收益 |

最新失败的直接证据：

1. IEC104 `result.json` 记载测试进程 `exit_code=-11`。目标 `unique_crashes=0` 不能抵消控制进程异常退出。原始 JSONL 有 mutation 47、rejected 63；统计快照 `structured_success=0`。两者不一致，原因尚未证明；候选构造事件不等同于成功发送或目标接收。
2. BACnet legacy 的 `fuzz.log` 显示 `seed04_read_vendorname.replay` 在初始化 dry run 超过 1000 ms，`perform_dry_run()` 主动中止。尚未进入变异阶段；超时成因未定位，不能归因为结构化变异错误，也不能沿用早期通过结论。

## 未完成与未验证内容

- 上述两项失败的修复及对应完整集成验收尚未完成。
- 五 TCP codec 的工业实现互通、最新工作树的完整二进制/源码来源绑定、最终交付包一致性和提交推送尚未完成。
- 通用 when/repeat/conditional_presence、任意状态图前置路径搜索和完整多事务数据库没有实现。现有特例不代表通用能力。
- near_valid/invalid 共享单条协议长度违例策略；guard/actions 等元数据不代表表达式执行器。
- 复杂路由、分段、并行事务、长期资源增长及长期效果仍未验证。不能声称统计显著的覆盖提高。

## 本次恢复后的实际修改与验证

新增 [只读证据核验工具](../tools/audit_protocol_evidence.py)，仅读取既有 JSON/JSONL 和源码哈希，不构建或启动目标，不重放输入，不修改旧证据。工具逐项保留进程退出码、目标异常计数、候选事件、统计快照和缺失模式；成功集成记录如果缺少来源绑定，仍标为当前工作树未验证。

```bash
python3 -m unittest discover -s tests/protocol -p test_evidence_audit.py -v
python3 tools/audit_protocol_evidence.py
```

核验工具退出码：0 表示其检查范围全部通过，1 表示存在已知失败，2 表示没有已知失败但证据不完整。它不是完整项目验收器；没有源码来源绑定的历史成功不能升级为当前代码通过。恢复时的核验快照见 [recovery-audit.json](../tests/protocol/evidence/recovery-audit.json)。快照中的哈希固定本次读取的文件，不证明测试执行时使用的二进制。

本轮新增证据审计的 22 项离线测试已实际通过，覆盖损坏/重复键/非有限数 JSON、截断 JSONL、信号退出、统计冲突、子测试失败、源码过期及路径越界。测试仅使用人工临时文件，已经加入协议测试入口；本轮没有重新执行该入口中的构建和网络测试。`git diff --check` 通过。审计工具在现有产物上返回 1，表示准确保留两项已知集成失败，不是新增单元测试失败。

后续工程顺序是先解决两项失败，再完成相应集成与兼容验收，固定源码/构建/测试证据，检查导出包，最后审查提交并推送。历史源码、日志和失败记录均应保留。只有这些要求都有实际证据，才可宣称原任务完成。

本次继续实施限于离线证据核验与文档一致性；没有增强工控目标自动定向探测的运行时路径，也没有运行新的 campaign。现有描述 ZIP 保留为恢复前产物，本次文档修订不代表已经重新生成最终交付包。

## 后续五协议 YAML 静态核验

五个 TCP 描述包已有 64 条消息和 575 个字段，不存在需要重新生成的大面积空白。它们的完整性仍限于各自 scope，不能标记为覆盖整部标准。

| 描述包 | 消息 | 字段 | 语义状态 | 状态边 |
| --- | ---: | ---: | ---: | ---: |
| [Modbus TCP](../protocols/modbus_tcp/protocol_spec.yaml) | 19 | 138 | 1 | 19 |
| [IEC104](../protocols/iec60870_5_104/protocol_spec.yaml) | 11 | 62 | 6 | 17 |
| [MMS/TCP](../protocols/iec61850_mms_tcp/protocol_spec.yaml) | 14 | 136 | 9 | 14 |
| [EtherNet/IP/CIP](../protocols/ethernet_ip_cip_tcp/protocol_spec.yaml) | 10 | 132 | 4 | 10 |
| [OPC UA TCP](../protocols/opcua_tcp/protocol_spec.yaml) | 10 | 107 | 6 | 14 |

新增 [独立静态校验入口](../tools/check_protocol_descriptions.py)，不导入项目编译器、native codec 或执行器，不调用 C 编译器。检查主 YAML 与状态 YAML 的本地 schema、消息/状态/来源引用、逐字段证据覆盖、fixture 数量、scope 及保存的 validation 记录一致性。报告记录每包四个输入文件的 SHA256；这些新静态证据不能补认证旧的运行时结果。

```bash
python3 tools/check_protocol_descriptions.py
python3 -m unittest discover -s tests/protocol -p test_description_checks.py -v
```

五包静态检查均通过；21 项新增离线测试通过，见 [检查结果](../tests/protocol/evidence/five-protocol-description-checks.json) 与 [测试日志](../tests/protocol/evidence/description-check-tests.log)。没有执行 wire 解码、依赖表达式、原生构建、变异执行或网络互通检查。来源 URL 的实际内容也未重新访问；报告对 master/main/latest 等未固定链接给出提示，未臆造历史 commit 或哈希。

本轮仅修正 IEC104 三种响应共用错误说明的问题，同步对应 YAML/IR 的 notes 和生成源；协议字节与执行字段保持原值。另修正状态 schema 中把通用策略写成 BVLC 的说明，为五个目录补充最新验收状态链接。通用解码器和变异执行器没有在本轮实现或增强，前述 IEC104/BACnet 两项集成失败仍未解决。最终 ZIP 尚未重建，提交与推送尚未完成。
