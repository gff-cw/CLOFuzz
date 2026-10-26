# 资料来源与证据边界

协议字段的可审计映射保存在每个 `protocols/<protocol>/evidence.yaml`，对应源描述的 `sources`、字段 `evidence` 和 `confidence`。以下索引区分协议标准、公开实现和本项目新设计；访问日期为 2026-10-25。来源存在不意味着本项目实现了整个标准。

## 方法和 Boofuzz

本地方法材料是工作区的 [`project/project.md`](../../project/project.md)。其中 Figure 3 描述 request → HEAD/CONTENT → primitive，Figure 4 描述消息连接与前置序列，Figure 5 描述解释器输出消息实体和消息状态序列。材料还描述 HEAD/CONTENT/SEQUENCE、内部/跨消息依赖、临时缓存，以及使用 AFL 变异内容。论文未披露完整语法、缓存结构、权重公式和通用修复算法；本次实现对此作出的具体工程选择不能写成论文已经提供的代码。本文引用的是本地方法整理及随附图，不声称重新获取了论文原文或原仓库。

官方 [Boofuzz Protocol Definition](https://boofuzz.readthedocs.io/en/stable/user/protocol-definition.html) 说明 Request、Block、Primitive 的组织关系，并列出 Static、String、Delim、Size、Checksum 等对象。[Boofuzz Quickstart](https://boofuzz.readthedocs.io/en/stable/user/quickstart.html) 展示用 Session.connect 建立消息图和发送前置请求。这些是结构与会话图设计的参考；ICP-IR 使用受 schema 约束的 YAML/JSON，不导入或兼容执行 Boofuzz Python 文件。

ICP-IR 名称、JSON schema、固定白名单依赖、资源上限、编译 IR、C runtime、独立语义命名空间、五种模式、SEQUENCE 删除/重复/交换、日志格式均为本次工程设计。`near_valid` 和 `invalid` 当前共享同一种单点 BVLC 长度违例，不能归因于论文提出了两种已实现的不同算法。

## 六种协议

| 协议 | 标准/官方公开资料 | 实际字段依据与限制 |
| --- | --- | --- |
| BACnet/IP | [ASHRAE 标准目录](https://www.ashrae.org/technical-resources/standards-and-guidelines/titles-purposes-and-scopes)，用于确认 ASHRAE 135 身份 | [BACnet Stack 1.5.0](https://github.com/bacnet-stack/bacnet-stack/tree/bacnet-stack-1.5.0)，本地 `npdu.c`、`bacdcode.c`、`rp.c`、`datalink/bvlc.c` 和 server；未访问 ASHRAE 完整付费正文，因此相关字段标 implementation |
| Modbus TCP | [官方 Application Protocol V1.1b3 PDF](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)，应用数据及功能码章节 | [libmodbus](https://github.com/stephane/libmodbus/blob/master/src/modbus.c) 及 `modbus-tcp.c` 补充 MBAP/实现布局；规范字段和实现补充字段分别标注 |
| IEC 60870-5-104 | [IEC 目录项](https://webstore.iec.ch/en/publication/25035)，用于标准身份/版本 | [lib60870 cs104_connection.c](https://github.com/mz-automation/lib60870/blob/master/lib60870-C/src/iec60870/cs104/cs104_connection.c) 的 APCI、参数宽度、序号及确认流程；完整 IEC 付费正文未访问 |
| IEC 61850 MMS/TCP | [RFC 1006](https://www.rfc-editor.org/rfc/rfc1006) 第 6 节支撑 TPKT；[IEC 61850-8-1 目录](https://webstore.iec.ch/en/publication/6021) 仅用于范围标识 | [libiec61850 MMS/ISO 实现](https://github.com/mz-automation/libiec61850/tree/master/src/mms) 的 ASN.1、ACSE、presentation 代码；不声称完整 IEC/ISO 规范已核验，本轮已补14条完整session/presentation/ACSE/MMS消息，参考实现revision和原始records归档 |
| EtherNet/IP CIP/TCP | [ODVA 规范目录及订阅边界](https://www.odva.org/subscriptions-services/specifications/) | [OpENer Encapsulation 实现](https://github.com/EIPStackGroup/OpENer/blob/master/source/src/enet_encap/encap.c)、CPF 和 EPATH 解析；未访问订阅规范，不将目录当作线格式规范证据 |
| OPC UA TCP | [OPC Foundation Part 6: Mappings](https://reference.opcfoundation.org/specs/OPC-10000-6)，UA Binary、UASC 和 UACP；本模型声明 v1.05 范围 | 官方在线正文是规范依据；公开入口当前列出 1.05.07。描述限 SecurityPolicy None、传输/安全会话头和 NodeId，已补None模式完整OPN/GetEndpoints/ServiceFault及实现profile的CLO服务体；不含CreateSession/ActivateSession或认证 |

每个模型的 `scope`、`support.excluded` 和字段级 confidence 比此汇总表更具体。`normative` 表示字段依据公开规范，`implementation` 表示依据公开实现或实现交叉验证，`inferred` 表示范围/结构推断。目录只能证明标准身份，不能单独证明字段位宽、枚举或状态行为。部分实现链接指向 `master`，不是可复现的固定 revision；后续修订应补不可变 commit 链接，现有本地 BACnet 构建已单独保存源码版本及 SHA-256。

## 仓库中的可复查证据

| 证据 | 可以支持的结论 |
| --- | --- |
| [compiler-tests.log](../tests/protocol/evidence/compiler-tests.log) | 当次 51 个编译器测试通过；六组源描述可确定性重编译；覆盖重复 ID、类型/范围、引用、环、YAML 拒绝等 |
| [runtime-results.json](../tests/protocol/evidence/runtime-results.json) | 当次独立 C runtime 的 sanitizer、随机输入、IR 拒绝及会话测试；具体范围和源哈希在文件内 |
| [BACnet 构建元数据](../tests/protocol/evidence/new-build/build-metadata.json) | 独立 Debug/IPv4 BACnet/IP 构建，工具版本、源码 revision、二进制及输入哈希 |
| [正常通信结果](../tests/protocol/evidence/new-build/communication.json) | 正常 Who-Is/ReadProperty 及范围排除/unknown-object 行为；不等价于 fuzz campaign |
| [本次 LLVM18 回归](../tests/protocol/evidence/llvm18-regression-driver.log) | 当前七组 LLVM 18 回归通过，包含内存 SHM/校准和有界网络测试；原始详细结果在 `tests/llvm18/out/protocol-integration-regression` |
| [LLVM18 测试报告](../LLVM18_TEST_REPORT.md) | 既有 LLVM 18 移植和内存状态反馈证据；应与本次运行结果分别报告 |

`validation.json` 的 `validated: true` 仅说明编译器检查通过。独立 parser 的随机测试不能证明网络互通，网络互通不能证明模糊测试持续执行或有内存状态反馈，短 campaign 未崩溃也不能证明协议实现无缺陷。最终验收须同时保留实际命令、产物、时间、退出状态和对应代码版本。


本轮协议完整性与来源核验的详细更新见 [protocol-model-audit.md](protocol-model-audit.md)。旧Modbus PDF路径实测404，已改为官方可访问的 `file/secure/modbusprotocolspecification.pdf`。MMS/OPCUA原不完整片段已由完整profile替换，原始参考构造records及独立解码结果保存在 `tests/protocol/evidence/reference-fixtures/`，不再将旧片段作为当前完整性证据。
