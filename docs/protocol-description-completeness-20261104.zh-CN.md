# 六协议描述文件完整性复核与修订源交付

> 历史快照：本文记述执行器扩展前的静态审查。后续六套修订源已实际执行 native 生成及 C 加载，部分原缺口已扩展；最新实现、运行结果与剩余限制见[执行器扩展与本地验证](executor-extension-20261104.zh-CN.md)。本文中“未运行”等表述仅指原静态交付阶段。

日期：2026-11-04。分支：`feature/description-driven-c-engine-20261027`。源基线：`ee8e35cfcf98e8931d907e4dec697a829664c713`。三个 agent 分别审查 Modbus/IEC104、BACnet/MMS、ENIP/OPC UA，随后分别构造两套修订源输入；主 agent 整合共同 schema、静态契约、来源清单、导出和文档。

## 判断与交付范围

**原描述不能统一称为“完整协议描述”。** 原发布的71条消息都有声明服务子集内的完整示例字节；部分字段可生成范围宽于 codec、异常关联及状态边不齐、动态结构依赖硬编码解析。六份 generic-wire 合计只覆盖其中14条，五份仍为 offline-only。完整 fixture 并不表示语法、事务状态或全部标准完整。

当前用户没有另指定标准版本及更多服务清单，本轮按仓库现有六套服务子集完成可静态构造的修订。源输入位于 [protocols/reviewed](../protocols/reviewed/README.md)，各有完整 YAML 输入对、逐消息约束清单及 README。新目录不是空骨架或合并片段；所有原消息都在，Modbus 补齐各功能码异常变体。

| 修订源 | 消息（请求/响应） | 字段 | 状态/边 |
| --- | ---: | ---: | ---: |
| BACnet/IP | 7（2/5） | 66 | 2/7 |
| Modbus TCP | 26（9/17） | 180 | 1/26 |
| IEC104 | 11（5/6） | 66 | 6/23 |
| MMS | 14（7/7） | 146 | 9/14 |
| EtherNet/IP/CIP | 10（4/6） | 132 | 4/10 |
| OPC UA TCP | 10（4/6） | 107 | 6/14 |
| 合计 | 78（31/47） | 697 | 28/94 |

78是消息示例/变体数，697是字段投影数，均不代表标准或通用语法覆盖率。

本轮保留静态/编译检查约定，没有运行 compiler/native validator 或测试。因此修订源不包含新 IR、validation 或模型种子，不伪造新原生 PASS。现有 `--source-dir` 是正式校验和生成包的入口。基线发布包、生成器、codec 与历史验证记录没有被替换；新源的原生可接受性和运行效果尚待分别验收。

## 逐协议发现、修订与剩余缺口

| 协议 | 发现与已构造修订 | 仍不能只靠描述解决 |
| --- | --- | --- |
| BACnet/IP | 路由 NPDU 与响应绝对偏移不一致，state 又暗示并发 invoke。修订源准确限定 un-routed；NPDU control 与示例一致，收紧 I-Am 类型/segmentation，移除追加并发请求边；绝对响应切片明确为 fixture 投影。 | I-Am/Error 等动态标签宽度与路由响应需要语义定位器；property/index 生成范围、并发事务、其他服务未补成执行能力。此项属于范围纠正，不能声称原先路由范围已全面补齐。 |
| Modbus TCP | 读 data 允许0..4096，但 codec 有更小合法域；唯一异常 function 可变却只关联 FC03。修订为读位1..250、读寄存器2..250，按八种功能码构造固定异常响应及实际 transaction/unit 关联。 | 现场请求 quantity 与响应字节长度/末字节 padding 的算术关系、地址空间及并发事务仍不完整。FC0F partial 与普通示例的 canonical alias 需后续实际 validator 核对。 |
| IEC104 | 原 COT 为宽 uint16 且响应沿用请求注释，负确认只 copy，部分 S/TESTFR 边缺失。修订显式 COT 低字节与 originator、实际 cause/PN，正负确认关联，补 S/TESTFR 边，移除响应侧本地 sequence_number。 | 完整双向序号、k/w、计时器、监测数据 ASDU、异步控制流程和 single-pending 限制尚需执行器扩展；有图边不保证 pending 时可发送。 |
| MMS | 标识符允许空串，version/context 可变，结构树宣称多变量/一般选择，宽于实际 codec。修订 CR 目的引用、非空 domain/item、固定 version/context，新增服务 context 投影，结构限定单 domain-specific variable、VisibleString Write 及受支持的 Read Data。 | ACSI 全映射、泛化数据与服务、认证、报告、完整错误/拒绝/中止，以及通用递归 BER 执行仍未覆盖。static tree 不自动成为编码器。 |
| ENIP/CIP | Identity EPATH、Vendor-ID 长度、响应状态等声明比当前 codec 宽。修订源精确标注这些字段及每条响应约束，逐消息登记 session/context/CPF/连接前提。 | SendUnitData 仍需外部 ForwardOpen 与双向 connection IDs；一般对象、其他服务、implicit I/O、CIP Security 与完整会话未实现。 |
| OPC UA | HEL/ACK 版本和 buffer、HEL/RHE URI/URL 的声明域过宽，None/服务编码 ID 等条件分散于 codec。修订范围与现有 codec 对齐，并列全逐消息、数组和诊断深度等附加约束。 | HEL/ACK 相向 buffer 关系、token 期限/序号完整性、Session/认证/加密、多 chunk 仍不完整；CLO 保留实现 profile 与规范措辞差异。 |

Modbus 全标准还定义本 profile 未覆盖的文件记录、Mask Write、读写组合、FIFO、设备识别等服务，不能将八种功能码称为整个标准完成。[官方 V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)

OPC UA 的版本0、None buffer 至少8192及 Hello EndpointUrl 编码大小条件已与官方 [Hello](https://reference.opcfoundation.org/specs/OPC-10000-6/7.1.2.3)、[Acknowledge](https://reference.opcfoundation.org/specs/OPC-10000-6/7.1.2.4)核对；CLO 的空 body 措辞仍见[关闭连接](https://reference.opcfoundation.org/specs/OPC-10000-6/7.1.4)。修订的字节上限同时反映本项目有界 codec，不能外推为所有 UA 服务的通用大小限制。

IEC/ASHRAE/ODVA 的付费正文未在本轮取得，相关完整性以已有公开实现、固定 fixture 与本地 codec 为依据。各修订 YAML 保留来源与置信度，每包 README 列出实际参考路径；未将实现证据升级为整部标准的规范验证。

## generic-wire 还缺什么

当前原发布包的实际迁入量为 BACnet2/7、Modbus2/19、IEC104 4/11、MMS2/14、ENIP2/10、UA2/10。Modbus 修订增加7个异常变体后，已迁入量为2/26。每套 `constraints.json` 的 `generic_coverage` 完整列出已实现和缺失消息ID，没有把未迁入的消息隐藏在统计之外。

这些差距需要语言及事务实现支持：BACnet 可选路由与 LVT；Modbus 数量换算、位打包及正常/异常选择；IEC104 序号、APCI/ASDU 和异步控制；MMS session/presentation/ACSE 与递归 BER；ENIP CPF/EPATH、现场 session/connection；UA 有符号长度、NodeId、嵌套数组和会话绑定。冻结完整服务体为 fixed/opaque bytes 只能复现一份报文，不能补成上述语义。五份 offline-only 不得仅靠改 online 标志开启。

## 静态交接契约与后续使用

`constraints.json` 记录修复项、覆盖每条消息的具体约束、执行位置和剩余缺口。其 schema 为 [reviewed_description.schema.json](../protocols/schema/reviewed_description.schema.json)，是作者元数据，不是第四套在线变异语法。`manifest.json` 绑定修订源及原发布来源 SHA256、消息/字段/状态/边统计，明确原生、运行和全标准验收均未完成。

[check_reviewed_protocol_descriptions.py](../tools/check_reviewed_protocol_descriptions.py) 只读核对 schema、字段/blocks/依赖/状态引用、单 writer、预期响应后继边、状态可达、每消息约束覆盖、generic 分区和来源摘要；绝对标量及 BACnet 固定头位置还核对实际 example 字节。它不加载 codec、不执行 compiler、不证明 wire 动态解码或运行语义。导出器复用这个契约并包含六套修订源与共同依赖。

后续正式包准备步骤见[目录入口](../protocols/reviewed/README.md)。例如：

```sh
python3 tools/init_protocol_spec.py \
  --source-dir protocols/reviewed/modbus_tcp \
  --require-runtime --output-dir /tmp/reviewed-modbus-package
```

这个命令本轮没有执行。它会进行现有 compiler/native 检查，生成实际 IR/validation/模型语料；不要直接将修订源目录当作已准备好的 campaign 输入。之后才分别验证实际目标的请求/响应、事务绑定、消息边界、内存状态与固定预算的方法对照。

本轮实际完成的是直接库 schema/数据检查、静态源码复核及文件构造；未 import/执行项目模块或回归测试。新增回归源码接入 protocol runner，覆盖来源漂移、虚假运行声明、重复状态边和约束漏覆盖，实际执行仍待后续验收。

| 实际静态检查 | 结果 |
| --- | --- |
| 12份 YAML 输入与6份约束清单 | 共18份通过直接 JSON Schema 库检查；字段/blocks/依赖/状态与逐消息约束引用一致 |
| 报文来源 | 原71条 example 字节保留；7条新增 Modbus 异常结构与固定功能码对应 |
| 可直接定位的标量 | 552个绝对位置及 BACnet 固定头标量与 example 范围一致 |
| YAML 可编辑性 | 六对源无 YAML alias；BACnet/MMS 的字段与结构树独立展开，ReadProperty NPDU control=4，其他六条 BACnet 消息为0 |
| 共同入口与导出 | 4个新增/修改 Python 源 AST 通过；49个显式导出文件存在，本地文档链接可达 |
| 差异与 runner | git diff --check、protocol runner 的 bash -n 通过；未运行 runner |

逐协议静态摘要与差异路径记录位于被忽略的 `tests/protocol/out/description-review-20261104/` 本地目录，不随源提交发布。没有把这些静态结果写成 native validation 或目标会话 PASS。
