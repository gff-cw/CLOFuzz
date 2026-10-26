# 六协议描述文件完整性与正确性审查

审查日期：2026-10-25。这里的“完整”是**明确列出的 profile 中，一条报文的所有层和服务体都存在**，且配套请求、响应、动态结构、依赖及状态都有说明。它不代表完整覆盖 ASHRAE 135、IEC 60870/61850、ISO 9506、ODVA 或整个 OPC UA 标准。字段数是声明的字段/投影数量，不是标准覆盖率；嵌套字段由 `structure_model` 树补充。

每种协议目录均含 `protocol_spec.yaml`、`state_transition.yaml`、可重现 JSON IR、`evidence.yaml`、`validation.json` 和完整请求的 replay seeds。`fixture_status=complete` 描述 fixture 完整性；`runtime_encode` 是已有 C 编码能力的断言。静态树、文字条件、状态 guard/actions 不会自动变成解析器或状态执行代码。

## 完成度矩阵

| 协议与明确 profile | 规范/实现依据及核验限度 | 请求 / 响应；字段 | 动态结构与依赖 | 状态与运行等级 |
|---|---|---:|---|---|
| BACnet/IP：Original-Unicast-NPDU、可选路由地址、Who-Is/I-Am、ReadProperty ACK/Error、Reject/server Abort | [ASHRAE 官方范围](https://www.ashrae.org/technical-resources/bookstore/bacnet)仅确认标准身份；wire 根据本地 BACnet Stack 1.5.0 的 `npdu/bacdcode/rp/iam/bacerror/reject/abort` 实现；未取得付费全文 | 2 / 5；66 | NPDU 目的/源地址和 hop count；Who-Is 同时存在的上下限；RP 可选数组索引；应用标签及成对 opening/closing；BVLC 长度和 invoke 相关 | 2 个粗粒度状态；**唯一 StateAFL 实际目标**。C 只编码 Who-Is/RP 请求，5 种响应为完整静态布局，I-Am 为 wire 上的非确认服务请求 |
| Modbus TCP：FC01–06、0F、10，各正常响应与通用异常；含 9-coil padding 样例 | [官方 V1.1b3 §§4、6.1–6.6、6.11–6.12、7](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)，由[官方索引](https://www.modbus.org/modbus-specifications)核对版本；不含 RTU CRC | 9 / 10；138 | MBAP 长度；coil 位打包与寄存器数组；byte-count；写响应回显地址和值/数量；transaction/unit 相关；异常功能码为请求码 OR 0x80 | TCP 连接内独立 MBAP 事务，1 状态；**静态完整 profile，无 C encoder、无 StateAFL 目标验证** |
| IEC104：I/S/U、STARTDT/STOPDT/TESTFR、单对象 C_IC_NA_1 激活/正负确认/终止，COT/CA/IOA=2/2/3 | [IEC 官方目录](https://webstore.iec.ch/en/publication/25035)仅确认版本；wire 和连接行为查 [lib60870](https://github.com/mz-automation/lib60870/blob/master/lib60870-C/src/iec60870/cs104/cs104_connection.c)；付费全文未核验 | 5 / 6；62 | APCI 长度；双向独立 15-bit 序号左移；SQ=0/count=1、IOA=0、QOI 20–36；CA/QOI 回显；P/N 负确认位 | 6 状态，激活确认后才 active，查询确认/终止分别迁移，TESTFR 独立；**静态完整 profile，无 C encoder/目标验证** |
| IEC61850 MMS/TCP：TP0、session/presentation 正常模式、ACSE association+内嵌 initiate、VMD domain GetNameList、一个 domain-specific named-variable Read/Write、conclude 与 release | [RFC1006 §6](https://www.rfc-editor.org/rfc/rfc1006)仅支持传输层；MMS/ACSE 等来自固定 [libIEC61850 revision](https://github.com/mz-automation/libiec61850/tree/6d231326bff8e9b6500aa1e345c076d3a329f211/src/mms)及其 ASN.1 定义；IEC/ISO 付费文本未核验 | 7 / 7；136 | 完整 TPKT/COTP→session→presentation→ACSE/MMS；BER definite lengths、context IDs、嵌入 Initiate、invoke、命名变量访问、MMS Data/results choice、bit-string padding | 9 状态；CR 等待 CC、AARQ 等待 accepted AARE+initiate，conclude 与 association release 分开；**静态完整 profile，无 C encoder**。仅参考实现本地交换用于构造 fixture，不算 StateAFL 集成 |
| EtherNet/IP/CIP：RegisterSession、UnregisterSession、SendRRData+NullAddress/UnconnectedData、SendUnitData+ConnectedAddress/ConnectedData、Identity Vendor-ID GetAttributeSingle 成功/错误与 encapsulation 错误 | [ODVA 官方目录](https://www.odva.org/subscriptions-services/specifications/)确认订阅边界；wire 以 [固定 OpENer revision](https://github.com/EIPStackGroup/OpENer/tree/d8820ef41ce30dda06d213438ba81c81de33ffe2/source/src)的 encap/CPF/ConnectionManager/class3 实现核验；未核验订阅卷全文 | 4 / 6；132 | assigned session、Sender Context；CPF item count=2、每项 length；ConnectedAddress 的双向 connection IDs；ConnectedData 首 UInt16 sequence（响应回显）；EPATH word count；响应服务位、general status、附加状态 UInt16 word count 与数据 | 4 状态；成功 RegisterSession **响应后**才 registered，失败回 connected，Unregister 不等待响应；**静态完整 explicit-message profile，无 C encoder/目标验证**。SendUnitData 另要求外部成功 ForwardOpen 建立 class-3；此状态不意味着已建连 |
| OPC UA TCP：HEL/ACK/ERR/RHE、None 单 final chunk、Issue OPN 双向、GetEndpoints 双向/ServiceFault、实现 profile CLO | [Part6](https://reference.opcfoundation.org/specs/OPC-10000-6/full)、[Part4 Discovery](https://reference.opcfoundation.org/specs/OPC-10000-4/5.5.1)、[官方 NodeIds](https://raw.githubusercontent.com/OPCFoundation/UA-Nodeset/latest/Schema/NodeIds.csv)；服务 fixture 与固定 [asyncua revision](https://github.com/FreeOpcUa/opcua-asyncio/tree/c321a240e53d083fd6e167c67f795915d8f236fd/asyncua/ua)完整解码/重编码一致；CLO 有下述规范措辞差异 | 4 / 6；107 | signed Int32 长度的 String/ByteString/数组、NodeId、完整 RequestHeader/ResponseHeader、OPN security/token、EndpointDescription→ApplicationDescription/UserTokenPolicy 数组；channel/token 绑定、双向 sequence、request ID/handle 相关 | 6 状态；HEL→ACK→OPN pending→OPN success；channel 不等于 activated Session。GetEndpoints 无需 Session；**静态完整 profile，无 C encoder/网络目标验证** |

合计 **71 条完整 fixture，641 个字段，31 条请求和 40 条响应**。所有静态协议仍为 `support.runtime=false`。71 是明确 profile 中的消息变体数量，不是声称实现了六部标准。

## 已修正的实质问题

- **MMS 原 fixture 不能作为有效 MMS wire 消息。** TPKT/COTP 后直接放 ACSE/MMS BER，没有 session/presentation 包装；Read/Write 体也不完整。现在 association 含 CONNECT/ACCEPT、CP/CPA、AARQ/AARE 和 EXTERNAL 内的 Initiate。删除伪独立 `initiate.replay`。GetNameList、Read、Write、conclude、ACSE release 都使用完整双向消息，conclude 与 release 不再混同。
- **OPC UA 原 OPN/MSG/CLO 只有头或编码 NodeId。** 现在提供完整服务体，二进制编码 ID 为 OPN request/response 446/449、GetEndpoints 428/431、ServiceFault 397、CLO 452。None 模式的证书、thumbprint、nonce 用 null ByteString。RHE 的发送方修为 server，不能把它当已建立 secure channel。没有把 OpenSecureChannel 成功写成 Session 已激活。
- **CLO 的证据级别保留限制。** [Part6 §7.1.4](https://reference.opcfoundation.org/specs/OPC-10000-6/7.1.4)描述空 body，asyncua 的对应实现发送编码 ID 452 和完整 RequestHeader。当前 fixture 是后者的完整**实现 profile**，字段标 `implementation`，没有声称解决该措辞差异或取得正式规范一致性；CLO 无响应。
- **EtherNet/IP 原状态过早 registered，且 SendUnitData 缺少 ForwardOpen。** 现在有独立 registering 状态、成功/失败响应、context/session 依赖、正常和错误 SendRRData 响应。CPF count 和每个 item length 按实际消息独立检查。保留完整 `send_unit.replay` 和匹配响应；它们含 0xA1 ConnectedAddress 与 0xB1 ConnectedData，后者先放 UInt16 sequence，再放完整 CIP 服务。发送前必须由外部 ForwardOpen 在同一 session 建立尚未超时的 class-3 连接并提供 O→T consumed / T→O produced IDs；RegisterSession 不能提供或替代这些 IDs。状态边只记录外部前提，没有伪造可自动到达的 class-3 建连状态。Unregister 无返回消息。
- **Modbus FC0F 原来把 quantity 反推为 `8*data_length`。** 这无法表示 9 个 coil。现在数量独立，字节数为 `ceil(quantity/8)`，末字节未使用高位须为零；新增 9-coil 请求及对应回显响应。FC10 仍是每寄存器两字节。正常读响应覆盖 FC01/02/03/04；写响应只回显地址和值/数量；异常没有 byte-count。
- **BACnet 原 ACK 字符串不完整。** 原 `75 00` 没有 CharacterString 的编码字节；现在 ObjectName 是含 encoding=0 的完整 `Device` 字符串。RP 的 NPDU expecting-reply 位修为 1。补充完整 I-Am、RP Error、Reject 和 server Abort；Reject/Abort 最后一个字节是 reason，不是 service choice。保留仅 Who-Is/RP 请求具有 runtime encoder 的真实限制。
- **IEC104 补齐查询生命周期。** 除 U 控制确认外，补充 interrogation 正/负激活确认和终止；负确认使用 P/N 位。确认与终止示例的服务端 N(S) 分别为 0、1（wire 0、2），N(R)=1（wire 2）。收到确认之后才进入查询数据阶段，收到终止才完成。查询期间的数据 ASDU 类型仍被排除。

## fixture 来源与检查方法

MMS fixture 来自临时构建的 libIEC61850 `6d231326bff8e9b6500aa1e345c076d3a329f211`。在 `127.0.0.1` 上使用 basic-IO 示例服务与 MMS 客户端，通过本地转发器按 TPKT 长度保存两方向记录。调用 connect、getDomainNames、readVariable、writeVariable、conclude 均返回 `MmsError=0`；变量为 `simpleIOGenericIO/GGIO1$DC$NamPlt$vendor`，写值 `audit`。固定 bytes 保存在 generator 的 `MMS_FIXTURES`，重新生成不需要外部服务。该实验仅证明这组参考实现消息的构造与往返，不证明 StateAFL 已为 MMS 实现变异/状态反馈或支持其他设备。

OPC UA fixtures 以标准库结构编码重现，固定时间为 `2026-10-25T00:00:00Z`；同一组服务体曾被固定 asyncua revision 解码耗尽并逐字节重编码。HEL endpoint 是本地示例 URL；OPN response 中 channel/token=1 是说明值，新连接必须使用对端分配值。没有对 OPC UA 服务发网络请求。

SendUnitData 对照 [固定 CPF 实现](https://github.com/EIPStackGroup/OpENer/blob/d8820ef41ce30dda06d213438ba81c81de33ffe2/source/src/enet_encap/cpf.c)的 `NotifyConnectedCommonPacketFormat` / `AssembleLinearMessage`：接收连接 ID 查 established connection，数据项先读 UInt16 sequence，响应改用 produced connection ID 并回显 sequence。ConnectionManager 的 `GetConnectedObject` 仅接受 established 且 consumed ID 匹配的连接；`EstablishClass3Connection` 才分配 explicit slot。也核对了 ConnectionManager 的普通 ForwardOpen command-specific header 长度 36 bytes 和成功响应中的 consumed/produced IDs；没有充分验证全部 ForwardOpen 参数/变体，因此不生成或声称完整支持 ForwardOpen。当前双向 fixture IDs `0x10000001` / `0x20000001` 是说明值，必须被外部协商结果替换；fixture 从未在 ENIP 服务上实际执行。对应来源为 [ConnectionManager](https://github.com/EIPStackGroup/OpENer/blob/d8820ef41ce30dda06d213438ba81c81de33ffe2/source/src/cip/cipconnectionmanager.c) 和 [class3](https://github.com/EIPStackGroup/OpENer/blob/d8820ef41ce30dda06d213438ba81c81de33ffe2/source/src/cip/cipclass3connection.c)。

`tests/protocol/test_model_completeness.py` 独立实现了有界结构读取器，检查：

1. BACnet NPDU、LVT/tag 容器、I-Am 四参数、ACK 字符串 encoding octet、Error/Reject/Abort 布局。
2. Modbus 功能码长度、数量范围、packed-coil padding、寄存器字节数及写回显/异常布局。
3. IEC104 I/S/U 长度、低位、序号编码和单对象 C_IC_NA_1 cause/IOA/QOI。
4. MMS COTP 参数、session 参数长度、所有 BER constructed 子树、presentation context、AARE/Initiate、变量名、服务结果、conclude/release；读取完整外层与服务体。
5. EtherNet/IP header、成功/失败注册、CPF 数量、每项长度和消费位置、CIP EPATH 与响应状态尺寸，以及 SendUnitData 的 4-byte connection ID、2-byte sequence、双向 IDs 和外部建连前提。
6. OPC UA 传输 Strings、OPN asymmetric 与 MSG/CLO symmetric header、服务编码 ID、完整请求/响应头、null nonce、token、嵌套 endpoint 数组，且消费所有字节。

测试还会破坏内部长度/计数而保持外层长度不变，证明检查不限于 envelope；单独检查 9-coil padding、请求的回复/无回复声明、仅两个 BACnet 请求可编码、响应驱动的建连状态，并在临时目录重新生成全部协议目录逐字节比较。

```sh
python3 tools/generate_protocol_models.py
python3 tests/protocol/test_model_completeness.py
python3 tests/protocol/test_compiler.py
```

编译器报告的 `validated=true` 主要是 schema、依赖/状态引用、报文 envelope 与 BACnet runtime 子集检查；**不能用该布尔值代替上述深层 fixture 测试或正式产品一致性测试**。

## 尚未覆盖或不能据此证明的事项

- BACnet 分段、BACnet/SC、BBMD/foreign-device 和其他服务不在范围。RP property/array 的 wire 可读 1–4 字节，但当前 runtime 字段变异用 UInt8，不能声称生成所有 property/index。两个 semantic states 是 C 当前的粗粒度序列模型；不能表达多个并发 invoke 的完整事务状态，也不会执行文字 guards/actions。
- Modbus 其他功能码、厂商地址空间语义和异常选择策略未实现；通用异常 fixture 以 FC03 为例，结构说明适用于列出的函数。
- IEC104 其他 ASDU、连续/多对象数据、完整窗口/定时器和 TLS 未实现。激活确认与终止之间可出现数据 ASDUs；本 profile 不描述那些数据类型。
- MMS 的 ACSI 全映射、报告、GOOSE/SV、泛化 alternate access/数组、数据集、认证/TLS，以及完整 association reject/abort、confirmedError/reject fixture 未核验。RFC1006 只为传输层提供规范依据，不能外推为 MMS 全规范已核验。
- EtherNet/IP SendUnitData 报文布局已覆盖，但 ForwardOpen/ForwardClose fixture 与自动 class-3 建连不在本 profile；implicit I/O、CIP Security、其他对象/服务、ODVA 全规范未实现/核验。
- OPC UA signing/encryption、Renew、token overlap、Session 创建/激活与认证服务、多 chunk/reassembly 均被排除。独立 decoder 是这组 fixture 的有界 checker，不是通用协议实现。
- 除 BACnet 外没有 StateAFL 实际目标的集成测试。静态描述、参考实现构造、结构读取器、StateAFL runtime 集成、正式标准符合性是不同证据，不能相互替代。
