# 六协议描述与 C 执行能力核验

本次核验以 `7b0e7ae` 后的源码和六套描述为基线，重新运行了描述检查与完整性回归。
结论是：六套文件在已声明的有限 profile 内具有完整报文示例、字段、依赖、状态和
证据清单，可以由现有六种 C codec 消费。它们不覆盖六部完整工业协议标准，也不能
直接作为通用 C 布局解释器的输入。具有请求 encoder 不代表每个标为可变的容器都
有对应写入能力；当前仍有明确拒绝的容器和未执行的状态文字条件。

本文件记录描述和 codec 契约侧证据。当前在线反馈接口、实际集成运行和覆盖位图的
核验见 [在线集成记录](online-directed-integration.md)。本次模型验证没有启动真实
工业目标服务，不能据此宣称工业设备互通或覆盖率已经提高。

## 六协议完成度矩阵

字段数量是模型投影数量；模型状态数量不是 StateAFL 实测内存状态数量。

| 模型 | 消息（请求/响应） / 字段 / 状态 / 边 | 声明 profile 内的能力 | 主要不足及扩展边界 |
| --- | --- | --- | --- |
| [BACnet/IP](../protocols/bacnet_ip/protocol_spec.yaml) | 7（2/5） / 66 / 2 / 8 | 完整 BVLC/NPDU；Who-Is/I-Am、ReadProperty 请求/ACK/Error、Reject/server-Abort。C 请求生成限 Who-Is 与 ReadProperty；可定位动态路由地址和标签，修复 BVLC 长度，关联 invoke。 | 未实现分段 APDU、BBMD/Foreign Device、BACnet/SC 及其他服务的在线编码。I-Am 在本模型按对端返回分类，不因此改变其 wire 上的未确认服务性质。 |
| [Modbus TCP](../protocols/modbus_tcp/protocol_spec.yaml) | 19（9/10） / 138 / 1 / 19 | MBAP，FC01–06/0F/10 正常请求响应和异常；packed coils、9-coil padding、寄存器数据、长度/byte-count、回显和 transaction/unit 关联。 | 不含 RTU、file-record/diagnostic 等其他功能族。异常 fixture 以 FC03 为例，关联只引用 `read_holding`，不能视为所有功能码异常关联均已建模。单状态模型不描述完整并行事务数据库或厂商地址语义。 |
| [IEC60870-5-104](../protocols/iec60870_5_104/protocol_spec.yaml) | 11（5/6） / 62 / 6 / 17 | I/S/U；STARTDT/STOPDT/TESTFR；COT/CA/IOA 宽度为 2/2/3 的单对象 C_IC_NA_1 请求、正/负激活确认和终止；APCI 长度、序号字段及服务类别可检验。 | 其他数据 ASDU、多对象生成、完整双向窗口/定时器和 TLS 不在范围。总召唤中的真实数据阶段可含未建模 ASDU。START/STOP/TEST 控制报文没有 HEAD/CONTENT 可变叶，适合序列层操作；不能把整包 encoder 声明解释为每层都有候选。 |
| [IEC61850 MMS/TCP](../protocols/iec61850_mms_tcp/protocol_spec.yaml) | 14（7/7） / 136 / 9 / 14 | 完整 TPKT/COTP TP0、session/presentation、ACSE AARQ/AARE 内嵌 MMS initiate；VMD domain GetNameList、一个 domain-specific variable 的 Read/Write、conclude 和 release。C 支持已声明 BER 叶字段替换并重算祖先长度。 | ACSI 全映射、报告、GOOSE/SV、通用数组/alternate access、数据集、认证/TLS 未实现；拒绝/abort/confirmed-error/reject fixture 未核验。`session`/`pdu` 容器虽可检查，不具有任意重编码能力。 |
| [EtherNet/IP CIP](../protocols/ethernet_ip_cip_tcp/protocol_spec.yaml) | 10（4/6） / 132 / 4 / 10 | Register/Unregister、SendRRData、SendUnitData，CPF item 长度/数量、Identity Vendor-ID GetAttributeSingle、EPATH、session/context、class-3 UInt16 sequence 与错误响应。 | SendUnitData 依赖同 session 上外部成功的 ForwardOpen 和双向 connection ID，模型没有实现该建连过程。ForwardClose、implicit UDP I/O、其他 CIP 对象/服务和 CIP Security 不在范围。`cip` 容器整体替换被拒绝。 |
| [OPC UA TCP](../protocols/opcua_tcp/protocol_spec.yaml) | 10（4/6） / 107 / 6 / 14 | HEL/ACK/ERR/RHE、SecurityPolicy None、单 final chunk、Issue OPN、GetEndpoints/ServiceFault 与实现 profile CLO；完整 UA Binary header、String/ByteString/NodeId/Endpoint 数组，channel/token/request 关联。 | 不含签名/加密、Renew/token overlap、CreateSession/ActivateSession、认证服务和多 chunk 重组。完整 `body` 容器整体替换被拒绝；CLO 的规范措辞与实现 profile 差异仍未解决。 |

合计 **71 个完整 fixture、641 个字段声明、31 个请求、40 个响应、28 个模型状态和
82 条边**。全部31个请求声明 `runtime_encode=true`；40个响应用于验证、关联和缓存，
不是响应端变异器。声明及测试通过均不代表覆盖了标准中全部消息和状态。

## 来源质量与模型一致性

| 协议 | 来源的实际证据级别 |
| --- | --- |
| BACnet/IP | wire 来自 BACnet Stack 1.5.0 的固定 tag；ASHRAE 页面只确认标准身份/范围，未读取付费标准全文。 |
| Modbus TCP | 标明公开 V1.1b3 规范章节；部分实现 URL 指向移动分支。 |
| IEC104 | IEC 目录确认版本，wire/连接行为来自 lib60870；未读取付费全文，部分实现 URL 指向移动分支。 |
| MMS | 固定 libIEC61850 commit 与 ASN.1 定义，历史 fixture 来自参考实现成功交换；RFC1006 只为传输层提供规范依据，不能作为 MMS 全规范证明。 |
| EtherNet/IP CIP | 固定 OpENer commit；ODVA 官方目录只确认订阅边界，不能代替订阅卷全文核验。 |
| OPC UA TCP | Part4/6 公共规范、NodeIds 和固定 asyncua commit；NodeIds `latest` URL 可变，CLO 差异显式保留。 |

本次未重新访问这些来源 URL；上述证据级别来自模型自身的 `sources`、`evidence.yaml`
与已有 [逐协议审查](protocol-model-audit.md)。六个保存的 `validation.json` 都未用
源文件哈希绑定全部 YAML 输入；本次静态 checker 实际计算了输入 SHA256。Modbus、
IEC104 和 OPC UA 仍存在指向移动分支的来源警告。要支持可重复审计，应同时保存
描述/IR/codec/二进制哈希和运行日志，而不是只依赖 `validated=true`。

## 已实际执行的验证

本次用户明确要求继续验证，覆盖先前 `AGENTS.md` 中的暂缓测试约定。以下检查
确实重新执行，而不是仅复述历史通过记录。

```bash
python3 tools/check_protocol_descriptions.py \
  --spec-dir protocols/bacnet_ip \
  --spec-dir protocols/modbus_tcp \
  --spec-dir protocols/iec60870_5_104 \
  --spec-dir protocols/iec61850_mms_tcp \
  --spec-dir protocols/ethernet_ip_cip_tcp \
  --spec-dir protocols/opcua_tcp
python3 tests/protocol/test_model_completeness.py
```

第一条命令退出码为0，六包全部 `passed`：检查 YAML schema、消息/状态/来源引用、
逐字段证据覆盖、fixture 计数，以及 `evidence.yaml` 与保存 validation 的一致性。
它不构建 native codec，不证明 wire 或依赖执行正确；默认命令只选五个 TCP profile，
本次显式加入 BACnet/IP。

第二条命令退出码为0，8项全部通过，运行时间约34.8秒：

| 已通过检查 | 验证对象 |
| --- | --- |
| `test_all_declared_complete_fixtures_decode_without_trailing_bytes` | 六模型的完整 fixture 被各协议有界独立 reader 解码且无尾随字节；同时执行模型语义校验。 |
| `test_complete_request_profiles_have_runtime_encoders` | 31条完整请求的请求方向、runtime 支持与 encoder 声明一致；不是每个字段可写的动态证明。 |
| `test_connected_enip_has_directional_ids_and_external_forward_open_precondition` | SendUnitData 双向 ID、连接序号和显式外部 ForwardOpen 前提；没有伪造建连依赖。 |
| `test_deep_checks_reject_corrupt_inner_lengths_and_counts` | 选定的内层长度、计数、padding/内容破坏会被独立 checker 拒绝。 |
| `test_partial_coil_quantity_and_padding` | 9-coil 正常样例及非法尾字节高位拒绝。 |
| `test_regeneration_preserves_all_committed_model_artifacts` | 在临时目录重新生成六个包，逐字节比较已提交模型、证据和 seed 内容。 |
| `test_requests_declare_a_reply_or_document_no_reply` | 请求声明响应，或明确属于 S ACK、Unregister、CLO 等无回复操作。 |
| `test_response_driven_connection_states` | ENIP、MMS、OPC UA 的成功响应前先进入 pending 状态，成功响应后才进入 established 状态。 |

该完整性回归会通过 `proto_spec_compiler.validate()` 调用
[native_protocol_codecs.py](../tools/native_protocol_codecs.py)，在私有临时目录编译五种
C codec 的共享库，实际调用 C validator/locator。不能将这8项结果描述成“未编译、
仅静态检查”。Python 在此负责离线模型校验、独立 reader 和测试编排；在线变异器
没有使用 Python。模型重现检查将 generator 输出定向到临时目录，没有覆盖工作区
协议文件；本子任务未修改任何协议 YAML、IR、seed、codec 或历史证据。

## 通用 C 解释器与在线 C 执行器是两种接口

| 组件 | 可执行输入与实际职责 | 与在线变异的关系 |
| --- | --- | --- |
| `native_json.c` / `native_layout.c` | 解释 `stateafl.offline-layout` JSON，执行有界布局读取和约束检查，支持本地文件与只读内存 buffer。 | 通过 `native_layout_inspect*` 输出检查结果；不提供通用 encoder 或变异 API。 |
| `native_observation.c` | 校验并报告已有协议/内存状态观测及共同边界声明。 | 不把状态 YAML 直接转换为真实运行的协议状态机或反馈学习器。 |
| `protocol_runtime.c` | 一次加载 `protocol_ir.json`/`state_ir.json`，解释字段/依赖/状态边，并调用六种 codec 实际变异、修复、序列化、绑定和响应分帧。 | 生产在线执行器，`proto_mutate`、`proto_before_send`、`proto_after_response` 都是 C。 |
| `protocol_codec_*.c` 与 runtime 内 BACnet codec | 协议特定 envelope、字段 locator、可编码叶、长度修复与帧边界。 | 现有“通用”能力是统一 IR/API 上的六 codec 分派，不是任意协议仅填 JSON 就获得 encoder。 |
| `protocol_schedule.c` | 在原 StateAFL 选中状态上下文内学习层选择；与协议语义节点分开。 | C 调度模块；是否实测提高覆盖，要看执行/位图和对照实验，不能由源码存在推断。 |

六套 YAML 的 `format_version/protocol_id/codec/messages` 与通用 native layout 的
`format/version/root` 不是同一格式；改扩展名或转换 YAML 为 JSON 不会补上编码语义。
`structure_model`、状态 `guard/actions`、依赖 `scope/when` 和 `invalid_strategy`
仍有静态元数据边界。通用 when/repeat/conditional_presence 没有被统一执行；精确
Modbus data/count repeat 与 MMS tagged_length 是 codec 管理特例。

## 实际存在的三级 C 变异策略

| 层级 | C 中的输入、选择与操作 | 修复与拒绝边界 |
| --- | --- | --- |
| HEAD | 选择请求中的可变 HEAD 标量；按声明策略做枚举、边界、bitflip 或算术变化。消息 weight 参与记录选择。 | 固定/派生字段不直接乱写；约束、编码宽度、消息类别和全序列检查必须通过。MMS BER INTEGER 变化可重编码宽度。没有 HEAD 叶的报文不能凭 encoder 声明生成 HEAD 变异。 |
| CONTENT | 使用原 AFL C 算子生成的 wire candidate，按原请求/字段偏移投影到声明 CONTENT 标量或受支持 codec 叶。可变字符串/bytes/EPATH 在明确支持范围内 resize。 | 不把 replay 长度前缀当内容，不将下个请求吞为本请求插入内容；修复父长度/计数与结构。MMS 整个 BER 容器、ENIP opaque CIP、OPC UA 整个 body 等未支持替换被明确拒绝。 |
| SEQUENCE | 对选中的 M2 请求序列作有界插入、删除、重复、重排；插入使用模型完整请求模板。保留 StateAFL 选择的 M1/M3。 | 检查最大消息数、重复数、序列字节预算与声明语义边。已有 M1 仅提供预测语义起点，不自动搜索任意 preamble，也不伪造真实 session/token/connection 响应。 |

三个层共享 `proto_mutate` 的“识别 → 模拟会话 → 层操作 → 序列检查 → 依赖修复 →
codec 校验 → replay 序列化”流程。模拟结束恢复真实连接缓存。发包前再以 C 的原子
绑定接口处理真实响应值；每连接清空缓存，响应仅在完整、通过校验和声明关联后
参与绑定。预测状态迁移不能当作目标已经接受请求的事实。

`valid` 表示结构化 profile 约束；`near_valid` 和 `invalid` 当前共享一条协议长度+1
违例，尚不是完整的错误策略库。`raw` 保留原 AFL 路径；hybrid 保留两者的显式比例。
采用 adaptive 时，结构化随机层放在 havoc/splice，确定性阶段仍执行原 AFL 候选，
避免将随机替换的结果错误归属到 effector map 和自动字典。

描述里还存在可检查但不可整体替换的 `session`、`pdu`、`cip`、`body` 容器，以及
没有可变叶的控制报文。这些范围必须从候选资格、拒绝计数和每层有效发送率中
单独观察；仅记录三层曾被选择，不能证明三层都有有效产出或效率更高。

## 如何判定覆盖联动有效

源码接入应能追踪完整链路：StateAFL 选择内存状态与 M1/M2/M3 → C 调度选择层 →
C runtime 构造与发送 → 原覆盖/状态采集与保存 → 将本次实际发现反馈给原状态下
的该层。重放和校准不能重复记奖，构造拒绝或 raw fallback 不能冒领结构化收益。
协议 `ready/channel/registered` 节点不能被当作新内存状态写入 StateAFL。

是否提高覆盖需要额外实测：相同初始语料、构建、时间预算和随机种子组下比较 raw、
uniform 与 adaptive；分别统计有效发送/拒绝、去重位图位置与 hit-count bucket、
StateAFL 内存状态/迁移、执行吞吐和故障，并保留源码/模型/二进制哈希。单轮短跑、
fixture 自检或入队增加只能证明部分联动，不能证明六种真实目标普遍覆盖提升。
