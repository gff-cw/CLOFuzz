# 五协议 YAML 的描述完整性与 C 接口审查

结论：五套描述在各自声明的有限 profile 内有较完整的静态字段、依赖和状态清单；不能据此认定它们已经能够驱动完整的通用 C 定向变异器。现有 YAML/IR 面向专用 codec，和新的通用 C 布局入口不兼容，状态条件与结构树也有明确的静态元数据边界。

## 审查范围与方法

源文件审阅基线为提交 `73622a5f90b0f5c5acc2f7ab8a7fe8b95d9f5176`。三组只读审查分别覆盖 Modbus/IEC104、MMS、EtherNet/IP/OPC UA，并交叉核对公共 schema、编译器和 C 入口。

本轮只读取 YAML/JSON/源码，使用本地 PyYAML/jsonschema 做数据解析、schema 与引用检查，比较保存的 IR 内容；没有导入会构建 native codec 的项目编译器，没有构建或调用 C codec，没有运行项目测试、变异或目标服务，也没有访问规范来源 URL。这里的静态配置检查不构成报文符合性、互通或效果测试。

五包 protocol_spec.yaml、state_transition.yaml、evidence.yaml 共 15 个 YAML 文件的只读重复 key 检查未发现重复或非字符串 mapping key。协议和状态文件的本地 schema 检查没有报告错误；已复核的字段、消息、状态、来源和依赖引用未发现悬空。编译器的全部语义检查和实际 wire 解码不在本轮范围。

## 文件规模与同步情况

| 描述包 | 消息（请求/响应） | 字段 | 模型状态 | 状态边 | YAML 与已保存两份 IR |
| --- | ---: | ---: | ---: | ---: | --- |
| [Modbus TCP](../protocols/modbus_tcp/protocol_spec.yaml) | 19（9/10） | 138 | 1 | 19 | 内容一致 |
| [IEC104](../protocols/iec60870_5_104/protocol_spec.yaml) | 11（5/6） | 62 | 6 | 17 | 内容一致 |
| [MMS/TCP](../protocols/iec61850_mms_tcp/protocol_spec.yaml) | 14（7/7） | 136 | 9 | 14 | 内容一致 |
| [EtherNet/IP/CIP](../protocols/ethernet_ip_cip_tcp/protocol_spec.yaml) | 10（4/6） | 132 | 4 | 10 | 内容一致 |
| [OPC UA TCP](../protocols/opcua_tcp/protocol_spec.yaml) | 10（4/6） | 107 | 6 | 14 | 内容一致 |
| 合计 | 64（29/35） | 575 | 26 | 74 | 五包均一致 |

IR 比较忽略额外的 ir_version 字段后，protocol/state JSON 与各自 YAML 的解析对象相同。这只说明保存内容同步，未重新编译或认证当前二进制。fixture_status=complete 和 request runtime_encode=true 也只是声明，不能从数量推导标准覆盖、有效发送或执行验收。

共有 49 个字段附带 structure_model，3 个 Modbus 字段附带 repeat，没有字段级 when。结构树数量不是可执行编码规则数量，请求、响应及各字段的实际可编码或可替换能力仍需分别理解。

## 共同的接口与执行边界

### 旧模型和新通用布局是两种契约

五套 YAML 的根键为 format_version/protocol_id/codec/messages，状态文件另有 states/transitions。旧编译器保留这些对象并添加 ir_version。旧 [proto_load](../protocol_runtime.c#L314) 按 codec 白名单分派现有实现。

新的 [native_layout_inspect](../native_layout.c#L855) 只读取 JSON，要求 format/version/root，且 format 必须为 stateafl.offline-layout。因此直接交给它五套 YAML 或已保存旧 IR 都不成立；只改变文件扩展名或序列化为 JSON 也不能补上结构执行语义。

当前 native_layout.c 是只读布局检查，没有通用编码/变异接口；native_observation.c 是对既有观测声明的校验与报告，也不会读取这些状态 YAML 后自动驱动状态机。五包 support.runtime=true 对应的是既有 scoped codec 支持，不能解释为新通用执行器已可用。

### 文字说明与可执行约束需要区分

[编译器元数据契约](../tools/proto_spec_compiler.py#L33) 明确将 structure/structure_model、依赖 scope/when、状态 guard/actions 和 invalid_strategy 等归为静态信息。schema 同样将[结构树](../protocols/schema/protocol_spec.schema.json#L347)与[状态文字](../protocols/schema/state_transition.schema.json#L59)标为说明。

已有 length_of、响应绑定、序号等白名单依赖有执行路径，但这不等于描述中的所有自然语言条件都被执行。通用 when/repeat 等也未被旧运行时统一解释；Modbus repeat 及 MMS tagged_length 有专门的 codec 管理范围。不能将静态校验通过解释为通用条件、循环和编码已经完成。

字段被标为 fuzzable 或出现 resize 策略，也不证明该整个容器可以被 C 替换路径编码。消息可解析、叶字段可替换、整容器可重编码和完整序列可执行是不同能力。

## 各协议的限定范围

### Modbus TCP

现有模型覆盖声明的读/写功能族及响应。单个 connected 状态是所选抽象粒度，本身不能被视为缺陷，也不证明事务并发或所有异常关联已经表达。

异常布局的[说明](../protocols/modbus_tcp/protocol_spec.yaml#L1805)称可用于支持的请求族，同时注明 fixture 对应 FC03；其[关联依赖](../protocols/modbus_tcp/protocol_spec.yaml#L1841)只引用 read_holding。因此当前示例和依赖不能被报告为所有功能族的完整异常关联覆盖。数量/data/count 的 repeat 元数据也依赖既有 codec 的特例语义。

### IEC104

[scope 和 excluded](../protocols/iec60870_5_104/protocol_spec.yaml#L5)限定于 APCI I/S/U、传输控制及单对象总召唤；其他 ASDU、多对象生成及 TLS 不在本模型范围。

六状态图包含所声明阶段，但[发送窗口、序号推进和匹配条件](../protocols/iec60870_5_104/state_transition.yaml#L60)仍有 guard/actions 说明。sequence_number 依赖及序号字段说明不等于通用双向连接、窗口和确认状态管理。

### MMS/TCP

模型在声明的成功路径内有较完整的关联、有限服务及关闭描述；[排除项](../protocols/iec61850_mms_tcp/protocol_spec.yaml#L5)包括未验证的拒绝/abort/confirmed-error 等，不能据此宣称完整异常生命周期覆盖。

26 个 structure_model 是静态树。比如 [pdu 容器](../protocols/iec61850_mms_tcp/protocol_spec.yaml#L2634)标为可变，不代表 [C 叶替换接口](../protocol_codec_mms.c#L484)支持任意 BER 容器。协商条件、pending invoke 及 outstanding 限制中的文字也不能替代执行证据。字段来源以固定实现修订为主，不能提升成独立的完整标准符合性证明。

### EtherNet/IP/CIP

[声明范围](../protocols/ethernet_ip_cip_tcp/protocol_spec.yaml#L5)明确保留连接型消息的外部前提。[连接标识字段](../protocols/ethernet_ip_cip_tcp/protocol_spec.yaml#L2472)的说明也指出模型没有建立它的写入者。runtime_encode=true 因而不能解释为该模型可以自行建立完整连接生命周期。

这是已注明的支持边界，不是本轮发现的悬空字段 ID。来源中的官方目录不等同于已查阅付费规范全文，字段证据覆盖也不意味着全标准校验。

### OPC UA TCP

[scope 和 excluded](../protocols/opcua_tcp/protocol_spec.yaml#L5)限定于 None、Issue、单 final chunk 及 Discovery；Session、Renew、签名加密和分块重组等明确不在范围。

已有 channel/token 字段依赖不能代替[有效期、顺序及事务条件](../protocols/opcua_tcp/state_transition.yaml#L36)的完整执行。CLO 的规范措辞与实现 profile 差异仍是既有未解决边界。本轮未重新访问规范来源，不据此认证标准符合性。

## 协议状态与 StateAFL 内存状态

表中的 26 个状态是五份模型定义的语义节点，不是 StateAFL 实际推断的内存状态数，更不是一一对应的覆盖指标。协议模型中的 ready/active 等条件与 TLSH/MVP 的快照聚类标签必须保留独立身份。

旧 [semantic_step](../protocol_runtime.c#L564)会在模拟序列中沿声明响应边推进，预测不能当作本次执行的确认。新的观测报告也只检查生产者声明的来源、关联和共同边界；原共享状态数组本身不足以建立同步证据。完整理论见[双状态模型](dual-state-observation-model.md)。

YAML 写出更多状态、guard 或 scope 文字不会自动消除采样边界、事务作用域或模型版本的差异。本轮没有把协议节点写入 state_ids，也没有改动 TLSH、队列或反馈调度。

## 可支持的结论

这五套文件可以保留为既有有界 profile 的描述基线，静态引用和保存 IR 当前一致。它们不构成完整标准描述，也不是新通用 C 布局的可直接执行输入。当前通用 C 定向变异器及其在线反馈融合仍未实现，不能只凭完善 YAML 宣告该实现完成。

本次只新增审查记录及文档索引，没有修改协议 YAML、IR、codec 或变异路径；不产生新的运行验收和覆盖收益结论。
