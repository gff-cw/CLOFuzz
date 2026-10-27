# ICP-IR v1 协议描述语言

ICP-IR 是本次工程新增的声明式描述及中间表示。它把消息结构和协议语义状态分为两个输入，供 StateAFL 的可选协议变异路径使用。它不是 SPFuzz 原解析器的复刻，也不执行 Boofuzz/Python 脚本。六个参考 profile 均有有界 C runtime codec：BACnet/IP 使用 UDP；Modbus、IEC104、MMS、EtherNet/IP/CIP 和 OPC UA 使用 TCP。支持范围以各 profile 的服务与排除项为准。

设计依据和标准访问边界见 [references.md](references.md)，组件及 StateAFL 集成见 [architecture.md](architecture.md)。

用户填写入口见 [统一描述模板与完整使用流程](../protocols/templates/README.md)。两个空白模板位于 `protocols/templates/*.template.yaml`；`tools/init_protocol_spec.py` 根据所选真实协议配置填入模板，`tools/run_protocol_campaign.py --spec-dir ...` 在测试启动前校验 YAML、重编译并加载对应 IR。模板、schema 和具体协议实例是不同产物。


## 两份输入与三个输出

每个 `protocols/<protocol>/` 目录包含：

| 文件 | 含义 |
| --- | --- |
| `protocol_spec.yaml` | 协议身份、版本、范围、消息、HEAD/CONTENT、字段、依赖、来源 |
| `state_transition.yaml` | 初始语义状态、消息边、响应边、序列上限 |
| `protocol_ir.json` / `state_ir.json` | 校验后的确定性 JSON；增加 `ir_version: 1` |
| `validation.json` | 消息/字段/状态数量、范围及 runtime 开关；不代表完整协议合规 |
| `evidence.yaml` | 字段来源、可信度及未访问资料说明 |
| `seeds/*.replay` | 示例请求；每条记录为 LE32 长度和报文字节 |

编译一组描述：

```bash
python3 tools/proto_spec_compiler.py \
  --protocol protocols/bacnet_ip/protocol_spec.yaml \
  --state protocols/bacnet_ip/state_transition.yaml \
  --output-dir /tmp/bacnet-ir
```

输入通过 YAML 安全加载器读取；JSON 作为 YAML 子集也可输入，但仍须符合 schema 和语义校验。源码以 [protocol_spec.schema.json](../protocols/schema/protocol_spec.schema.json)、[state_transition.schema.json](../protocols/schema/state_transition.schema.json) 和 [proto_spec_compiler.py](../tools/proto_spec_compiler.py) 为准。编译器只解析本地文件，不按来源 URL 下载数据，不使用 `eval`、`exec` 或对象构造标签。

非 BACnet runtime 描述通过 `tools/native_protocol_codecs.py` 检查同一 C codec 的完整报文和字段定位；每个编译进程只在临时目录构建一次共享库。需要 C11 编译器（`CC` 或 `cc`）、`protocol_codecs.h` 及五个 `protocol_codec_*.c` 文件。在线 StateAFL 直接链接这些 C 文件，不在每次变异或网络 I/O 时调用 Python。

## 消息、块和字段

顶层必须声明 `format_version: 1`、`protocol_id`、`name`、`version`、`scope`、`transport`、`framing`、`codec`、`support`、`sources` 和 `messages`。`support.runtime` 明确表示是否具有运行时支持，`support.excluded` 列出范围以外的功能。协议与状态文件的 `protocol_id` 必须相同。

每条消息包含 `id`、`direction`、`weight`、`example`、`match`、`blocks`、`fields`、`dependencies` 和 `notes`。消息方向可为 `request`、`response`、`both`；当前 C runtime 接受 request/response。`example` 是完整单条线报文的十六进制模板，不包含 replay 长度前缀。`weight` 为 1..1000，运行时用于在当前待变异请求序列中按消息权重选取记录。

消息必须有 `HEAD` 和 `CONTENT` 两个块。每个字段只能列入一个块，字段的 `block` 必须与列表一致。块可声明 `parent`；编译器检查引用和父子环路。字段的 `role` 决定当前运行时如何选取变异对象，不能仅靠块名称推导其行为。

字段有如下信息：

| 属性 | 语义 |
| --- | --- |
| `id`、`block`、`path` | 稳定标识、所属块及解释性路径 |
| `locator` | codec 定位器，或 `abs:<十进制偏移>` |
| `type`、`width`、`endian` | 数据类型、字节宽度及大小端 |
| `role` | `head`、`content`、`fixed`、`derived` |
| `mutability` | `fixed`、`fuzzable`、`derived`、`conditional`、`runtime_bound` |
| `default`、`min`、`max`、`values` | 默认值、范围、最多 32 个标量枚举值 |
| `strategies` | 描述候选策略：`enum`、`boundary`、`bitflip`、`arithmetic`、`afl`、`resize` |
| `evidence`、`confidence` | 来源 ID，以及 `normative`、`implementation` 或 `inferred` |

整数为 `uint8/16/24/32/64`，声明宽度必须分别为 1/2/3/4/8；IR 支持 `0..2^64-1`，并按各字段位宽进一步限制。`abs:` 标量定位严格取声明宽度；MMS BER 等动态 locator 返回实际编码宽度并检查逻辑整数范围。变长类型 `bytes/string/bacnet_tags/ber_tlv/epath/nodeid` 的 `width` 必须为 0、默认值为字符串；不支持标量枚举。接受某个类型名称不意味着允许替换整个该类型的容器。

以下是现有 BACnet 模型中的长度字段和依赖摘录；完整可编译输入见 [protocol_spec.yaml](../protocols/bacnet_ip/protocol_spec.yaml)：

```yaml
id: bvlc_length
block: HEAD
path: bvlc.length
locator: bvlc.length
type: uint16
width: 2
endian: big
role: derived
mutability: derived
default: 0
min: 0
max: 65535
values: []
strategies: [enum, boundary, bitflip, arithmetic]
evidence: wire
confidence: implementation
```

```yaml
dependencies:
  - op: length_of
    target: bvlc_length
    source: $message
```

`default` 是描述信息，当前 runtime 从 `example` 模板构造报文；不会按所有字段的 default 重新生成完整报文。`strategies` 对 HEAD 标量字段启用列出的 enum/boundary/bitflip/arithmetic 子集；空列表使用这四项默认策略。CONTENT 标量使用 AFL 候选的字段投影，不执行 strategies/values 列表；变量叶的 resize 允许在字段范围内选择新长度并交给 codec 重组、验证。未知策略在编译和 C 加载阶段均明确拒绝。`path`、`match` 和描述字符串也不是表达式。

消息匹配先限制方向，再检查 codec 的服务/格式类别、固定标量及所有必需字段的实际范围。消息 ID 不选择编码器。新增 TCP profile 只有运行字段约束和依赖形状相同的别名才可共享首个规范模型；例如 `write_coils_partial` 和 `write_coils`，对应关系写入 `validation.json.message_aliases`。任意重叠约束或说明性 `match` 名称不能消除歧义。

## 状态迁移

状态输入声明 `initial`、`states`、`transitions`、`limits` 和 `invalid_strategy`。每条边包含 `from`、`to`、`message`、`response`、`guard`、`actions`。`response` 为空字符串表示没有声明响应；非空时须引用 response/both 消息。编译器检查消息/状态引用及所有状态从初始状态可达；C runtime 进一步拒绝同一 `from + message` 的歧义边。

BACnet 模型摘录：

```yaml
initial: ready
states:
  - {id: ready, meaning: UDP endpoint ready; requests independent}
  - {id: pending, meaning: Confirmed request outstanding, scoped by invoke ID}
transitions:
  - from: ready
    to: pending
    message: read_property
    response: read_property_ack
    guard: request sent
    actions: [cache invoke_id]
```

这只是文件片段，完整模型还定义响应返回 `ready` 及其他边。`guard`、`actions`、`invalid_strategy` 是人读说明，当前没有表达式解释器。运行时按明确的状态/消息边推进，不执行这些字符串。序列检查先按已有 M1 前缀计算 M2 的语义起点，再对请求 replay 模拟已声明的响应边，以检查请求顺序；模拟不证明目标真正返回该响应，也不产生响应绑定值。它不从图中搜索任意会话前缀。

语义状态位于 `proto_engine`，与 StateAFL 从内存快照推断的状态 ID、状态图和选择算法分开。提供状态描述不会替换、重编号或关闭内存状态反馈。

## 依赖与缓存

依赖必须有 `op`、当前消息中的 `target` 和 `source`；可用 `message` 指向另一条消息，`$message` 表示本条报文。每个 target 只允许一个写入者。复制/绑定两端须为类型、宽度一致的整数。编译器检查引用、整数范围、重复写入和依赖环；结构性依赖须来自当前消息。

| 操作 | 当前能力 |
| --- | --- |
| `length_of` / `count_of` | `(本地源字节长度 / unit) * multiply + add`；要求整除及目标范围内 |
| `offset_of` | 本地源相对报文起点的偏移加 `add` |
| `checksum_of` | 本地 `sum8` 或 `crc32`；目标位于源范围内时先清零 |
| `copy_from_message` | 复制明确的消息 ID + 字段 ID 标量；同消息可直接求值 |
| `bind_from_response` | 从缓存中的 response 消息标量读取；无缓存值时拒绝 |
| `correlate_request_response` | 实际响应须满足已发 pending 请求对应字段的关联；BACnet live 路径另记录 outstanding invoke 统计 |
| `sequence_number` | 同消息/字段上次缓存值按 `unit` 递增并按字段位宽回绕；首次为 0 |
| `tagged_length` | 仅 MMS 的 `ber:presentation` 变长目标、当前 `$message` 源，由 codec 修复 BER 祖先长度 |
| `conditional_presence` | 仅静态描述及引用检查，runtime 拒绝 |

`multiply` 仅用于 length/count；`unit` 仅用于 length/count/sequence；`add` 仅用于 length/count/offset。其他操作不能借这些属性声明未执行的变换。`scope`、依赖 `when` 是元数据；没有按字符串执行条件或建立独立的 transaction 数据库。实际缓存为每个 engine 一份，键是消息和字段，保存最近的标量及 pending 请求，每次网络执行/连接开始全部清除。变异期间在独立模拟会话中修复并缓存请求，结束后恢复真实网络会话缓存；发包前仅处理会话绑定类依赖。真实响应须先通过帧、服务、字段范围和声明的请求关联检查，才能供后续绑定使用。M1 状态模拟和 example 中的说明值不能替代实际分配的 session/channel/token。

TCP 响应可以分片或合并到一次读取；runtime 按 codec 的协议长度缓存和拆帧，完整响应才进入关联与缓存。它不提供被 profile 排除的协议级多 chunk/分段服务。

字段 `when`（掩码选择）、`repeat`（有界计数）和 `structure_model`（sequence/choice/repeat/TLV 等树）可表达静态结构。编译器检查引用、深度及重复上限；它们不是通用编码程序。runtime 拒绝通用 when/repeat，唯一 repeat 例外是 Modbus 请求 `abs:13` 的 bytes 数据：FC0F 使用 byte_count、element_width=1、min=1/max=246；FC10 使用 quantity、element_width=2、min=1/max=123。count 字段的类型和偏移及 data 长度边界必须精确匹配已有 codec。BACnet 的地址、标签、Who-Is 可选范围及已存在 ReadProperty array-index 仍由专用 codec 解析。

## 三级变异与模式

层集合只接受 `head`、`head,content`、`head,content,sequence`。每轮从启用层等概率选择一层，再在当前 M2 请求记录中按 `weight` 选消息。这里没有实现论文未披露的自适应策略权重公式。

| 层 | 实际行为 |
| --- | --- |
| HEAD | 对可变 head 标量使用枚举、边界、位翻转或算术；限制字段范围，保留 NPDU 可选地址布局位 |
| CONTENT | 使用 AFL 已生成候选在原始字段线偏移上的字节投影；标量及 codec 支持的叶字段按类型重组并验证 |
| SEQUENCE | 对 M2 请求插入模板、删除、重复或交换顺序，并检查状态边、消息数、重复数和序列字节上限 |

插入/删除/重复/重排是本次扩展设计；论文材料直接描述的 SEQUENCE 操作是把当前消息插入正确序列的随机位置。三层都在序列检查和依赖修复后序列化。

变量替换限定为已实现的叶字段，例如 Modbus data、MMS domain/item/value、CIP EPATH 和 UA String/ByteString/NodeId。codec 修复该叶的长度/计数和所有需要调整的外层长度，再检查完整报文；未知 opaque CIP/UA/BER 容器明确拒绝。MMS 替换重编码 BER 祖先长度，并处理短长度转长长度、ISO session 长度头及 invoke INTEGER 宽度变化。IEC104 当前 profile 全部为标量，没有变量叶替换接口。解析或显示某个容器不代表可以把 AFL 数据当作完整容器替换。

| 模式 | 实际含义 |
| --- | --- |
| `valid` | 保持当前模型所检查的结构、范围、依赖和请求序列约束；不是全标准有效性保证 |
| `near_valid` / `invalid` | 当前二者相同：修复后故意把一条对应协议的线长度加 1，并记录 wire_length 约束 |
| `raw` | 使用原 AFL 字节变异和现有消息边界路径 |
| `hybrid` | 默认以 70% 概率尝试 valid 结构化候选，其余走 raw；比例是尝试概率，拒绝会改变实际发包占比 |

结构化失败默认拒绝本次候选，只有显式 `--protocol-fallback` 才允许回到 raw，并写出 fallback 事件。结构化日志的 mutation 事件表示候选已构造，不能直接当作目标成功接收、响应或覆盖增加的计数。

## 资源边界与现有模型

输入及展开后 JSON 均至多 1 MiB；展开最多 65536 节点、嵌套最多 24 层，结构元数据最多 16 层。重复 YAML key、对象构造标签、递归别名及非 JSON 标量被拒绝。标识符为 ASCII 字母开头、后续字母数字或 `_.-`，总长最多 63。schema 限制最多 64 个状态、256 条边、每条消息 64 个字段；序列最多 64 条报文、同类重复上限最多 8、总 replay 字节最多 1 MiB。当前六个模型实际配置为 32 条报文、同类最多 4 次。

| 模型 | 消息 / 字段 / 语义状态 | 支持范围 |
| --- | --- | --- |
| [BACnet/IP](../protocols/bacnet_ip/README.md) | 7 / 66 / 2 | Who-Is/I-Am、ReadProperty ACK/Error、Reject/Abort，动态 NPDU 和 BACnet 标签；请求子集在线实测 |
| [Modbus TCP](../protocols/modbus_tcp/README.md) | 19 / 138 / 1 | FC01–06/0F/10 请求响应、异常、packed coils、9-coil padding；有界 TCP codec |
| [IEC 60870-5-104](../protocols/iec60870_5_104/README.md) | 11 / 62 / 6 | I/S/U、STARTDT/STOPDT/TESTFR、单对象总召唤确认和终止；有界 TCP codec |
| [IEC 61850 MMS/TCP](../protocols/iec61850_mms_tcp/README.md) | 14 / 136 / 9 | 完整 COTP/session/presentation/ACSE association、GetNameList/Read/Write、conclude/release；有界 TCP/BER codec |
| [EtherNet/IP + CIP/TCP](../protocols/ethernet_ip_cip_tcp/README.md) | 10 / 132 / 4 | Register/Unregister、SendRRData、SendUnitData、CPF/EPATH；有界 TCP codec，连接型消息仍有外部前提 |
| [OPC UA TCP](../protocols/opcua_tcp/README.md) | 10 / 107 / 6 | HEL/ACK/ERR/RHE、完整 None OPN、GetEndpoints/ServiceFault、实现 profile CLO；有界 TCP/UA Binary codec |

合计71条完整fixture、641字段，31条 request 可断言 runtime_encode；明确范围见[协议审查](protocol-model-audit.md)。六个 codec 可被显式选择，未选模型时仍走原路径。真实工业目标证据仍限 BACnet；新增五种 TCP 功能测试使用本地 C fixture double，不证明工业产品互通、吞吐或覆盖收益。CLO 的规范措辞与实现 profile 差异、SendUnitData 的外部 ForwardOpen 前提均保留；“报文完整”“独立检查”“功能夹具”“工业目标集成”“标准符合性”分别记录。
