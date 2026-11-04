# 协议描述文件是否具备完整统一模板：静态复核

日期：2026-11-04（America/Phoenix）。审查分支：`feature/description-driven-c-engine-20261027`。生产源码和描述基线：`7f165ba6ea921d1258b78d52a3abac18020fef98`；审查时已 fetch 并核对与远端一致。本轮由主审及三个 agent 分别检查 schema/实例结构、不同 runtime 的语义、模板生成和使用流程。

**结论：六套旧 codec YAML 有统一、覆盖必需字段的配置骨架；整个项目还没有完整覆盖新通用引擎、全部可选语法和使用闭环的统一模板体系。** 不能说“没有模板”，也不能说“所有协议已经完整由同一个模板驱动”。统一文件结构、覆盖语言全部能力、能生成新协议执行器、具备完整运行材料，是四个不同判断。

本轮审查采用源码阅读与 YAML/JSON 文件解析，使用不导入项目模块的脚本统计键、对象和 schema 的 required/额外键；交付变动限于审查文档。不运行项目校验器、编译器、测试、示例、目标或网络会话。结构键检查未发现问题，不等于类型、数值、跨消息语义或运行验证通过。此前构建成功及历史测试不作为本轮模板完整性证明。

## 1. 目前实际有哪些模板

| 描述体系 | 正式模板或参考入口 | 独立 JSON Schema | 可支持的判断 |
| --- | --- | --- | --- |
| 旧 ICP-IR v1 / 六个专用 codec | [protocol_spec.template.yaml](../protocols/templates/protocol_spec.template.yaml)、[state_transition.template.yaml](../protocols/templates/state_transition.template.yaml)，六套具体 YAML | [protocol schema](../protocols/schema/protocol_spec.schema.json)、[state schema](../protocols/schema/state_transition.schema.json) | 必需结构统一，有可填写骨架；能力受 codec 限制 |
| 新在线 `stateafl.generic-wire` v1 | [语言文档](generic-wire-language.md)、[fictional_protocol.json](../tests/generic-wire/fictional_protocol.json)、六个迁移子集 | 没有对应独立 schema；C loader 内有严格键、类型和语义检查 | 已有可执行语言，尚无模板目录中的专用模板和完整模板集合 |
| `stateafl.offline-layout` | [native_layout.template.json](../protocols/templates/native_layout.template.json) | 没有对应独立 schema；C 内置检查 | 有结构示例，限本地被动检查，不是在线编码/变异模板 |
| `stateafl.offline-observations` | [native_observations.template.json](../protocols/templates/native_observations.template.json) | 没有对应独立 schema；C 内置检查 | 有起始事件骨架，没有展示完整事件与关联结构 |

[模板 README 第3行](../protocols/templates/README.md#L3)明确说明当前目录没有新在线 generic-wire 的模板；[第25行](../protocols/templates/README.md#L25)明确两份 schema 只约束旧 YAML。没有独立 schema 不表示 C loader 没有校验，也不应将另外一种格式的 schema 当作它的校验依据。

## 2. 六套旧 YAML 的统一程度

本次逐文件统计如下，状态数是各 profile 的声明数之和，不是 StateAFL 实际推断出的内存状态数。

| Profile | 消息数 | 字段数 | 声明状态数 | 声明迁移数 |
| --- | ---: | ---: | ---: | ---: |
| BACnet/IP | 7 | 66 | 2 | 8 |
| Modbus TCP | 19 | 138 | 1 | 19 |
| IEC 60870-5-104 | 11 | 62 | 6 | 17 |
| IEC 61850 MMS/TCP | 14 | 136 | 9 | 14 |
| EtherNet/IP + CIP/TCP | 10 | 132 | 4 | 10 |
| OPC UA TCP | 10 | 107 | 6 | 14 |
| 合计 | 71 | 641 | 28 | 82 |

核对发现：

- 六个 `protocol_spec.yaml` 与公共模板都使用完全相同的11个顶层键：`format_version/protocol_id/name/version/scope/transport/framing/codec/support/sources/messages`。
- 六个 `state_transition.yaml` 与公共模板都使用完全相同的7个顶层键：`format_version/protocol_id/initial/states/transitions/limits/invalid_strategy`。
- 71条消息均使用同一组11键：`id/direction/weight/fixture_status/runtime_encode/match/example/blocks/fields/dependencies/notes`。
- 641个字段都具有16个必需键：`id/block/path/type/locator/width/endian/role/mutability/default/min/max/values/strategies/evidence/confidence`。
- block 的必需项为 `id/fields`；dependency 为 `op/target/source`；state 为 `id/meaning`；transition 为 `from/to/message/response/guard/actions`；limits 为 `max_messages/max_repeat/max_bytes`。
- 对上述六套 YAML 及两份公共 YAML 模板，按 schema 递归比较对象键和本地 `$ref`，没有发现缺失必需键或 `additionalProperties:false` 禁止的额外键。该检查没有执行 schema 类型与数值验证。

因此，“六套文件各写各的，没有共同结构”不符合当前事实。消息类型、定位器、长度计算、编码和状态图不同，则是协议语义差异，不能为了让模板看起来一致而将它们抹平。71条完整消息也只指项目声明的服务子集，不代表六个工业标准已完整建模。

## 3. 尚未完整的具体问题及解决思路

以下优先级表示模板交付和维护顺序，不表示现有六套文件已经出现结构错误。

### T01：新通用 C 引擎缺少自己的正式模板与独立 schema（优先）

`generic_runtime.c` 已明确 [9个必需顶层键](../generic_runtime.c#L301)：`format/version/protocol_id/transport/online/framing/messages/states/limits`；[消息对象](../generic_runtime.c#L258)必需 `id/direction/weight/example_hex/grammar`，可选 `correlate`。但这些契约主要分散在 C 代码、语言文档、测试实例和迁移生成脚本中。

测试目录的 `fictional_protocol.json` 是完整的 UDP 单向消息实例，没有 TCP framing、响应消息和关联规则，不能单独承担全部模板示范职责。旧 YAML 骨架也不能直接交给 `--generic-spec`。

建议补齐 generic-wire 的专用填写骨架和独立 schema，并提供 UDP 单向、UDP 请求响应、TCP 长度分帧与响应关联的完整小实例。实例应包含声明、请求语料及其来源说明；schema 明确必需键、严格额外键、角色与类型分支、资源上限。跨字段引用、长度方程和状态可达性仍由语义检查承担，不能声称 JSON Schema 足以替代 C loader。

### T02：模板不是嵌套配置的唯一生成来源（中）

[init_protocol_spec.py 第40–49行](../tools/init_protocol_spec.py#L40)只读取模板的顶层键，然后从选定的真实 profile 逐块 `deepcopy`。`messages/fields/dependencies/states` 的内容来自现有 profile，而不是从模板内的 command/length/payload 示例实例化。

直接影响是：修改公共模板中的字段默认值、策略或依赖示例，并不会相应修改六个生成包。现有 [README 第45行](../protocols/templates/README.md#L45)对此已有准确说明，所以这是模板系统的边界，不是生成器暗中违反文档。

建议明确 schema、基础模板、能力片段和具体 profile 各自的职责。若保持 profile 复制器设计，应增加模板与 schema 的结构漂移检查，并明确嵌套默认值属于具体 profile；若希望模板驱动生成，需设计可显式验证的参数替换规则和 codec 定位映射，不能仅把顶层复制改名为通用生成器。

### T03：基础骨架覆盖必需项，但没有完整的可选语法示例（中）

模板展开了一条 [length_of 依赖](../protocols/templates/protocol_spec.template.yaml#L88)，跨消息复制和响应绑定主要放在结尾注释。schema 还定义了 `block.parent`、字段 `when/repeat/structure/structure_model`，以及依赖的 `message/algorithm/multiply/scope/when` 等可选形式。现有实例确实使用结构树、Modbus repeat、响应绑定、关联、序号和 MMS tagged_length，不能只靠基础三字段示例说明它们。

建议保留简洁基础模板，另提供按能力分开的合法片段和完整案例，分别列出字段类型、必需条件、适用 codec 和负例。不要把静态条件、通用 repeat 或协议不具备的 checksum 强塞进所有在线模板；片段必须标明“在线执行”“codec 特例”“仅静态说明”中的对应类别。

### T04：显式完整性声明尚未成为统一的强制契约（较低）

模板与71条消息均显式提供 `fixture_status` 和 `runtime_encode`，但 [message.required](../protocols/schema/protocol_spec.schema.json#L464)没有要求这两个键。compiler [第378行](../tools/proto_spec_compiler.py#L378)将缺省 fixture_status 按 complete 处理，[第393行](../tools/proto_spec_compiler.py#L393)只在 runtime_encode 存在时核对其能力声明。

这意味着当前实例的完整显式声明属于约定，并非所有第三方包都被强制遵守。另一方面，schema 允许静态 `direction: both`，模板注释只列 request/response，compiler 在线模式才拒绝 both。不能将其描述为当前六套实例字段缺失。

建议在新模板契约中要求显式完整性和能力声明，说明旧版本缺省语义及兼容策略；方向等选项应同时标注静态与在线允许范围。任何收紧 required 的改动都应有版本/迁移说明。

### T05：编辑描述后，启动流程没有强制检查生成语料同步（优先）

[run_protocol_campaign.prepare](../tools/run_protocol_campaign.py#L13)读取和校验 YAML，[第25行](../tools/run_protocol_campaign.py#L25)重编 IR，随后构造启动命令。它没有读取、刷新或检查 `seed_manifest.json` 与现有 seeds。修改 example、请求/响应关系、状态边或前缀后，可能用新模型配旧语料进入 fuzzer，后续表现为拒绝或无效初始化，不能据此评价变异方法。

[模板 README 第49–51行](../protocols/templates/README.md#L49)已要求手动重规划，因此不能说项目没有任何同步方式；问题是“编辑→启动”的一致性尚未由入口保证。相比之下，[导出器第25–41行](../tools/export_protocol_bundle.py#L25)已经比较 IR、manifest、fixtures 和 seeds 的一致性。

建议启动入口对包内受管理 corpus 做只读身份和内容检查，过期时明确拒绝并给出重规划命令。自定义 `-i` 目录应有独立策略，不能直接用包的 manifest 认证任意输入目录，也不能悄悄覆盖用户的自定义语料。规划应使用当前实际状态模型和资源约束，不伪造现场响应。

### T06：最小可运行示例尚未交付完整运行包（中）

`minimal_runnable_example` 实际只有 README 和两份 YAML。其单寄存器请求与两字节数据响应已经配套，是完整配置输入对；但目录没有 fixtures、seeds、seed_manifest，也没有配套目标和完整启动步骤。[README 第28行以后](../protocols/templates/minimal_runnable_example/README.md#L28)主要给出编译命令，而 [compile_spec](../tools/proto_spec_compiler.py#L678)生成 IR、bundle 和 validation，不生成语料。

建议将名称准确限定为最小配置输入，或补齐“该输入对→编译→规划语料→准备受控目标→启动”的完整文档和材料。已有 `init_protocol_spec.py` 只能选择六个固定 base，不能假设它会自动读取这个最小目录。

另有一处明确文案混淆：[最小 README 第24行](../protocols/templates/minimal_runnable_example/README.md#L24)把带 LE32 头的磁盘格式标成 `.raw`；当前队列 raw 字节不含该头，replay 输入和权威快照才包含长度头。应按实际存储契约说明，避免用户生成错误输入；扩展名本身不是解析凭据。

### T07：离线 JSON 模板只展示部分能力（较低）

布局模板展示 struct/uint/bytes/bits/choice/repeat/bounded，C 还支持 [int/align](../native_layout.c#L324)。观测模板只给 session_start 和 unobserved protocol；解析器支持 [session_start/reset/observation/timeout/partial/unmatched](../native_observation.c#L356)，并有 memory、boundary、reset_evidence 等关联结构。

建议增加节点与事件的合法示例，补 schema 和条件约束说明；观测模板摘要占位符仍须填写真实 SHA256。此项完善的是本地检查格式，不增加在线变异能力。

## 4. 为什么不能把不同格式套进同一个字段模板

| 维度 | 旧 YAML / codec IR | generic-wire |
| --- | --- | --- |
| framing | 说明字符串，实际由 codec 实现 | 可执行 datagram 或 length_field 对象 |
| 字段 | locator、role/mutability、codec 类型与受支持依赖 | 平铺 uint/bytes，fixed/head/content/derived；派生操作限 size_of |
| 会话值 | 有受支持的 bind_from_response、跨消息复制和关联 | 关联规则做整数相等检查，不实现一般服务器分配值绑定 |
| 状态声明 | 显式 states 列表，请求与响应都有独立边 | initial/transitions；transition.message 必须是请求，pending 响应完成后进入目标状态 |
| 静态说明 | default、结构树、guard/actions、依赖 scope/when 等被保留为元数据 | 严格键白名单，不支持的结构或执行字段拒绝 |

证据见 [旧执行元数据分类](../tools/proto_spec_compiler.py#L35)、[generic 字段 loader](../generic_wire.c#L58)、[generic framing](../generic_runtime.c#L312)、[generic 状态 loader](../generic_runtime.c#L347)。独立模板文件之间可统一目录、命名、版本、能力分类与交付材料，但实际语法必须与各自 loader 一致。

[build_generic_wire_profiles.py](../tools/build_generic_wire_profiles.py#L8)的消息选择、framing、状态和关联来自固定表；[第153行](../tools/build_generic_wire_profiles.py#L153)只读取旧 protocol IR，不读取 state IR。因此修改旧 YAML 的状态或依赖，不能推断新 generic 描述自动等价更新。当前 generic 迁移只含14/71条消息，五份 offline-only，只有 Modbus FC03 单寄存器 pair online；这属于迁移和语言能力范围，不能由增加模板或改 online 标志补齐。

## 5. 建议的完整统一交付标准

1. 每种格式都有明确的 `format/version`、schema 或规范源、填写模板、完整最小实例、能力限制和实际加载入口；旧 YAML 用自身的 format_version 与配对 IR 契约，不混用版本键。
2. 公共字段、可选结构和运行时支持的分类有一致清单；模板、schema、Python 检查和 C loader 之间有版本绑定的正反例核对。
3. 模板复制、字段修改、IR 生成、fixture/seed 规划和启动一致性检查形成闭环；每步输出有清楚的来源和适用范围。
4. 对任意新增协议，只承诺现有通用原语能表达的范围；超出原语或 codec 能力的部分明确拒绝或列为尚待扩展。
5. 文件结构检查、真实 loader 接受、字段/序列行为、受控目标会话和方法对照分别记录证据，不互相替代。

可优先完成 T01 与 T05，再补 T02/T03/T06，最后完善显式声明和离线片段。现有模板测试源码的 [六包实例化用例](../tests/protocol/test_templates.py#L74)覆盖 Python 校验、IR 与语料拼接；其 [C 行为 harness](../tests/protocol/test_templates.py#L100)主要覆盖 BACnet 字段和改名，不能单独证明所有协议和全部模板能力。新增规划器测试也不运行实际目标。本轮没有执行这些测试，结论仅限当前源码与描述文件的静态审查。
