# 旧 codec 模板契约与高级片段

本目录补齐 ICP-IR v1 配置骨架的能力清单和上下文示例。它属于旧 `--protocol-spec/--state-spec` 路径，使用六种已有 codec；不产生新 codec，也不作为 generic-wire JSON 的模板。

结构由 `protocols/schema/protocol_spec.schema.json` 和 `state_transition.schema.json` 决定。两份公共 YAML 展示必需的填写形状；具体 profile 拥有真实 wire、locator、默认值、依赖和状态。生成器现在递归检查模板和源 profile 的 required/额外键，拒绝形状漂移，并保留全部 schema 允许的属性，避免只做顶层投影而静默丢字段。它不把骨架的演示字段、默认值或依赖覆盖到真实协议中。

`tools/protocol_template_contract.py` 提供可复用的 `check_object_shape`、`checked_profile_copy`、`load_capability_catalog` 和 `contract_metadata`。形状检查允许骨架占位符；实例化后仍由原 compiler 做 schema 类型、值域、引用及实际 codec 语义检查，形状检查本身不是运行验证。

`capabilities.json` 对 schema 中全部字段属性和十种 dependency op 作机器可读分类；`advanced_fragments.yaml` 给出对应片段、上下文、来源和约束。catalog 的字段及操作集合与 schema 不一致、片段 ID/引用清单不一致时，实例化会明确拒绝。

高级片段使用具体值，因此还逐个检查所引用 schema 组件的类型、枚举和值域，保留原 schema 的本地引用解析。能力分类、codec/方向集合和显式消息声明策略也须与契约一致。真实摘录在实例化/导出入口核对仓库内来源文件 SHA256、所选规则/字段及上下文字段；编辑来源 profile 后必须显式更新相关片段与摘要。来源路径只能指向其声明 profile 的协议文件，不能借模板目录切换到其他来源。语法示范必须明确不作工业 profile 声明。这些检查不调用 codec 或目标。

| 规则 | 当前执行含义 | 示例来源与边界 |
| --- | --- | --- |
| `length_of` | `(source 编码字节数 / unit) * multiply + add`，要求整除且结果适配目标范围 | 真实 Modbus MBAP `length`，`add=-6` |
| `count_of` | 用相同公式计算编码单位数，不任意解释业务数组元素 | 真实 ENIP `send_rr.path_words`，EPATH 字节数除以2 |
| `offset_of` | 当前消息中 source 的实际定位偏移加 add | 六份当前 profile 无对应规则，提供无工业 wire 声明的语法片段；不是可运行协议包 |
| `checksum_of` | `sum8` 或 `crc32`；目标完整落在源区域内时先清零目标字节 | 同样仅提供规则语法，不声称 Modbus TCP 等协议具有该校验和；必须有真实格式依据 |
| `copy_from_message` | 本消息读取当前 source；跨消息读取兼容的已缓存标量，消息与字段均须明确存在 | 真实 Modbus 请求与响应的 unit 字段 |
| `bind_from_response` | 从当前会话实际接收并验证的响应取得兼容标量 | 真实 ENIP register_response → unregister.session；示例值不能伪造现场 session |
| `correlate_request_response` | 检查实际响应标量与对应请求值相等 | 真实 Modbus transaction；不会改写接收的响应 |
| `sequence_number` | 一般目标使用自身先前值及 unit 增量；UA 的共享序号路径按1前进 | 真实 OPC UA open_channel.sequence 省略 unit 即1；不能用任意其他字段作来源，也不能把非默认 unit 当成 UA 共享路径已实现的增量 |
| `tagged_length` | MMS codec 管理 BER/presentation 的长度修复 | 仅 MMS `ber:presentation`、`ber_tlv`、本消息 `$message` source 特例，不是一般 ASN.1 编译器 |
| `conditional_presence` | 仅静态依赖说明 | 在线 runtime 明确拒绝；不会创建通用条件解析器 |

另外的片段说明：

- `repeat` 给出真实 Modbus FC10 data/count 描述。FC0F/10 只有精确的 codec 管理例外；`generic_static_repeat` 展示一般 repeat 的静态写法，不能用于在线任意数组。
- `when` 展示声明字段存在条件的静态结构；runtime=true 时拒绝。它和 codec 处理缺失字段所用的 conditional mutability 不等价。
- `structure_model` 摘录真实 OPC UA 的类型化结构树；树和其中 condition 不作为编码程序运行。
- `block_parent` 只说明分组层级；parent 必须存在且无环，字段仍按 role 选择变异层。
- `dependency_annotations` 中只有 copy 操作执行；scope 不创建独立缓存，when 字符串不控制复制执行。作用域和条件只是元数据。
- `state_guard/state_actions` 明确只说明这两个属性；真正的迁移边仍由 state/message 选择，不能靠 guard 消除重复边，也不执行 actions 中的字符串。
- `length_transform` 单独展示 unit/multiply/add 的语法和整除要求，不给已有工业协议添加无依据的换算规则。
- `values` 仅作为 HEAD 枚举建议；HEAD 标量执行其 scalar strategies。CONTENT 标量使用 AFL 投影，不执行这些标量候选策略；可替换的 codec 变量叶则会消费 resize 标志。BACnet Who-Is 的可变内容由专用路径选择合法长度，不能把所有 CONTENT 策略一概说成注释或一概说成脚本。

片段是完整的 schema 组件与所需上下文，不是可直接交给 compiler 的整个协议文件，也不是自动合并补丁。`source.kind=profile_excerpt` 保留对应文件和 SHA256；`rule_syntax_only` 明确没有完整工业 wire 案例。整合片段时必须使用所属 profile 的真实字段、方向、codec 定位能力、完整报文和状态关系，再编译校验。

## 从具体输入生成完整包

原有 `instantiate(base, output, protocol_id, runtime_required)` 调用保持兼容。已有六包可继续使用 `--base`；任意其他明确的 YAML 输入对可以通过 `--source-dir` 复制，但它仍必须使用 compiler 支持的 codec：

```sh
python3 tools/init_protocol_spec.py \
  --source-dir protocols/templates/minimal_runnable_example \
  --require-runtime --output-dir /tmp/minimal-modbus-package
```

`--base` 与 `--source-dir` 互斥。源 `protocol_id` 必须先配对相同；`--protocol-id` 可以对这一合法输入对同时更名。新生成包要求每条消息显式声明 `fixture_status` 和 `runtime_encode`，旧 compiler 对省略字段的兼容行为仍单独存在。方向 both 仅用于静态描述，在线仍限定 request/response。

实例化在同父目录的临时包中完成具体 YAML 校验、IR、validation、fixtures、模型 seeds、seed_manifest、evidence、README 和 `template_contract.json`，全部准备完成才 rename 发布；已有目的路径包括 broken symlink 均拒绝覆盖。源 YAML 在生成期间变化也会拒绝发布。

`template_contract.json` 记录源文件、schema、骨架、能力 catalog 与片段的摘要，明示真实字段值由源 profile 提供以及没有生成新 codec。这些摘要描述文件来源，不认证进程映像，也不证明目标会话或变异方法效果。修改自己的 YAML 后仍须按照最新启动入口要求同步 IR 与受管理语料。

新增 `tests/protocol/test_template_contract.py` 与扩展的 `test_templates.py` 保存结构漂移、完整属性保留、能力分类、显式源目录和生成来源的回归源码。本轮未运行测试、compiler、codec helper 或目标；这里只完成文件创建和静态源码检查。
