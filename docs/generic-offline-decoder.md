# 通用离线描述解释与解码

本轮新增 `tools/offline_protocol_decoder.py`。它解释结构树并读取已经存在的二进制文件，不调用六种专用 C codec，不按协议名选择分支。相同解释器处理不同描述。节点描述报文的编码机制，具体协议名不进入执行语义。

该实现的格式为 `stateafl.offline-layout`、`version: 1`，与已有 ICP-IR v1 是不同格式。已有 `structure_model`、`guard` 等静态注释不会被自动升级为执行规则。当前六套描述尚未迁移；在线 `protocol_runtime.c` 继续使用既有接口。本文不宣称通用在线变异执行器已经完成。

## 文件和入口

- [解释器](../tools/offline_protocol_decoder.py)：描述校验、整数表达式解释、游标解码、字段范围检查与 JSON 报告。
- [可编辑模板](../protocols/templates/offline_layout.template.yaml)：虚构的有界记录格式，展示位域、重复、TLV 式长度容器和分支，不是某个真实协议的符合性模型。
- [双状态契约](dual-state-observation-model.md)：解码证据与协议状态、内存状态的区别。
- [离线双状态报告](offline-state-relation.md)：显式边界观测文件及多对多关系输出。
- [离线字段变换](generic-offline-editor.md)：对已有本地样本执行显式、保持结构的字段编辑，并完整复验。

命令行仅从文件读取数据，结果写到标准输出：

```bash
python3 tools/offline_protocol_decoder.py \
  --layout path/to/layout.yaml --input path/to/existing-message.bin
```

解释器需要 Python 3.10 或更新版本。JSON 描述仅使用标准库；YAML 描述另使用项目已有 PyYAML 依赖。Python API 为 `load_layout(path)` 或 `LayoutDecoder(document)`，随后调用 `decoder.decode(existing_bytes)`。返回值为报告字典，输入必须是不可变 `bytes`。

退出码 0 表示按该描述完整解码，1 表示输入未通过解码，2 表示描述或输入文件错误。结构上解码成功不证明业务操作成功、目标执行了状态转换或完整标准符合性。

## 节点的执行语义

每个节点都有唯一于同级的 `id` 和一个 `kind`。根节点不隐式跳过任何输入；未声明的尾部字节导致失败。未知节点和未知属性被拒绝。

| kind | 参数 | 读取语义 |
| --- | --- | --- |
| `struct` | `fields` | 按顺序解释字段，进入独立词法作用域 |
| `uint` / `int` | `width`, `byte_order` | 读取 1–8 字节的无符号/有符号整数；字节序为 `big` 或 `little` |
| `bytes` | `length`；可选 `encoding`、`expected_hex` | 读取指定字节数，返回 hex、ascii 或 utf8；文本严格解码 |
| `bits` | `width`, `byte_order`, `fields` | 先读整数载体，再按数值的最低位编号提取位域 |
| `choice` | `selector`, `cases`；可选 `default` | 用已解析整数选择一个分支，未匹配且无默认分支时报告 unsupported |
| `repeat` | `count`, `max_items`, `item` | 按已解析计数重复；显式上限和全局展开预算同时生效 |
| `bounded` | `length`, `body` | 子树只能消费该字节区间，且必须恰好消费完 |
| `align` | `multiple`；可选 `fill` | 相对最近 struct 或 bounded 起点对齐，并可检查 padding 字节 |

整数可附加 `min`、`max`、`expected`、`values`。所有已到达的字段都检查约束；描述中的互相矛盾约束在加载时拒绝。`values` 是穷尽允许集合，不是变异候选列表。位域子字段使用 `id`、`lsb`、`width` 和可选 `expected`，同一载体内禁止重叠。未声明的位不自动认定为保留位；需要检查时应显式描述。

`choice.cases` 的键使用规范十进制字符串，例如 `"0"`、`"7"`、`"-1"`。YAML 中必须加引号。默认分支也必须提供可解释的节点，不能通过默认分支静默忽略数据。

固定头 TLV 可组合为 `struct(tag:uint, size:uint, payload:bounded(choice(...)))`。这不自动提供 BER 高 tag、长长度、无限定长度、BACnet LVT、压缩或加密等未定义机制。递归类型、未来字段引用、任意脚本和 TCP 流重组均不在当前能力内。

## 引用、表达式和重复作用域

长度、计数和分支判别式接受整数，或者受限表达式对象：

```yaml
length:
  op: mul
  args:
    - {ref: count}
    - 2
```

允许的二元操作为 `add/sub/mul/div/mod/and/or/xor/shl/shr`。`div` 必须整除；移位量为 0–63，位运算只接受非负整数。布尔值、浮点数、代码字符串和任意函数均不作为表达式。中间整数限于 `[-2^63, 2^64-1]`，负长度、溢出和除零导致失败。

`{ref: size}` 从最近 struct 作用域查找已成功解码的字段，再向外查找。`{ref: header.size}` 可引用已完成子 struct 的整数叶。引用不包含根节点名称，不能索引 repeat 数组，不能引用未来字段。每次重复中的 struct 建立新作用域；前一项的局部字段不会遗留到下一项。

`bounded` 和 `choice` 在引用值上是透明包装。例如父 struct 的字段 `payload` 包装一个名为 `case_a` 的 struct，引用其 `size` 应写 `payload.size`；诊断树仍保留 `payload.case_a.size` 的结构路径。诊断树路径用于展示实际解析结构，引用路径用于词法取值，两者不能互相直接替换。

加载阶段校验表达式形状、节点及静态限制；引用是否在所选分支中已经存在，在解码到该节点时检查。当前实现没有完整的编译期引用及分支可达性证明。未解析引用不会返回 0 或猜测默认值。

## 输出与诊断

成功报告包含描述内容摘要、输入摘要、消费字节数和结构树。字段有类型、结构路径、字节半开区间 `[start,end)` 与值；位域另有 `bit_lsb/bit_width`。byte_order、encoding 来自实际描述，source_node_path 是描述中的 JSON Pointer；choice 的 selected_case 保留选中判别值，默认分支记为 default:值。这些元数据用于本地字段编辑的结构一致性检查。整数是整数，二进制叶是 hex，复合节点用 children 表示，不重复复制整个子树值。

LayoutDecoder 保存加载时的描述快照，description 属性返回副本；修改该副本不改变已加载语义或摘要。

解码结果区分：

- `decoded`：严格按当前描述消费完整输入。
- `truncated`：根输入没有提供描述要求的字节。
- `invalid`：字段约束失败、完整容器内部越界、未消费的字节或引用/算术错误。
- `unsupported`：当前描述没有覆盖观测到的分支。
- `resource_limit`：动态输出或表达式执行超出预算。

若一个 bounded 容器的长度已经完整存在，即使其末尾恰好等于文件末尾，内部字段越界也属于 invalid。失败报告只返回诊断路径、当时游标和已消费字节数，不输出可被误认为完整成功结果的部分树。

描述文件与单份输入均限 1 MiB；展开描述最多 65536 个值、结构节点最多 4096 个、结构和表达式深度各至多 32、单节点重复至多 4096 项、动态字段最多 65536 个、表达式求值最多 524288 步。未知 YAML 对象构造、重复键及递归/过度展开的别名被拒绝。格式的语义校验以解释器代码为准。

## 与状态层的边界及迁移

解码器只证明“这些已存在的字节可由这份布局解释”。它不把解码成功转换成协议状态确认，也不产生内存状态编号。协议状态解释还需要事件方向、目标观测、事务关联和作用域；与内存状态建立关系还需要共同的观测边界。

六套旧描述仍由旧 compiler/runtime 处理。迁移需要把原来藏在 C codec 中的结构、长度规则、分支及精确限制逐项写成布局；仅修改 codec 名称或复制静态 structure_model 不会完成迁移。当前通用布局也不应导出成旧 IR，避免出现“静态通过却依赖另一套执行语义”的情况。

本轮仅完成源代码编写与静态审阅，按用户要求未执行测试、报文解码命令、服务或 fuzzing。新模块的实际正确性与兼容性尚未通过运行验证。
