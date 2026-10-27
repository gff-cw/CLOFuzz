# 描述模板与编译器一致性审查

审查日期：2026-10-25。范围为通用模板、两个 JSON Schema、Python 编译器、描述包生成/启动入口及其回归测试。协议本身的补齐和本地服务器实验另见各协议证据及集成实验文档。

## 已修复的问题

| 问题 | 原先结果 | 修复与验证 |
| --- | --- | --- |
| `role` 与 `mutability` 仅单向约束 | fixed 字段可标为 fuzzable，derived 可没有写入依赖；runtime_bound 可没有绑定来源 | 双向一致性检查；derived 恰有一个产生值的依赖；runtime_bound 必须有复制、绑定、关联或序列依赖；拒绝改写固定值的依赖 |
| 类型、定位器、方向和策略超出 C 能力 | Python 接受 `both`、未实现变量类型、变量 HEAD 或只含 AFL/resize 的 HEAD 策略，C 随后拒绝或无法执行 | BACnet 保留实际类型/定位器/服务检查；五种 TCP profile 通过同一有界 C codec 检查切片和服务。I-Am 保持线上 unconfirmed APDU 编码 |
| `example` 仅检查 BVLC 外壳 | 分段/截断 APDU、非法 NPDU 地址、错误标签嵌套、失效 Who-Is 上下限和超范围字段仍可编译 | runtime 配置使用与 C 范围一致的 NPDU/APDU/tag 检查，并读取实际字段值验证范围；静态协议仍明确仅做其封装与引用检查 |
| Python 接受空格十六进制 | `bytes.fromhex` 接受的文本无法由 C 的逐字节 reader 加载 | example 必须为连续、完整的十六进制 octet pairs；字节型 default 同样使用明确的十六进制语义；string default 按 UTF-8 字节数检查 |
| 固定字节字段被不可能条件拒绝 | 字符串 default 不可能等于整数 min/max | 静态 fixed bytes/string 的 min=max 等于 default 的字节长度；runtime 明确拒绝固定 blob 匹配，因为当前 C 匹配只实现固定标量 |
| 状态 guard 看似可消歧 | 同一 `(from,message)` 多条边在 Python 通过，C 拒绝；声明 response 却缺少真实后继边也可通过 | runtime 模型拒绝歧义边，要求非空 response 在目标状态有对应接收边；guard/actions 明确为注释 |
| 消息名/match 看似能影响匹配 | 重复 fixed 签名仅改消息名仍通过；C 总选首个模型 | 按方向、codec 服务类别、固定值和必需字段范围匹配；拒绝不等价重叠。新增 TCP profile 仅允许运行约束/依赖形状相同的别名，并报告规范映射；BACnet 重复签名仍拒绝。样例检查不证明任意报文上的模式互斥 |
| 新增 codec 与编译器分离检查 | 静态 envelope 通过不能证明内层计数、定位器和真实范围可执行 | native helper 每进程构建一次五种 C codec，以实际 validate/field/same_kind 检查；独立结构读取器仍保留。需要 C11 编译环境，在线不执行 Python |
| 输入上限不等于最终 IR 上限 | 不足 1 MiB 的输入可生成大于 1 MiB 的格式化 JSON，C 无法读取；输入预算也未计 JSON key token | 发布前检查实际 JSON 字节数、包含 key/container 的 token 数和深度；两个 IR 都通过后才写入；负测确认旧文件保持完整 |
| 深依赖图使用 Python 递归 DFS | 1,200 个合法跨消息字段依赖触发未捕获 RecursionError | 改为迭代 DFS；测试同一 1,200 字段链正常通过、闭合成环后以 SpecError 拒绝 |
| 描述包输出边界 | broken symlink 会被当作不存在；fragment 请求也会生成 replay seed | 保留一切已存在路径，包括 broken symlink；fragment 保留为静态描述并记录跳过的 seed |

## 明确的执行边界

模板、Schema 描述及每次编译输出的 `validation.json.execution_contract` 均区分执行字段和注释：

- `example` 是真实模板，字段 default 不会重写 example；运行时按 locator 查找字段，按 role 选择层。
- `match`、块层次、path、structure/structure_model、state guard/actions、invalid_strategy 均不执行。
- 字段 when/repeat 不构成通用执行器；runtime 仅接受精确的 Modbus FC0F/10 data/count repeat，其他通用构造拒绝；各 codec 处理自己的可选结构。
- 依赖 scope/when 是元数据。scope 不创建独立 transaction 缓存，when 不控制依赖是否执行。
- HEAD 标量使用配置的枚举/边界/位翻转/算术策略；CONTENT 标量使用 AFL 字节投影，不执行 strategies/values 列表。变量叶的 resize 可选择新长度，再由 codec 修复和验证；opaque 容器替换明确拒绝。
- `fixture_status` 声明完整样例或静态片段；`runtime_encode` 是能力断言，不是启停开关。只有 runtime=true 的 request 可断言 true。
- 模型通过静态编译或本次解析差分校验，不构成真实服务器服务语义、完整标准合规性或覆盖率提升的证明。

## 历史 BACnet 阶段验证

`tests/protocol/evidence/template-audit-tests.log` 记录以下两条实际命令的结果：

```bash
python3 -m unittest discover -s tests/protocol -p test_compiler.py -v
python3 -m unittest discover -s tests/protocol -p test_templates.py -v
```

此前 BACnet 阶段记录编译器 86 项及模板 14 项全部通过，包含当时六种模型重新编译后 IR/validation 字节重现。此处保留原数值，不作为本次五种 TCP codec 最终回归结果。模板测试编译真实 C runtime，并用 ASan/UBSan 检查 invoke 枚举配置为 33/77 后只改变选定字段、Who-Is 改名后仍使用实际服务 codec，以及无效编辑不会替换现有 IR。

独立解析差分脚本 `tests/protocol/evidence/template-parser-differential.py` 固定随机种子 111，生成 15,000 个封装长度一致、不同 NPDU 路由/APDU flags/tag 结构的案例，比较 Python 与真实 C decoder 的接受结果及 13 个定位器的 present/offset/width。接受 1,031 个，拒绝 13,969 个，13,403 次定位器比较，差异 0。日志 `template-parser-differential.log` 记录源文件 SHA256，可按同一脚本复跑；此项没有启动网络服务器。

## 本次五种 TCP codec 扩展

描述编译覆盖完整 UInt64、精确 abs 标量宽度、变量叶切片、内部长度/计数、等价别名、严格 Modbus repeat 和 MMS tagged_length。length/count 执行 unit、multiply、add，其他依赖不能声明未执行的变换；MMS 叶替换能改变 BER 长度头和 invoke INTEGER 编码宽度。模板/CLI 负例继续保留未知 codec、显式 runtime=false、错误传输、非法编辑和失败时保留旧 IR。

新增 C 功能夹具检查五种 TCP fuzzer/socket 路径、响应分片/合并和实际绑定；M1 前缀只模拟语义起点，连接缓存必须由真实 I/O 填入。独立 codec/runtime 测试与 `multicodec_integration.py` 的输出须分别审阅。当前文档不提前宣告最终回归全部通过，也不以本地 fixture double 代替工业产品目标互通或覆盖/吞吐收益实验。
