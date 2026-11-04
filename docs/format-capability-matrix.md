# 三种描述格式的能力与模板边界

本项目有三种格式。它们共享部分用途词汇，不共享全部语法或执行语义。下表依据当前 C loader、编译器和模板源码，不表示本轮已运行验证。

| 维度 | 旧 ICP-IR v1 / 专用 codec | 被动 native-layout | generic-wire v1 |
| --- | --- | --- | --- |
| 格式 | YAML 经 `proto_spec_compiler.py` 生成配对 `stateafl.protocol-ir`、`stateafl.state-ir`，`ir_version:1` | `stateafl.offline-layout`，`version:1` | 自包含 `stateafl.generic-wire`，`version:1` JSON |
| 入口 | `--protocol-spec` 与 `--state-spec` | 本地只读检查工具 | `--generic-spec` |
| 解析/编码 | 六种已有 codec 实现的限定服务和叶字段；新增编码仍需 codec | 固定偏移、位域及有界容器的只读断言；不编码 | 顺序平铺 struct，uint 与 bytes；无专用协议名称分派 |
| 变异 | HEAD/CONTENT/SEQUENCE，依赖实际 codec 叶替换和修复能力 | 无在线变异 | HEAD/CONTENT/SEQUENCE；CONTENT 仅投影声明字段并遵守 grammar 范围，不是任意未约束负载 |
| 派生/绑定 | 白名单依赖，包括长度、复制、序号、实际响应绑定/关联；依赖 scope/when 为注释 | 长度/计数引用用于检查 | `size_of` 消息或字段字节长度，加 signed add；bytes 长度可引用前置 uint；无一般服务器会话值绑定 |
| 状态 | 旧 IR 独立模型状态及显式响应边；不等同目标内存状态 | 无在线状态机 | 确定性请求边及可选预期响应；不等同目标内存状态 |
| 响应关联 | 有界 cache/outstanding，当前按单 pending 使用；不是并发事务数据库 | 无 | 响应消息的 `correlate` 数组，以 `request`、`source`、`field` 表示整数相等规则；单 pending |
| TCP/UDP | codec 分帧与独立 UDP 回调，磁盘 replay 外封装另计 | 无网络执行 | TCP `length_field` 或 UDP `datagram`；接收数据报截断是观察不完整 |
| 源码硬上限 | 128 消息模型、每消息64字段、64状态、256迁移、64条 replay 记录、单 wire 65,507字节；序列最大 `MAX_FILE`（1 MiB），声明可更小 | 输入和容器有独立预算，不能套用在线预算 | 128 消息模型、每 grammar 256字段、64状态、256迁移、16关联规则/消息、64条 replay 记录、单 wire 65,507字节；序列最大 `MAX_FILE`（1 MiB），声明可更小 |
| 资格/范围 | 六份旧 profile 的有界 codec 路径；不表示完整工业协议 | offline-only | 引擎支持原语可表达的自定义描述；随仓六份迁移 profile 仅 Modbus FC03 单寄存器子集为 online，其余五份 offline-only |

资源数值分别见 [protocol_runtime.c](../protocol_runtime.c)、[generic_runtime.c](../generic_runtime.c)、[generic_wire.c](../generic_wire.c)，不可将消息模型数、单次序列记录数或字段数混写。通用 grammar 的 uint 宽度为1至8字节；TCP framing 长度字段宽度为1至4字节。资源边界不增加语言表达能力。

## 旧 YAML 字段的实际分类

- **参与执行或加载校验**：ID、方向、字段 role/mutability、类型/宽度/字节序、locator、min/max、supported dependencies、模型迁移边。`values` 是 HEAD 候选值，不是解析枚举值域；CONTENT 标量使用 AFL 投影，不解释任意策略脚本。
- **用于一致性或能力断言**：protocol_id、版本、runtime_encode、support.runtime、成对 bundle 声明。共同 digest 表示包配对声明，运行时不据此认证实际执行映像；它不是数字签名。
- **说明性或静态元数据**：description、path、default、structure_model/structure、状态 meaning/guard/actions、invalid_strategy、依赖 scope/when。这些字段可被编译器保留或检查，不能声称它们全被拒绝，也不能声称运行时执行表达式。guard 不消歧，等价边规范化之后 `(from,message)` 仍须唯一。
- **runtime=true 不支持的通用结构**：字段 when 拒绝；通用 repeat 拒绝，只有精确匹配 codec 管理的 Modbus FC0F/10 data/count 描述例外。静态描述与在线描述边界不同。未知代码钩子不能作为语言扩展方式。

以上分类专指旧 YAML/IR。generic-wire 使用严格 JSON 键白名单，unknown 属性以及 `guard`、`actions`、条件字段、array/choice 等不在当前语法内的结构会被拒绝。离线布局支持 repeat/位域不表示两种在线路径具备相同能力。

## 加载和模板隔离

旧 `proto_load` 要求 IR 版本正确；若有 format，须与 protocol/state IR 对应，generic-wire/offline-layout 不能代替。`gr_load` 要求正确 format/version 和全部必需键，拒绝 `online:false`。`online:true` 只是描述声明，不能由一个布尔值推导协议实现完整；loader 不会识别任意 profile 的全部缺失标准语义。

[模板目录](../protocols/templates/README.md)分别提供旧 codec YAML、在线 generic-wire starter/UDP/TCP 输入包和被动布局/观察 JSON。旧格式新增 schema 驱动的递归形状与来源契约、能力片段及 `--source-dir`；generic-wire 有独立 online schema 和显式语料刷新工具。没有一般 YAML→generic-wire 无损翻译器，六 profile 迁移器仍有固定消息、状态和关联表。最新实现与验证范围见[模板修复记录](template-system-repair-20261104.zh-CN.md)。

所有在线描述都与 StateAFL 的内存边界提供者分开。共享 ABI v3 的 `trace_message_boundary()` 只供受控单进程、单线程目标在应用消息处理完成后按序调用；没有有效提供者时 region 为 UNKNOWN，不能拿协议模型状态替代。实际 wire 的默认确认策略为精确相等，不静默掩码会话字段。

源码修复与尚未执行的验证见[修复清单](repair-status-20261102.md)。
