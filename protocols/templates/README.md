# 协议描述模板、能力契约与准备流程

本目录按实际加载入口提供旧 codec YAML、在线 generic-wire JSON 和离线检查 JSON 模板。各自语法由对应 schema/loader 约束。

| 格式 | 输入与执行路径 | 能力边界 |
| --- | --- | --- |
| ICP-IR v1 YAML | 两份 YAML → compiler → IR 对 → 已有 C codec | schema 统一结构、profile 提供真实值；递归契约与高级片段见 [legacy_contract](legacy_contract/README.md)。 |
| `stateafl.offline-layout` / 原生观测 JSON | `native_layout.template.json` / `native_observations.template.json` → 本地检查 | 被动解码与观测检查；没有在线编码、变异或网络执行能力。 |
| `stateafl.generic-wire` v1 JSON | [正式模板](generic_wire.template.json) 与 [UDP/TCP 完整输入示例](generic_wire_examples/README.md) → 通用 C 引擎 | 独立 [online schema](../schema/generic_wire.schema.json)、fixture/seed 清单及显式刷新工具；语义仍由 C loader 检查。 |

完整的三格式十维度能力对比矩阵与边界定义参见 [三种协议描述格式能力矩阵与识别边界](../../docs/format-capability-matrix.md)。

修复前依据见[模板复核](../../docs/template-unification-review-20261104.zh-CN.md)。五个缺口的实际改进、编译范围及运行验收条件见[模板体系修复记录](../../docs/template-system-repair-20261104.zh-CN.md)。

### 模板字段与执行语义

模板字段不能只按名称判断是否执行。旧 YAML 中 `role/mutability`、locator、字段范围、支持的依赖和迁移边参与加载或执行；`values` 是 HEAD 候选值，不是封闭解析枚举。状态 `guard/actions`、依赖 `scope/when`、`default`、`structure` 等为说明或静态元数据，不运行表达式，也不会统一因出现而拒绝。runtime=true 的字段 `when` 及一般 `repeat` 则拒绝，只有精确匹配 codec 管理的 Modbus FC0F/10 data/count 描述例外。generic-wire 的严格 JSON 键规则与这套 YAML 不同。详细分类和真实容量见[格式矩阵](../../docs/format-capability-matrix.md)。

描述中的协议模型状态不是 StateAFL 内存状态。受控目标如需逐消息内存边界，须按共享 ABI v3 契约在完整应用消息处理后显式调用 `trace_message_boundary()`；当前限定单进程、单线程。模板不会自动推导该边界，没有提供者仍为 UNKNOWN。当前两套在线 runtime 按单 pending 使用，不提供一般并发事务队列。

[native_layout.template.json](native_layout.template.json) 和 [native_observations.template.json](native_observations.template.json) 用于 [C 原生本地检查](../../docs/native-inspection.md)。前者是虚构结构示例，后者需填写实际摘要及作用域；均不启动目标。离线布局支持某种结构，不代表在线引擎具备相应解析、编码或变异能力。

旧的独立 Python 布局和编辑计划模板已移除。C 本地检查使用上述两个 JSON 模板；下面的 YAML 模板仍用于现有 ICP-IR 编译流程，不能把两种格式混用。

下面的带注释 YAML 及 `protocol_spec.schema.json/state_transition.schema.json` 属于 ICP-IR 路径；`generic_wire.schema.json` 单独约束在线 generic-wire。离线 JSON 由其原生 loader 检查，不能混用上述 schema。

- [protocol_spec.template.yaml](protocol_spec.template.yaml)：消息、HEAD/CONTENT、字段、取值策略、长度/跨消息依赖、协议来源。
- [state_transition.template.yaml](state_transition.template.yaml)：独立语义状态、消息边、请求/响应关系、序列上限。

`{{...}}` 必须替换为真实协议内容；模板中的 command/length/payload 是字段形状示例，不是任意工控协议通用的线格式。空白模板不能直接启动测试。两份 YAML 的 protocol_id 必须相同。

### 新通用引擎的填写入口

```sh
python3 tools/generic_template_catalog.py --base tcp_request_response \
  --protocol-id my_protocol --output-dir /tmp/my-generic-protocol
python3 tools/generic_template_catalog.py --check-package /tmp/my-generic-protocol
```

可选 `udp_oneway/udp_request_response/tcp_request_response`。编辑模型及清单中的请求路径后，显式运行 `--refresh-corpus /tmp/my-generic-protocol` 更新包内受管理 fixture/seed。静态检查不会启动目标或认证其他 `-i` 目录；实际 `--generic-spec` 加载仍检查 wire、引用、framing 与状态语义。完整步骤见[示例目录](generic_wire_examples/README.md)。

### 最小完整源码包

[minimal_runnable_example](minimal_runnable_example/README.md) 提供独立受控 Modbus TCP 夹具、静态输入、只编译 Makefile，以及从具体 YAML 生成正式包的完整步骤。入口为 `--source-dir`；运行验收与源码材料分别记录。

## 1. 复制已有 profile 的描述包

在 stateafl 根目录运行：

```bash
python3 tools/init_protocol_spec.py --list
python3 tools/init_protocol_spec.py \
  --base bacnet_ip \
  --protocol-id my_bacnet_target \
  --require-runtime \
  --output-dir ./my-specs/bacnet_ip
```

工具依据 schema 递归检查骨架和源 profile 的必需项及额外键，并保留全部允许属性。真实字段、默认值、依赖与状态来自具体 profile，骨架的嵌套演示值不会覆盖它们。输出 `template_contract.json` 记录源文件、schema、模板与能力片段摘要。输出目录必须尚不存在；字段独立展开，不使用 YAML 引用别名。

生成器将原始单包报文保存到 `fixtures/requests/<消息ID>.replay`。`seeds/<消息ID>.replay` 则通过有界图搜索，从 `initial` 开始补上该请求可达所需的请求前缀；每步严格按旧 runtime 的 request edge 与一次 expected-response edge 投影状态，不把响应字节写入种子。例如 MMS Read 前有 COTP CR 与 associate，OPC UA message 前有 HEL 与 OPN。canonical aliases 共用 repeat 预算，LE32 前缀计入 `max_bytes`，同时限制 `max_messages/max_repeat/MAX_FILE`。不可达、片段、缺少可解析响应模型或搜索预算耗尽时，只保留 fixture，并在 `seed_manifest.json` 写明原因。

manifest 记录每个种子的请求 ID 序列、模型状态、响应投影和字节数。它证明声明模型内的可达性，不能证明实际目标接受该会话；`guard/actions`、外部 ForwardOpen、响应中分配的 session/channel/token 值均没有在离线规划中验证。响应示例只提供解析能力依据，实际运行仍须由真实目标响应满足相关与绑定条件；没有伪造现场响应。编辑 YAML 后需重新规划种子；单独重编译 IR 不会自动更新已有种子。

重编译修改后的 YAML 后，执行 `python3 tools/protocol_seed_planner.py --spec-dir ./my-specs/bacnet_ip` 更新生成的 corpus。这个纯文件转换入口核对 YAML、保存的 IR 对及 bundle identity，使用已有 `validation.json` 快照，不调用编译器、native helper 或目标；不会重新证明 codec 验证结论。它替换包中受管理的 `seeds/*.replay` 与 `fixtures/requests/*.replay`，自定义语料请另放目录。

`--base` 可选六种已有协议配置：bacnet_ip、modbus_tcp、iec60870_5_104、iec61850_mms_tcp、ethernet_ip_cip_tcp、opcua_tcp。它不会自动从标准网页推导协议；真实字段由各协议配置提供。六种参考 profile 均有有界旧版 C runtime codec，`--require-runtime` 可用于任一配置；显式设为 runtime=false 的静态描述仍会被拒绝。这里的 runtime 能力声明属于旧 codec 路径，不是对应 `generic_wire.json` 的在线资格。BACnet 使用 UDP，其余五种使用 TCP。支持的是描述中列出的服务与叶字段，新增服务仍需相应 codec 实现。

## 2. 按被测实现修改生成的 YAML

其他具体 YAML 输入对可用 `--source-dir <目录>` 代替 `--base`，两者互斥；仍须通过现有 codec 与 compiler 校验，不产生新编码器。新实例化包要求显式声明每条消息的 `fixture_status/runtime_encode`，旧 compiler 的缺省兼容单独保留。

依次填写/检查：

1. 协议版本、传输方式、测试服务和范围。
2. 每种消息完整的 `example` 十六进制线报文；不含 StateAFL 的 LE32 外层长度。
3. HEAD/CONTENT 字段及固定字段、定位器、类型、宽度、大小端。
4. 字段 `min/max/values/strategies` 和消息 `weight`。
5. 长度、计数、复制和响应绑定等 `dependencies`。
6. 真实状态与迁移、请求响应关联、序列上限。

例如，在生成的 BACnet ReadProperty 消息中，将 invoke_id 的枚举变异候选改为：

```yaml
id: invoke_id
# 其余字段信息保留，包括 role: head、mutability: fuzzable、min/max 等
values: [33]
strategies: [enum]
```

当 HEAD 选择该字段时会使用描述中的 33；改为 `[77]` 后会使用 77。其他可变 HEAD 字段仍可能被选择。这里的 `values` 是枚举策略的候选集合，不能单独代替输入解析的值域约束。固定字段受保护，派生长度由依赖修复。既有旧版 C runtime 测试记录验证了“只允许 invoke_id 变异”的两份配置分别得到 33 和 77，其他报文和外层封装字节不变；这不是新通用引擎的验证结果。

消息 ID 可以更名，但必须同步更新状态边和跨消息引用；编码器按实际协议类型/服务选择，已验证 Who-Is 更名后 CONTENT 变异不受影响。

字段定位由已有 codec 解析，不只依靠固定偏移。新增另一种编码或未实现的服务，需要扩展对应 codec；仅填写一个 locator 名称不能自动生成解析器。`match/default/guard/actions` 等字段的执行边界见 [语言文档](../../docs/protocol-description-language.md)。

## 3. 直接选择描述目录启动

编辑生成包后，先重编 IR，再显式刷新受管理语料：

```sh
python3 tools/proto_spec_compiler.py \
  --protocol ./my-specs/bacnet_ip/protocol_spec.yaml \
  --state ./my-specs/bacnet_ip/state_transition.yaml --output-dir ./my-specs/bacnet_ip
python3 tools/protocol_seed_planner.py --spec-dir ./my-specs/bacnet_ip
```

包装器先临时编译当前模型，再只读核对 validation、manifest、fixtures 和 seeds；陈旧或缺失时拒绝并保留原 IR 和语料，通过后才发布 IR。包内受管理 `-i` 与该模型关联；外部 `-i` 单独检查分帧和可验证预算，不认证协议语义或改写输入。`-i -` 的恢复快照由宿主在输出锁内核验。

准备期间还会在读取前、加载后和发布前比较 YAML 摘要，拒绝编译期间发生的编辑；这不锁定发布后的外部编辑。旧输出的异常 queue/.state 标记与意外权威快照项也会提前拒绝。

旧 codec 路径的入口每次从所选目录读取两个 YAML，校验并重编译旧版 IR，然后用 `--protocol-spec` / `--state-spec` 启动原 afl-fuzz。它不会改用 `--generic-spec`。无需手工修改 C 代码来切换已有 codec 所支持的描述包：

```bash
BACNET_IFACE=lo BACNET_IP_PORT=47818 \
setarch "$(uname -m)" -R python3 tools/run_protocol_campaign.py \
  --spec-dir ./my-specs/bacnet_ip -- \
  -d -i ./my-specs/bacnet_ip/seeds -o /tmp/bacnet-described-run \
  -N udp://127.0.0.1/47818 -D 200000 -E -K -q 3 -s 3 -m none -t 5000 \
  --mutation-mode hybrid --mutation-layers head,content,sequence \
  -- ../bacnet-stack/build-protocol-integration/server 123
```

`--spec-dir` 决定加载哪个描述包，后面的 `--` 将其余参数交给原 afl-fuzz。再后面的 `--` 分隔目标程序参数。输出目录应使用新的路径。上例只连接本机已有 BACnet 测试目标。

预览最终启动参数而不启动目标（仍检查模型与所选 `-i` 并编译 IR）：

```bash
python3 tools/run_protocol_campaign.py --spec-dir ./my-specs/bacnet_ip \
  --print-command -- -i ./my-specs/bacnet_ip/seeds -o /tmp/bacnet-run \
  -N udp://127.0.0.1/47818 -- /path/to/server 123
```

仅校验/编译模型（返回 model_only，不检查语料或启动目标）：

```bash
python3 tools/run_protocol_campaign.py --spec-dir ./my-specs/modbus_tcp --validate-only
```

错误描述会在运行目标前失败；不会跳过错误后使用旧 IR，也不会因为某个静态模型被选中就静默改用 raw 模式。

## 4. 也可以手工编译后加载

```bash
python3 tools/proto_spec_compiler.py \
  --protocol ./my-specs/bacnet_ip/protocol_spec.yaml \
  --state ./my-specs/bacnet_ip/state_transition.yaml \
  --output-dir ./my-specs/bacnet_ip

# 将以下两个选项加入原有 afl-fuzz 命令：
# --protocol-spec ./my-specs/bacnet_ip/protocol_ir.json
# --state-spec ./my-specs/bacnet_ip/state_ir.json
```

模板的结构在六种旧 codec 配置中相同；各协议的字段、编码和状态定义不同。六种已有 profile 可通过旧路径加载并进行限定范围的在线变异。五种 TCP 路径的既有仪器化 C fixture double 和本地功能测试用于检查 fuzzer/socket 路径、字段变化和响应绑定。真实工业服务目标的既有证据仍是 BACnet Stack，不把 C 夹具当作其他五种工业产品的互通或标准合规证明，也不据此认定六份新通用描述已经在线验证。

`tools/build_generic_wire_profiles.py` 是六份迁移子集的专用生成脚本，不是 YAML 到通用语法的编译器。它读取旧 `protocol_ir.json`，不读取 `state_ir.json`；消息选择、状态边和关联规则由脚本中的固定配置给出，部分复杂结构保留为样例固定字节。因此修改 YAML 的状态图、依赖或绑定，并不保证在新 JSON 中得到等价转换。六份新描述的在线资格与遗漏服务见[迁移范围](../../docs/generic-wire-profile-scope.md)。

## 5. 配置的执行边界

`protocol_spec.template.yaml` 与 `state_transition.template.yaml` 是待填写骨架，不能直接编译。完整参考输入是六个 `protocols/<协议>/protocol_spec.yaml` / `state_transition.yaml`；使用 `tools/init_protocol_spec.py --base <协议> --output-dir <新目录>` 复制它们，可保留字段证据、状态边和真实报文，避免把骨架里的演示布局当成协议。

| 配置 | 当前含义 |
| --- | --- |
| `support.runtime` | 当前 C codec 是否可用。六种参考 profile 均可用；设为 false 的静态模型不能启动定向变异。 |
| 消息 `fixture_status` | `complete` 为声明范围内完整消息；`fragment` 为静态片段，不能用于 runtime=true，也不生成 replay seed。新实例化包要求显式声明；旧 compiler 的缺省兼容按 complete 处理。 |
| 消息 `runtime_encode` | 能力断言：仅 runtime=true 的 request 为 true。它不是开关，不能靠它开启静态协议或禁用请求。 |
| `role` / `mutability` | `fixed`、`derived` 必须双向一致；derived 恰有一个依赖写入者；runtime_bound 必须有绑定、关联或序列依赖。 |
| `locator` / `path` | `locator` 参与执行，`path` 只是说明。各 codec 解析实际结构和精确切片；abs 标量严格取声明宽度，变量字段不吞入相邻字段。 |
| `example` / `default` | `example` 是完整单报文模板，连续十六进制、不含 replay LE32 前缀；`default` 只是字段默认值说明，不会重写模板。字节型 default 为十六进制，string 为 UTF-8 文本。 |
| `blocks` / 字段 `block` | 编译器检查分组与引用；运行时按字段 role 选择 HEAD / CONTENT，不解释任意块层次。 |
| `strategies` / `values` | HEAD 标量执行枚举、边界、位翻转、算术；空列表使用默认策略。CONTENT 标量投影 AFL 字节；变量叶的 resize 允许在范围内调整长度并交给 codec 验证。 |
| `structure_model` / `structure` | 有界、类型化的结构元数据，不是编码程序；其中 condition 不执行。 |
| 字段 `when` / `repeat` | 通用构造在 runtime=true 下拒绝；唯一 repeat 例外是精确匹配 FC0F/10 data/count 的 Modbus 描述。各 codec 处理自身可选结构。 |
| 依赖 `scope` / `when` | 注释；不创建按 scope 区分的缓存，也不执行条件。缓存按 engine、消息、字段保存最近标量和 pending 请求；绑定须来自实际响应并满足声明关联。 |
| 状态 `guard` / `actions` | 注释；运行时按当前 state 和 message 选择边，不按 guard 消歧或执行 actions。运行时同一 `(from,message)` 只能有一条边。 |
| `invalid_strategy` | 描述性说明；当前 invalid/near_valid 在修复后修改一条对应协议长度为原值+1，不解释该字符串。 |

编译器检查引用、完整报文、实际字段范围和消息匹配。非 BACnet runtime 编译通过 native helper 使用同一 C validator；BACnet 保留专用 NPDU/APDU/tag 检查。`validation.json` 的 `execution_contract` 明确列出静态元数据与运行时限制。通过这些检查不等于经过真实目标的成功交换，也不等于覆盖整个协议标准。

高级写法及机器分类见 [legacy_contract/capabilities.json](legacy_contract/capabilities.json) 与 [advanced_fragments.yaml](legacy_contract/advanced_fragments.yaml)。清单覆盖全部 schema 字段属性与十种依赖操作，区分执行字段、HEAD 策略、静态说明和 codec 特例；片段带真实上下文或明确的语法示范范围，不作为自动合并的整个协议包。

非 BACnet 编译需 C11 编译器（`CC` 或 `cc`）、`tools/native_protocol_codecs.py`、`protocol_codecs.h` 和五个 `protocol_codec_*.c`。helper 每进程在临时目录构建一次；StateAFL 在线直接执行 C，不在每次变异运行 Python。标量支持完整 UInt64 范围。

变量 CONTENT 仅支持 codec 明确实现的叶替换，不能复制任意 opaque CIP/UA/BER 容器。MMS 叶变化会重新编码祖先 BER/session 长度和必要的 INTEGER 宽度。运行时按 TCP 协议长度处理响应分片与合并；M1 前缀仅提供模拟语义起点，session/channel/token 等仍绑定实际响应。生成器提供离线模型请求前缀搜索；运行时没有目标交互式前缀探测、任意 guard/actions 或完整多事务数据库。
