# 统一描述模板 → 具体协议描述 → 加载定向变异

这里是用户填写协议描述的起点。JSON Schema 是格式检查规则；本目录的带注释 YAML 才是可复制、填写的模板。

- [protocol_spec.template.yaml](protocol_spec.template.yaml)：消息、HEAD/CONTENT、字段、取值策略、长度/跨消息依赖、协议来源。
- [state_transition.template.yaml](state_transition.template.yaml)：独立语义状态、消息边、请求/响应关系、序列上限。

`{{...}}` 必须替换为真实协议内容；模板中的 command/length/payload 是字段形状示例，不是任意工控协议通用的线格式。空白模板不能直接启动测试。两份 YAML 的 protocol_id 必须相同。

## 1. 根据模板生成某个协议的完整描述包

在 stateafl 根目录运行：

```bash
python3 tools/init_protocol_spec.py --list
python3 tools/init_protocol_spec.py \
  --base bacnet_ip \
  --protocol-id my_bacnet_target \
  --require-runtime \
  --output-dir ./my-specs/bacnet_ip
```

工具按统一模板的顶层结构，填入现有 BACnet 的真实字段、定位器、消息和状态定义，同时生成初始 IR、来源和种子。输出目录必须尚不存在；不会覆盖现有描述。生成的字段独立展开，不使用 YAML 引用别名，修改一个消息不会意外修改另一个消息。

`--base` 可选六种已有协议配置：bacnet_ip、modbus_tcp、iec60870_5_104、iec61850_mms_tcp、ethernet_ip_cip_tcp、opcua_tcp。它不会自动从标准网页推导协议；真实字段由各协议配置提供。当前只有 BACnet 有在线 codec；其他五种可生成、编辑和静态校验，不能启动定向变异。`--require-runtime` 会提前拒绝这些静态配置。

## 2. 按被测实现修改生成的 YAML

依次填写/检查：

1. 协议版本、传输方式、测试服务和范围。
2. 每种消息完整的 `example` 十六进制线报文；不含 StateAFL 的 LE32 外层长度。
3. HEAD/CONTENT 字段及固定字段、定位器、类型、宽度、大小端。
4. 字段 `min/max/values/strategies` 和消息 `weight`。
5. 长度、计数、复制和响应绑定等 `dependencies`。
6. 真实状态与迁移、请求响应关联、序列上限。

例如，在生成的 BACnet ReadProperty 消息中，将 invoke_id 的允许枚举策略改为：

```yaml
id: invoke_id
# 其余字段信息保留，包括 role: head、mutability: fuzzable、min/max 等
values: [33]
strategies: [enum]
```

当 HEAD 选择该字段时会使用描述中的 33；改为 `[77]` 后会使用 77。其他可变 HEAD 字段仍可能被选择。固定字段受保护，派生长度由依赖修复。测试已通过 C runtime 验证“只允许 invoke_id 变异”的两份配置分别得到 33 和 77，其他报文和外层封装字节不变。

消息 ID 可以更名，但必须同步更新状态边和跨消息引用；编码器按实际协议类型/服务选择，已验证 Who-Is 更名后 CONTENT 变异不受影响。

字段定位由已有 codec 解析，不只依靠固定偏移。新增另一种编码或未实现的服务，需要扩展对应 codec；仅填写一个 locator 名称不能自动生成解析器。`match/default/guard/actions` 等字段的执行边界见 [语言文档](../../docs/protocol-description-language.md)。

## 3. 直接选择描述目录启动

推荐入口每次从所选目录读取两个 YAML，校验并重编译 IR，然后用这些 IR 启动原 afl-fuzz。无需手工修改 C 代码来切换已支持的描述包：

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

预览最终启动参数而不启动目标：

```bash
python3 tools/run_protocol_campaign.py --spec-dir ./my-specs/bacnet_ip \
  --print-command -- -i ./my-specs/bacnet_ip/seeds -o /tmp/bacnet-run \
  -N udp://127.0.0.1/47818 -- /path/to/server 123
```

仅校验/编译（包括其他五种静态配置）：

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

统一模板的结构在六种具体协议配置中相同；各协议的字段、编码和状态定义不同。当前“可加载、可在线变异”只验证了 BACnet 有限范围，不等于其他五种协议已完成在线运行时。

## 5. 配置的执行边界

`protocol_spec.template.yaml` 与 `state_transition.template.yaml` 是待填写骨架，不能直接编译。完整参考输入是六个 `protocols/<协议>/protocol_spec.yaml` / `state_transition.yaml`；使用 `tools/init_protocol_spec.py --base <协议> --output-dir <新目录>` 复制它们，可保留字段证据、状态边和真实报文，避免把骨架里的演示布局当成协议。

| 配置 | 当前含义 |
| --- | --- |
| `support.runtime` | 当前 C codec 是否可用。目前仅 BACnet/IP；静态模型通过编译不代表有执行器。 |
| 消息 `fixture_status` | `complete` 为声明范围内完整消息；`fragment` 为静态片段，不能用于 runtime=true，也不生成 replay seed。省略时兼容旧描述，按 complete 处理。 |
| 消息 `runtime_encode` | 能力断言：仅 runtime=true 的 request 为 true。它不是开关，不能靠它开启静态协议或禁用请求。 |
| `role` / `mutability` | `fixed`、`derived` 必须双向一致；derived 恰有一个依赖写入者；runtime_bound 必须有绑定、关联或序列依赖。 |
| `locator` / `path` | `locator` 参与执行，`path` 只是说明。BACnet 动态定位由专用解析器完成。 |
| `example` / `default` | `example` 是完整单报文模板，连续十六进制、不含 replay LE32 前缀；`default` 只是字段默认值说明，不会重写模板。字节型 default 为十六进制，string 为 UTF-8 文本。 |
| `blocks` / 字段 `block` | 编译器检查分组与引用；运行时按字段 role 选择 HEAD / CONTENT，不解释任意块层次。 |
| `strategies` / `values` | HEAD 标量执行配置的枚举、边界、位翻转、算术；空 strategies 使用四种默认策略。CONTENT 标量投影 AFL 候选字节，不执行此列表。 |
| `structure_model` / `structure` | 有界、类型化的结构元数据，不是编码程序；其中 condition 不执行。 |
| 字段 `when` / `repeat` | 静态结构描述及引用检查；runtime=true 拒绝这些通用构造。BACnet 可选字段由专用 codec 处理。 |
| 依赖 `scope` / `when` | 注释；不创建按 scope 区分的缓存，也不执行条件。当前缓存按 engine、消息、字段保存最近标量。 |
| 状态 `guard` / `actions` | 注释；运行时按当前 state 和 message 选择边，不按 guard 消歧或执行 actions。运行时同一 `(from,message)` 只能有一条边。 |
| `invalid_strategy` | 描述性说明；当前 invalid/near_valid 实现固定修改一条 BVLC 长度，不解释该字符串。 |

编译器检查静态引用、数值边界和协议封装长度；运行时 BACnet 还检查专用 NPDU/APDU/tag 结构、例子的字段范围、方向及可用编码器。`validation.json` 的 `execution_contract` 明确列出静态元数据与运行时限制。通过这些检查不等于经过真实目标的成功交换，也不等于覆盖整个协议标准。
