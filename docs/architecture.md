# 可选协议描述路径的架构

本次扩展在现有 StateAFL LLVM 18 版本上增加离线描述编译器和可选协议运行时。StateAFL 原有的覆盖率、内存快照、TLSH/MVPTree、状态选择、队列和 replay 路径继续承担反馈与调度职责。协议语义状态是独立上下文，不写入内存状态命名空间。

```mermaid
flowchart TD
    P[protocol_spec.yaml<br/>消息 / HEAD / CONTENT / 字段 / 依赖] --> C[Python schema 与语义校验]
    S[state_transition.yaml<br/>独立语义状态与边] --> C
    C --> IR[protocol_ir.json + state_ir.json]
    IR --> R[可选 C proto_engine<br/>当前仅 BACnet/IP]
    Q[原 StateAFL 队列与内存状态选择] --> M[选择 M1 / M2 / M3]
    M --> A[原 AFL 内容候选]
    M --> B[保存 M2 的显式消息边界]
    B --> R
    A --> R
    R --> L[HEAD / CONTENT / SEQUENCE]
    L --> D[序列检查 / 格式整理 / 依赖修复]
    D --> W[M2 线字节与显式 regions]
    W --> N[原网络执行 M1 + M2 + M3]
    A --> RAW[raw 或 hybrid 的 raw 分支]
    RAW --> N
    N --> T[本机目标服务]
    T --> RESP[响应与 invoke 关联 / 会话缓存]
    RESP --> R
    T --> F[原覆盖率与内存状态反馈]
    F --> Q
```

## 离线层

[proto_spec_compiler.py](../tools/proto_spec_compiler.py) 安全加载两份描述，执行 JSON Schema 及跨对象检查，生成确定性 JSON 和验证摘要。字段来源和支持级别随 IR 保留；描述中的 source URL 是证据引用，不会触发网络请求。可执行依赖类型由白名单限制，普通文本不能调用代码。语法及能力边界见 [protocol-description-language.md](protocol-description-language.md)。

每个协议目录保存源 YAML、编译 JSON、字段证据和请求 fixture。六种协议的共同中间表示便于离线比较和后续增加 codec；当前共同表示没有为其余五种协议提供在线编解码能力。

## 在线候选路径

`--protocol-spec` 和 `--state-spec` 必须成对出现。只有显式启用时才创建 `proto_engine`、协议日志和协议统计。启用后的模型必须具有 BACnet runtime 支持，并使用 UDP；当前禁止与 legacy `-P` 或 `AFL_POST_LIBRARY` 共用消息边界。

原 `fuzz_one` 继续选择队列及待变异的 M2，保留 M1 前缀和 M3 后缀。`protocol_capture` 额外保存 M2 的 LE32-length replay 记录；AFL 的输入和内容变异仍然使用不带长度前缀的线字节。`common_fuzz_stuff` 根据模式选择 raw 或结构化路径。结构化路径在 `proto_mutate` 中选层、按消息权重选记录，生成候选并检查依赖和序列。

runtime 输出是带 LE32 长度的记录；适配层解包为线字节和精确 `region_t`，再进入原 M2 替换逻辑。长度前缀仅用于磁盘/模块间边界，不作为 UDP payload 发送。结构化 SEQUENCE 可以改变 M2 消息数，因此该分支不会按旧 `max_seed_region_count` 合并多条结构化消息；适配层另检查包含 M1/M3 和 replay 前缀的完整序列不超过 MAX_FILE。M1/M3 复用仍由 StateAFL 原逻辑负责；当前不是从语义图自动搜索并重建整个会话前缀的实现。

## 格式、依赖与会话

[protocol_runtime.c](../protocol_runtime.c) 包括受限 JSON IR 读取、BACnet 动态定位、请求序列变异、依赖求值、会话标量缓存和统计。BACnet codec 检查 BVLC、可选 NPDU 地址、未分段 APDU 和 BACnet LVT 标签边界；它不把 BACnet 标签当作 BER。

构造候选时先按 codec 重组，再按依赖图修复本地长度/计数/偏移/校验和及可解析的缓存绑定，最后序列化。该过程在临时模拟会话执行，结束时恢复 live cache。每次 `send_over_network` 开始调用 `proto_session_begin` 清除真实会话缓存和 outstanding invoke 集合。

结构化发包前使用 `proto_before_send` 处理会话绑定，接收新响应字节后用 `proto_after_response` 更新字段缓存和相关响应计数。消息标记区分本次结构化 M2 与继承的 M1/M3；后者可能包含 raw 消息，解析失败时按原样发送。故意破坏的 BVLC 长度不能在发包前重新修复。缓存键包含消息 ID 和字段 ID；当前不是通用事务数据库，不支持任意响应内容编码或执行 guard/action 字符串。

## 两条状态通路

| 通路 | 来源及职责 | 输出 |
| --- | --- | --- |
| StateAFL 内存状态 | LLVM 18 插桩的目标长期对象快照，TLSH/MVPTree 推断，原状态/种子选择 | 原 IPSM 图、内存状态 ID 和队列注解 |
| 协议语义状态 | 用户描述的状态和消息边；runtime 会话、请求序列检查及响应观察 | 独立 `protocol_semantic_state` 和协议日志/统计 |

协议模型中的 `ready`、`pending` 等名字不代表 StateAFL 已观察到相同数量的内存状态。语义状态图可达不证明目标行为正确；非零 invoke 关联计数也不证明覆盖增加。两种反馈应分别检查和报告。

## 日志、关闭行为和验证

`protocol_mutations.jsonl` 记录成功候选、拒绝及显式 fallback；`protocol_stats.json` 记录 runtime 层计数、响应、关联响应和独立语义状态。`fuzzer_stats` 保留原反馈指标，并在启用时补充 raw/structured/rejection 计数。候选成功、实际网络执行、响应、覆盖发现属于不同阶段，应按相应产物解释。

没有提供描述文件时，协议 engine 不创建，候选继续走现有 AFL 路径。新增模块被链接进 fuzzer 不等于启用结构化变异。generic replay 读取新增了显式小端解码及截断/零长度检查，保存路径清空旧文件并显式写入 LE32 长度。共享网络层确保每条 UDP 消息一次发送，使用 65536 字节接收缓冲并检测截断；这些共享路径改动需要同时验证关闭功能的兼容性。

LLVM 18 工具链、New PM 插桩及原内存运行时保持现有移植设计；本次协议层不引入替代 LLVM 工具链。[LLVM18_MIGRATION_AUDIT.md](../LLVM18_MIGRATION_AUDIT.md) 和 [LLVM18_TEST_REPORT.md](../LLVM18_TEST_REPORT.md) 是既有证据，不能替代本次修改后的回归。当前结果和未完成项见 [implementation-review.md](implementation-review.md) 及 [BACnet 集成验证](bacnet-integration-test.md)。


## 模板与按描述目录启动

用户先参考 `protocols/templates/*.template.yaml` 的统一结构，或用 `tools/init_protocol_spec.py --base <协议配置> --output-dir <目录>` 生成已经填入真实协议字段的描述包。模板是填写起点，schema 是检查规则，各协议目录是实例；三者不混用。生成器不使用 YAML 别名，避免一处字段修改联动另一条消息。

`tools/run_protocol_campaign.py --spec-dir <目录> -- <afl-fuzz参数>` 每次读取两份 YAML，校验字段/依赖/状态，重新编译对应 IR，然后使用 `os.execv` 把控制权交给原 afl-fuzz。无效配置或仅静态支持的协议在目标启动前失败，不使用旧 IR 继续执行。手工编译后传入两个原 CLI 参数的方式仍然可用。

当前六种协议的统一描述均可生成与校验；在线codec仍只有BACnet有限范围。Who-Is 内容编码器不再按描述消息ID判断，改按解析得到的APDU服务类型判断，使消息重命名与线编码解耦。模板填写不自动实现尚未存在的协议编码器。
