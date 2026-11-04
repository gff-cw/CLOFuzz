# 五个模板缺口的实现与交接

分支：`feature/description-driven-c-engine-20261027`。起点：`bc65bbc`；生产源码与描述审计基线为 `7f165ba`。本轮由三个 agent 分别实现 generic-wire 模板、旧格式模板契约和语料启动门控；交叉复核阶段再由三个 agent 检查并补强对应模块，主 agent 整合导出、文档、最小夹具并复核编译。修复前问题与证据保留在[模板统一性审查](template-unification-review-20261104.zh-CN.md)。

**五个缺口已落实为工具、模板、语料材料和回归源码。验证范围为静态检查与编译，没有运行新增工具、描述编译器/原生 validator、单元测试、示例或目标服务。** 下文“实现”不等于已运行验收。原有六协议生产模型、codec 能力和历史证据未因此扩展。

| 原缺口 | 本轮实现 | 直接入口 |
| --- | --- | --- |
| 模板与生成器的关系不完整，通用引擎缺专用模板 | schema 负责结构，具体 profile 负责真实值。旧生成器递归核对模板及 profile 的必需项、额外键、对象/数组结构，保留所有允许属性；模板值不静默覆盖真实 wire。输出来源契约。新增正式 generic-wire 模板、独立 online schema 和三套输入包。 | [protocol_template_contract.py](../tools/protocol_template_contract.py)、[init_protocol_spec.py](../tools/init_protocol_spec.py)、[generic_wire.schema.json](../protocols/schema/generic_wire.schema.json)、[generic_wire.template.json](../protocols/templates/generic_wire.template.json) |
| 高级语法示例不齐 | 提供19个组件片段、10种依赖操作的上下文、约束和来源。真实摘录携带原 profile SHA256；offset/checksum 等语法示范明确不声称已有工业 wire。 | [legacy_contract](../protocols/templates/legacy_contract/README.md)、[advanced_fragments.yaml](../protocols/templates/legacy_contract/advanced_fragments.yaml) |
| 声明字段与执行能力混淆 | 机器清单覆盖 schema 中全部字段属性及依赖操作，区分执行、HEAD 策略、经过校验的说明、静态条件和 codec 特例。实例化要求显式 fixture_status/runtime_encode，来源文件与 schema/模板/片段摘要写入 template_contract.json。 | [capabilities.json](../protocols/templates/legacy_contract/capabilities.json) |
| 修改模型后可能带旧语料启动 | 包装器临时编译当前模型，只读比较当前编译结果、model manifest、fixtures、seeds 和所选输入范围；拒绝时不发布新 IR，不改写语料。导出器复用同一 managed-corpus 检查。 | [protocol_corpus_contract.py](../tools/protocol_corpus_contract.py)、[run_protocol_campaign.py](../tools/run_protocol_campaign.py)、[export_protocol_bundle.py](../tools/export_protocol_bundle.py) |
| 最小示例缺完整运行材料 | 新增受控单进程/单线程 Modbus TCP 目标源码、只编译 Makefile、单请求/双请求静态输入、独立响应示例和静态来源清单。新增 --source-dir 将最小输入对生成完整正式包，README 给出准备、构建、启动及修改后重新准备步骤。 | [最小源码运行包](../protocols/templates/minimal_runnable_example/README.md) |

## 1. 统一契约如何工作

旧 YAML 的公共骨架仍是填写形状示例。`checked_profile_copy()` 递归检查当前 schema 的必需键、已知键、对象/数组和数量结构；模板或 profile 出现形状漂移会拒绝，不再只读取顶层键然后丢弃其他属性。schema 新增的允许属性会完整复制，嵌套字段默认值仍来自实际 profile。组合 schema 等尚未由形状检查解释的新结构要求显式更新契约，不能静默跳过。

`instantiate()` 保留原有位置参数调用，新增 keyword-only `source_directory`；CLI 的 `--base` 与 `--source-dir` 互斥。生成前后核对源 YAML 摘要；在同父目录临时包内完成具体校验、IR、validation、fixtures、模型 seeds、manifest、证据与 README，完成后 rename 发布，已存在的目的路径拒绝覆盖。

`template_contract.json` 记录源目录/基准 profile、输入摘要、schema/骨架/能力清单/片段摘要、输出 protocol_id 和具体值来源。它表示包创建来源；用户之后编辑输出 YAML，必须重新校验当前模型与语料，旧来源契约不认证新内容。它不生成新 codec、不恢复旧 session，也不认证进程映像。

高级片段按 schema 组件填写，不作为自动合并的完整协议。`length_of/count_of` 执行编码字节单位换算；`copy/bind/correlation/sequence` 明确引用和现场条件；MMS tagged_length、Modbus repeat 有专门范围。`when`、通用 repeat、结构树和 guard/actions 的静态边界明确标注。旧 compiler 对省略声明的兼容仍保留；新实例化契约要求两项消息声明显式存在。

实例化与导出入口持续校验19个具体片段的 schema 类型、枚举和值域；9个真实摘录同时核对仓库内来源路径、SHA256、实际选段和上下文字段。修改参考 profile 后，相关片段及摘要也必须显式更新。能力清单的版本类型、codec/方向集合、消息声明策略、字段分类集合和依赖分类也有漂移检查，语法示范须明确不作工业协议声明。这些都是文件静态契约，不调用 codec 或目标。

## 2. generic-wire 的正式填写流程

[示例目录](../protocols/templates/generic_wire_examples/README.md)包含三包：

| 包 | 报文 fixture | 请求 replay seed | 语义范围 |
| --- | ---: | ---: | --- |
| udp_oneway | 1 | 2 | 单向数据报，单请求与重复请求 |
| udp_request_response | 2 | 2 | 请求/响应分离，serial 整数相等关联 |
| tcp_request_response | 2 | 2 | 长度字段分帧、serial 关联；C 回归源码覆盖分片响应 |

复制和编辑的入口如下；这些是可复现命令，不是本轮运行记录：

```sh
python3 tools/generic_template_catalog.py --base tcp_request_response \
  --protocol-id my_protocol --output-dir /tmp/my-generic-protocol
python3 tools/generic_template_catalog.py --check-package /tmp/my-generic-protocol
# 编辑 generic_wire.json 及 manifest 中作者选择的 request_ids 路径后：
python3 tools/generic_template_catalog.py --refresh-corpus /tmp/my-generic-protocol
```

复制通过临时目录发布；检查只读；刷新只处理该包受管理 fixture/seed，先核对全部路径、预算和模型投影，再逐文件发布、manifest 最后发布。未知文件、隐藏文件、软链、特殊文件、目录型 seed 和越界路径拒绝；不删除未知输入。每个声明请求须有一条有效的作者指定路径，不能给空 corpus 发“完整”结果。刷新不自动寻找新协议会话，不写入响应到 seeds，不更新外部输入目录。

schema 明确 strict keys、uint/bytes 属性分支、fixed/derived 必需值、传输分帧分支和数值容量；它只覆盖 online:true 的 v1 输入。词法正则使用实际字符串结束约束，防止字段 ID、引用或 hex 在末尾追加换行后被 Python 的 `$` 锚点误接收。词法资源、UTF8 字节长度、唯一性、跨字段引用、wire/framing 方程、可达状态和真实会话仍须语义/原生检查，不能由 schema 通过推导。包 helper 返回 `native_loader_executed:false`。五份 offline-only 工业迁移描述保持原范围，不能改 online 标志充当实现。

## 3. 模型、语料和实际输入的门控

旧包装器把当前模型编译到 `.campaign-check-*` 临时目录，检查通过后才准备并替换4个编译输出。陈旧模型/validation、缺失或被修改的 manifest、不同 fixture/seed 字节和额外目录项都明确拒绝，提示显式重编与重规划。当前模型的校验不能借用保存的旧 validation。

准备过程在读取前、加载后和发布前核对两个 YAML 的有限读取 SHA256；编译期间发生变化则拒绝发布，并在 preparation.source_sha256 返回实际检查的源身份。这是前后稳定性检查，没有锁住发布后至宿主 exec 之间的外部编辑。旧输出的 queue/.state 文件或断链标记、权威快照中的意外目录或名称也会提前拒绝，与宿主输入选择契约保持一致。

| 所选输入 | 返回范围 | 保证 |
| --- | --- | --- |
| 包内受管理 seeds | managed_model_corpus | 当前模型与编译结果、声明路径及实际文件一致；不是实际目标会话证明 |
| 自定义 -i | external_unmanaged | 独立检查文件类型、LE32 分帧、可测消息数和字节预算；不认证协议语义、canonical repeats 或来源模型，不改写输入 |
| 旧输出/queue | external_unmanaged | 还需权威 replay 快照与 raw 字节一致；不从 raw 猜分帧 |
| -i - | runtime_resume / deferred_to_host | 由 StateAFL 在输出锁内核验权威快照，包装器不提前替代该检查 |
| --validate-only | model_only | 只模型编译，不宣称 corpus/实际输入已验收 |

参数解析完整消费值，支持 `-iPATH`、`-i PATH`、短参数组合与恢复形式，在目标 argv 边界停止；重复/缺失 -i、冲突模型参数和非字符串参数明确拒绝。`--print-command` 也检查输入与语料，但不执行目标。IR 发布是逐文件原子替换，不是整个目录的事务；I/O 中断仍依赖原有 bundle 配对检查。

导出器复用模板形状契约、managed-corpus 检查和 generic 模板清单，保留原 IR 字节一致性检查。导出允许静态包没有运行 seed，但启动要求可用模型种子。新工具、schema、模板、语料、能力片段、最小夹具和报告都进入导出清单；历史证据没有改成新 PASS。

## 4. 最小源码包的交付范围

最小模型固定 quantity=1，响应 data 恰好2字节。独立夹具检查完整12字节请求并复制现场 transaction/unit，address=0 返回0001；它不读取模型或响应 fixture 来回答请求。完整处理与响应提交后调用显式 boundary hook，volatile heap 状态避免构建器消除观察用状态存储。一次连接最多32条消息。

源码包自带的输入清单明确 `native_validation_executed:false`，只说明请求/响应 example 的字节构造。正式包由当前 `--source-dir` 实例化生成真实 validator 结果和标准 seed_manifest，避免在未执行原生检查时伪造已验证的 IR/validation。构建目录默认在 /tmp，不混入模板资产；Makefile 跟踪 wrapper、运行时、pass 和共享头依赖。

```sh
python3 tools/init_protocol_spec.py \
  --source-dir protocols/templates/minimal_runnable_example \
  --require-runtime --output-dir /tmp/stateafl-minimal-package
```

之后按最小包 README 启动受控夹具。该准备命令本轮没有运行；实例存在、夹具能编译、模型路径可达都不证明已经自然产生非零内存状态并实际进入 M2。

## 5. 本轮实际检查与编译

| 检查 | 本轮结果与边界 |
| --- | --- |
| Python 静态 AST | 13个新增/修改 Python 源通过解析；没有 import/执行项目模块 |
| 静态数据与 schema | JSON/YAML 可解析；正式 generic starter 与3包共4个描述通过直接 JSON Schema 库的结构检查；未调用项目 checker 或 C loader |
| 高级片段 | 19个片段按引用 schema 组件检查结构/类型，真实摘录与当前 profile 内容及 SHA256 相符；不作为完整工业消息执行 |
| generic 语料文件 | 三包合计5个 wire fixture、6个 replay 文件，核对源摘要、消息方向、LE32 拼接与长度；未发送或接收任何目标数据 |
| 最小包静态材料 | 源摘要、一条/两条请求拼接及独立响应 example 核对一致；不声称实际目标响应 |
| 主项目 | `make -j2 build-only` 退出0；生产 C 未变化，按依赖复用现有产物；未运行默认 smoke test |
| 最小夹具 | 用实际 afl-clang-fast 编译/链接退出0；`nm` 显示 `trace_message_boundary` 定义；未启动夹具 |
| 新 generic C 合同 | C11、Wall/Wextra/Werror、ASan/UBSan 编译和链接退出0；未执行断言或 sanitizer |
| Shell/差异 | 两个 runner 的 bash -n、git diff --check 通过 |

原始编译产物和日志在被忽略的 [template-repair-20261104](../tests/protocol/out/template-repair-20261104) 本地目录，不随提交发布。新 C 合同只编译命令为：

```sh
clang -std=c11 -O1 -g -Wall -Wextra -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer -I. \
  tests/generic-wire/test_generic_template_contract.c \
  generic_runtime.c generic_wire.c native_json.c -o /tmp/generic-template-contract
```

新增/更新的 Python 回归覆盖模板深层漂移、允许属性保留、显式来源、能力分类、源摘要、实例化与编辑拒绝、managed/custom/resume 输入、编译期间编辑与异常队列标记拒绝、拒绝前 IR 保持、generic 清单/刷新、词法末尾换行及最小包生成；新 C 合同调用真实 loader、序列和响应事务。它们已接入各自 runner，但本轮没有运行这些测试。后续执行时应先验证这些合同，再核对受控目标会话和逐消息边界，最后开展固定预算的重复方法对照。
