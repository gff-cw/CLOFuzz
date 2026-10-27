# C 原生描述解释与双状态检查

本轮把通用布局解释、只读解码、字段约束校验及双状态观测处理写为 C，加入 StateAFL 本体的本地检查入口。它们读取已有文件，报告后退出，不生成或修改输入、不启动目标、不消费覆盖或状态反馈。

这是被动检查功能的原生接入。通用定向变异器、在线反馈联动和六套旧模型迁移尚未实现，旧 protocol_runtime.c 不由此替换。早期三个独立 Python 解码、字段编辑及观测分析脚本与旧模板已移除；C 路径只读，尚不具备原 Python 编辑器的字节修改功能。现有 YAML 描述编译器、回归和证据工具仍保留。

## 文件与构建

| 文件 | 职责 |
| --- | --- |
| native_json.c / native_json.h | 严格有界 JSON、整数、Unicode、属性校验及报告输出 |
| native_layout.c | 通用节点解释、字段解码和约束检查 |
| native_observation.c | 双状态声明校验、会话历史及关联证据管理 |
| native_inspect.c / native_inspect.h | 共用本地检查参数及诊断 |
| afl-fuzz.c | main 起始分派，检查后返回，不进入原目标初始化 |
| afl-protocol-inspect.c | 使用同一实现的独立入口 |

Makefile 直接把模块链接进 afl-fuzz。独立 afl-protocol-inspect 不依赖 Python、Graphviz 或 LLVM 插桩。布局整数解释需要编译器支持 __int128，面向当前 Clang/GCC 工具链；不支持时布局入口明确返回 unsupported_platform，源码保留其他模块与原程序的构建路径。这里没有验证任何平台的实际构建结果。

后续可使用以下构建入口；本轮没有执行：

```bash
make afl-protocol-inspect
make afl-fuzz
```

afl-fuzz 保留原构建检查。独立检查器不依赖 test_x86。

## 本地文件入口

检查选择器必须是第一个参数，不能混入 -i/-o、目标命令或其他 fuzzer 参数：

```bash
./afl-fuzz --inspect-layout layout.json --inspect-input existing-message.bin
./afl-fuzz --inspect-observations existing-observations.json
./afl-fuzz --inspect-help
./afl-protocol-inspect --inspect-layout layout.json --inspect-input existing-message.bin
```

这些是文档示例，本轮没有运行。成功报告写 stdout，诊断写 stderr。退出码为 0（检查通过）、1（输入不满足布局）或 2（文件、描述、参数或报告错误）。先完整验证再输出报告；流本身 I/O 失败仍可能留下部分 stdout，不能当作完整成功结果。

## 通用描述解释

C 入口只读 JSON，布局格式为 stateafl.offline-layout/version 1，支持 struct、uint、int、bytes、bits、choice、repeat、bounded、align，不按协议名称选择专用函数。新 [JSON 模板](../protocols/templates/native_layout.template.json) 描述虚构的有界记录。

长度、计数及判别式使用常量、已解析字段引用或受限整数 AST。完整输入与 bounded 容器严格消费；范围、枚举、常量、位域及文本编码约束必须明确声明。未知属性/节点、未覆盖分支、未来引用、除零、溢出和资源超限明确报错。递归类型、压缩、密码学、BER 无限长度与 TCP 重组不自动受支持。

报告使用 native 命名空间，不冒充 Python 规范化摘要或逐字兼容旧报告。入口不接收 YAML、不启动 Python 转换，也不把旧 ICP-IR 目录当作通用结构树。检查成功只表示满足已表达约束，不证明完整标准符合性或目标执行成功。

输入文件各限 1 MiB；JSON 深度至多 96、节点至多 65536（包含对象 key），仅接受整数型 JSON 数值。布局节点至多 4096（含位域子字段），结构/表达式深度至多 32，单次 repeat 至多 4096，解码字段至多 65536，表达式求值至多 524288 步，路径至多 8191 字节。整数域为 [-2^63,2^64-1]。观测至多 10000 事件、每次至多 64 个候选，普通身份文本至多 256 个 Unicode 字符。这些界限不构成运行稳健性验证。

## 双状态观测管理

协议状态是模型抽象，内存状态是快照及聚类标签。二者通常为多对多关系，ID 不互换，不能按数组下标对应。

输入沿用 stateafl.offline-observations/version 1。预测、确认、歧义、未知和模型不相容分别保留；预测不升级确认，超时不重置状态，部分或未匹配响应不建立确定关系。候选集合整组保留，历史确认与最近预测分开记录。

只有完整且因果关联明确的协议观测、非零 snapshot 内存标签、生产者声明的共同完成边界与同步证据齐备才关联。记录保留模型、内存命名空间、校准、参考库修订、run/session/epoch 身份；不同版本不合并。报告逐事件输出 aligned_observations，明确 relations_aggregated=false，不把记录数解释为概率或转换次数。未关联事件及原因保留。

[观测模板](../protocols/templates/native_observations.template.json) 只展示 unobserved 会话起点，摘要占位符必须替换，身份须来自实际记录。共同标记及同步都是生产者声明，JSON 校验不证明真实因果或线程静止；旧共享状态数组缺少共同边界，不能自动生成确定关系。详见[理论模型](dual-state-observation-model.md)和[记录契约](offline-state-relation.md)。

## 验证状态

按用户要求，本轮没有运行编译器、构建、测试、示例、解码命令或目标服务。交付仅有源码、构建配置、文档和静态审阅；尚不能据此确认可编译、兼容或运行正确，更不能认为论文方法的效果已经验证。
