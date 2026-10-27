# 在线定向变异器与 StateAFL 的集成

本轮以 `feature/protocol-aware-integration-20261025` 为交付分支，合并远程
`origin/main` 后继续修改。三个 agents 分别静态审阅运行时、网络执行链及模型契约。
遵循 `AGENTS.md` 中暂缓测试的要求，本轮只审查源码及 Git 差异；未构建、未运行
测试、未启动目标服务。历史测试记录不代表本轮源码已通过回归。

## 真实响应与发送绑定

`receive_network_responses` 包装 `net_recv`，将每次追加的响应字节精确一次交给
`proto_after_response`。覆盖发第一条请求前的响应、常规收包、错误返回前已经收到
的部分字节以及结束时的 drain。TCP 分帧和不完整帧缓存仍由协议运行时负责；
返回码、原响应缓冲和 `response_bytes` 的使用遵循原网络流程。

`proto_before_send` 在有界私有副本上求解跨消息/响应/序号绑定。所有依赖和 wire
校验成功后才复制回调用方并记录 pending/cache；失败时调用方报文字节和会话状态
均不变化。依赖求值阶段仅读取缓存，实际缓存提交在最后的 `remember` 中完成。
这避免继承的 M1/M3 在允许原样发送的错误路径上带入半修复报文。

标记为本次结构化 M2 的 `near_valid`/`invalid` 消息直接跳过发送前修复，保留
刻意破坏的字节。继承的 M1/M3 仍可建立真实会话上下文。故意无效请求不登记为
正常 pending 请求，因此不将其响应关联率用于评判合法请求成功率。

Python `runtime_profile_signature` 纳入消息权重，与 C `equivalent_models` 的
等价约束一致；相同 wire 类别、字段和依赖但权重不同的别名在编译期明确拒绝。

新增的原子绑定、无效输入及模型权重负例仅为回归测试源码，尚未执行。

## 当前边界

在线生产路径仍是 ICP-IR 与六种有界 codec。`native_layout_inspect_buffer` 的
通用布局入口提供只读检查，不能作为通用在线字段编辑器使用。不同 wire alias
的状态迁移冲突、模型文件整体原子发布、分布式导入和恢复格式仍需独立审阅。
当前修改不证明五个工业目标的互通、覆盖率提升或所有恢复场景正常。
