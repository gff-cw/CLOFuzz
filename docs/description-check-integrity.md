# 离线描述检查的资源边界和记录完整性

本次只修改已有的 `tools/check_protocol_descriptions.py` 及对应测试源码和文档。检查器不导入协议编译器、C codec 或执行器，不生成报文、不构建 C 代码、不启动目标；它不能修复或验证[生产集成缺口](current-integration-gaps.md)。

## 有限读取

旧实现先完整 `read_bytes()`，再检查 1 MiB 上限。新实现通过二进制流最多请求读取 `MAX_DESCRIPTION_BYTES + 1` 字节，超限后拒绝，不继续 UTF-8、YAML 解析或哈希。恰好 1 MiB 的文件仍接受其他检查，异常时由上下文管理器关闭文件。

## 保存记录契约

`validation.json` 必须声明布尔值 `validated: true`，且 `runtime` 的类型和值必须与主描述的 `support.runtime` 一致。整数 1 不能冒充布尔值 true。记录声明不构成重新验证的证据，但显式失败或不一致记录不能作为一致的成功记录通过检查。

可选 `validation.source_sha256` 必须是恰好包含 `protocol_spec.yaml` 和 `state_transition.yaml` 两键的对象，值是64位十六进制字符串，允许大小写，逐项与本次读取的原始源文件摘要比较。空对象、缺项、额外键、类型错误、非法摘要或不匹配均失败。旧实现只检查键是否存在，没有核验内容。

未声明该键的旧记录保持兼容，并保留缺少绑定的提示。本次不重新生成六套模型、IR 或历史证据。报告新增 `source_hash_binding`：

| 值 | 含义 |
| --- | --- |
| `unchecked` | 尚未完成检查或此前步骤已失败 |
| `absent` | 旧记录未声明源摘要，不能绑定历史验证 |
| `matched` | 两个声明摘要与本次源字节一致 |

不把 evidence/validation 自身纳入摘要，以免循环声明。`matched` 不证明发布者身份或历史验证真实发生，不绑定 C 源码、codec、二进制或测试结果，也不证明完整协议语义被执行。`status: passed` 仅指此工具列出的静态检查。

## 验证状态

测试源码新增有限读取、大小边界、非法编码、记录标志和哈希声明检查。本轮只做静态复读和补丁格式检查，未调用 Python、编译器、测试、示例或目标；没有运行通过结果。历史测试记录不能替代新增修改的验证。

后续可以独立执行 `tests/protocol/test_description_checks.py`；本轮没有执行。完整三级变异、非零状态定位、M3 一致性、确定性阶段归因和收益实验不属于此次完成范围。
