# 通用离线字段变换

[offline_protocol_editor.py](../tools/offline_protocol_editor.py) 在已有本地二进制样本上执行用户显式指定的字段修改。它复用通用布局解释器，不识别协议名称，不调用专用 C codec，不自动选择操作、生成序列、驱动服务或消费覆盖/状态反馈。

当前支持定宽有符号/无符号整数、独立位域及等长二进制/文本叶。所有修改作为一个整体校验，输出必须保持原结构、字段区间和选中分支，并通过完整重新解码。这是有明确范围的离线字段变换模块，尚未替换现有 StateAFL 在线变异器。

## 计划格式

使用 [offline_edits.template.json](../protocols/templates/offline_edits.template.json) 填写计划。两个摘要占位符必须替换成原样本解码报告中的 layout_sha256 和 input_sha256，不匹配时拒绝执行。只接受 stateafl.offline-edits、version=1 和 edits 数组。

每个 edit 只有 path 和 value。path 使用解码报告的完整结构路径，包括根节点、实际分支节点及重复索引，不能改用表达式的词法引用路径。编辑器自行解码原始 bytes，不接受调用者提供的偏移或解码树。

| 叶类型 | value | 限制 |
| --- | --- | --- |
| uint / int | JSON 整数 | 编码宽度、字节序和 signedness 来自描述；拒绝布尔值 |
| bit | 非负 JSON 整数 | 不超过位宽，只替换目标位，保留载体其他位 |
| bytes，hex | 偶数个十六进制字符 | 不含分隔符，编码后等长 |
| bytes，ascii/utf8 | JSON 字符串 | 严格按声明编码，以字节数检查等长 |

struct、choice、repeat、bounded、align 和整块 bits 载体不可直接编辑。字段不存在、重复 path 或实际写入位重叠时拒绝整个计划。同载体中不相交的位域可以同时编辑。

原描述的 expected、expected_hex、values、min/max 等仍然有效，计划不能覆盖这些约束。修改常量通常会在后验解码时被拒绝。请求值与原值相同则是有效空改动，报告为 unchanged，不计为字节变化。

## 执行与文件输出

```bash
python3 tools/offline_protocol_editor.py \
  --layout path/to/layout.yaml \
  --input path/to/existing-message.bin \
  --edits path/to/explicit-edits.json \
  --output path/to/new-message.bin
```

原文件保持不变，目标文件必须不存在。完整校验后先在目标目录写入私有临时文件，再以不覆盖已有路径的原子链接发布。不支持该文件操作的文件系统会显式报错，不退回覆盖写入。报告包含布局/输入/输出摘要、逐字段旧值与新值、实际改变的字节数及校验范围。

退出码：0 为编辑成功（包括 unchanged）；2 为发布前拒绝或失败；3 为文件已发布但报告输出失败。发布后临时文件清理失败会在成功报告中给出 warning，不把已发布文件误报为拒绝。约束校验失败时不发布候选文件，也不回退到未校验字节。

Python API：

```python
from tools.offline_protocol_decoder import load_layout
from tools.offline_protocol_editor import apply_field_edits

# existing_bytes 和 explicit_plan 由调用方提供。
result = apply_field_edits(load_layout(layout_path), existing_bytes, explicit_plan)
new_bytes = result.data
report = result.report
```

API 不写文件、不改变原始 bytes 或传入的 decoder。描述通过私有快照重新校验，避免公开字典修改造成摘要与执行内容不一致。

## 保持结构的含义

处理顺序为：检查描述及输入摘要 → 完整解码原样本 → 校验全部操作及真实位重叠 → 修改副本 → 完整重新解码 → 比较结构及请求值 → 发布本地文件。

结构比较覆盖所有节点的实际路径、类型、字节区间、位位置、字节序、编码、描述节点 JSON Pointer 和选中 case。不同分支即使同名、同字节布局，也不能通过分支身份检查。默认分支保留实际判别值，因此切换到同一 default 下的其他判别值也被拒绝。

写入从原始数据副本开始，不重新序列化整条消息。位掩码按载体字节序映射到真实字节；未指定位必须不变。前后均完整检查布局已表达的所有已到达字段约束。

当前不支持变长替换、容器插入/删除、repeat 数量变化、分支切换或序列重排，也不提供依赖字段自动修复。不能用固定偏移覆盖猜测这些操作。本模块没有通用编码器，不能据此宣称完整通用变异执行器已完成。

## 与双状态模型的关系

输出只有新的本地字节与摘要，不携带目标执行结果。解码成功不能确认协议状态转换，修改文件不能产生 StateAFL 内存状态。

原样本的协议观测、会话缓存和内存标签不能自动继承给新摘要。若后续有实际观测，仍须按[双状态契约](dual-state-observation-model.md)提供新的运行、会话、关联与共同边界证据。本模块不接收或写入 state_ids、TLSH/MVP 数据或原队列。

layout_validated 只表示满足当前布局已表达的结构约束。未表达的校验和、业务条件、跨报文依赖、密码学条件及协议状态约束均不在保证内，不代表完整标准符合性。

## 资源和验证状态

输入、布局和计划均限 1 MiB；计划展开 JSON 也限 1 MiB，每次至多 256 个显式操作，其他预算沿用解码器。未知属性、重复 JSON key、非有限数、过长路径及非法整数被拒绝。

按用户要求，本轮没有运行 Python、样本变换命令、测试或目标服务，仅完成实现、文档与静态审阅。
