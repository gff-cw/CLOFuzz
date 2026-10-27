# C 内存缓冲区的只读解码与约束校验

本次交付是现有通用布局解释器的内存入口，不是离线定向变异器。它不编码、编辑或生成输入，没有目标字段选择、状态迁移规划、消息序列生成或 StateAFL 变异回调。

## 接口契约

接口声明位于 [native_inspect.h](../native_inspect.h)，实现位于 [native_layout.c](../native_layout.c)：

```c
int native_layout_inspect_buffer(const unsigned char *layout_json,
                                 size_t layout_length,
                                 const unsigned char *input,
                                 size_t input_length,
                                 FILE *out,
                                 native_diagnostic *diagnostic);
```

`layout_json` 指向 `stateafl.offline-layout` version 1 的 JSON 字节，使用显式长度，不要求结尾 NUL。`input` 是待检查的原始内容字节。两个范围各至多 1 MiB；布局指针、输出流及诊断必填；输入指针仅在长度为 0 时可以为 NULL。

描述和输入均借用，必须在调用期间保持稳定。内部 JSON 解析器复制描述；二进制数据通过 const 视图读取，不释放或修改调用方缓冲。描述、字段和报告所需的临时对象在返回前释放。诊断和报告输出的存储不得覆盖任一输入范围。

返回值延续现有检查入口：

| 返回值 | 含义 |
| --- | --- |
| 0 | 所有已声明约束通过，已写出报告 |
| 1 | 内容截断、不符合约束、含未消费字节或没有已声明的适用分支 |
| 2 | 参数、描述、资源、平台或报告错误 |

入口清空可用诊断，成功保持为空，失败填写当前错误。验证失败不输出成功报告；I/O 错误可能留下部分报告。输出流由调用方拥有，接口不关闭或刷新它，调用方仍需处理 `ferror`、`fflush` 及延迟写入错误。

无 `__int128` 的平台也定义此符号：先执行相同的必填参数和长度检查，其余调用返回 `unsupported_platform`，不承诺解释描述内容。

## 复用现有实现

```text
native_layout_inspect（文件入口）
  -> 加载 JSON -> compile_layout_document -> 读取输入文件
  -> inspect_layout_content -> decode_spec / write_field

native_layout_inspect_buffer（内存入口）
  -> 校验参数 -> 解析 JSON -> compile_layout_document
  -> inspect_layout_content -> decode_spec / write_field
```

两条路径共用同一份节点解释、表达式求值、作用域、边界和资源限制。文件入口仍按原顺序先处理描述，再读取输入。文件报告的 `scope` 保持 `passive local-file structural inspection`；内存报告使用 `passive in-memory structural inspection`，其余字段含义一致。

## 与仓库其他接口的关系

此接口使用 C 字节指针和 `size_t`，可以检查调用方已经持有的数据，但它不是 [proto_mutate](../protocol_runtime.h) 的替代接口，也不返回候选缓冲区。现有协议运行时使用 LE32 长度加消息内容的记录容器；该入口不会识别或剥除记录前缀，调用方应提供与布局明确一致的字节范围。

五套旧协议 YAML/ICP-IR 仍不是此布局入口的直接输入，见[描述审查](five-protocol-yaml-readiness.md)。本次没有更改协议状态、内存状态身份、网络、队列、覆盖率或调度，没有把新接口接入生产变异调用链。

## 验证状态

新增测试源码通过同一测试程序检查文件/内存报告内容、输入不变、零长度、参数和大小边界、错误返回、诊断复用及流所有权。独立审阅关注了 const 视图、释放顺序、空指针算术、完整消费和资源错误分类。本轮仅静态阅读与补丁格式检查，未编译、运行测试、sanitizer、示例或目标；没有运行通过结果。

构建及测试入口仍为以下命令，本轮均未执行：

```sh
make native-inspection-tests
make native-inspection-tests-sanitized
make check-native-inspection
make check-native-inspection-sanitized
```

此交付不能证明完整变异功能、五协议互通、真实双状态同步或论文方法效果。通用编码、定向/序列变异及相应完整 C 离线变异器仍未交付。
