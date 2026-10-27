# 本地虚构夹具的 C 确定性变换

此模块仅服务仓库已有的原生解析器测试。它复用 `test_layout` 原有的虚构输入 `{42, 2, 'a', 'b'}`，格式为固定标记 42、一字节 body 长度和相应内容。它不是五种实际协议的通用变异器，也未接入 StateAFL 的候选生成、执行或反馈循环。

## 修改文件和调用链

| 文件 | 改动 |
| --- | --- |
| [fixture_packet.h](../tests/native-inspection/fixture_packet.h) | 固定夹具格式、操作、返回值和所有权契约 |
| [fixture_packet.c](../tests/native-inspection/fixture_packet.c) | 两种确定性操作及共享原生布局描述 |
| [test_native_inspection.c](../tests/native-inspection/test_native_inspection.c) | 增加夹具变换测试组，复用原有 C 解码器校验结果 |
| [README.md](../tests/native-inspection/README.md) | 测试范围及未执行状态 |
| [Makefile](../Makefile) | 仅本地测试目标链接夹具模块 |
| [native-inspection.md](native-inspection.md) | 补充本地测试模块文档入口 |
| [source-call-chain-native-contracts.md](source-call-chain-native-contracts.md) | 区分前一阶段接口维护与后续测试夹具变换 |

实际源码调用关系为：

```text
测试 main -> test_fixture_mutations -> fixture_packet_mutate
                                  -> inspect_fixture -> layout_case
                                       -> native_layout_inspect
```

在支持 `__int128` 的编译器上，测试将生成结果交回同一个生产 C 解码器检查；其他平台仍检查夹具变换接口，布局语义检查保持跳过。上述是源码关系，本轮未执行。`afl-fuzz` 和独立检查程序不链接此夹具模块，现有生产执行链参见[源码审计](source-call-chain-native-contracts.md)。

## 接口与操作

```c
int fixture_packet_mutate(const unsigned char *input, size_t input_length,
                          const fixture_packet_edit *edit,
                          unsigned char *output, size_t output_capacity,
                          size_t *output_length,
                          char *error, size_t error_capacity);
```

- `FIXTURE_PACKET_SET_BYTE`：`argument` 指定已存在的 body 索引，`value` 是替换值。固定标记和长度不改变。
- `FIXTURE_PACKET_RESIZE_BODY`：`argument` 指定新的 body 长度，范围为 0 至 255；保留前缀，扩展部分填充 `value`，同步更新长度字节。
- 返回 0 表示内容改变，1 表示合法但无变化，-1 表示拒绝；两种成功结果都会复制完整结果并设置输出长度。
- 输入必须已完整且符合该固定格式；未知操作、缺少必填参数、越界、输入长度不符及输出容量不足均拒绝，不自动修复非法原输入。

所有缓冲区均借用；不分配或释放堆内存。输入与输出可以重叠，模块先用最多 257 字节的局部数组暂存，再提交结果。输入、输出、edit 和输出长度指针必填；错误文本可选。

调用入口将可用的输出长度归零并清空可写错误缓冲；失败不修改输出数据字节。成功和失败均不关闭文件或保存持久状态。`edit`、输出长度和错误缓冲不得与数据缓冲或彼此别名，实际存储大小由调用方保证。

## 验证状态与命令

本轮只静态审阅源码与 Makefile，并检查补丁格式。没有编译、运行测试、sanitizer 或目标，因此没有运行通过结果。新增测试源码覆盖合法更改、无变化、空内容、最大长度、索引/容量错误、重叠及失败原子性；未执行的测试不能证明其通过。

后续可以在仓库根目录分别使用以下命令；本轮全部未执行：

```sh
make native-inspection-tests
make native-inspection-tests-sanitized
make check-native-inspection
make check-native-inspection-sanitized
```

前两个仅构建测试程序，后两个会执行。默认 `all` 不增加测试执行步骤。

此夹具没有协议状态模型或目标内存状态。它不能验证双状态同步、五协议 YAML 可执行性、覆盖率收益、论文方法效果或完整通用变异器的集成。通用编码、定向/序列变异及其生产执行反馈闭环仍未实现。
