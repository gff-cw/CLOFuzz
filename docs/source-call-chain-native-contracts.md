# 真实调用链与原生只读接口契约

本次先审阅已有源码，再修改只读组件的边界处理并添加测试源码。没有新增变异、目标执行或反馈调度接口。用户明确要求静态分析，因此这里没有构建或测试通过结论。

本文记录只读接口维护阶段。其后新增的[虚构夹具变换](native-fixture-mutation.md)仅在本地测试程序中使用，不改变下述生产调用链或原生检查入口。

## 已有程序的实际调用链

下列函数均存在于 [afl-fuzz.c](../afl-fuzz.c)，不是拟议接口：

| 阶段 | 实际函数/数据 | 职责 |
| --- | --- | --- |
| 选择 | main、choose_target_state、choose_seed、queue_cur | 状态感知分支选择原状态与种子；另一分支遍历原队列 |
| 输入准备 | fuzz_one、construct_kl_messages、M2_prev/M2_next | 构造消息链，选择 M1/M2/M3 和 M2 线字节 |
| 可选协议路径 | protocol_capture、protocol_prepare、proto_mutate | 保存边界并调用现有有界协议运行时 |
| 输入交付 | common_fuzz_stuff、region_t、kl_messages | 替换 M2，保留周围消息，再调用原执行入口 |
| 执行与收发 | run_target、send_over_network | 原 forkserver/超时机制，在 use_net 时收发 |
| 协议上下文 | proto_session_begin、proto_before_send、proto_after_response | 可选缓存清理、发送绑定和响应观察 |
| 覆盖及队列 | save_if_interesting、has_new_bits、save_kl_messages_to_file、add_to_queue | 原位图/异常处理，保存完整消息链、加入原队列 |
| 状态回采 | update_state_aware_variables、extract_response_state_tracer | 状态感知路径重新执行并更新原状态信息 |
| 后续调度 | update_fuzzs、cull_queue、choose_target_state、choose_seed | 延续既有状态及队列统计 |

核心路径可概括为：

```text
choose_target_state / choose_seed（或原队列遍历）
  -> fuzz_one -> common_fuzz_stuff
  -> 可选 protocol_prepare / proto_mutate -> M2 替换
  -> run_target -> 可选 send_over_network
  -> save_if_interesting -> add_to_queue
  -> 可选状态回采 -> 后续原调度
```

这说明旧有界 C 协议候选已接入原循环，不能将项目说成没有 C 变异。但该路径仍依赖专用 codec；新 native_layout 只在 main 开始时的 --inspect-* 模式工作并返回，不参与候选生成。源码存在这些调用不等于本轮运行验证通过。

原 AFL 候选是线字节。协议运行时使用 LE32 长度加消息内容的记录格式，适配层再恢复线字节和 regions；前缀不能作为 payload。proto_mutate 输出属于 engine，直到下一次调用；适配层复制其内容并管理自己的 regions，见 [protocol_runtime.h](../protocol_runtime.h)。本轮未修改这些契约及实现。

## 只读接口与所有权

| 接口 | 参数和内存 | 返回与失败 |
| --- | --- | --- |
| nj_read_file | 路径借用；输出 malloc 缓冲由调用方 free | 0/-1；失败指针为空、长度为 0 |
| nj_parse_buffer / nj_load_file | 输入复制到 caller-owned document，由 nj_free 释放 | 0/-1；失败输出为空，不可覆盖未释放 document |
| nj_get | 借用节点，只在 document 存活期有效 | 未找到返回 NULL，不可单独释放节点 |
| 字符串/数字 getter | 输出由调用方拥有；字符串输出不得与源别名 | 失败清空可写字符串输出，数字只在成功改变 |
| native_layout_inspect | 两个路径、out、diagnostic 必填，均借用 | 0 成功、1 数据不满足布局、2 配置/资源/平台/报告错误 |
| native_observation_inspect | 路径、out、diagnostic 必填，均借用 | 0 成功、2 声明/配置/资源/报告错误 |
| native_inspection_dispatch | argc>=1、argv 及其 argc 个条目、out/errors 必填 | -1 仅表示未选择检查；检查已选择时返回 0/1/2，不能回落目标执行 |

两个原生报告入口清空复用诊断，成功保持为空、失败填写当前错误；临时数据和树在返回前释放。FILE 不关闭，调用方负责刷新。验证失败不写成功报告，流自身失败仍可能留下部分字节，需检查返回及 ferror/fflush。头文件见 [native_json.h](../native_json.h) 和 [native_inspect.h](../native_inspect.h)。

## 本轮确定的问题及源码处理

- 布局与观测入口原先可能在成功后残留旧诊断；现开始时显式清空。观测入口也统一要求非空诊断参数。
- 分派器原先直接访问 argv/输出流；现检查 argc、argv、所有条目和两个流，无效 API 参数返回错误，不返回未选择。
- 诊断辅助函数原先可能把 NULL format 传给 vsnprintf；现提供明确缺省错误说明。
- 参数错误报告主动刷新错误流，仍不关闭调用方流。
- 补充返回常量与所有权契约，没有新增变异或目标执行接口。

这些是源码修改，不是运行结果。正常参数应保持原分支行为，但兼容性尚未执行验证。

## 测试源码与后续命令

[tests/native-inspection](../tests/native-inspection/README.md) 直接链接同一组生产模块，不实现另一套解析器。测试仅使用 JSON、虚构布局、本地临时文件和观测声明，不启动目标或网络。共享检查分派的局部测试不等于原 fuzzer 的执行/覆盖反馈回归。

新增 Makefile 目标显式选择，不加入默认 all，也不替换原协议回归入口。以下命令本轮全部未执行：

```bash
make native-inspection-tests
make native-inspection-tests-sanitized
make check-native-inspection
make check-native-inspection-sanitized
make afl-fuzz
```

前两个目标只构建被动模块测试，两个 check 目标明确执行测试；afl-fuzz 保留原构建检查。当前编译、单元、sanitizer、平台兼容和完整回归结果均未知。分配失败注入及真实目标执行闭环也未验证。

## 完整性边界

五种协议见[现有 YAML 审查](five-protocol-yaml-readiness.md)，其 scoped codec 模型并非 native 通用布局的直接输入。静态 guard/actions/structure_model 不会因接口修复变为可执行语义。

协议模型状态、预测和实际内存观测仍需分离。原共享状态数组没有共同协议边界，native_observation 只校验生产者声明，不自动证明同步。本次未修改 TLSH、state_ids、原队列、覆盖率或调度。

通用编码、定向/序列变异及新的执行反馈融合仍未实现。本次不满足完整通用定向变异器验收，仅交付调用链审计、只读 API 修复、契约和未执行的测试源码。
