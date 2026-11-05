# 六协议修订源描述

> 2026-11-04 后续状态：六套修订源已实际经过 native 生成及 C 加载，执行器也已扩展。最新范围、测试结果和未通过项见[执行器扩展与本地验证](../../docs/executor-extension-20261104.zh-CN.md)。下文保留最初静态交付时的记录。

本目录交付六套独立、可编辑的 `protocol_spec.yaml` / `state_transition.yaml` 输入对。它们补充了本轮静态审查发现的字段域、响应模型、状态边和能力说明问题。每套另有逐消息 `constraints.json` 及具体修复说明；完整分析见[六协议描述完整性复核](../../docs/protocol-description-completeness-20261104.zh-CN.md)。

这里的交付范围是现有 codec 服务子集的修订源文件。**完整报文示例、完整动态语法、完整会话执行、整个协议标准覆盖是四件不同的事。** BACnet 动态响应定位、完整 IEC104 会话、ENIP 外部 Class-3 建连、UA 安全/Session，以及通用引擎未实现的语法，仍在各包剩余清单中。不能把这些文件解释成六部标准或六套 generic-wire 模型已经全部完成。

| 协议源文件 | 状态输入 | 本轮重点 |
| --- | --- | --- |
| [BACnet/IP](bacnet_ip/protocol_spec.yaml) | [状态](bacnet_ip/state_transition.yaml) | 准确限定 un-routed 和 fixture 投影；明确 single-flight，移除并发暗示 |
| [Modbus TCP](modbus_tcp/protocol_spec.yaml) | [状态](modbus_tcp/state_transition.yaml) | 收紧读数据范围；八种功能码各有固定异常响应与请求关联 |
| [IEC104](iec60870_5_104/protocol_spec.yaml) | [状态](iec60870_5_104/state_transition.yaml) | 拆分 COT/originator、正负确认关联、S/TESTFR 状态边 |
| [MMS](iec61850_mms_tcp/protocol_spec.yaml) | [状态](iec61850_mms_tcp/state_transition.yaml) | 非空标识符、固定上下文/版本、单变量与实际受支持的 Data 结构 |
| [EtherNet/IP/CIP](ethernet_ip_cip_tcp/protocol_spec.yaml) | [状态](ethernet_ip_cip_tcp/state_transition.yaml) | 准确描述 Identity 路径、成功/错误状态及 Vendor-ID 数据大小 |
| [OPC UA TCP](opcua_tcp/protocol_spec.yaml) | [状态](opcua_tcp/state_transition.yaml) | 版本、缓冲区、URL 字节范围与逐消息服务/codec 条件 |

`constraints.json` 的 schema 为 [reviewed_description.schema.json](../schema/reviewed_description.schema.json)。清单区分 `codec`、`model`、`codec_and_model`、`static_only`、`external`，自身不作为在线约束程序执行。`generic_coverage` 引用原发布包实际 generic 消息，逐项列出未迁入的消息；没有创建一组冻结服务体的假通用语法，也没有改变 online 标志。

`manifest.json` 绑定六包全部源文件摘要、原发布 YAML/generic 来源摘要以及静态统计。它明确 `native_validator_executed=false`、`runtime_tests_executed=false`、`whole_standard_complete=false`。本轮没有执行项目工具、codec validator、测试或目标，不能复制旧 validation 作为新输入的证明。

## 静态检查与正式包准备

后续可从仓库根目录运行下面的只读来源/schema/引用检查；它不调用 C、compiler 或网络：

```sh
python3 tools/check_reviewed_protocol_descriptions.py
```

准备正式运行包时，使用当前生成器的明确源目录入口，例如：

```sh
python3 tools/init_protocol_spec.py \
  --source-dir protocols/reviewed/modbus_tcp \
  --require-runtime --output-dir /tmp/reviewed-modbus-package
```

`--source-dir` 可换成上表任一目录，输出目录须尚不存在。该步骤才会执行当前 compiler/native codec 校验，生成配对 IR、validation、当前模型 seeds/manifest 和创建来源契约。成功准备不证明现场会话或方法效果；仍需匹配目标及各包外部前提。不要直接把源目录当作 `run_protocol_campaign.py --spec-dir` 的已准备包。

这里没有 IR、validation、seeds 或目标会话结果。`protocols/<协议名>` 仍保存此前发布的包和其历史记录，`--base` 仍选择那些包；旧 `generate_protocol_models.py` 不会自动生成本目录。修订后必须重新审查约束及来源身份，再通过 `--source-dir` 准备新包。未被实际执行的原生或运行验收不能通过刷新摘要获得。
