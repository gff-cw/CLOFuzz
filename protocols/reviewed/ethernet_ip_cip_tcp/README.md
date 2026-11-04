# EtherNet/IP/CIP：审查后的完整子集描述输入

本目录是原10条完整消息的独立审查副本，保留原 wire example，修订字段范围、服务语义和执行边界。文件为 `protocol_spec.yaml`、`state_transition.yaml` 与机器可读 `constraints.json`。没有发布 IR、validation 或 seeds；`support.runtime:true` 只表示已有有界 C codec，不表示本副本已经完成原生验证。

| 问题 | 本次修订 |
| --- | --- |
| 成功/错误 status 与 Vendor-ID 长度不精确 | 成功固定0、指定错误固定0x14；Vendor-ID恰2字节，错误无结果数据 |
| EPATH 声明像通用数组 | 明确class/instance/attribute=1/1/1及支持的8/16/32位逻辑段，总长6..18字节 |
| 派生长度、session及响应context范围含糊 | 按当前子集调整长度范围/默认值，要求已注册句柄非零，响应context明确关联绑定 |
| 服务和外部前提主要散落在说明里 | constraints逐消息列出具体服务、状态/长度、外部Class-3条件及仍未实现的语义 |

消息覆盖：RegisterSession请求/成功/0x69错误、无回复UnregisterSession、SendRRData Identity Vendor-ID请求/成功/0x14错误、SendRRData 0x64无效session、SendUnitData Identity Vendor-ID请求/成功，共10条。响应包含完整CPF/CIP体；字节完整不等于所有服务和会话语义完整。

SendUnitData仍必须先由外部成功ForwardOpen在同一session建立未过期Class-3连接并提供双向ID。当前副本没有把RegisterSession当成这一前提，没有新增ForwardOpen实例、绑定API或计时器。状态guard/actions和结构树只作静态说明；ID默认值与序号缓存都不是外部协商证据。

现有独立 `generic_wire.json` 仍只迁移RegisterSession双向（2/10），且 `online:false`。其余8条及session绑定、CPF/EPATH、连接生命周期仍需通用语言/运行时扩展；本目录不提供伪造的通用实现，不将完整CIP体固定为opaque bytes后声称完成迁移。

本轮只做文件静态审查与直接JSON Schema检查，未运行compiler、原生validator、测试或目标。要形成正式包，需要在后续允许执行的环境中从本目录显式准备、原生校验并生成IR及语料；再单独验证现场响应、外部前提、内存状态和方法收益。

来源：原发布输入[protocol_spec.yaml](../../ethernet_ip_cip_tcp/protocol_spec.yaml)、[state_transition.yaml](../../ethernet_ip_cip_tcp/state_transition.yaml)，当前[有界C codec](../../../protocol_codec_enip.c)及[执行器](../../../protocol_runtime.c)。wire实施依据保留原输入固定[OpENer revision](https://github.com/EIPStackGroup/OpENer/tree/d8820ef41ce30dda06d213438ba81c81de33ffe2/source/src)；[ODVA目录](https://www.odva.org/subscriptions-services/specifications/)只说明标准获取边界，没有声称已阅读付费规范全文。完整问题、修订、约束与剩余缺口见[constraints.json](constraints.json)。
