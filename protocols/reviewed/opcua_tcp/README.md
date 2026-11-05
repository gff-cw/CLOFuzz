# OPC UA TCP：审查后的完整子集描述输入

本目录独立保留10条完整wire example及其服务体结构，修订原字段范围和执行边界。输入为 `protocol_spec.yaml`、`state_transition.yaml`，逐消息约束及剩余缺口见[constraints.json](constraints.json)。没有IR、validation或seeds；`support.runtime:true`表示现有有界codec可用，不是本副本的原生验收结果；本轮另行生成的native包及测试记录见[执行器扩展报告](../../../docs/executor-extension-20261104.zh-CN.md)。

| 问题 | 本次修订 |
| --- | --- |
| HEL/ACK版本、buffer和URL范围宽于实际profile | protocol_version固定0，None buffer至少8192，HEL/RHE传输String内容最多4091字节 |
| 服务NodeId和共享notes没有准确限定每个服务 | 明示namespace0 IDs 446/449/428/431/397/452；保留可变NodeId类型，内容长度4..7且精确身份仍由codec检查 |
| None安全头及分配值允许不支持的边界 | policy长度47；证书/thumbprint内容长度0并由codec要求null；channel/token/lifetime非零 |
| 成功与ServiceFault状态混淆 | 成功服务状态固定Good(0)，ServiceFault要求bit31置位（当前codec检查范围，不代表完整状态码枚举/保留位校验） |
| 某些codec限制和运行未实现语义隐含 | 补齐null auth/AdditionalHeader、匿名None endpoint、array/depth限制与逐消息约束，明确静态guard/actions边界 |

消息覆盖：HEL、ACK、ERR、server-to-client RHE、None Issue OpenSecureChannel双向、GetEndpoints双向、其MSG ServiceFault，以及实施profile CLO，共10条。完整RequestHeader/ResponseHeader与嵌套EndpointDescription/ApplicationDescription/UserTokenPolicy结构保留；这不是整个OPC UA标准或Session服务集合。

现有codec接受单final chunk、None安全策略、匿名None endpoint；数组最多64项、DiagnosticInfo深度最多8。String/ByteString/数组长度有signed Int32与null语义。结构树只是静态说明；codec负责真实定位和约束，不能把完整body当作支持任意opaque变异的编码程序。

`protocol_session_constraints.c`现已执行HEL/ACK相向buffer上限、协商后的单final chunk和消息体限额；0限额按无限制解释。None Issue响应绑定channel/token，寿命保守地从本地OPN提交时刻起计；双向序号各自要求后续exact-next，response的request ID/handle必须匹配。拒绝不消耗pending，prepare/cancel通过快照回滚；CLO提交后本地关闭并清除token。guard/actions仍是说明，这些行为来自实际会话模块。Renew、重叠token、完整序号回卷、加密和Session服务仍未实现；UInt32序号耗尽要求重连。

当前独立generic-wire描述仅HEL/ACK（2/10），`online:false`。另外8个模型及其UA Binary长度/null/NodeId/嵌套数组和token绑定不能靠固定整个服务体补齐。本目录没有修改该迁移状态，也没有冒称完整通用执行器。

CLO保留实施profile的NodeId452+RequestHeader；[Part6 §7.1.4](https://reference.opcfoundation.org/specs/OPC-10000-6/7.1.4)描述空body且无响应。两者差异未解决，不能将此fixture称为全规范CLO。

本轮已另行执行本输入对的native准备、会话ASan/UBSan回归及受控本地discovery-profile运行。精确输出路径和当前结果见[执行器扩展报告](../../../docs/executor-extension-20261104.zh-CN.md)。源目录与静态catalog仍不保存派生validation或声称运行通过；这些本地测试也不等于独立实现互通或固定预算的方法收益证明。

来源：原发布[协议输入](../../opcua_tcp/protocol_spec.yaml)与[状态输入](../../opcua_tcp/state_transition.yaml)，当前[有界C codec](../../../protocol_codec_opcua.c)及[执行器](../../../protocol_runtime.c)。HEL/ACK修订核对官方[Hello](https://reference.opcfoundation.org/specs/OPC-10000-6/7.1.2.3)、[Acknowledge](https://reference.opcfoundation.org/specs/OPC-10000-6/7.1.2.4)；服务仍以原输入的[OPC UA Part4/6](https://reference.opcfoundation.org/specs/OPC-10000-6/full)和固定[asyncua实施revision](https://github.com/FreeOpcUa/opcua-asyncio/tree/c321a240e53d083fd6e167c67f795915d8f236fd/asyncua/ua)为依据。历史fixture来源核验不转写成本轮执行证据。
