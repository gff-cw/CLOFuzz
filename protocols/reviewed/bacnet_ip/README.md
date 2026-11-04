# BACnet/IP 静态复核描述候选

本目录保留7条完整示例消息（2请求、5响应）和其字段、依赖与状态声明。它是原有 profile 的独立修订输入，不替换 `protocols/bacnet_ip` 发布包，不包含已验证 IR、validation、seeds 或验收结论。

| 问题 | 本候选的处理 | 仍然存在的边界 |
| --- | --- | --- |
| 可选路由 NPDU 的范围与响应绝对偏移不一致 | 将本候选明确收紧为 un-routed；Who-Is/响应 control=0，ReadProperty control=4 | 不能将底层 parser 的较宽能力当成本描述已覆盖路由。扩展须增加动态定位器及真实报文 |
| state 暗示多个并发 invoke | 删除 pending→pending 的 ReadProperty 请求边，明确 single-flight | guards/actions 是文字；不实现多事务表 |
| I-Am Device/segmentation 的范围过宽 | Device object type固定为8，segmentation范围0..3 | I-Am的绝对字段切片只适用当前fixture标签宽度 |
| 响应示例完整与动态语法完整易混淆 | I-Am/Error/Reject/Abort字段和notes逐条注明fixture投影 | 不虚构语义locator；原有完整字节不等于能识别任意动态响应 |

Who-Is和ReadProperty仍是仅有的请求编码范围。I-Am在协议线上是非确认服务请求，在这里按跟随Who-Is的响应角色组织；它也可能由设备主动发送。ReadProperty的字段和可选数组索引保留原有语义定位器；property/index生成仍限UInt8。响应的协议语义状态不等于StateAFL推断的内存状态。

`constraints.json` 逐消息列出实际条件、执行位置与剩余缺口。原generic描述仍为 `online:false`，只包含ReadProperty/ACK，缺少另外5条消息；本目录没有用固定opaque payload冒充通用语义，也没有更改online标志。

来源是原包的 `protocol_spec.yaml` / `state_transition.yaml`、`protocol_runtime.c` 的BACnet解析和single-flight检查、`tools/proto_spec_compiler.py` 的位置映射，以及本地BACnet Stack `src/bacnet/{iam,bacerror,npdu,rp}.c`。公开实现依据保持原YAML的 `sources` 声明；没有据此声称核验了付费ASHRAE全文。

这里只做静态schema/引用/示例身份检查；没有运行项目编译器、原生validator、测试或目标服务。后续可在仓库根目录将此输入对实例化到新目录：

```sh
python3 tools/init_protocol_spec.py --source-dir protocols/reviewed/bacnet_ip \
  --require-runtime --output-dir /tmp/reviewed-bacnet-package
```

这条命令本轮未运行；是否通过现有原生检查、实际响应关联、内存边界和方法对照，仍需分别保留证据。`runtime_encode`继承已有codec能力，不能视为本候选已经运行验收。
