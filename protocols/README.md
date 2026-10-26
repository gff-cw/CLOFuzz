# 六种工业协议描述文件

本目录包含同一 ICP-IR v1 模板下的六套具体协议描述。当前共 **71 条完整消息示例、641 个字段声明**，含31条请求、40条响应。这里的“完整”指明确声明 profile 中报文的各层与服务体完整，不代表覆盖整部工业协议标准。

| 协议描述 YAML | 状态 YAML | 消息 / 字段 / 状态 | 明确范围 | 支持等级 |
| --- | --- | --- | --- | --- |
| [BACnet/IP](bacnet_ip/protocol_spec.yaml) | [状态](bacnet_ip/state_transition.yaml) | 7 / 66 / 2 | Who-Is/I-Am、ReadProperty ACK/Error、Reject/Abort，动态 NPDU 和 BACnet 标签 | BACnet 请求子集已实测 |
| [Modbus TCP](modbus_tcp/protocol_spec.yaml) | [状态](modbus_tcp/state_transition.yaml) | 19 / 138 / 1 | FC01–06/0F/10 请求响应、异常、packed coils、9-coil padding | 静态描述和完整报文检查；无在线编码器 |
| [IEC 60870-5-104](iec60870_5_104/protocol_spec.yaml) | [状态](iec60870_5_104/state_transition.yaml) | 11 / 62 / 6 | I/S/U、STARTDT/STOPDT/TESTFR、单对象总召唤确认和终止 | 静态描述和完整报文检查；无在线编码器 |
| [IEC 61850 MMS/TCP](iec61850_mms_tcp/protocol_spec.yaml) | [状态](iec61850_mms_tcp/state_transition.yaml) | 14 / 136 / 9 | 完整 COTP/session/presentation/ACSE association、GetNameList/Read/Write、conclude/release | 静态描述和完整报文检查；无在线编码器 |
| [EtherNet/IP + CIP/TCP](ethernet_ip_cip_tcp/protocol_spec.yaml) | [状态](ethernet_ip_cip_tcp/state_transition.yaml) | 10 / 132 / 4 | Register/Unregister、SendRRData、SendUnitData、CPF/EPATH；连接型消息有显式外部前提 | 静态描述和完整报文检查；无在线编码器 |
| [OPC UA TCP](opcua_tcp/protocol_spec.yaml) | [状态](opcua_tcp/state_transition.yaml) | 10 / 107 / 6 | HEL/ACK/ERR/RHE、完整 None OPN、GetEndpoints/ServiceFault、实现 profile CLO | 静态描述和完整报文检查；无在线编码器 |

每套目录另含 protocol_ir.json、state_ir.json、evidence.yaml、validation.json、README.md 和完整请求的 seeds/。通用可填写模板在 [templates/](templates/README.md)，格式校验规则在 schema/。

- [完整性与来源审查](../docs/protocol-model-audit.md)：逐协议范围、规范/实现证据、未覆盖内容。
- [模板与 C/Python 一致性审查](../docs/template-audit.md)：已修复的问题及执行语义边界。
- [BACnet 多轮对照结果](../docs/bacnet-controlled-results.md)：真实发送样本、功能 A/B 和五模式重复实验。
- 描述包导出：`python3 tools/export_protocol_bundle.py --output deliverables/industrial-protocol-descriptions.zip`。ZIP 内含六套模型、模板、schema 和 SHA-256 MANIFEST。

## 重新生成与验证

```bash
python3 tools/generate_protocol_models.py
python3 tests/protocol/test_model_completeness.py
bash tests/protocol/run_all.sh
```

运行 BACnet 时可直接选择本目录的 bacnet_ip 描述包：

```bash
BACNET_IFACE=lo BACNET_IP_PORT=47818 setarch "$(uname -m)" -R \
python3 tools/run_protocol_campaign.py --spec-dir protocols/bacnet_ip -- \
  -d -i ../bacnet-stack/inputs -o /tmp/bacnet-described-test \
  -N udp://127.0.0.1/47818 -D 200000 -E -K -q 3 -s 3 -m none -t 5000 \
  --mutation-mode hybrid --mutation-layers head,content,sequence \
  -- ../bacnet-stack/build-protocol-integration/server 123
```

原 inputs 包含故意错误控制种子；做 valid-only 对照时使用实验驱动器筛选的四个正常种子。其他五种协议目前仅可 `--validate-only`，不能用模型完整性代替尚未实现的在线编码器。
