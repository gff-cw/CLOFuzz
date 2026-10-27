# 六种工业协议描述文件

本目录包含同一 ICP-IR v1 模板下的六套具体协议描述。当前共 **71 条完整消息示例、641 个字段声明**，含31条请求、40条响应。这里的“完整”指明确声明 profile 中报文的各层与服务体完整，不代表覆盖整部工业协议标准。

| 协议描述 YAML | 状态 YAML | 消息 / 字段 / 状态 | 明确范围 | 支持等级 |
| --- | --- | --- | --- | --- |
| [BACnet/IP](bacnet_ip/protocol_spec.yaml) | [状态](bacnet_ip/state_transition.yaml) | 7 / 66 / 2 | Who-Is/I-Am、ReadProperty ACK/Error、Reject/Abort，动态 NPDU 和 BACnet 标签 | BACnet 请求子集已实测 |
| [Modbus TCP](modbus_tcp/protocol_spec.yaml) | [状态](modbus_tcp/state_transition.yaml) | 19 / 138 / 1 | FC01–06/0F/10 请求响应、异常、packed coils、9-coil padding | 有界 C runtime；配套 TCP 功能夹具 |
| [IEC 60870-5-104](iec60870_5_104/protocol_spec.yaml) | [状态](iec60870_5_104/state_transition.yaml) | 11 / 62 / 6 | I/S/U、STARTDT/STOPDT/TESTFR、单对象总召唤确认和终止 | 有界 C runtime；配套 TCP 功能夹具 |
| [IEC 61850 MMS/TCP](iec61850_mms_tcp/protocol_spec.yaml) | [状态](iec61850_mms_tcp/state_transition.yaml) | 14 / 136 / 9 | 完整 COTP/session/presentation/ACSE association、GetNameList/Read/Write、conclude/release | 有界 C runtime；配套 TCP 功能夹具 |
| [EtherNet/IP + CIP/TCP](ethernet_ip_cip_tcp/protocol_spec.yaml) | [状态](ethernet_ip_cip_tcp/state_transition.yaml) | 10 / 132 / 4 | Register/Unregister、SendRRData、SendUnitData、CPF/EPATH；连接型消息有显式外部前提 | 有界 C runtime；配套 TCP 功能夹具 |
| [OPC UA TCP](opcua_tcp/protocol_spec.yaml) | [状态](opcua_tcp/state_transition.yaml) | 10 / 107 / 6 | HEL/ACK/ERR/RHE、完整 None OPN、GetEndpoints/ServiceFault、实现 profile CLO | 有界 C runtime；配套 TCP 功能夹具 |

每套目录另含 protocol_ir.json、state_ir.json、evidence.yaml、validation.json、README.md 和完整请求的 seeds/。通用可填写模板在 [templates/](templates/README.md)，格式校验规则在 schema/。

- [完整性与来源审查](../docs/protocol-model-audit.md)：逐协议范围、规范/实现证据、未覆盖内容。
- [六协议描述与 C 执行能力核验](../docs/six-protocol-executable-readiness.md)：profile边界、codec写入能力、在线三级C路径及实际验证结果。
- [五协议 YAML 与通用 C 接口审查](../docs/five-protocol-yaml-readiness.md)：静态字段/状态清单、保存 IR 一致性及执行契约边界；未运行编译、codec 或目标。
- [模板与 C/Python 一致性审查](../docs/template-audit.md)：已修复的问题及执行语义边界。
- [BACnet 多轮对照结果](../docs/bacnet-controlled-results.md)：真实发送样本、功能 A/B 和五模式重复实验。
- 描述包导出：`python3 tools/export_protocol_bundle.py --output deliverables/industrial-protocol-descriptions.zip`。ZIP 内含六套模型、模板、schema 和 SHA-256 MANIFEST。

## 重新生成与验证

仅检查五个 TCP profile 的 YAML schema、消息/状态/来源引用、字段证据完整性和保存的统计一致性：

```bash
python3 tools/check_protocol_descriptions.py
python3 tools/check_protocol_descriptions.py --spec-dir protocols/modbus_tcp
```

这个入口不调用 C 编译器、codec 或网络目标。逐包结果及四个描述文件的 SHA256 见 [静态检查记录](../tests/protocol/evidence/five-protocol-description-checks.json)。通过只说明列出的静态检查成立，不证明整个标准覆盖、解码正确或 StateAFL 执行验收完成。当前集成失败与证据边界见 [任务恢复记录](../docs/task-recovery.md)。

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

原 inputs 包含故意错误控制种子；做 valid-only 对照时使用实验驱动器筛选的四个正常种子。五种 TCP 描述包也可由同一入口加载，须使用 `-N tcp://...` 及符合该 profile 的目标和请求序列。真实工业目标的既有测试仍是 BACnet；新增五种 TCP 测试使用仪器化 C 功能夹具，不能据此声称工业产品互通、吞吐或覆盖收益。SendUnitData 仍要求外部 ForwardOpen，MMS/OPC UA 的认证、安全和完整会话排除项不变。

非 BACnet 描述编译由 `tools/native_protocol_codecs.py` 构建并调用原生 validator，需要 C11 编译器（`CC` 或 `cc`）、`protocol_codecs.h` 和五个 `protocol_codec_*.c` 源文件。在线 StateAFL 直接链接 C codec，不在每次变异执行 Python。实际回归状态应检查当前测试产物；此说明不宣告本轮最终测试全部通过。
