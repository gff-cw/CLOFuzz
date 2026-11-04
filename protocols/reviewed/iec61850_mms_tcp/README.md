# IEC 61850 MMS/TCP 静态复核描述候选

本目录保留14条完整参考报文（7请求、7响应）及全部字段、依赖与状态，并按当前有界codec收紧声明。它是原有profile的独立修订输入，不替换 `protocols/iec61850_mms_tcp`，不包含已验证IR、validation、seeds或运行验收结论。

| 问题 | 本候选的修复 | 边界 |
| --- | --- | --- |
| CR destination reference可任意变异 | fixed=0；CC仍关联CR的source reference | 只实现TP0连接和既有参数范围 |
| context/version允许codec拒绝的值 | association context/version固定1；服务/conclude显式context3，release显式context1 | context是协议presentation ID，不是目标内存状态ID |
| Read/Write树声称多变量与variable-list-name | 仅保留一个domain-specific变量，domain/item非空 | 不添加named-variable-list、alternate-access或一般数组 |
| Write树声称一般MMS Data | 仅一条VisibleString，Read响应明确列出codec支持的Data分支 | 静态树不执行，也不证明所有Data分支具备完整标准语义 |
| state暗示通用negotiated-outstanding处理 | 明确single-flight与guards/actions的静态地位 | 不实现并发事务数据库 |
| 完整容器字段容易误解为通用编码器 | 标注完整session/presentation投影与named-leaf变异边界 | 不将opaque BER/ACSE替换视为任意容器生成 |

association包含TPKT/COTP、session CONNECT/ACCEPT、presentation CP/CPA、ACSE AARQ/AARE及嵌入MMS Initiate。Initiate不被伪造为独立TCP消息。GetNameList限VMD domain枚举；Read/Write限一个domain-specific变量，Write值为VisibleString。MMS conclude与ACSE/session release分别建模。

`constraints.json` 为14条消息分别列出执行条件与执行位置。原generic描述仍仅含COTP CR/CC、`online:false`，缺少其余12条消息；本候选没有把完整BER消息塞进fixed opaque payload冒充通用服务语义。

依据为原包的YAML及其固定参考fixture、`protocol_codec_mms.c`、`protocol_runtime.c`，以及本地libIEC61850的 `src/mms/iso_cotp/cotp.c`。原YAML保留固定libIEC61850 revision与RFC1006等来源声明；RFC1006只支持TPKT/COTP依据，不能外推为MMS/ACSE全规范已核验；付费IEC/ISO全文未因此取得。

这里只完成静态schema/引用/示例身份检查；没有运行项目编译器、原生validator、测试或目标服务。以后可在仓库根目录将候选生成到新包：

```sh
python3 tools/init_protocol_spec.py --source-dir protocols/reviewed/iec61850_mms_tcp \
  --require-runtime --output-dir /tmp/reviewed-mms-package
```

本轮未执行此命令。`runtime_encode`保留已有codec能力断言，不能充当本候选的运行证据。现有完整fixture、模型约束、实际目标会话和方法有效性须分别验收。
