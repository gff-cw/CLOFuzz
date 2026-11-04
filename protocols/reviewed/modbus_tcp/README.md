# Modbus TCP：复核后的完整配置输入

本目录是从原发布包独立复制并修订的源描述，使用已有 Modbus codec。包含26条完整布局消息：9条请求、9条正常响应、8条按功能码区分的异常响应，以及1个语义状态、26条状态边。这里的“完整”限定为FC01/02/03/04/05/06/0F/10的客户端请求/响应布局；没有覆盖整个Modbus标准，也没有声称全部事务语义已执行验证。

## 问题与修复

| 问题 | 修复 |
| --- | --- |
| 读响应data范围为0..4096，超出codec且允许空数据 | 位读数据1..250字节，寄存器2..250字节；偶数由codec检查 |
| 唯一异常模型function可变，却只关联FC03 | FC03异常固定0x83；另补FC01/02/04/05/06/0F/10七种固定异常function，分别关联现场请求transaction/unit |
| 响应关联目标仍标记普通可变 | 对copy/correlate目标明确使用runtime_bound |
| 异常状态材料不完整 | 每个新增异常均有独立response状态边；正常请求仍声明正常预期响应，异常由实际correlate依赖识别pending请求 |

`write_coils_partial`的数量9与`write_coils`数量8是不同示例值；它们保留相同的执行字段范围、策略、依赖和状态迁移，供当前runtime作为canonical aliases处理。因此FC0F异常只声明一个`write_coils_exception`，共享canonical请求缓存与pending身份。该别名与新增输入的实际native接受情况仍须后续校验。

`constraints.json`逐消息列明codec/model约束、修复项、generic覆盖及剩余问题。四类读响应当前只关联transaction/unit，**没有执行请求quantity与响应数据长度的跨消息方程**。FC05候选values也不是接受白名单，其离散有效值由codec检查。

## 使用及验证范围

本目录不包含IR、validation、seeds或声称已验证的派生产物。准备正式包的命令如下，属于后续使用步骤，本轮未执行：

```sh
python3 tools/init_protocol_spec.py --source-dir protocols/reviewed/modbus_tcp \
  --require-runtime --output-dir /tmp/reviewed-modbus-package
```

该步骤使用现有codec做实际编译/原生检查，随后由生成器规划新的受管理语料。不要把原包的IR、validation或manifest拷贝过来作为新源的证明。原发布包及其历史证据保持原状；本目录也不由旧`generate_protocol_models.py`自动生成。

## 剩余执行限制

- 读位响应的`ceil(quantity/8)`、寄存器响应的`2*quantity`，以及响应末字节位填充未与现场请求联合核对；需要运行时算术关联。
- address+quantity的范围及设备实际映射不是执行约束；完整服务布局不保证设备接受所有地址。
- 运行时仅允许一个pending请求，未实现并发transaction数据库。
- 原`generic_wire.json`仍是FC03单寄存器两消息online子集，不等于本目录的26消息描述；generic语言仍缺完整数量方程、位打包、正常/异常选择等能力。
- 本轮仅静态文件/schema/引用检查；未运行项目工具、native validator、测试或目标。未获得现场会话与方法收益证据。

## 来源

- [原发布描述](../../modbus_tcp/protocol_spec.yaml)及其[state模型](../../modbus_tcp/state_transition.yaml)。
- [Modbus Application Protocol V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)，对应6.1–6.6、6.11–6.12及第7节；未将未覆盖的其他服务计入本profile。
- [libmodbus实现](https://raw.githubusercontent.com/stephane/libmodbus/master/src/modbus.c)用于交叉核对读数量与响应长度关系；它不替代项目当前codec的执行边界。
- [当前codec](../../../protocol_codec_modbus.c)和[运行时关联逻辑](../../../protocol_runtime.c)。
