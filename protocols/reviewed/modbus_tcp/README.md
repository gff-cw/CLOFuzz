# Modbus TCP：复核后的完整配置输入

本目录是从原发布包独立复制并修订的源描述，使用已有 Modbus codec。包含26条完整布局消息：9条请求、9条正常响应、8条按功能码区分的异常响应，以及1个语义状态、26条状态边。这里的“完整”限定为FC01/02/03/04/05/06/0F/10的客户端请求/响应布局；没有覆盖整个Modbus标准，也没有声称全部事务语义已执行验证。

## 问题与修复

| 问题 | 修复 |
| --- | --- |
| 读响应data范围为0..4096，超出codec且允许空数据 | 位读数据1..250字节，寄存器2..250字节；偶数由codec检查 |
| 唯一异常模型function可变，却只关联FC03 | FC03异常固定0x83；另补FC01/02/04/05/06/0F/10七种固定异常function，分别关联现场请求transaction/unit |
| 响应关联目标仍标记普通可变 | 对copy/correlate目标明确使用runtime_bound |
| 异常状态材料不完整 | 每个新增异常均有独立response状态边；正常请求仍声明正常预期响应，异常由实际correlate依赖识别pending请求 |

`write_coils_partial`的数量9与`write_coils`数量8是不同示例值；它们保留相同的执行字段范围、策略、依赖和状态迁移，供当前runtime作为canonical aliases处理。因此FC0F异常只声明一个`write_coils_exception`，共享canonical请求缓存与pending身份。本轮执行器扩展已对本目录输入另行做native准备；具体结果和产物路径以[扩展报告](../../../docs/executor-extension-20261104.zh-CN.md)为准。

`constraints.json`逐消息列明codec/model约束、修复项、generic覆盖及剩余问题。会话执行器已按现场已提交请求检查四类读响应的quantity与数据长度方程，位响应的末字节未用高位也必须为零。FC05候选values也不是接受白名单，其离散有效值由codec检查。

## 使用及验证范围

本目录不包含IR、validation、seeds或声称已验证的派生产物。准备正式包的命令如下；本轮已在独立输出目录执行native准备，避免把派生产物写回源目录：

```sh
python3 tools/init_protocol_spec.py --source-dir protocols/reviewed/modbus_tcp \
  --require-runtime --output-dir /tmp/reviewed-modbus-package
```

该步骤使用现有codec做实际编译/原生检查，随后由生成器规划新的受管理语料。不要把原包的IR、validation或manifest拷贝过来作为新源的证明。原发布包及其历史证据保持原状；本目录也不由旧`generate_protocol_models.py`自动生成。

## 剩余执行限制

- `protocol_session_constraints.c`已执行读位`ceil(quantity/8)`、读寄存器`2*quantity`、位填充和写回显检查；拒绝响应保留pending，prepare取消回滚会话。该能力仍限定为上述八类服务。
- address+quantity的范围及设备实际映射不是执行约束；完整服务布局不保证设备接受所有地址。
- 运行时仅允许一个pending请求，未实现并发transaction数据库。
- 原`generic_wire.json`仍是FC03单寄存器两消息online子集，不等于本目录的26消息描述。generic语言已增加数量算术、位长度/填充和响应备选；独立`tests/generic-wire/full_modbus.json`以24条canonical grammar验证八类功能，尚未作为本发布包替换。
- 本轮已另行做native准备、C/sanitizer回归和受控本地运行。每项结果及路径见[执行器扩展报告](../../../docs/executor-extension-20261104.zh-CN.md)；这些测试不等于独立设备互通或固定预算的方法收益证明。本目录仍只保存可编辑源。

## 来源

- [原发布描述](../../modbus_tcp/protocol_spec.yaml)及其[state模型](../../modbus_tcp/state_transition.yaml)。
- [Modbus Application Protocol V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)，对应6.1–6.6、6.11–6.12及第7节；未将未覆盖的其他服务计入本profile。
- [libmodbus实现](https://raw.githubusercontent.com/stephane/libmodbus/master/src/modbus.c)用于交叉核对读数量与响应长度关系；它不替代项目当前codec的执行边界。
- [当前codec](../../../protocol_codec_modbus.c)和[运行时关联逻辑](../../../protocol_runtime.c)。
