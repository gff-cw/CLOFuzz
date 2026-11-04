# IEC 60870-5-104：复核后的完整配置输入

本目录独立复制并修订已有IEC104 codec的源描述。包含11条完整布局消息、6个语义状态、23条状态边，覆盖客户端发起的STARTDT/STOPDT/TESTFR、S确认和单对象C_IC_NA_1的请求、正/负激活确认与结束。它不是整个IEC104标准的完整描述，也没有把数据ASDU、窗口、计时器或异步连接会话声明成已经实现。

## 问题与修复

| 问题 | 修复 |
| --- | --- |
| COT整个当作uint16，响应仍继承cause=6的注释 | 显式拆成abs8 cause/PN/test与abs9 originator，保持线上2字节；每种响应写明自己的cause/PN值 |
| originator没有现场关联 | 三种响应都比较缓存请求的originator，CA/QOI也保留实际请求比较 |
| 负确认只copy而不完成pending | positive/negative的CA改用correlate_request_response；termination继续copy，作为正确认之后的后续响应 |
| 响应继承本地序号写入依赖 | 移除响应端sequence_number，避免把收到的对端序号描述为本地自增程序 |
| TESTFR及S确认状态边不全 | 补starting/stopping的TESTFR请求/确认，以及两个interrogation阶段的S确认自环 |

COT低字节的低6位分别为6/7/10，P/N区分正/负确认；test位是独立标志。当前codec用低7位区分对应消息，允许test位变化，描述保留0..255范围并明确这一执行规则。`values`仅为候选建议，不能用它声称枚举接受校验；旧compiler的fixed标量也只允许单值，不能用fixed+多个values伪装掩码。

`constraints.json`逐消息登记实际约束与剩余缺口。状态guard/action仍是静态说明。新增图边不会解除当前runtime的single-pending发送限制，也不会凭空获得现场N(R)、计时器或数据ASDU解析能力。

## 使用及验证范围

本目录没有IR、validation或seeds。生成正式包的后续使用步骤如下，本轮未执行：

```sh
python3 tools/init_protocol_spec.py --source-dir protocols/reviewed/iec60870_5_104 \
  --require-runtime --output-dir /tmp/reviewed-iec104-package
```

这会使用当前codec实际校验并规划新包；不要复用原发布包的validation/manifest为新源背书。原发布包、生成器与历史证据保持不变；本目录不是旧生成器的自动输出。

## 剩余执行限制

- 线上N(S)/N(R)是各方向独立的15位序号，线上左移1；现有单条request sequence_number不等于完整连接序号机。receive_seq缺少实际对端进度绑定。
- k/w窗口、t0/t1/t2/t3计时器、重连及复位没有作为执行程序建模。
- pending期间即便图中存在TESTFR或S确认边，当前runtime仍可能拒绝发送；图完整不等于并发控制通道已经实现。
- 真正interrogation可能在确认和结束间发送监测数据ASDU；当前codec不解析它们。服务器主动控制流程和独立收到S确认的完整会话也未覆盖。
- 原generic描述仍是4消息offline-only迁移子集，序号固定，未与本目录的源字段和状态等价；不得仅改online标志开启。
- 本轮只做静态schema、字节、引用与状态检查，未执行compiler/native validator、测试或目标，未认证现场会话和方法有效性。

## 来源

- [原发布描述](../../iec60870_5_104/protocol_spec.yaml)及其[state模型](../../iec60870_5_104/state_transition.yaml)。
- [lib60870连接实现](https://raw.githubusercontent.com/mz-automation/lib60870/master/lib60870-C/src/iec60870/cs104/cs104_connection.c)用于交叉核对默认COT/CA/IOA宽度2/2/3、APCI控制及收发序号/窗口/计时器。
- [IEC官方目录](https://webstore.iec.ch/en/publication/25035)只作版本出处；没有读取付费标准全文，字段依据不升级为规范全文已验证。
- [当前codec](../../../protocol_codec_iec104.c)及[运行时响应关联](../../../protocol_runtime.c)。
