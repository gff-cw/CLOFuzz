# IEC 60870-5-104：复核后的完整配置输入

本目录独立复制并修订已有IEC104 codec的源描述。包含11条完整布局消息、6个语义状态、23条状态边，覆盖客户端发起的STARTDT/STOPDT/TESTFR、S确认和单对象C_IC_NA_1的请求、正/负激活确认与结束。本轮已实现有界APCI连接序号、窗口和调用边界计时检查；监测数据ASDU、自动调度和服务器主动控制仍不属于该profile。它不是整个IEC104标准的完整描述。

## 问题与修复

| 问题 | 修复 |
| --- | --- |
| COT整个当作uint16，响应仍继承cause=6的注释 | 显式拆成abs8 cause/PN/test与abs9 originator，保持线上2字节；每种响应写明自己的cause/PN值 |
| originator没有现场关联 | 三种响应都比较缓存请求的originator，CA/QOI也保留实际请求比较 |
| 负确认只copy而不完成pending | positive/negative的CA改用correlate_request_response；termination继续copy，作为正确认之后的后续响应 |
| 响应继承本地序号写入依赖 | 移除响应端sequence_number，避免把收到的对端序号描述为本地自增程序 |
| TESTFR及S确认状态边不全 | 补starting/stopping的TESTFR请求/确认，以及两个interrogation阶段的S确认自环 |

COT低字节的低6位分别为6/7/10，P/N区分正/负确认；test位是独立标志。当前codec用低7位区分对应消息，允许test位变化，描述保留0..255范围并明确这一执行规则。`values`仅为候选建议，不能用它声称枚举接受校验；旧compiler的fixed标量也只允许单值，不能用fixed+多个values伪装掩码。

`constraints.json`逐消息登记实际约束与剩余缺口。状态guard/action仍是静态说明。实际N(S)/N(R)、窗口、计时检查来自`protocol_iec104_session.c`及其runtime集成，而不是图中文字。S确认和TESTFR控制可以在应用pending期间发送；应用事务仍为单pending。数据ASDU解析和自动调度未实现。

## 使用及验证范围

本目录没有IR、validation或seeds。生成正式包的使用步骤如下；本轮已在独立输出目录进行native准备：

```sh
python3 tools/init_protocol_spec.py --source-dir protocols/reviewed/iec60870_5_104 \
  --require-runtime --output-dir /tmp/reviewed-iec104-package
```

这会使用当前codec实际校验并规划新包；不要复用原发布包的validation/manifest为新源背书。本轮同步修订了原发布IEC描述及生成器的固定字段、会话绑定和S确认边；历史执行证据保持原状。本目录仍是独立可编辑输入，不是旧生成器的自动输出。

## 执行范围与剩余限制

- 发送侧N(S)/N(R)已由连接实际进度绑定，接收侧检查独立15位序号、回卷和累计确认窗口。单值VSQ/IOA固定；会话重绑定序号不作为有效字段变异候选。
- k/w和t0/t1/t2/t3在发送/接收调用边界检查，默认k=12、w=8，本地k上限128；应用pending与START/STOP/TEST控制pending分别跟踪。会话开始会重置连接状态，prepare/cancel不提前提交序号。
- 没有自动发送S/TESTFR、deadline轮询或自动重连调度器；长期空闲连接不能仅凭这些检查获得自主保活。应用事务仍为单pending。
- 真正interrogation可能在确认和结束间发送监测数据ASDU；当前codec不解析它们，也不实现服务器主动U控制流程。独立收到的S确认已接入发送窗口更新。
- 原generic描述仍是4消息offline-only迁移子集，未与本目录源字段和状态等价；不得仅改online标志开启。
- 本轮已另行执行native准备及ASan/UBSan会话与runtime回归；受控本地运行、字段采样结果和限制见[执行器扩展报告](../../../docs/executor-extension-20261104.zh-CN.md)。这不认证完整工业设备会话或固定预算的方法有效性。本目录仍不保存生成证据。

## 来源

- [原发布描述](../../iec60870_5_104/protocol_spec.yaml)及其[state模型](../../iec60870_5_104/state_transition.yaml)。
- [lib60870连接实现](https://raw.githubusercontent.com/mz-automation/lib60870/master/lib60870-C/src/iec60870/cs104/cs104_connection.c)用于交叉核对默认COT/CA/IOA宽度2/2/3、APCI控制及收发序号/窗口/计时器。
- [IEC官方目录](https://webstore.iec.ch/en/publication/25035)只作版本出处；没有读取付费标准全文，字段依据不升级为规范全文已验证。
- [当前codec](../../../protocol_codec_iec104.c)及[运行时响应关联](../../../protocol_runtime.c)。
