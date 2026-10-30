# 最小完整可运行协议描述示例 (Minimal Runnable Profile)

本目录提供一份已经过完整静态校验、可直接由 `tools/proto_spec_compiler.py` 编译并由 StateAFL C 运行时加载的最小参考示例（对应治理计划 **G04** 项）。

---

## 1. 核心概念与防误配要点

### 1.1 `values` 枚举候选 vs `min`/`max` 解析边界
* **`min` 与 `max`**：定义该字段在线格式物理编码中的数值边界。用于输入报文解码验证，任何合法报文的数值必须满足 `min <= value <= max`。
* **`values`**：定义模糊测试 HEAD 变异层级下的离散枚举候选值池。
  * **注意 1**：`values` 仅用于为变异器提供推荐测试值，**不作为**接收对端响应时的封闭枚举过滤。
  * **注意 2**：`values` 内部的所有值必须严格落在 `[min, max]` 区间内，否则编译器将报错拒绝。

### 1.2 预测状态 (Predicted State) vs 目标内存状态 (Target Memory State)
* **预测状态**（`state_transition.yaml`）：属于协议模型层。依据已发送的请求及接收的响应在预定义状态机（如 `connected`）上流转，用于约束和生成合法的报文序列（M1/M2/M3）。
* **目标内存状态**（StateAFL Tracer）：属于被测程序执行层。通过对目标进程内存区域（如 `state_shared.c` 快照）的哈希聚类动态推断状态。
* **隔离契约**：协议模型的预测状态**绝不直接等同于**被测程序的内存状态。两者分别独立维护，互不污染。

### 1.3 线分帧 (Wire Framing) vs 录制前缀 (Replay Prefix)
* **线分帧 (Wire Framing)**：目标网络套接字上实际传输的报文分帧协议（如 Modbus MBAP 报头的 16-bit 长度字段，或 UDP 独立数据报边界）。
* **录制前缀 (Replay Prefix)**：StateAFL / AFLNet 保存于磁盘种子文件（`.raw`）中的测试用例存储封装。每个消息前面会携带一个 **4 字节的小端序（LE32）长度头**，用于离线恢复多报文序列。在填写 YAML 模板的 `example` 时，**严禁**包含此 4 字节 LE32 前缀。

---

## 2. 编译与验证

在 stateafl 根目录下执行：

```bash
python3 tools/proto_spec_compiler.py \
  --protocol protocols/templates/minimal_runnable_example/protocol_spec.yaml \
  --state protocols/templates/minimal_runnable_example/state_transition.yaml \
  --output /tmp/minimal_modbus_ir
```

该命令将成功生成绑定的 `protocol_ir.json`、`state_ir.json` 和 `spec_bundle.json`。
