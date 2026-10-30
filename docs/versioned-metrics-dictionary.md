# 版本化指标字典与分母对账契约 (Versioned Metrics Dictionary & Denominators)

本文档规范 StateAFL 与 Generic-Wire 运行时在不同管道阶段的指标定义、触发点、计算分母与诊断分类，彻底消除候选构造、网络执行、响应观察和奖励提交之间的统计分母混杂。

---

## 1. 管道阶段指标与生命周期

变异候选从生成到奖励经历严格的顺序阶段。各阶段指标具有独立的单位与触发点，禁止跨阶段混用分母。

| 指标名称 (Metric) | 统计单位 | 触发点 (Trigger Point) | 作用域与生命周期 | 终态性质 | 推荐对账分母 (Denominator) |
| --- | --- | --- | --- | --- | --- |
| `candidate_attempts` | 候选 (candidate) | 进入结构化变异选择入口 (`protocol_prepare` / `gr_mutate`) | 单次候选生成 | 过程计数 | 总尝试预算 (attempt budget) |
| `construction_success` | 候选 (candidate) | 变异规则应用完成且模型 pack 成功 (`proto_mutate` / `gr_pack`) | 单次候选生成 | 成功出口 | `candidate_attempts` |
| `changed` | 候选 (candidate) | 变异后序列内容与原始输入不相等 (`*olen != length || memcmp != 0`) | 单次候选生成 | 成功出口子集 | `construction_success` |
| `unchanged` (no-op) | 候选 (candidate) | 变异后序列内容与原始输入逐字节一致 | 单次候选生成 | 成功出口子集 | `construction_success` |
| `unavailable` | 候选 (candidate) | 请求变异层在当前序列中无任何可变字段 (`gw_has_role == 0`) | 单次候选生成 | 快速拒绝 | `candidate_attempts` |
| `host_accepted` | 候选 (candidate) | 完整序列通过宿主全量校验 (M1+M2+M3 预算及语义转移契约) | 单次执行前 | 准入出口 | `construction_success` |
| `structured_runs` | 执行 (execution) | 目标被 forkserver 启动且挂载结构化报文 | 单次运行 | 运行状态 | `host_accepted` |
| `complete_transmissions` | 执行 (execution) | 会话所有请求均完整写入套接字 (`sent == count`) 无网络异常中断 | 单次运行 | 完整传输 | `structured_runs` |
| `valid_observations` | 执行 (execution) | 完整传输且非异常崩溃，具备反馈采集资格 | 单次运行 | 观测就绪 | `complete_transmissions` |
| `reward_committed` | 候选 (candidate) | 产生新覆盖或新内存状态，完成调度器奖励更新 (至多一次) | 单次候选生命周期 | 奖励终态 | `valid_observations` |

> [!IMPORTANT]
> **分母除以零规则**：当分母计数为 0 时，对应比率必须标为 `N/A` (不适用)，严禁伪造为 0.0% 或 100.0%。

---

## 2. 响应诊断分类矩阵 (Response Diagnostics)

目标服务返回的网络数据被解析并严格归入以下互斥分类。无未知静默吞噬，不混淆待补齐帧与协议错误。

| 诊断类型 | 严重性 | 触发条件 | 说明 |
| --- | --- | --- | --- |
| `incomplete_frames` | 瞬态缓冲 | 接收字节数小于报头声明长度 (`n > receive_size - at`) | 仍可继续接收后续流数据补齐，不计入终局失败 |
| `framing_errors` | 协议错误 | 报头解析失败、长度小于固定头部或超出 `GR_WIRE`/`MAX_FILE` | 非法帧，清空残余流缓冲 |
| `grammar_mismatches` | 模型不符 | 数据包不匹配当前协议描述中声明的任何响应文法 | 响应内容不符合 Grammar 约束 |
| `unrelated_responses` | 逻辑不符 | 响应文法合法，但当前会话无 pending 请求或不属于期望的响应类型 | 收到与当前期待请求无关的报文 |
| `correlation_mismatches` | 关联失败 | 响应类型正确，但关键关联字段 (如 Transaction ID, Invoke ID) 不匹配 | 响应未通过请求关联校验 |
| `expected_complete` | 成功关联 | 响应文法合法、类型匹配且所有声明关联字段完全一致 | 完成 pending 状态，推进语义自动机 |

---

## 3. 按执行用途划分响应计数 (Responses By Purpose)

响应计数按执行上下文严格隔离，防止确认运行、校准运行或同步导入干扰真实变异的响应统计：

- `original` (`EXEC_PURPOSE_ORIGINAL` = 1)：覆盖率引导的常规模糊测试探索运行。
- `confirmation` (`EXEC_PURPOSE_CONFIRMATION` = 2)：新颖性确认重放运行，用于验证状态和路径稳定性。
- `calibration` (`EXEC_PURPOSE_CALIBRATION` = 3)：初始种子或校准阶段执行。
- `sync` (`EXEC_PURPOSE_SYNC` = 4)：多实例协作中的同步导入回放。
- `unknown` (`EXEC_PURPOSE_UNKNOWN` = 0)：未明确标记执行用途的辅助运行。

---

## 4. 统计文件输出格式规范 (Stats Schema)

统计输出声明 `stats_version: 2` 与 `metrics_version: 1`：

```json
{
  "stats_version": 2,
  "metrics_version": 1,
  "attempts": 100,
  "structured_success": 95,
  "rejected": 5,
  "HEAD": 40,
  "CONTENT": 40,
  "SEQUENCE": 15,
  "changed": [38, 37, 15],
  "unchanged": [2, 3, 0],
  "unavailable": [3, 2, 0],
  "responses": 80,
  "completed_responses": 75,
  "correlated_responses": 70,
  "response_diagnostics": {
    "incomplete_frames": 2,
    "framing_errors": 0,
    "grammar_mismatches": 1,
    "unrelated_responses": 2,
    "correlation_mismatches": 2,
    "expected_complete": 75
  },
  "responses_by_purpose": {
    "original": 70,
    "confirmation": 10,
    "calibration": 0,
    "sync": 0,
    "unknown": 0
  },
  "protocol_semantic_state": "ready",
  "engine": "generic-wire"
}
```
