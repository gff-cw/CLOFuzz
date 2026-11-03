# U06/U07：最小 profile 与模型请求语料修复

本记录只涉及描述生成与静态文件转换。没有运行单元测试、描述编译器、native helper、fuzzer、示例或目标服务；不据此宣称在线验收通过。

| 问题 | 具体修复 | 保留的边界 |
| --- | --- | --- |
| U06：最小 Modbus 请求 quantity 可到 125，但配对响应只能容纳 2 字节数据 | `minimal_runnable_example` 的 quantity 改为 fixed role/fixed mutability，`min=max=default=1`。README 明确只读一个 holding register。完整 `modbus_tcp` profile 的多寄存器范围没有收窄。 | 扩大最小示例必须同步调整请求/响应模型；此轮未运行 codec 或目标。 |
| U07：生成器把每条独立请求直接作为种子，MMS/OPC UA 等缺建链前缀 | 新增 `tools/protocol_seed_planner.py`，由模板生成器及参考模型生成器共用。原始单包保留到 `fixtures/requests/`，`seeds/` 只放从 initial 开始、经过模型投影可达的请求序列。 | 这是旧 codec 状态模型的路径证明，未验证实际目标会话或动态绑定。 |
| 只有未来生成结果变好，当前交付包仍保留坏种子 | 六个现有包已通过纯文件转换更新：31 个单包原样保存，31 个种子重新规划，新增 6 份 `seed_manifest.json`。 | 原始 `evidence.yaml`、`validation.json` 与历史日志没有重写。使用保存的 compiler validation 快照，未重新运行 parser 验证。 |
| 导出后缺少 helper 或模型与语料不同步 | 导出器包含 helper，并对 manifest、fixture、seed 的清单和内容做一致性检查；YAML 修改后可显式刷新受管理的 corpus。 | 导出器自身原有的 compiler 调用仍存在；本轮没有运行导出器。 |

## 规划规则

规划器不含按协议名硬编码的前缀表。它使用 compiler 提供的 canonical aliases；对应别名必须保持相同请求/预期响应角色与迁移语义。按旧 runtime `semantic_step()` 的规则，从当前状态选择请求边，先到达该边的 `to`，如有 expected response，再从该状态选择对应响应边并投影一次。不会递归追随响应边的 response，也不会借助无关的主动响应跨越状态。

BFS 为每个可达语义状态保存非支配资源标签；标签包含 canonical request repeat 计数和 replay 字节数。相同状态下，消耗不多的标签可以替代另一标签，因为该投影不执行 guard/actions 或事务缓存。搜索默认最多安排 16384 个节点，并遵守模型 `max_messages`、canonical `max_repeat`、包含全部 LE32 头的 `max_bytes`、1 MiB `MAX_FILE` 及单包 65507 字节限制。搜索预算或模型限制导致不可证明时，manifest 写明原因，fixture 保留，种子不生成。

`seed_manifest.json` 逐请求记录 fixture 路径、种子路径、请求 ID 序列、canonical repeats、模型状态、每步请求/预期响应投影、请求数量和序列化字节数。`actual_target_session_verified=false` 与 `responses_written_to_seeds=false` 明确其证据范围。片段、runtime 未验证或缺少完整可解析响应模型只作为 fixture；静态模型的 guard 分支不被伪装成可执行状态路径。

ENIP SendUnitData 仍只获得 `register → send_unit` 的模型路径；外部 ForwardOpen 与连接 ID 前提保留在 profile/manifest 中，没有构造或探测它们。session/channel/token 等现场值仍由实际响应绑定，规划器不会伪造响应。

| 描述包 | 原始请求 fixture / 模型种子 | 代表性请求路径 |
| --- | --- | --- |
| BACnet/IP | 2 / 2 | `read_property` |
| Modbus TCP | 9 / 9 | `read_holding` |
| IEC 60870-5-104 | 5 / 5 | `start_act → interrogation`；`start_act → stop_act` |
| MMS/TCP | 7 / 7 | `cotp_cr → associate → read`；`cotp_cr → associate → conclude → release` |
| ENIP/CIP TCP | 4 / 4 | `register → send_rr`；`register → unregister` |
| OPC UA TCP | 4 / 4 | `hello → open_channel → message`；`hello → open_channel → close_channel` |

## 本轮实际执行与未执行

执行前，以纯文件读取核对六包保存的 IR 各源字段与 YAML 一致，原有每个单包 seed 的字节与对应 YAML example 加 LE32 头完全一致；随后另存相同字节并规划新的请求序列。最终执行的静态资产转换命令如下，每项均成功返回，未耗尽搜索预算：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 tools/protocol_seed_planner.py --spec-dir protocols/bacnet_ip
PYTHONDONTWRITEBYTECODE=1 python3 tools/protocol_seed_planner.py --spec-dir protocols/modbus_tcp
PYTHONDONTWRITEBYTECODE=1 python3 tools/protocol_seed_planner.py --spec-dir protocols/iec60870_5_104
PYTHONDONTWRITEBYTECODE=1 python3 tools/protocol_seed_planner.py --spec-dir protocols/iec61850_mms_tcp
PYTHONDONTWRITEBYTECODE=1 python3 tools/protocol_seed_planner.py --spec-dir protocols/ethernet_ip_cip_tcp
PYTHONDONTWRITEBYTECODE=1 python3 tools/protocol_seed_planner.py --spec-dir protocols/opcua_tcp
```

该入口核对源 YAML、保存的 IR 对及 bundle identity，信任保存的 validation 快照；不执行 compiler、native helper 或网络。它更新受管理的 `seeds/*.replay`、`fixtures/requests/*.replay` 与 manifest，自定义语料应放在另一个目录。模板生成器仍在同父目录临时包中完成全部文件后原子 rename，生成失败不发布半包。

新增 `tests/protocol/test_seed_planner.py` 的测试源码覆盖虚构多阶段模型与六份标准文件，包含前缀、响应边缺失、资源限制、canonical aliases/repeat、片段、预算耗尽、源/IR 不一致和单寄存器范围。现有模板测试的单包字段 harness 改用 fixtures 路径；综合 runner 与导出测试源码同步。以上测试均未运行，只对 Python 源码执行 `ast.parse`，并进行文件差异/空白检查。

后续获准运行时应执行这些新增及更新的回归，并核对 `proto_load` 的 canonical alias 归一化与 compiler alias 结果一致，然后才验证受控目标的实际请求/响应绑定。模型级语料生成成功不能替代这些验收。
