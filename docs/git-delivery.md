# Git 交付

本文件前半部分记录首轮实际提交与推送；当前工作树恢复情况见文末和 [任务恢复记录](task-recovery.md)。历史交付结果不覆盖其后未提交的实现。

- 基础分支：`feature/spfuzz-protocol-aware-mutation-v3`，基础提交 `775515c`。
- 新分支：`feature/protocol-aware-integration-20261025`。
- 远程：`origin`，`git@github.com:gff-cw/CLOFuzz.git`。
- 未改写或强制推送已有历史；保留原 LLVM18 修改及 BACnet 源码/输入。

实现提交：

| 提交 | 内容 |
| --- | --- |
| `25378c2` | ICP-IR 编译器、schema、六种有限范围协议模型及编译器测试 |
| `9e911bc` | BACnet C runtime、三级变异、依赖、缓存和 sanitizer 测试 |
| `0900faa` | StateAFL CLI/真实循环接入、UDP 接收发送、LE32、回放和集成侧测试 |
| `2d26104` | 真实 BACnet 五模式/额外hybrid/最终smoke证据、LLVM18回归、构建、文档 |

已实际执行 `git push --set-upstream origin feature/protocol-aware-integration-20261025`，远端成功创建分支并设置跟踪。最终审查又发现模型生成器的注释辅助模块尚未纳入暂存，补充到本记录所在提交，并用仅包含 Git 追踪文件的临时导出运行编译器套件验证交付完整性。最新提交哈希及远端一致性由提交后的 `git rev-parse HEAD`、`git ls-remote` 和最终交付回复记录。

远端分支：[GitHub](https://github.com/gff-cw/CLOFuzz/tree/feature/protocol-aware-integration-20261025)。上述首轮交付时其他五种协议还没有在线 codec；这是历史支持范围，不能当作当前工作树状态。

## 恢复时的后续提交与工作树

本地分支 HEAD 为 `2bdfeb1264c1b561a693481063303d05953cd016`，与本地 `origin/feature/protocol-aware-integration-20261025` 引用一致。本次没有查询实时远端，也没有重新推送。

| 后续提交 | 内容 |
| --- | --- |
| `d1455a1` | 可填写模板与按 YAML 目录启动流程 |
| `a755d53` | 六个有界协议 profile 与模板一致性修复 |
| `a0bb76c` | 多轮 BACnet 对照与完整描述包 |
| `2bdfeb1` | 独立描述包核验及索引 |

恢复开始时另有 55 个 tracked 文件修改和 14 个 untracked 文件，包含五 TCP codec 与相关集成。它们已落盘，但不属于上述 HEAD；IEC104 功能测试异常退出，最新 BACnet legacy 初始化超时，完整验收未通过。恢复后的只读核验工具和文档修订也尚未提交。不得据此声明新扩展已经提交或推送。

## 在线 StateAFL 反馈调度交付（2026-10-26）

继续在上述功能分支工作，执行 `git fetch origin` 后合并远程 `origin/main`，
再按本地 `AGENTS.md` 要求将各独立功能提交推送至原远程分支。没有改写历史。

| 提交 | 内容 |
| --- | --- |
| `85f1f81` | 将所有网络接收增量送入协议响应运行时 |
| `4ce4d18` | 合并远程 `origin/main` |
| `1b3d321` | 原子化会话绑定、同步 Python/C alias 权重契约及文档/回归源码 |
| `9d541f4` | 增加可选的按 StateAFL 内存状态学习变异层调度 |
| `fe01dc4` | 精确限定本次 M2 完整发送统计，保留刻意损坏的字节 |

最终提交 `fe01dc4a34b25962da82c84a9590e5ac9c8ca495` 已推送。推送后通过
`git ls-remote --heads origin feature/protocol-aware-integration-20261025`
核实远端 tip 与本地相同，工作区无未提交更改。

新增 `--protocol-schedule adaptive` 为显式 opt-in；默认 `uniform` 保留旧选层。
新增 scheduler、runtime 事务/API、别名权重、CLI 和网络集成回归源码。根据当前
`AGENTS.md` 的测试延期要求，本轮未构建、未运行测试或目标服务；只完成 Git 差异、
Python AST、shell 语法及静态源码检查。此前 IEC104 异常及 BACnet 启动超时的历史
限制仍然成立；这次推送不构成工业目标互通或覆盖收益证据。
