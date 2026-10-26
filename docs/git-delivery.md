# Git 交付

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

远端分支：[GitHub](https://github.com/gff-cw/CLOFuzz/tree/feature/protocol-aware-integration-20261025)。本文件是实际提交/推送结果记录，不代表其他五种协议已经有在线codec；具体限制见 implementation-review.md。
