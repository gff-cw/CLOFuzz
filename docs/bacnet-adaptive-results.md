# BACnet adaptive 对照结果

本次实验比较原始 AFL (`raw`)、三层均匀选择 (`uniform`) 和按 StateAFL
bitmap/状态反馈学习的三层调度 (`adaptive`)。三种配置均使用同一份
`seed04_read_vendorname.replay`、同一 BACnet Stack instrumented server、同一
fuzzer snapshot、随机种子按轮配对，启动等待 1,000,000 us，单次执行超时 5000 ms，
ready 后运行 15 s。实验由 C 变异器和 C 调度器执行；Python driver 只负责启动、
采集和分析。完整产物位于 `/tmp/stateafl-schedule-compare-seed04-final-20261026`。

启动前记录的关键哈希为：fuzzer
`a26124392d17bf928172e526c5e3931aae9d2e262150a1abb27274cee7f55085`，目标
`8b030a7fe5ef4d96cff35c1cbd5339a20cbc40084f07e5ae16ac887c8902bbdc`，模型包摘要
`d9714bacb2ee961634d64db8088955d8b14abacc37e9f9535f3399a53271e24c`，单种子目录清单摘要
`fc34a56f1264e21b3c469beb08960cd9fff8805a11aef210b06e9d87217fbb03`；种子文件字节的
SHA256为`2cfec5237ea0644058cfda8ee8209b0068854de14ec3a72f64ce966c3af20814`。实验绑定CPU 3。

表中的 bitmap 增量是 `fuzz_bitmap` 中新非 `0xff` 的位置数，已扣除同步校准
baseline；它可能包含边哈希碰撞，不是源代码分支数。exec 同样扣除校准执行数。
每轮三臂使用相同 RNG 种子，依次为 `20261026/20261027/20261028`；运行顺序按轮
轮转为 raw/uniform/adaptive、uniform/adaptive/raw、adaptive/raw/uniform。

| 轮次 | raw bitmap 增量 / exec | uniform bitmap 增量 / exec | adaptive bitmap 增量 / exec |
| --- | ---: | ---: | ---: |
| 1 | 4 / 14 | 8 / 14 | 0 / 13 |
| 2 | 4 / 14 | 12 / 14 | 26 / 13 |
| 3 | 24 / 14 | 7 / 13 | 10 / 14 |

三轮队列增长分别为 raw `2/2/2`、uniform `1/2/2`、adaptive `1/2/2`；uniform
结构化尝试的拒绝数为 `1/1/5`。候选构造成功及本地发送不证明目标语义接受，下面
的 success 只表示 C runtime 成功构造了结构化候选。

九次运行均 ready、正常 SIGINT 退出，具有非零覆盖、完整 replay framing、`0`
crash、`0` hang，并产生两个 StateAFL memory state。adaptive 每轮的结构化尝试、
反馈和覆盖对账如下：

| 轮次 | attempts | success / rejected | HEAD / CONTENT / SEQUENCE | new tuples | new buckets |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 8 | 5 / 3 | 3 / 1 / 1 | 0 | 339 |
| 2 | 6 | 4 / 2 | 1 / 0 / 3 | 26 | 378 |
| 3 | 12 | 6 / 6 | 1 / 3 / 2 | 10 | 379 |

每轮 `layer_feedback` 行数等于 scheduler `observations`，逐行 tuple/bucket 累加值
等于 `protocol_schedule.json` 的总值；三层均被实际选中。该组所有结构化反馈的
`memory_state_id` 都是 `0`，因此证明了状态 0 的学习与归属，尚未证明多个非零
内存状态各自学习不同权重。独立的双请求 adaptive 运行另观察到 state 0、23 条
feedback、`13` new tuples 和 `377` new buckets，baseline 为 45 executions/1 path/
1935 bitmap bytes，结束为 67 executions/5 paths；它同样不是多状态收益证明。

这些结果只说明当前 C 调度器已经接入原始 bitmap 消费、StateAFL 队列和状态反馈，
并完成了这九次实验。三轮单种子、15 秒预算的结果波动明显，adaptive 没有
在每轮都优于 uniform 或 raw；不能据此声称覆盖率提升、统计显著性或真实工业目标
普遍收益。更长时间、多个种子和真实设备/服务器仍需单独实验。

此前四种子组中一次 uniform 初始化被 StateAFL 判定为 crash；单独重放 Object_Name
种子时未复现，原失败没有记录具体信号，原因仍未定。第一次 seed04 组的 orchestrator
提前结束，uniform fuzzer 继续运行，超出 15 秒预算；对该任务 PID 发送 SIGINT 后，
最终统计为两项 `sig:06` replayable crash，未做故障复现或根因归类。这两批结果均保留
在原目录，不计入上述九次配对结果，新的九次 `0` crash 不能抹除这些历史异常。
历史 200 ms 启动等待导致请求早于 UDP bind 的 BACnet 失败也不属于本组。

本机完整复现命令为：

```bash
taskset -c 3 python3 /tmp/stateafl-schedule-compare-seed04-final-20261026/driver.py \
  --output /tmp/stateafl-schedule-compare-seed04-rerun --seconds 15 --repeats 3
```

driver、实际执行的 campaign 函数、各次精确命令/环境、来源哈希、同步 baseline、
每秒采样的持久化 coverage/stats snapshot 和原始 fuzzer 输出都保存在该临时证据目录。
采样文件可能在fuzzer下一次落盘前保持旧值，不是逐execution曲线。该 driver 没有
提交进仓库，原始产物不随 Git 发布；重新构建或迁移机器后应重新保存源码、模型、
输入和二进制身份，不能用本次旧哈希认证新的运行。
