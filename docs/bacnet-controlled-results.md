# BACnet YAML 与定向变异：功能对照和重复运行结果

实验对象：本机 BACnet Stack 1.5.0 `build-protocol-integration/server 123`，lo/UDP。没有修改BACnet源码或原始inputs。模板及描述正确性审查见 [template-audit.md](template-audit.md)，六协议范围与完整性见 [protocol-model-audit.md](protocol-model-audit.md)。

## 模板与描述检查

本轮修复了role/mutability矛盾、derived/runtime_bound缺少依赖、Python接受C不支持配置、样例只校验外壳、歧义匹配和状态边、最终IR资源预算、深依赖递归等问题。86项编译器测试、14项模板测试通过；15000个BACnet结构随机案例与真实C解析器比较，13403次字段定位检查零差异。六协议当前为71完整消息fixture、641字段声明，独立深层结构/破坏内部长度负例及生成重现检查通过。这里的完整只指明确profile；其他五协议的C编码器仍未实现。

## 实际发包功能对照

独立控制使用同一个原始ReadProperty Object_Name种子、同一目标/随机种子、仅HEAD。把其他可变头字段固定，分别通过YAML把Invoke ID枚举设为33和77，另运行33的near_valid模式。

最终每组运行15秒有效阶段、统一启动等待500ms，并保存最多24条真实发送序列，校准阶段不采样。保存发生在会话绑定和实际完整send之后；每条replay外有sent_messages/structured/forkserver等sidecar。验证并非只看mutation日志：

- A：所有采样报文只把原Invoke ID改为33。
- B：所有采样报文只把原Invoke ID改为77。
- near_valid：只比A多一个BVLC宣告长度=实际长度+1，其他字节及LE32封装不变。
- 缺失依赖负对照：启动入口报错，目标启动marker没有生成。

功能试验中发现一次模型签名和种子不匹配：固定了模板NPDU control=4，而原种子=0，导致候选全被拒绝。修正为按不变原种子生成固定签名后重新验证。它说明YAML静态通过与能够驱动当前种子是不同检查层；失败原始记录保留在controlled-functional-initial-failure中，后续脚本单种子阈值修正后又独立重跑最终功能组。另一次200ms单种子复测出现两组初始化无响应/无推断状态；记录在controlled-functional-final中。提高三组统一启动等待至500ms后，三组各24条采样全部通过，缺失依赖负对照也通过。最终组见 [controlled-functional-stable/summary.json](../tests/protocol/evidence/controlled-functional-stable/summary.json)。

## 五模式重复对照

同一四个正常LE32种子、同一目标二进制、同一fuzzer二进制、同一模型副本、相同网络/超时配置。5模式各3轮，共15次；同轮种子配对20261025、20261026、20261027，轮换执行顺序；每次完成初始校准后运行20秒（实测约20.01–20.10秒）。

新增同步experiment_baseline.json及协议计数基线，在ready前写出；下表执行数和覆盖增量均扣除该基线。有效阶段仍包括新队列项触发的必要反馈重放，不等同于独立mutation数量。15份命令记录验证fuzzer SHA、目标SHA、输入种子及模型SHA各自一致；核心C和启动入口源码哈希一致。

| 模式 | 通过次数 | 有效执行数中位数 | 新增位图位置中位数 | 新增队列中位数 | 首24条发送序列符合profile结构比例中位数 |
| --- | ---: | ---: | ---: | ---: | ---: |
| legacy | 3/3 | 81 | 31 | 7 | 0.00% |
| head | 3/3 | 82 | 1 | 3 | 100.00% |
| head_content | 3/3 | 82 | 1 | 3 | 100.00% |
| all | 3/3 | 81 | 1 | 4 | 100.00% |
| hybrid | 3/3 | 82 | 9 | 5 | 54.17% |

“位图位置”是AFL bitmap字节非0xff的计数，可能有哈希碰撞，不是源代码分支数量。样本符合率只检查Who-Is/ReadProperty这个profile的结构，是最先保存的有界样本，不是全程无偏有效率，也不是服务业务成功率。legacy的0%并不意味着这些输入没有测试价值；它们可覆盖协议错误处理路径。

15次都保持原有内存状态反馈，观察到dummy状态0和一个推断状态1；部分序列增加1→1边。这不意味着协议语义状态ready/pending与它们一一对应。所有运行观察到0 crash/0 hang。

完整三级的结构化候选拒绝率中位数19.23%，混合模式为15.38%；混合模式结构化执行占比中位数67.86%，与配置70%的尝试概率不能混同。HEAD/CONTENT/SEQUENCE在真实运行中均有计数。拒绝原因保留在逐次mutation JSONL，默认不静默回退。

## 能支持的结论

1. YAML能改变真实发送字节，长度修复与单点故意违例在原网络路径中保留，描述/执行链路有效。
2. 已实现的valid结构化路径提高了本profile有界样本的结构符合比例；raw仍有价值，hybrid保留了它。
3. 本轮短测**没有证明覆盖率提升**：legacy新增位图位置中位31，高于hybrid的9和完整三级的1。原始数据如此，不能因工程目标是改进就改写结论。
4. 执行速率各组约4次/秒，主要受每次200ms服务器等待及网络/反馈流程约束；该配置不适合比较纯变异计算开销。
5. 3轮、每轮20秒只提供描述性分布，不能作统计显著性或缺陷发现能力结论。长期价值仍需更多轮次、更长时间、更多服务与状态场景验证。

## 数据与复现

[15轮总结果](../tests/protocol/evidence/controlled-comparison/summary.json)包括逐次检查、分位数、按轮与legacy配对的差值。每次repeat-NN/MODE/的archive保存退出后的统计、位图、语义日志、原内存状态图和24条真实发送样本；ready/保存同步基线。工作out目录保留在本机，但不作为必须重新生成的大型Git产物。

```bash
python3 tests/protocol/controlled_experiments.py \
  --output /tmp/bacnet-repeated-new \
  --repeats 3 --seconds 20 --seed-base 20261025
```

实验设置与指标口径见 [controlled-experiment-design.md](controlled-experiment-design.md)。随机种子控制内部伪随机序列，不能保证网络调度、目标运行时和反馈引起的整个执行流逐位重现。采样开销对所有模式使用同一24条预算；纯速度研究可统一设为0。


复现最终功能组（不与五模式性能表混合统计）：

```bash
python3 tests/protocol/controlled_experiments.py \
  --output /tmp/bacnet-functional-new --controls-only \
  --control-seconds 15 --startup-usecs 500000 --seed-base 20261025
```

启动等待是既有可配置条件。UDP connect并不保证服务器已监听；本机短等待确实导致过校准失败，故保留失败记录并给出已通过的统一功能配置。不能将初始化失败当作变异器产生了目标崩溃，也不能只删除失败记录后声称重复实验永不失败。
