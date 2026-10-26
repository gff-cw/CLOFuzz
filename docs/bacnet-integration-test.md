# BACnet Stack 1.5.0 集成验证

## 独立构建

验证对象是工作区现有的开源 `../bacnet-stack`，其 CMake 项目版本及构建后二进制的 `--version` 均为 `1.5.0`。构建使用系统 Clang/LLVM 18.1.3，经当前仓库的 `afl-clang-fast` 插桩；没有修改 BACnet Stack 源码、原有 `build-stateafl` 或 `inputs`。

在 `stateafl` 目录执行以下命令；`AFL_DONT_OPTIMIZE=1` 防止编译器包装器额外加入 `-O3`，保留 CMake Debug 配置。

```bash
export AFL_CC=/usr/bin/clang-18
export AFL_CXX=/usr/bin/clang++-18
export LLVM_CONFIG=/usr/bin/llvm-config-18
export AFL_DONT_OPTIMIZE=1

cmake -S ../bacnet-stack -B ../bacnet-stack/build-protocol-integration \
  -DCMAKE_C_COMPILER="$PWD/afl-clang-fast" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DBACDL_BIP=ON \
  -DBACDL_BIP6=OFF \
  -DBACDL_ZIGBEE=OFF \
  -DBACDL_MSTP=OFF \
  -DBACDL_ETHERNET=OFF \
  -DBACDL_ARCNET=OFF \
  -DBACDL_BSC=OFF

cmake --build ../bacnet-stack/build-protocol-integration --target server -j 4
```

两条命令均成功退出。产物为 `../bacnet-stack/build-protocol-integration/server`。配置日志确认仅选择 IPv4 BACnet/IP；编译命令包含 `-g`、`DEBUG_ENABLED=1` 和 `BACDL_BIP`。

完整命令、编译输出、工具版本、CMake 缓存选项、源码版本、输入及二进制 SHA-256 记录在：

- [`configure.log`](../tests/protocol/evidence/new-build/configure.log)
- [`build.log`](../tests/protocol/evidence/new-build/build.log)
- [`build-metadata.json`](../tests/protocol/evidence/new-build/build-metadata.json)

## 正常 UDP 通信

从 `stateafl` 目录运行：

```bash
python3 tests/protocol/validate_bacnet.py
```

脚本以 `BACNET_IFACE=lo BACNET_IP_PORT=47818` 启动上述 `server 1234`，通过 `127.0.0.1:47818/UDP` 发送请求；验证完毕后清理自己启动的进程。若端口已被占用，脚本直接失败。服务端使用临时工作目录，避免生成运行文件到源码目录。

现有 `../bacnet-stack/inputs/*.replay` 使用 `LE32 长度 + UDP 数据报` 记录格式；脚本先移除每条记录的长度前缀。原始 Who-Is 范围是 0..100，三个 ReadProperty 种子请求 Device 123，而本次服务端为 Device 1234。因此脚本同时保留并验证原请求行为，并在内存中的发包副本上适配设备实例；原始文件的 SHA-256 在结束时再次检查。

实测 9 项检查全部通过：

| 请求 | 实际结果 |
| --- | --- |
| 原始无范围 Who-Is | I-Am：Device 1234、Max APDU 1476、Vendor ID 260 |
| 原始范围 0..100 Who-Is | 300 ms 内无响应，符合范围排除当前设备 |
| 发包副本范围改为 1234..1234 | I-Am：Device 1234 |
| 原始三个 ReadProperty，请求 Device 123 | 均返回 Error，error-class=object (1)、error-code=unknown-object (31) |
| ReadProperty，发包副本请求 Device 1234 的 Object_Name (77) | Complex-ACK：`SimpleServer` |
| ReadProperty，发包副本请求 Device 1234 的 Vendor_Name (121) | Complex-ACK：`BACnet Stack at SourceForge` |
| ReadProperty，发包副本请求 Device 1234 的 Object_List (76)、array-index=0 | Complex-ACK：77 |

脚本检查 BVLC 长度、NPDU、APDU 类型、服务号、invoke ID、对象标识、属性及数组索引和值标签，并确认服务端在检查完成后仍运行。种子中的 unknown-service 和错误 BVLC 长度仅被离线解析记录，本步骤没有发送这两项异常请求。

原始请求/响应十六进制、结构化解析和断言结果见 [`communication.json`](../tests/protocol/evidence/new-build/communication.json)；命令结果见 [`communication.log`](../tests/protocol/evidence/new-build/communication.log)，服务端日志见 [`server.log`](../tests/protocol/evidence/new-build/server.log)。此步骤验证正常协议互通，不代表模糊测试覆盖率或故障发现结论。


## 五模式实际回归与启动时序修正

初次照用 `-D 10000` 时，strace 显示插桩 Debug 子进程仍在初始化网卡，尚未 bind/recvfrom 就被本轮结束信号终止。UDP connect 不等待监听者，因此无响应且无内存状态。原失败日志保留在 `compatibility-five/`。随后采用现有 `-D 200000`，没有修改服务器源码或伪造协议状态。第二次测试还发现重定向 stdout 缓冲导致驱动无法及时看到 ready 标志；在该标志后增加 fflush，并重新完整运行。

最终五组使用同一个独立 server、同四个原种子（Who-Is 和三个 ReadProperty），server Device 123 与种子匹配、相同等待/超时参数，每组校准完成后运行 15 秒：

| 模式 | 执行数（含校准） | 队列 | bitmap | HEAD / CONTENT / SEQUENCE 成功候选 | 拒绝 |
| --- | ---: | ---: | ---: | --- | ---: |
| legacy | 175 | 7 | 3.09% | 0 / 0 / 0 | 0 |
| head | 175 | 6 | 3.09% | 53 / 0 / 0 | 0 |
| head_content | 175 | 6 | 3.08% | 6 / 10 / 0 | 0 |
| all | 174 | 7 | 3.08% | 11 / 17 / 6 | 8 |
| hybrid | 207 | 7 | 3.08% | 0 / 4 / 1 | 0 |

五组检查均通过，均有覆盖率、原内存状态 0→1、有效 TLSH 校准、正常 SIGINT 退出和格式正确的 replayable 队列；BACnet 各组均为 0 crash / 0 hang。这不证明协议实现无缺陷，也不能根据短测 bitmap 值宣称覆盖提升。各组原始命令、时间、哈希、检查项、日志及归档样本位于 [compatibility-final/summary.json](../tests/protocol/evidence/compatibility-final/summary.json) 和相邻目录的 archive/。

额外运行 hybrid 45 秒，全部三个层均实际触发：HEAD 11、CONTENT 14、SEQUENCE 6，raw 15，候选拒绝 7；成功候选中结构化占比 67.39%，候选拒绝占比 18.42%。执行 265 次、队列 13、bitmap 3.09%、invoke 关联响应 43。状态图仍为原内存状态及其自环，不来自协议语义状态。见 [hybrid-final 结果](../tests/protocol/evidence/hybrid-final/hybrid/result.json)。最后一次 HEAD 策略列表加载修订后，另对最终源码运行完整三级 10 秒确认通过，见 [final-source-smoke](../tests/protocol/evidence/final-source-smoke/all/result.json)。

复现（输出目录必须尚不存在）：

```bash
python3 tests/protocol/integration.py --output tests/protocol/out/bacnet-five --seconds 15
python3 tests/protocol/integration.py --output tests/protocol/out/bacnet-hybrid --modes hybrid --seconds 45
```

## 异常保存与原工具重放

BACnet 短测没有发现异常，不能凭空给出 BACnet 崩溃样本。另使用独立本机 UDP 测试替身 `fixtures/failure_server.c`，让它在长度不一致时执行明确的测试 assertion，验证新 near_valid 候选经过原 fuzzer 执行和保存流程后可再次触发相同 SIGABRT。该 assertion 是测试夹具行为，不是 BACnet Stack 缺陷。

实际保存 1 个 SIGABRT 样本，LE32 外层长度正确、唯一的 BVLC 长度违例保留；新增的 `aflnet-replay ... BACNET ...` UDP 路径重放后，替身再次以 signal 6 退出。见 [result.json](../tests/protocol/evidence/failure-replay/result.json) 与 [保存样本](../tests/protocol/evidence/failure-replay/saved-failure.replay)。执行命令为 `python3 tests/protocol/test_failure_replay.py`；脚本拒绝覆盖既有证据目录。

## 原工具链和自动化测试

`make all`、`make -C llvm_mode` 成功；`bash tests/protocol/run_all.sh` 通过 51 项编译器测试、8 项 CLI 测试、83 项 C loader 用例、250 份随机 IR、25000 次随机 wire/变异，共 100125 项 C 断言。ASan/UBSan/LSan 无报告。独立网络测试还验证 7000 字节单 UDP 数据报、多个数据报接收、原 TCP 路径和文件截断/LE32 写入。

原 LLVM18 七组完整回归在最终共享网络/回放修订后再次通过；简要日志 [llvm18-final.log](../tests/protocol/evidence/llvm18-final.log)，可移植的详细 JSON 和 TCP 流拆包/合包证据保存在 [llvm18-final/](../tests/protocol/evidence/llvm18-final/)。插桩、内存快照、TLSH、MVPTree 源码未被本次改动替换。
