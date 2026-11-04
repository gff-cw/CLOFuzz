# 最小 Modbus 源码运行包

本目录提供已有 Modbus codec 的 FC03 单寄存器请求/响应配置、请求语料、独立受控 TCP 夹具和完整准备步骤。目标是核对描述、输入、响应及消息边界；不以发现漏洞为要求。本包不是 generic-wire 格式，也不扩展工业 Modbus 的服务范围。当前交付的验证限于静态检查与编译，目标会话和方法效果尚待运行验收。

| 材料 | 用途 |
| --- | --- |
| `protocol_spec.yaml`、`state_transition.yaml` | 可编辑的完整旧 codec 输入对 |
| `fixtures/requests/read_holding.replay` | 从声明 example 序列化的单请求，带 LE32 长度头 |
| `fixtures/responses/read_response.wire` | 声明的响应示例原字节，仅作参考，不能当作实际收到的响应 |
| `seeds/read_holding.replay`、`seeds/read_twice.replay` | 一条或两条请求的静态示例序列，不含响应 |
| `static_input_manifest.json` | 源文件摘要、记录数与静态构造范围；不是 codec 或目标验收结果 |
| `fixture_server.c`、`Makefile` | 独立实现该受控范围的单进程、单线程目标及只编译入口 |

正式运行包由下面的 `--source-dir` 步骤生成。它用当前 YAML 做原生 codec 校验、生成 IR 和受管理语料，并发布 `seed_manifest.json` 与 `template_contract.json`。因此源码目录没有预置声称已经执行原生验证的 `validation.json` 或 IR；`static_input_manifest.json` 不代替正式语料契约。

## 1. 从仓库根目录准备工具和夹具

需要项目支持的 Linux C/LLVM 构建环境、Python3 及 `tools/requirements-protocol.txt` 中的依赖。所有命令在 StateAFL 根目录执行。

```sh
make -j2 build-only
make -C llvm_mode -j2 build-only
make -C protocols/templates/minimal_runnable_example build-only \
  BUILD_DIR=/tmp/stateafl-minimal-modbus-build
```

第三条命令默认使用当前仓库的 `afl-clang-fast`，将显式边界目标链接进相同版本的 tracer。这个 Makefile 只编译，不启动服务。普通 `cc` 编译也可检查语法或构建无 tracer 的参考服务；无 tracer 的构建不能提供内存状态边界证据。

## 2. 生成正式描述包

选一个尚不存在的输出目录：

```sh
python3 tools/init_protocol_spec.py \
  --source-dir protocols/templates/minimal_runnable_example \
  --require-runtime --output-dir /tmp/stateafl-minimal-package
```

生成结果包含可编辑 YAML、配对 `protocol_ir.json/state_ir.json`、bundle、validation、`template_contract.json`、fixtures、从 initial 可达的请求 seeds 和 `seed_manifest.json`。该命令会编译并调用现有 codec validator，不是本轮已经执行的步骤。它不会覆盖已有目录，也不会把 source-dir 名称变成新的 codec。

## 3. 使用生成包启动受控会话

夹具只绑定本机 `127.0.0.1`，参数是十进制 TCP 端口。下面使用23555端口；如果修改端口，`-N` 与目标参数须同时修改。输出目录使用新路径。

```sh
python3 tools/run_protocol_campaign.py \
  --spec-dir /tmp/stateafl-minimal-package -- \
  -d -i /tmp/stateafl-minimal-package/seeds -o /tmp/stateafl-minimal-output \
  -N tcp://127.0.0.1/23555 -D 100000 -E -K -q 2 -s 2 -m none -t 3000 \
  --mutation-mode valid --mutation-layers head,content,sequence \
  --protocol-schedule uniform -- \
  /tmp/stateafl-minimal-modbus-build/fixture_server 23555
```

按 Ctrl+C 结束。包装器在执行目标之前检查所选模型与受管理语料；`--print-command` 可预览准备后的参数，但仍会校验模型、语料并编译 IR。要只校验模型可使用 `--validate-only`，其结果不代表输入目录已经通过运行准备检查。是否需要按部署环境设置 ASLR、CPU governor 等，应遵循 StateAFL 本身报告的启动条件。

夹具只接受 MBAP protocol=0、length=6、FC03、quantity=1 的12字节请求。响应复制现场 transaction/unit，返回一个值为 `(address + 1) mod 65536` 的寄存器；请求示例 address=0 对应响应数据0001。一次连接最多处理32条完整应用消息，错误或不完整请求结束该连接。夹具独立校验报文，不链接协议模型解释器，不读取 fixture 文件来假造现场响应。

夹具在完整请求处理和响应提交之后调用 `trace_message_boundary(ordinal)`。volatile heap 状态在应用消息间存活；实际是否保留快照、产生非零状态并进入 M2，仍必须查看该次执行的 provider 身份、边界映射、状态序列及调度记录，不能由源码中存在这个调用推断验收通过。

## 4. 修改模型后的完整准备流程

编辑生成包中的 YAML 后，重编并重新规划受管理语料：

```sh
python3 tools/proto_spec_compiler.py \
  --protocol /tmp/stateafl-minimal-package/protocol_spec.yaml \
  --state /tmp/stateafl-minimal-package/state_transition.yaml \
  --output-dir /tmp/stateafl-minimal-package
python3 tools/protocol_seed_planner.py --spec-dir /tmp/stateafl-minimal-package
```

随后重用启动命令并选择新的运行输出目录。夹具只实现上述范围；扩展描述 quantity、服务或会话状态时，也需要匹配的受控目标。重规划会替换包内受管理 seeds/fixtures，自定义 corpus 应放在独立目录。

本 profile 的 quantity 为 fixed 且 `min=max=default=1`，正常响应 data 恰好2字节。扩大 quantity 必须同步请求与响应约束，不能只改 `values`。`values` 是 HEAD 候选池，`min/max` 才是解析范围；字段 `default` 不会重写 example。协议语义状态与 StateAFL 推断的目标内存状态分别维护。

YAML `example` 和响应 `.wire` 是目标线上字节，不含 LE32 头。`.replay` 请求记录及权威队列快照包含 `LE32(length) || wire`；运行队列的 raw 字节已经去头，不能再当 replay 去头一次。依据格式契约读取输入，不能只看扩展名猜测。

## 5. 运行验收时需保留的证据

至少核对现场请求/响应、transaction/unit 关联、单寄存器数据、实际提交的保存输入和完整传输；启用 `-E` 时还要核对显式边界映射、自然非零状态选种和实际 M2 入口。固定模型/种子/预算后，再按方法验证契约进行重复对照。编译、模型规划或一次正常连接都不能单独证明方法有效性。
