# CKB L1 verifier cycles 优化报告

日期：2026-10-14。范围：CKB 上的 SP1 Groth16 验证器。
本次只运行本地测试、CKB-VM 回放和隔离 devnet；**没有运行 CI**。

## 结果

同一份真实 proof、公开输出和交易上下文，仅替换所执行的 type-script ELF：

| 测量对象 | 原版 cycles | 优化后 cycles | 降幅 |
| --- | ---: | ---: | ---: |
| Proof receipt type script | 3,974,969,445 | 332,484,740 | 91.6355% |
| A3 settlement type script | 3,983,164,412 | 333,144,448 | 91.6362% |

这两行是 **CKB-debugger 1.1.1 所选脚本组**的执行成本，不是完整交易成本。
原版允许最多 100 亿 cycles 以完成测量；优化版以 35 亿为硬上限运行并返回 0。
receipt 原版 ELF 与历史归档的 SHA-256 完全一致。

另外，在 **CKB 0.210.0 的全新隔离 devnet** 中将 `max_block_cycles` 显式设置为
`3_500_000_000`，部署优化后的 verifier，真实提交两笔 receipt 交易：

| 完整交易 | 节点估算 cycles | 提交结果 |
| --- | ---: | --- |
| 第一笔 receipt | 334,102,402 | committed |
| 第二笔 receipt | 334,139,176 | committed |

完整交易包含 verifier 之外的锁脚本等成本，约占该区块 cycle 预算的 9.55%。
这不是吞吐量预测，还需考虑其他交易、字节限制和实际运行条件。
28 个非法交易均由节点按预期的脚本错误拒绝。

## 优化点及单独贡献

使用同一 receipt 上下文的逐步测量：

| 实现 | cycles |
| --- | ---: |
| 原版 | 3,974,969,445 |
| Jacobian 公开输入累加 | 3,618,663,627 |
| 上述优化加 LTO / 单 codegen unit | 3,434,422,258 |
| 再加 Montgomery 域乘法 | 332,484,740 |

### 1. 将公开输入标量乘法和累加保留在 Jacobian 坐标

上游 `sp1-verifier` 的 `prepare_inputs` 使用 `AffineG1`。其标量乘法会在每次
加倍/加法后转回仿射坐标，反复求域逆元。现在使用同一底层库现有的 `G1`
Jacobian 运算，直到 pairing 边界才归一化，并借用 VK，避免克隆。

计算仍然是 `k[0] + sum(k[i+1] * public_input[i])`；输入长度检查、零标量处理、
验证方程、proof 解码、公开输出哈希、SHA-256/Blake3 回退、退出码、VK root 和
发布的验证密钥均未更改。

### 2. 用 Montgomery 算术替换域乘法中的逐位模约简

`substrate-bn-succinct-rs` 的上游 CPU 路径对每次 512-bit 乘积执行 512 轮二进制
长除法。Pairing 会大量调用这种运算，是本次测得收益最大的来源。

新路径只识别 BN254 的确切 base/scalar field 模数，并只对规范范围内的操作数
使用 `ark-ff = 0.5.0` 的 portable Montgomery 运算。`from_bigint` 进入 Montgomery
表示，乘法后通过 `into_bigint` 返回原有整数表示。外部字段布局和序列化不变。
其他模数或非规范操作数继续走原版实现，因此原有整数约简构造器仍可工作。

没有新增 CKB syscall、native precompile、RISC-V 指令扩展或协议变更。
没有跳过任何验签、曲线点检查或 proof 验证。

### 3. 对三个 CKB verifier workspace 启用 LTO

`ckb-proof-check`、`ckb-settlement`、`ckb-native-settlement` 均设置
`lto = true`、`codegen-units = 1`，并显式选用两个受控的 vendored ports。
SP1 guest、prover host、EVM 执行规则和其 Cargo.lock 未修改。

## 测试与证据

- 底层 BN 库 **39 项测试通过**，包含原有域、群、pairing 等测试及两项新增测试。
  新增测试比较 **8,321 组乘积**：两个模数的边界组合、非规范输入回退、其他模数，
  以及 canonical/full-width 随机样本；同时对照原版逐位约简和独立 BigUint 取模。
- 公开输入累加等价测试通过：发布的 VK、全零/一/负一等 scalar 边界、32 组确定性
  dense vectors，以及错误输入长度。对照保留的原版仿射算法。
- `ckb-proof-check` 的本地测试通过。
- `ckb-settlement` **4 项本地测试通过**，包括真实 A3 proof 接受、14 处公开输出
  篡改、错误 guest key、损坏 proof 的密码学拒绝及状态连续性检查。
- `ckb-native-settlement` **3 项本地测试通过**；其 CKB ELF 也已成功构建。
  这不补足该分支尚缺的成功 native custody proof/payout 证据。
- 实际节点：1 笔代码部署、2 笔 receipt 提交、**28 个拒绝**。覆盖公开字段、错误 key、
  proof 字节、长度、重复输出及 receipt 消费/替换。拒绝必须来自预期的 script error，
  而不是超时或超出 cycle 上限。
- 新的回放脚本独立重跑两组 baseline/optimized 对照，结果一致。
- 原始 crate 归档、逐文件哈希和声明的修改集合通过 provenance 检查。
- shell 语法、Python 编译检查及 `git diff --check` 通过。

证据目录：[verifier-cycles](evidence/verifier-cycles/)。其中：

- `result.json`：脚本组 cycles、输入/ELF/debugger 哈希；
- `receipt.json.gz` / `settlement.json.gz`：解析完成的真实交易回放上下文；
- `baseline-*.elf.gz`：未优化基线；
- `node/`：真实节点的交易、错误、manifest 和 35 亿 cycles 配置；
- `*-tests.txt`：本地测试日志；`SHA256SUMS`：归档完整性清单。

真实 receipt 的交易哈希：

```
0xdfe3e756275488dd98ea4171c06371ad74fdceb8ff40390f97fe018c01f165cc
0x458aa737bc519b49f5b38ec2f091553dd5651b516372f8eb35f37c472c2b887f
```

## 复现（本地，不运行 CI）

需要 Rust 1.92.0、已安装的 RISC-V target、CKB-debugger 1.1.1；节点实验另需
CKB 0.210.0。测试使用仓库已有的真实 proof，无需重新生成约 78 分钟的证明。

```bash
python3 scripts/check-ckb-crypto-port.py
python3 scripts/test-ckb-crypto-port.py
bash scripts/build-proof-check-script.sh
bash scripts/build-settlement-script.sh
bash scripts/build-native-settlement-script.sh
python3 scripts/bench-ckb-verifier-cycles.py --debugger /path/to/ckb-debugger
cargo test --locked --release --manifest-path proofs/ckb-proof-check/Cargo.toml
cargo test --locked --release --manifest-path proofs/ckb-settlement/Cargo.toml
cargo test --locked --release --manifest-path proofs/ckb-native-settlement/Cargo.toml

CKB_BIN=/path/to/ckb \
TACTUS_DEVNET_SUITE=replay-proof-verifier \
TACTUS_PROOF_DIR="$PWD/specs/evidence/execution-groth16-proof/proof" \
TACTUS_DEVNET_MAX_BLOCK_CYCLES=3500000000 \
TACTUS_DEVNET_RPC_PORT=18944 TACTUS_DEVNET_P2P_PORT=18945 \
bash scripts/run-devnet-experiments.sh
```

两个 vendor crate 的完整来源及修改说明分别记录在各自的 `CKB_PORT.md`。
独立算术测试在 `artifacts/` 下复制源文件，并使用归档的测试 lockfile；不会修改
运行时 vendor 源文件，也不会运行 SP1 的完整 SDK/prover 测试。

## 范围与剩余问题

1. **这是 L1 验证成本优化，不是 L2 proving 加速。** 没有重测、更改或宣称降低
   那次约 78 分钟的生成证明时间；guest 的密码学 patches、增量状态 witness
   和历史重放仍是独立工作。
2. Settlement 对照使用 debugger 的 `--bin` 替换，保留原部署身份及其真实 proof。
   它测量完整 settlement type-script 的新实现，但不验证所有其他脚本或共识，
   也不构成新部署的一次真实 SettlementTip 更新。
3. 新 ELF 会改变 CKB code hash/type identity。新的 settlement 部署必须正确绑定
   新身份并生成匹配的新 proof；不能把旧 proof 或旧 deployment config 直接改名使用。
   实际节点正向证据是 receipt，而非新 settlement 部署或 native custody payout。
4. 两个 ports 引入了关键密码学实现变化和新的 ark-ff 依赖。本地差分和实际 proof
   测试不替代独立代码审查/形式化证明。生产 readiness 的 G1–G9 不因此关闭。
5. 本次没有 commit、push、部署主网或运行 CI。
