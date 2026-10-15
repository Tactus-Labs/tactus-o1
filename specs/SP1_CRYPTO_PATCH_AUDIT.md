# SP1 crypto patches 接入核查与执行对照

日期：2026-10-14。SP1 6.8.1，CPU 本地执行；本轮执行对照没有运行 CI 或生成证明。
后续完整 proving 已于 10 月 15 日通过：同口径阶段合计约 **78 → 59 分钟，减少 24.34%**，
详见[完整 proving 重测](SP1_PATCHED_PROVING_REPORT.md)。下文的“未重测”描述本轮执行对照的范围。

10 月 15 日后续状态：[第二轮优化](SP1_OPTIMIZATION_ROUND2_REPORT.md)已将固定版本
patches 接入两个正式 workspace，并让 zkVM 内的 ECRECOVER 使用 patched k256。
下文保留最初审计时的配置与测量结果；“未接入”和“ECRECOVER 没有改变”均指最初那轮，
不是当前工作树状态。既有链上部署没有随源码改动自动升级。

## 结论

最初审计时，`proofs/sp1` 和 `proofs/native-sp1` 的正式 workspace **没有配置这些官方 crypto
patches**。锁文件中的 k256、sha3、两个 sha2 版本均来自 crates.io。
这不等于 SP1 没有 precompiles，而是这些应用密码学调用没有通过 patched crates 接入。

在隔离源代码副本中接入官方 patches 后，真实 guest 执行记录显示 Keccak、secp256k1
曲线加法/加倍、SHA-256 precompiles 已被调用；所有测试的完整公开 journal 保持一致。

**原约 78 分钟实验的 retained sealed-chain 输入：指令减少 31.44%，prover gas
估算减少 28.91%。不是之前 L1 verifier 的 91.6%，也不是完整证明耗时减少 31.44%。**

正式 guest 的 Cargo.toml/Cargo.lock 和既有部署配置未修改。本次交付的是经过执行
验证的候选配置、对照工具和证据。更换 guest ELF 会改变验证密钥，不能将它直接视为
原部署已经授权的 guest；后续实际接入需要同步处理部署绑定并生成新证明。

## 调用路径核查

| 路径 | 当前后端 | 本次隔离实验 |
|---|---|---|
| Alloy 的 Keccak / 状态与交易哈希 | sha3 0.11.0，普通软件实现 | 官方 sha3 0.11.0 patch；出现 KECCAK_PERMUTE |
| 交易发送者恢复 | k256 0.13.4，普通 Rust 运算 | 官方 k256 patch；出现 SECP256K1_ADD/DOUBLE |
| SHA-256 | sha2 0.10.9 与 0.11.0 两个版本 | 两个版本均 patch；出现 SHA_EXTEND/COMPRESS |
| revm 的 EVM ECRECOVER | secp256k1 0.31.1 C 后端，显式启用 feature | **没有改变**；k256 patch 不覆盖这条路径 |

Alloy 1.6.0 的实际 feature tree 没有启用 tiny-keccak，因此仅 patch tiny-keccak 不会
加速本次的 Keccak 路径。旧的 sha3 0.10.8 patch 也不满足这里的 0.11 依赖。
现有官方 secp256k1 0.30.0 patch 不能直接替换 revm 依赖的 0.31.1。

SP1 patches 将运算路由到 zkVM 已有的专用 precompile circuits；不是把任意 Rust
算法自动变成电路。本实验没有嵌入 CKB interpreter，也没有新增 SP1 precompile。

## 同输入前后对照

三个变体采用相同 SP1 版本、release 构建参数和输入；没有混入 LTO 或其他业务逻辑
优化。每个变体在 SP1 中真实执行。计量使用 `ExecutionReport.total_instruction_count()`
和 `ExecutionReport.gas()`，后者是 SP1 的归一化 proving-cost 估算，不是 EVM gas、
CKB cycles，也不是墙钟时间。

| 输入 | 原版指令 | 仅 Keccak patch | 组合 patches | 指令降幅 | Prover gas 降幅 |
|---|---:|---:|---:|---:|---:|
| three-envelope-types | 15,851,885 | 14,788,056 | 6,644,301 | 58.09% | 54.71% |
| invalid-slots-then-valid | 27,012,412 | 25,875,718 | 6,932,200 | 74.34% | 71.72% |
| deploy-write-clear | 16,249,761 | 14,879,899 | 6,733,534 | 58.56% | 55.02% |
| revert-after-store-log | 12,972,464 | 11,981,500 | 6,536,453 | 49.61% | 45.88% |
| halt-after-store-log | 12,972,081 | 11,981,117 | 6,536,070 | 49.61% | 45.88% |
| shanghai-selfdestruct | 13,349,067 | 12,081,216 | 6,636,093 | 50.29% | 46.33% |
| context-and-empty-block | 14,717,979 | 12,328,007 | 6,882,884 | 53.23% | 48.49% |
| sha256-identity-precompiles | 12,773,518 | 11,942,857 | 6,491,836 | 49.18% | 45.75% |
| block-gas-exhaustion | 16,075,149 | 14,807,298 | 6,664,676 | 58.54% | 55.02% |
| retained-sealed-chain | 33,923,696 | 31,402,567 | 23,257,553 | 31.44% | 28.91% |

独立复现脚本从另一目录重新构建并完成全部 30 次执行。表格采用该次结果；与首轮
相比，少数组合版本用例存在最多 32 条指令的微小构建/执行差异，收益百分比不变。

9 个 fixture 的 state/transactions/receipts roots 对照归档的 Geth 1.17.8 oracle。
第 10 个 workload 使用 `specs/evidence/sealed-chain-proof/proving-input.json` 的原始
完整链输入，核对 native replay 以及其中原有的 expected journal；本轮没有重新连接
CKB 或 Geth 来认证该历史导出。

对原链输入，基线为 **33,923,696** 条指令，组合 patches 后为 **23,257,553**。
只接入 Keccak 后是 **31,402,567**，降低约 7.43%；再接入 k256 与 SHA-256 后取得
其余收益。这组对照没有把 k256 与 SHA-256 的收益分别隔离，不能给两者各自归因。

## 实际 precompile 调用证据

原链输入的 syscall 计数：

| Crypto syscall | 原版 | 仅 Keccak | 组合 patches |
|---|---:|---:|---:|
| KECCAK_PERMUTE | 0 | 173 | 173 |
| SECP256K1_ADD | 0 | 0 | 771 |
| SECP256K1_DOUBLE | 0 | 0 | 1,536 |
| SHA_EXTEND | 0 | 0 | 13 |
| SHA_COMPRESS | 0 | 0 | 13 |

这证明 patches 已进入实际执行路径，而不只是出现在 Cargo.toml 中。这里展示的是
SP1 gas report 的 crypto-precompile 计数；其中普通 IO/HALT 计数不代表完整 ecall 统计。

## 版本与复现

使用官方补丁，直接依赖以 immutable git revision 固定：

| 包 | revision |
|---|---|
| sha3 0.11.0 | `540d99e46fbe7aab00caf83c4144cb4eaaf62a17` |
| k256 0.13.4 | `476243d31d3ffd9d882d0e5da1f6adaa2a204b62` |
| sha2 0.10.9 | `e48b656ebc806117554bb33c2f8687e4637e37ff` |
| sha2 0.11.0 | `8993e08b9f7c47cd4a056decbf85d2d7ab3fe77c` |

k256 引入的官方 patched ecdsa/rfc6979 来源也由归档 Cargo.lock 固定；不是手写
密码学替代实现。可参照 [SP1 官方 precompiles 文档](https://docs.succinct.xyz/docs/sp1/optimizing-programs/precompiles)
核对版本、feature 后端与 ExecutionReport 检查方法。

```bash
python3 scripts/bench-sp1-crypto-patches.py
```

需要仓库使用的 Rust 1.92 / host Rust 1.97.1、SP1 6.8.1 cargo-prove 和 succinct
工具链。首次获取官方 git patches 需要网络。输出在新的 `artifacts/sp1-patches-*`
目录；源代码副本保留在其 `source/` 中。原 guest 清单和部署身份不改变。

[证据目录](evidence/sp1-crypto-patches/) 包含前后报告、完整 journal、固定 lockfiles、
候选清单、构建日志、源文件/ELF/输入哈希和 SHA256SUMS。

## 结论的边界

- 没有重跑 core/recursive/Groth16 proving，因此没有新的证明耗时或内存峰值数据。
  原约 78 分钟还包含递归、压缩和最终 wrapping，不能乘一个指令降幅来推算新耗时。
- 未测 native-sp1 guest 的前后收益；它的静态依赖审计也发现未接入这些 patches，
  但其 custody 工作负载不同，不能套用本表百分比。
- 未测试 EVM ECRECOVER 后端替换的收益，也未覆盖全部 EVM 密码学 precompiles。
- 旧 proof 对应旧 guest key；本实验保留相同业务输入以比较计算，不声称新 ELF
  已完成合法结算、验证旧 proof 或获得原部署授权。
- 这些数字只来自给定工作负载，不是整个 Tactus 的通用性能倍数。
