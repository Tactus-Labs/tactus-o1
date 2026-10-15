# SP1 patched guest 完整 proving 重测

状态：**完整证明已生成并通过 fresh-process verification**。
本地时间：2026-10-14 23:18:50 开始计时，2026-10-15 00:18:30 左右完成独立验证（UTC+8）。

同口径阶段合计从 **77 分 54.7 秒降至 58 分 56.9 秒**，减少 **24.34%**，
节省约 **18 分 57.8 秒**，约 **1.32×** 加速。
新的统一 pipeline 计时为 **58 分 57.6 秒**；加上独立新进程验证为 **59 分 39.5 秒**。

这是完成真实 proving 后的实测结果，和之前的 **31.44% guest 指令降幅**、
**91.6% CKB L1 verifier cycles 降幅**属于三个不同指标。

后续[增量证明与执行热点审计](PROOF_SCALING_AUDIT.md)确认：本次输入是零历史前缀、
九个新区间批次（前八个为空块），不能把 59 分钟归因于重复证明已结算历史。
隔离候选将固定执行配置哈希缓存后，guest 指令进一步减少 84.57%；该候选尚未
重跑完整 proving，不能把本报告的时间或该指令降幅当作它的新证明耗时。

后续[第二轮优化](SP1_OPTIMIZATION_ROUND2_REPORT.md)进一步采用构建时预计算、批次
校验复用和 guest ECRECOVER 加速。正式 guest 对同一输入生成的新完整证明已通过
独立验证，同口径耗时为 **19 分 49.9 秒**；这不是上述仅缓存候选的测量结果。

## 实验定义

- 工作负载：`specs/evidence/sealed-chain-proof/proving-input.json`，与历史约 78 分钟实验相同。
- Guest：crypto-patch 对照中的 `combined.elf`，SHA-256
  `7ffaa9eb909684c15fee884aeccf815a856fff0feffb8108662041f926acd018`。
- 官方 Keccak、k256、两个版本 SHA-256 patches，配置与 lockfile 见
  [patch audit](SP1_CRYPTO_PATCH_AUDIT.md)。
- SP1 6.8.1，release circuit v6.1.0，本地 CPU。4 个 Rayon/Tokio 线程，单 worker，
  Go wrapping 2 线程；分阶段释放内存的策略与历史实验相同。
- 本次输入只修改 `guest_verifying_key` 以绑定新的 guest。批次、allocation、domain、
  prefix、expected journal 均不改变。这是计算性能实验，不是旧部署授权的新 guest。
- 证明链包含执行、core proving、递归聚合、shrink/wrap、Groth16 wrapping、密码学
  验证和 fresh-process verification。没有从旧 witness 恢复，也没有跳过证明阶段。
- 在完整 recursive witness 生成后，沿用已有 runner 的进程交接，以避免递归与最终
  wrapping 同时保留高峰内存。这是完整的分阶段 pipeline，不声称单进程连续成功。

## 实测结果与历史比较

| 阶段 | 历史原版 | 本轮 patches 后 |
|---|---:|---:|
| CPU prover 初始化至完整 recursive witness | 4,560.600 s | 3,415.892 s |
| 独立进程 Groth16 wrapping 与验证 | 114.078 s | 120.971 s |
| 同口径阶段合计 | 4,674.679 s | 3,536.863 s |
| 包含阶段交接的统一 pipeline 计时 | 未记录 | 3,537.624 s |
| 额外 fresh-process verification | 无同口径计时 | 41.884 s |
| pipeline + fresh verification | 无同口径计时 | 3,579.509 s |

收益主要来自最终 Groth16 wrapping 之前的计算，前一阶段减少 **25.10%**。
最终 wrapping 本轮约 121 秒，历史约 114 秒，**没有获得加速**；这也说明不能直接用
31.44% 的指令降幅推算完整 proving 时间。

递归阶段峰值 RSS：历史 **20,975,204 KiB**，本轮 **19,475,648 KiB**（约 18.57 GiB）。
本轮最终 wrapping 峰值 **17,539,916 KiB**（约 16.73 GiB）。运行期间存在整机内存
压力和 swap 使用；这些是同一机器上的历史单次对照，不是多次统计性能保证。

历史记录没有包含两阶段全部进程切换和最终 fresh verification 的统一计时；将同口径
阶段合计作为历史比较，同时单独报告新 runner 的 pipeline 总计时及 fresh verification。
历史基线来自 10 月 10 日，非本轮交错 A/B 重测，机器负载、频率、缓存可能不同。

## 正确性与证据

- 新 proof 的 guest key 为
  `0x009af0b301570b9ccd54ee580352b3ec73d45eee3cadf93d61c365117c3ff42c`。
- 完整 768-byte public journal 与历史输入中的 expected journal 字节一致。
- SDK proof container 为 2,462 bytes，Groth16 wire proof 为 356 bytes。
- 新生成的 proof 通过 verifier；14 处公开字段篡改和错误 guest key 均被拒绝。
- 独立进程重新 setup 新 ELF、验证 proof，并核对输入重放结果，成功退出。
- 整条 staged pipeline 与 fresh verification 均退出 0；递归子进程的 -15 是
  完整 witness 落盘后的既定交接行为，非崩溃后恢复旧 witness。

[证据归档](evidence/sp1-patched-proving/) 保存 proof、公开输出、计时日志、原始链输入的
候选副本、witness、环境、源代码快照和文件哈希。`comparison.json` 保存精确比较数字。

## 复现

先按 patch audit 构建 `combined.elf`，并构建带 native-gnark 的本地 host：

```bash
CARGO_TARGET_DIR=artifacts/prover-host/target CARGO_BUILD_JOBS=4 \
cargo +1.97.1 build --release --locked --manifest-path proofs/sp1/Cargo.toml \
  -p tactus-o1-sp1-host --features native-gnark --bin chain-proof --bin wrap-witness

python3 scripts/run-patched-proof-benchmark.py \
  --elf artifacts/sp1-patches-reproduced/combined.elf
```

需要本地已安装的 SP1 release Groth16 circuit artifacts；可通过 `--circuit-parent`
指定目录。输出写入新的 `artifacts/patched-chain-proof-*`，计时排除编译、预先推导
验证密钥和输入文件哈希。过程由 `.proof-run.lock` 防止与另一个本地证明实验重叠。

本次运行目录：`artifacts/sp1-patched-full-proof`。未运行 CI，未修改正式 guest 或
部署配置，未提交 CKB 交易。
