# Tactus 0.02 实施与验收计划

日期：2026 年 10 月 15 日。本文配套 [协议设计](V0_02_PROTOCOL_DESIGN.md)，定义从当前 0.01 实验代码走向统一协议的工作包。**这是原始实施计划；10 月 18 日已完成八个工作包的隔离开发验收，10 月 26 日按开发预发布版发布。真实 proof 相关用例仍按原计划进入 0.03。** 当前完成范围、验证记录和剩余工作见 [实施状态](V0_02_IMPLEMENTATION_STATUS.md)，新编码见 [wire 定义](V0_02_WIRE.md)。不自动发布新版本。

## 1 交付边界

0.02 的设计交付包括决策及依据、状态与操作定义、不变量、资金分区、资源参数、信任假设、故障矩阵、代码落点、依赖和可执行验收用例。

0.02 的实现交付要求新协议的编码、纯状态机和 CKB 脚本约束都能运行，并验证规定的失败路径。真实完整原生证明、结算和资产释放由 0.03 验收；不能把纯状态模型、guest execute 或结构检查代替真实 proof。

0.04 的增量化必须保持 0.02/0.03 的协议语义。独立接管和长时间故障演练在 0.05–0.07 扩大验证；基本独立构造权和退出条件必须从 0.02 就进入设计，不能事后补成运营承诺。

## 2 编码和部署清单

新增编码版本使用单独模块，旧格式只读兼容用于历史恢复，不在旧 key 下重新解释。推荐沿用现有显式 tag、固定宽度整数、exact decode 风格，正式 magic 与字节偏移由 WP1 交付并经双实现向量固定。

| 对象 | 必须编码的字段和约束 |
| --- | --- |
| Policy | version、CKB/rollup/chain 身份；全部代码/key/profile/DA/rules 承诺；lane/slot/epoch 常量；batch/gas/系统调用上限；B_max/D_max；T_stall_blocks；claim 和每操作资源上限；固定退出支持范围 |
| DomainConfig | 不可变 Policy hash、各唯一 type 身份、allocation commitment、桥地址与 runtime hash；联合创建的交叉引用 |
| NativeBatch 新版 | 完整用户 batch、epoch/snapshot hash、实际消费的 `(lane,sequence,payload)` 前缀、连续 DepositReceipt 列表；无调用者自选结果 root |
| NativeCheckpoint 新版 | config、完整 Anchor、d_o/count/cumulative/hash、q_o 向量、snapshot 及两个处理 cursor；真实 APPEND 同交易创建 |
| SettlementControl | tag/version、RUNNING/FROZEN、initialized、config/profile、S、完整已结算边界、d_s/C/hash、q_s、EVM root/header、证明绑定的桥总供应 T 和累计 burn B；冻结状态的身份不再可花费 |
| DepositReceipt 新版 | 原 sequence/recipient/amount/accumulator/cumulative，加 refund_lock_hash；资金提供者明确授权，不能从任意 fee input 推断 |
| AdmissionReceipt | domain、lane、sequence、payload hash、epoch；对应真实 lane 转换和不可变 payload 来源 |
| EpochSnapshot 新版 | 全部有序 lane 编码、sealed epoch、存款起止 cursor 及累积承诺、对应 Policy；不能只给消息 count |
| WatchTicket | domain、工作类型、确切不可变凭据身份与序号、创建时观察的结算边界、退款锁；冻结时重新判断是否仍欠此项工作 |
| 证明 journal 新版 | Policy/profile/config、起止完整边界、EVM root/header、d/C/hash/q、T/B、outcomes commitment、连续输入 digest；总长与 witness 限额同步变更 |
| Claim witness | tagged RELEASE/REFUND/ESCAPE；精确 Frozen/Running 边界、收款锁与金额、相应 MPT/receipt/签名、对应 nullifier 路径；拒绝多解释和尾随字节 |

整数除已有 EVM/ABI 特定大端编码外统一无符号小端；hash preimage 给出完整域 tag、字段次序和长度，变长列表长度前缀先校验再分配。金额/容量运算使用足够宽类型后检查可表示范围；禁止隐式截断。每一项都要有空、最小、最大、截断、未知 tag、重复字段、超长和溢出向量。

单一 Policy hash 不足以替代脚本绑定。不同脚本必须读取相同配置、验证各自负责的字段，并在 joint genesis 与每个跨对象操作核对匹配。代码可变性也必须纳入身份：不能把可被第三方替换的依赖当作已固定 code hash。

## 3 按依赖排序的工作包

| 工作包 | 依赖 | 主要代码落点 | 交付和退出条件 |
| --- | --- | --- | --- |
| WP1 统一规格与 wire | 无 | `crates/tactus-o1-protocol/src/` 新版本模块、specs | 字段/偏移、Policy、部署 DAG、状态转换；独立编码向量一致；不得沿用旧 profile |
| WP2 全定义执行与时间 | WP1 | `batch.rs`、执行器两个 profile、checkpoint 和 settlement | equal-time 全路径一致、优先 gas 保留、系统 credit gas/溢出边界、错误分类、L1 since 检查 |
| WP3 Control 与积压 | WP1 | 新 Control 协议模块、`proofs/ckb-native-settlement`、Anchor/Lane/Vault adapters | 唯一状态、B_max/D_max、模式门控，SETTLE 不与当前 Anchor 共花；填满不阻塞已有结算和退出 |
| WP4 A3 与原生存款集成 | WP1–WP3 | `sealed.rs`、`native_bridge.rs`、`tactus-o1-sealed-script`、native anchor/vault/checkpoint | 同交易 SEAL 认证完整 deposit tail；两个 FIFO 强制前缀；AdmissionReceipt；guest 义务绑定 |
| WP5 Watch 与终止冻结 | WP3–WP4 | 新 Watch/Control adapter、所有 RUNNING 操作入口 | 双 since、精确未完成凭据、无 heartbeat，冻结/结算竞态、冻结后全入口拒绝 |
| WP6 三类领取 | WP1、WP3、WP5 | native vault、state-proof、NativeCKB 绑定、领取工具 | refund identity、三类 nullifier、EOA 双账户授权、资金守恒、费用与 reserve；未支持合约路径明确拒绝 |
| WP7 证明与联合部署 | WP2–WP6 | native-sp1 guest/journal、native-prover、checkpoint、settlement | 新完整 journal、同域配置、合约总量绑定、负面域/key 向量；输出供 0.03 真实证明的输入 |
| WP8 恢复与可观测性 | WP1–WP7 | native-vault-lab、observer-rpc、devnet-driver、scripts | 新状态索引、重组 rollback、可独立导出 claims、fresh-process 恢复和统一证据报告 |

WP2/3 的基础模块可以分别开发，但跨模块集成按依赖推进。任何工作包如果改变共识字段、合约代码或 proof public inputs，必须更新所有下游身份，不能用兼容开关混入旧部署。

WP6 需移除或改写现有 vault 对交易 typed-input 组合的旧假设；SEAL 会共同消耗 Schedule、lanes、Vault。替代规则应是精确允许的协议组合，不能简单放开任意 typed inputs。现有每操作 cell 上限也必须随真实合并交易重新测量。

## 4 验收矩阵

所有测试记录具体配置、输入、规范交易、对应脚本和失败代码。仅“交易没上链”不足以证明指定脚本拒绝。实际 proof 的正面路径与模拟/结构正面路径分开存档。

| ID | 场景与攻击输入 | 必须观察到的结果 | 负责包 |
| --- | --- | --- | --- |
| V02-01 | 同 genesis seed 重复建立 Control/Vault；错域或依赖旧 Anchor 建新状态 | 类型唯一性与联合创建边界拒绝 | WP1/3/7 |
| V02-02 | 编码最小/最大、尾随 bytes、长度先溢出后分配 | 两种实现一致；超限在分配前拒绝 | WP1 |
| V02-03 | 相同 timestamp 的连续批次、倒退、极未来 timestamp | equal-time 从发布到结算结构全部允许；倒退拒绝；future since 未成熟不能被 CKB 接受 | WP2/7 |
| V02-04 | 第一优先槽用满保留 gas，后面有合规提现 | 后续保留槽可执行；普通交易不能挤占；过大优先 gas 有固定拒绝结果 | WP2/4 |
| V02-05 | malformed/wrong chain/签名错误/nonce错误/REVERT/HALT 混合 | 固定 outcome 与 receipt 语义；区间仍可证明 | WP2/7 |
| V02-06 | 缺失或错误状态见证、引擎故障 | guest/host 失败，不产生“合法拒绝用户输入”的证明 | WP2/7 |
| V02-07 | 极限存款额、总余额上限、最大系统 gas | L1 拒绝不能安全 credit 的 envelope；已接纳 credit 不因额度或实现上限意外回滚 | WP2/4 |
| V02-08 | A-S 达 32，继续排序；d_v-d_s 达 32，继续存款 | 对应新增操作拒绝；SETTLE/RELEASE/WATCH/FREEZE 仍可构造和通过 | WP3 |
| V02-09 | 改旧 S、换错 Control、复用已花 RUNNING dep | 不能伪造新增额度或冻结后继续进展 | WP3/5 |
| V02-10 | seal 漏 lane、取旧 Vault、漏已存在 deposit tail、未用完 quota | 精确拒绝；合法 snapshot 包含全部被共同认证的尾部 | WP4 |
| V02-11 | 刚封存后存款、满 32 存款、后续 DEPOSIT 与 SEAL 竞争 | 旧快照不变；8 次批次内处理封存前缀；记录重试和真实矿工纳入条件 | WP4 |
| V02-12 | APPEND 用户义务正常但漏存款，反向亦然 | 任一义务缺失均拒绝；不能以交易总数替代身份 | WP4/7 |
| V02-13 | 持续目标 lane 抢跑、填满 queue、多 fee/签名延迟/矿工策略 | 公布接纳失败率和等待分布，区分 admission/seal/publication/settlement；失败保持 G2 OPEN | WP4/8 |
| V02-14 | 任意自建/untyped/外域 AdmissionReceipt 或 DepositReceipt | 不能作为必须处理或冻结凭据 | WP4/5 |
| V02-15 | 系统很久没证明，新请求立即 WATCH/FREEZE | WatchTicket 年龄不足，拒绝；两个 since 任一不足均拒绝 | WP5 |
| V02-16 | heartbeat 重建 Control、同 S proof、用错误 since metric | 拒绝重置计时；只有真实严格推进才更新年龄 | WP3/5/7 |
| V02-17 | 未完成 Watch 到期，SETTLE 与 FREEZE 两种竞争顺序 | 同一规范链仅一个有效；先 SETTLE 重置 timer，先 FREEZE 拒绝后续 proof | WP5/7 |
| V02-18 | watch 对应工作已经处理；另一个工作仍欠着 | 不能拿已处理 ticket 冻结；未完成者需自己的真实凭据与成熟条件 | WP5 |
| V02-19 | 已排序存款未证明，尝试 RUNNING 退款，再 proof | RUNNING 退款拒绝；冻结后退款允许、后续 proof 永久拒绝 | WP5/6 |
| V02-20 | 已入账存款退款；相同 deposit/id/address 二次领取 | 分区与 nullifier 拒绝；其他 claim 类别不能伪装绕过 | WP6 |
| V02-21 | 先 burn 后余额逃生、先普通 release 后冻结 | 余额是销毁后的值；普通领取历史跨冻结保留，守恒成立 | WP6/7 |
| V02-22 | 恶意 relayer 改 amount/recipient、跨域重放余额签名 | commitment/签名与付款脚本拒绝 | WP6 |
| V02-23 | 用合约账户余额、错 code hash、错 frozen root 申请 EOA 逃生 | 拒绝；不把 contract deployer 当资产主人 | WP6 |
| V02-24 | 首份 proof 前停机；P>0，Control 未初始化 | 成熟 freeze 后全部真实未入账存款可退款；不得从零 root 领取余额 | WP5/6 |
| V02-25 | 小额提现低于新 payout cell 最低容量、恶意挪 reserve付费 | 外部补足后可付款；侵占本金或 reserve 拒绝 | WP6 |
| V02-26 | 最大 Batch/Seal/Settle/Refund/Escape 组合 | 完整 CKB tx bytes/cycles 和 guest 资源均在固定 policy 范围，合法见证不会被错误上限排除 | WP2–WP7 |
| V02-27 | 新 guest配旧key、旧v1/sparse proof配native journal、截断边界 | 精确拒绝；execute成功不记为proof成功 | WP7 |
| V02-28 | 中途新builder推进Anchor；另一prover先结算重叠区间 | 前者不破坏不可变proof边界；后者引发正确起点重建，不跳过历史 | WP3/7 |
| V02-29 | 重组撤销 deposit/seal/settle/freeze/release | 所有状态、付款和任务从共同祖先一致回滚；不保留孤块权益 | WP8 |
| V02-30 | 关闭原服务，仅保留规范 CKB 数据和公开程序 | 新进程可重建并构造所有支持的 claim；0.03/0.05 再扩展实际证明与独立运营方接管 | WP8 |
| V02-31 | 改key/code/policy、试图FROZEN解冻、用新域花旧vault | 没有合法原地路径，旧权利保持 | WP1/5/6/7 |
| V02-32 | fee补贴耗尽、prover无报酬、archiver故障 | 不侵占用户本金、不宣称继续活性；展示欠费、积压和恢复/冻结条件 | WP8 |
| V02-33 | APPEND 不创建 checkpoint；ENQUEUE 不创建 receipt；创建任意多份 | 发布/入队本身拒绝缺失或多份记录，不能只在记录创建脚本里单向检查 | WP4/7 |
| V02-34 | ticket 创建者失联、relayer 替换 ticket 退款锁、同一 ticket 再使用 | 任意人可合法 FREEZE；容量只退固定锁；重复花费拒绝；已完成 ticket 可关闭 | WP5 |
| V02-35 | lane 首条 sequence=0、存款首条 sequence=1，逐个推进对应完成 count | lane 使用 `sequence >= q_s`，存款使用 `sequence > d_s`；不丢首条或多算已完成项 | WP1/4/5 |
| V02-36 | 有 wCKB 但原生账户不存在的地址、假的账户不存在 witness | 真实账户不存在证明加 owner 签名可逃生；伪 witness 或仅零占位拒绝 | WP6 |

在 0.02 阶段，V02-05/07/21/27 的完整密码学正面证据可以按路线交给 0.03，但报告必须明确写“待真实 proof”，不能把 0.02 脚本通过扩张成资产可用声明。负面 controls 必须与对应正面合法交易配对，防止“所有请求都拒绝”冒充安全完成。

## 5 部署前必须确定的参数和产品门槛

| 项目 | 当前设计状态 | 如何取得最终值或结论 | 放行节点 |
| --- | --- | --- | --- |
| B_max/D_max/G_priority | 开发候选 32/32/250,000 | 混合负载、最大状态见证、CKB envelope 和故障恢复测量 | 新公开 profile 前 |
| T_stall_blocks | isolated-devnet 候选 120 | 独立恢复加 proof p99、确认和重组余量；公开风险取舍 | 公开 custody 前 |
| 每操作 bytes/cycles/见证上限 | 现有组件上限不可直接相加沿用 | 合并交易最大正面用例、独立 estimator 和真实纳入 | 0.02 实现验收 |
| 同 lane 及单 vault 公平性 | 有已知冲突，不宣称解决 | 真实争抢/重签/纳入实验；失败就修改协议 | G1/G2/G7/G9 对应声明前 |
| 合约资产灾难退出 | EOA 路径明确，任意合约不支持；terminal freeze 可能永久锁住合约持仓 | 按应用验证适配器，或另设计与已领取资产不冲突的恢复执行；不能仅用风险提示放行 | 对应 DeFi 资金开放前 |
| 时间新鲜度 | 非递减及不得超前；允许滞后 | 如应用要求最大滞后，补有共识依据的界限与反例 | 时间敏感应用前 |
| gas 与 prover 费用 | 开发 gas allocation + 明示补贴 | CKB/wCKB/gas转化和无效输入成本方案、参与者经济实验 | 生产前 |
| DA 和 checkpoint 增长 | 首版永久保留，无 pruning | 容量预算、归档恢复、运行成本；要prune另设计完整可用性证明 | G4/G6/G9 |
| CKB 确认深度 | 作为部署策略，不凭空给固定安全数 | 威胁模型及重组演练，记录各API状态的深度 | 公开测试/资金前 |

这些是显式配置与资格门槛，不允许使用未填写的生产 manifest 启动资金实例。研究交付不等于把这些项标记完成。

## 6 建议执行顺序与证据组织

1. 先完成 WP1 与 WP2 的一致性修订，尤其相同时间戳和优先 gas。保留旧实验格式及证据，不修改其历史含义。
2. 实现新 Control 与新原生 A3，在纯状态机和隔离 CKB 上验证 B_max/D_max、完整 seal 与两个强制前缀。
3. 实现 Watch/Freeze/Claims，先跑正面+反面配对、竞态和守恒，再扩大资源上限。
4. 构建固定新 guest/journal、联合部署和统一恢复工具，生成与真实 canonical checkpoints 对齐的 proving inputs。
5. 进入 0.03，实际生成并验证两段连续原生 proof，在同域释放 CKB，再做重组与独立恢复。

证据按工作包保留命令、源码commit和脏工作树差异、ELF/code/key/config/Policy hash、节点版本与配置、所有输入输出、实际 tx 和确认位置、proof阶段耗时、脚本定位错误及独立审计结果。旧实验只作为回归基线，不能用旧脚本 positive 覆盖新脚本。

本次研究仅运行独立的有限状态模型与文档检查，不触发 CI、不启动真实 prover 或链上实验。未来实施先本地验证；是否执行外部流水线遵守用户指令。

## 7 设计交付核对

| 路线图要求 | 对应设计证据 |
| --- | --- |
| 统一状态机与确认阶段 | 协议设计第 3、4、11 节 |
| 生产候选排序及强制义务 | 第 5 节；V02-10–14；明确 A3 接纳公平性未完成 |
| 准入、总定义执行和资源边界 | 第 6 节；V02-02–07、26；Policy 标定清单 |
| 积压、停滞、恢复和退出 | 第 7–9 节；V02-08–09、15–25、28–30 |
| 支持资产、授权及守恒 | 第 8–9 节；三类资金分区、签名和nullifier定义 |
| 升级与权限边界 | 第 3、10 节；不可原地升级和主动迁移；V02-31 |
| 程序/key/DA与起止状态绑定 | 第 3、7 节；编码清单、WP1/7、V02-01/27 |
| 成本承担和活性假设 | 第 1、10–12 节；V02-32、生产门槛 |
| 状态表、权限表、限制表、故障矩阵和验收用例 | 协议设计第 1/3/4/6/12 节及本计划第 4 节 |

设计复核发现与有限模型的具体结果另记于 [研究审查记录](V0_02_RESEARCH_REVIEW.md)。任何模型通过只支持其明示的抽象不变量，不证明 CKB、MPT、签名、SP1 或经济活性。
