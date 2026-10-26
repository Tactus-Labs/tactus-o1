# Tactus 0.02 协议设计

日期：2026 年 10 月 15 日。状态：**0.02 设计及隔离开发实现已验收，发布为开发预发布版，未通过生产验收**。详见 [验收记录](V0_02_ACCEPTANCE_AUDIT.md)。

本设计将 [版本路线图](ROADMAP.md) 的 0.02 展开为状态机、信任边界、准入与积压规则、结算和退出协议。目标是让同一套规则支撑 0.03 的真实资产闭环及后续高速运行。当前开发发布版本为 0.02；历史 0.01 二进制、合约、验证密钥和实验结论保持独立。

文中的“必须”约束将要实现的新协议实例。现有行为以代码及 [生产准备状态](PRODUCTION_READINESS.md) 为准。本文收敛先前规范中相应的开放选择，但不覆盖历史实验格式；新格式必须使用新的 magic、rules/profile/policy hash 和部署身份。

## 1 结论和边界

推荐以 **A3 不可变快照、原生资产统一结算状态、受限证明积压、终止式应急退出** 作为下一轮实现主线。普通交易在链下传播，CKB 决定规范批次顺序并保留完整重建数据，SP1 证明 EVM 与系统存款执行。任何合规参与者均可构建、证明、提交和代付。

以下选择在本提案中明确固定：

| 决策 | 选择 | 代价与条件 |
| --- | --- | --- |
| 规范排序 | CKB 消耗唯一 Anchor 的合法继承关系 | 单个 Anchor 仍串行；批量承载交易而不是每笔抢 Anchor |
| 优先处理 | A3 sealed snapshots，按确定顺序处理 | 已接纳后的处理有界；共享 lane 的接纳公平性仍须验证 |
| DA | 重建所需字节直接保留在 CKB | 永久容量和带宽成本必须计入，后续不能静默换外部 DA |
| EVM | 固定 Shanghai 规则、revm，明确 L2 时间规则 | 不宣称支持后续硬分叉或全部 Ethereum 共识规则 |
| 证明 | SP1、固定程序身份、连续区间 | 初始全量重放；增量实现必须维持相同语义和边界绑定 |
| 原生资产 | 固定 NativeCKB ERC-20 账本和对应 CKB vault | 不是已经将 CKB 接入 EVM 原生 gas 余额 |
| 停滞 | 第三方继续证明；达条件后可终止并退出 | 冻结后永不恢复同一状态域的普通执行 |
| 升级 | 本代实例不可原地升级，用户主动退出再迁移 | 不提供管理员换 key、代迁资产或紧急解冻后门 |

需要区分三个性质：**安全性**由链上规则、证明和签名保证；**协议活性**还要求 CKB 纳入合法交易、数据可获取且有愿意工作的参与者；**经济可持续性**需要实测费用和参与激励。任何一个组件测试通过，都不能替代另外两项。

本文没有证明普通用户在所有敌对 lane 争抢中都能成功接纳，也没有提供任意 EVM 合约的通用无 prover 清算。两者保留为明确产品门槛，不能用“架构已写完”关闭 G2 或 G7。

## 2 现有证据和必须补齐的差异

| 当前代码或证据 | 已有能力 | 0.02 设计要求的差异 |
| --- | --- | --- |
| [sealed.rs](../crates/tactus-o1-protocol/src/sealed.rs)、[A3 规范](A3_SEALED_V1.md) | 有界 lanes、全 lane seal、强制原始交易前缀 | 接入原生存款、明确优先 gas 预算、独立公布接纳凭据 |
| [接纳费率实验](ADMISSION_FEE_DENSITY_REPORT.md) | 按字节匹配费用后，同 lane 竞争仍会产生过期输入 | 不把多 lane 或提高费用写成接纳公平性的证明 |
| [native_bridge.rs](../crates/tactus-o1-protocol/src/native_bridge.rs)、[原生发布](NATIVE_PUBLICATION_REPORT.md) | 真实存款凭据、连续 cursor、完整数据发布 | 与 A3 原子集成，强制覆盖已封存存款前缀 |
| [batch.rs](../crates/tactus-o1-protocol/src/batch.rs) | 允许非递减时间戳、输入资源边界 | 加 CKB 时间上界绑定与明确的执行总量边界 |
| [原生 checkpoint](../proofs/ckb-native-checkpoint/src/lib.rs)、[原生结算](../proofs/ckb-native-settlement/src/lib.rs) | 原生完整 checkpoint、固定 key 和 journal 绑定 | 当前严格递增时间规则与批次相同时间戳规则不一致，必须统一 |
| [原生发布 adapter](../proofs/ckb-native-anchor/src/onchain.rs) | 验证实际 batch 输出与真实 deposit receipts | 新 APPEND 必须反向强制创建 checkpoint，不能只由 checkpoint 脚本验证自身创建是否合法 |
| [执行器](../crates/tactus-o1-execution/src/lib.rs) | 无效输入有固定状态码，正常 REVERT/HALT 可证明 | 资源失败不能被当作普通无效交易；优先输入不能被前序交易挤光 gas |
| [原生 vault](../proofs/ckb-native-vault/src/lib.rs) | 真实资金入账、提现 commitment 的 MPT 证明和领取 nullifier | 没有冻结、存款退款或余额逃生路径；不能直接把余额读取证明当领取授权 |
| [NativeCKB.sol](../contracts/bridge/NativeCKB.sol) | slot 3 余额、slot 7 永久提现承诺、系统入账 | 系统入账必成功依赖要与 L1 金额上限和固定代码共同验证 |
| [原生结算实验](NATIVE_SETTLEMENT_REPORT.md) | 联合 genesis 避免类型哈希循环，真实拒绝边界 | 实际新证明结算和实际 payout 待 0.03 验收 |
| [增量实验](SP1_OPTIMIZATION_ROUND3_REPORT.md) | 独立 sparse profile 两次真实结算 | 不具备原生托管权限，需显式新 profile 集成 |

普通完整结算目前也保留严格递增时间检查，只有 sparse 分支允许相同时间戳；统一时必须覆盖全量、原生、增量和 checkpoint，不能只修其中一个。

## 3 状态和身份

### 3.1 命名

所有计数采用“已完成项数”，区间用半开区间 `[start,end)`。存款凭据沿用从 1 开始的 sequence；`d=0` 表示无已处理存款。不得混用 batch 下标与 batch 数量。

lane 消息沿用从 0 开始的 sequence；`q=0` 表示 sequence 0 尚未处理，`q=1` 表示它已经处理。因此 lane 凭据未完成条件是 `sequence >= q`，与存款的 `sequence > d` 不同。统一 work-end 表示时使用 checked `sequence + 1`。

- `A`：已排序批次数，由 Anchor 记录。
- `S`：已证明结算批次数，由 SettlementControl 记录，始终 `0 <= S <= A`。
- `d_v`：vault 累计存款条数；`d_o`：已经发布到规范 L2 输入的条数；`d_s`：已证明入账条数。始终 `d_s <= d_o <= d_v`。
- `q_o[i]`、`q_s[i]`：lane i 已发布与已证明处理的累计消息数。处理包含固定规则下的有效执行或确定性拒绝，不保证交易成功。
- `P`、`C`、`B`、`R`：累计存入本金、已证明入账本金、已证明销毁提现金额、实际已释放的普通提现金额。
- `V`：vault 当前可偿付本金，排除不可动用的 cell reserve。

### 3.2 唯一可变状态

| 对象 | 主要字段 | 变更权限 |
| --- | --- | --- |
| Anchor | 实例身份、A、规范输入累积承诺、最后 block/time、d_o 及存款累积承诺、q_o | 仅合规 APPEND，绑定同交易 Schedule 更新 |
| Schedule | epoch、8 次 batch 配额、快照 commitment、用户消息和存款的独立处理 cursor | APPEND 或完整 SEAL |
| Lane[i] | epoch、sequence、最多 8 条待封存消息、历史累积承诺 | 一次 ENQUEUE 或 SEAL 清空本期队列 |
| Vault | reserve、P、R、d_v、存款累积承诺、claim roots、累计退款与余额逃生额 | DEPOSIT、SEAL 的原值重建、合法 RELEASE/REFUND/ESCAPE |
| SettlementControl | RUNNING/FROZEN、实例和 profile、S、完整已结算原生边界、d_s/C/q_s、EVM root/header、桥总供应 T 与累计 burn B | 真实 SETTLE 或一次 FREEZE |

SettlementControl 是新实例中扩展后的 SettlementTip，**不是另加一个可与 Tip 脱节的状态副本**。新脚本必须禁止缺失、复制、销毁、替换锁或重置 genesis。FROZEN 后该 cell 永久保留；领取仅更新 Vault。

完整边界必须包含存款累积 hash 和累计金额，不能只有 `d_s`。q_s 为固定配置 lane 数的完整向量。未初始化结算状态使用显式标志，root/hash 的零占位不构成可信余额状态。

### 3.3 不可变记录

保留 GenesisAllocation、Policy、BatchData、完整 NativeCheckpoint、EpochSnapshot 和真实 DepositReceipt。增加 AdmissionReceipt：绑定 lane、sequence、payload hash 及入队事件；仅在对应 lane 的真实接纳交易中创建。它用于独立跟踪和停滞证据，不代表全球队列完整性。

EpochSnapshot 同时记录所有 lane FIFO 队列，以及封存时的存款 tail/cumulative/hash。NativeCheckpoint 记录该批次后的完整 Anchor/Schedule 处理边界。每个创建脚本都验证对应权威状态确实在同交易被合法消耗并更新；任意同字节 cell 不能冒充类型认证。

还必须反向约束：Anchor 的每次 APPEND 强制同交易创建一个正确 checkpoint，Lane 的 ENQUEUE 强制创建一个 AdmissionReceipt。仅验证“如果创建，则来源正确”不保证“每次推进必有记录”。否则最新批次可能没有可用于结算或 WATCH 的合法终点。

### 3.4 避免哈希循环

延续现有联合 genesis 的思路：由固定 funding input 和输出索引派生实例身份；先计算代码承诺、Policy 和 allocation，再构建只引用预先可知身份的 type args，最后把完整互相绑定的配置写入共同创建的状态数据。不存在通过尝试哈希不动点求 vault/control/anchor 身份的步骤。

正式编码前交付一张无环构建依赖图和独立 genesis 向量。所有创建脚本交叉验证同交易的完整配置；之后配置不可变。新 domain 不继承旧实验资产或旧 proof 权限。

## 4 CKB 交易状态转换

下表的“读 Control”要求精确类型身份、合法模式和活的 CellDep。FREEZE 与 SETTLE 消耗该 cell，因此旧 RUNNING 依赖不能在冻结之后授权新动作。依赖失效后重建交易是显式成本。

| 操作 | 消耗并重建 | 必需的认证数据 | 主要效果与拒绝条件 |
| --- | --- | --- | --- |
| GENESIS | 创建唯一 Anchor/Schedule/lanes/Vault/Control | 真实 CKB genesis、固定 allocation、Policy | 空队列、空存款、无预置 wCKB；身份及 occupied capacity 完全匹配 |
| ENQUEUE | 指定 Lane | RUNNING Control | 追加一条、创建 AdmissionReceipt；满队列或过大输入拒绝，不改变 Anchor |
| DEPOSIT | Vault | RUNNING Control | 本金由额外资金输入提供；追加真实 Receipt；遵守未结算条数和金额上限 |
| SEAL | Schedule、全部 Lane、Vault | RUNNING Control、当前 Anchor | 用完 8 次配额后封存全部 lane 和当时全部待处理存款；Vault 金额/count 不变；不附带 APPEND |
| APPEND | Anchor、Schedule | RUNNING Control、当前不可变 snapshot、所需存款 receipts | 必须处理固定用户前缀和存款前缀；发布完整输入并创建 checkpoint；受积压上限约束 |
| SETTLE | SettlementControl | 真实证明、起止完整 checkpoints、公开 journal | 从当前 S 连续推进，绑定所有边界；只有成功证明可重置该 cell 的存活年龄 |
| RELEASE | Vault | RUNNING Control，或 FROZEN Control | 对认证状态中的永久 burn commitment 付款；同一提现 id 只能一次 |
| WATCH | 创建独立 WatchTicket | RUNNING Control、不可变未完成工作凭据 | 任何人可出资；不得以无来源数字或用户自报余额创建有效停滞证据 |
| CLOSE_WATCH | WatchTicket | 当前 Control，证明该义务已履行或已经 FROZEN | 退还 ticket 容量到创建时承诺的退款锁，不能延长或修改其他 ticket 的计时 |
| FREEZE | SettlementControl、WatchTicket | 仍未完成的凭据、两个 input 的到期 since | 固定最后已结算状态，终止该实例；不消耗 Anchor、lanes 或 Vault |
| REFUND | Vault | FROZEN Control、未入账存款 Receipt | 仅 sequence > d_s；付给凭据预先承诺的 CKB refund lock |
| ESCAPE | Vault | FROZEN Control、余额/账户证明、所有者授权 | 仅规定范围内余额，按地址整额领取一次 |

所有费用由额外输入支付，不能少付用户金额、侵占 reserve 或凭空减少 vault 本金。领取输出可以由代付者补足 CKB 最小 occupied capacity；这不是多领本金。

WatchTicket 采用协议锁，任何人都可在条件满足时用它触发 FREEZE；不能要求 ticket 创建者再次签名。FREEZE/CLOSE_WATCH 都将其完整容量返还固定退款锁，额外费用另付，避免监控票据形成第三方资金窃取路径。

每笔协议交易有唯一 operation tag，各脚本核对同一操作及表中精确的输入/输出角色。GENESIS 和上述显式组合除外，不在首版混合 APPEND+SETTLE、DEPOSIT+RELEASE 或 FREEZE+领取；未列出的组合拒绝。领取一次处理一个 claim，批量领取另行定义，避免重复 payout 索引或部分验证造成多次减账。

**重要取舍：**不再引用会随每次接纳变化的 live lane 作为 APPEND 依赖；Control 则是刻意保留的模式和结算权威依赖。它在结算时改变，仍可能令在途交易过期，必须测量重试率。不能把它描述成“完全没有 mutable-dependency contention”。

## 5 接纳与强制处理

### 5.1 普通交易和优先交易

普通 Ethereum 交易通过 gateway/P2P 传播。RPC 接收只表示进入本地队列；builder 反馈为 speculative。只有 CKB 接受 Anchor 与完整数据发布后才是 ordered。

优先路径的消息身份为 `(domain,lane,sequence)`。候选开发配置保留最多 4 lanes、每 lane 每期 8 条、每条 1024 字节、每批次 4 条、每期 8 批次。按深度优先、lane 索引次序合并 FIFO。每条已封存消息必须占据第一 EVM block 的精确前缀位置，不能换到后面的 block。

在消息成功接纳且规范进度继续的条件下，从刚错过 seal 到被发布至多需要剩余本期 8 次、一次 seal 和下期 8 次 batch 推进。此界限不是 CKB 区块数，不是墙钟时间，更不是 proof settlement 的即时保证。

### 5.2 优先 gas 不能被挤占

现有执行器按 block 剩余 gas 判断交易，后面的优先消息可能因为前一条用掉预算而成为 `BlockGas`。候选新规则为每个强制槽保留 `G_priority = 250,000` gas，四槽合计不超过当前每 block 1,000,000 的用户 gas 上限。

在优先槽中，decoded gas limit 超过 G_priority 的消息得到固定 `PriorityGasLimit` 拒绝；其他状态相关校验按确定次序进行。普通交易只能使用处理完强制前缀后的剩余 gas。失败的优先消息也提交可验证 outcome，不得删除其身份。系统存款 gas 独立预算，不能消耗优先槽保留量。

这定义的是受限强制调用能力。1024 字节或 250,000 gas 以外的合约调用不能声称已有强制纳入保障；提高参数须先满足 snapshot/CKB/prover 资源边界。短提现调用是首先需要验收的用例。

### 5.3 原生存款必须加入封存义务

每次 SEAL 在同交易消耗并原值重建 Vault，以认证完整当前存款 tail。假设上一 snapshot 的存款已经发布完，则新 snapshot 范围为 `(d_o,d_v]`。每个后续 APPEND 必须先系统入账该范围的 `min(4,remaining)` 条，然后执行用户交易；具体 recipients、amounts 和累积承诺都来自真实 Receipt。

DEPOSIT 要求 `d_v + 1 - d_s <= 32`。因此 seal 时最多 32 条未证明存款，8 个 batch 必能发布封存的全部存款。系统存款与用户队列是两个独立义务，不可用处理其中一个抵消另一个。SEAL 前检查前一期两个义务都完成。

由于 DEPOSIT 需要 Vault 而 SEAL 也需要它，两者仍竞争；但未证明存款条数有硬上限，且 seal 消耗前一期批次配额后不能继续 APPEND。已证明前缀最多释放有限接纳额度，不能在没有新规范进度时无限补充。真实 miner/txpool 下的 seal 活性仍须实验，不能从计数界限推导无条件纳入。

### 5.4 接纳公平性的明确结论

选择 A3 是下一轮实现选择，不是 G2 完成声明。同一 lane 上的定向竞争已在实验出现；换 lane、relay 和提高费用只是可测缓解手段。有限队列也会被攻击者填满。

不采用“独立 A2 cell 出现就自动全局强制处理”的假设：CKB 脚本不能凭几个调用者选择的 CellDep 得知所有尚未处理的消息。没有完整集合承诺或经验证的历史扫描，独立 cell 真实性不证明集合完整性。

G2 的放行条件见验收矩阵：在公开的 CKB 纳入和对手模型下测量普通用户接纳、封存及处理。若失败，应更改接纳机制并重开相关设计；不通过删除用户可达性要求来发布生产版本。

## 6 全定义执行与资源边界

### 6.1 任何已接纳输入都有唯一结果

外层编码错误、错误 domain、错误前缀、缺失数据、超出结构上限在 CKB APPEND 前拒绝。合法外层中的 Ethereum 字节按固定顺序产生 Malformed、UnsupportedType、InvalidSignature、WrongChain、PriorityGasLimit/BlockGas、InvalidTransaction，或者 Success/Revert/Halt。

拒绝槽不产生伪造的 Ethereum receipt；协议 outcome 保留输入 hash、位置、固定状态码和处理身份。执行成功、REVERT 和 HALT 按固定 EVM 语义消耗 gas、更新相应状态并生成 receipt。RPC 分别暴露协议拒绝与 Ethereum 执行失败。

缺失/错误 MPT 见证、数据库损坏、panic、内存耗尽和 prover 失败是实现或运行故障，**不能被证明为用户交易拒绝**。不能让 prover 通过选择缺失见证跳过有效执行。

### 6.2 两层资源参数

| 参数 | 代码当前值或提案 | 新协议要求 |
| --- | --- | --- |
| batch 输入字节 | 当前 262,144 | 新原生 wrapper 连同新增字段整体计费，不可每层各享同一上限 |
| blocks / transactions | 当前每批 16 / 1024，每 block 256 | 开发配置先保留；所有计数和相乘 checked arithmetic |
| 普通 transaction 字节 | 当前 16,384 | 与优先 1024 字节限制分别标识 |
| 用户 gas | 当前每 block 1,000,000 | 同时限制整批最大 16,000,000 |
| 系统 credit gas | 当前每条最高 200,000，最多 32 条/批 | 提案每批强制最多 4 条，最多额外 800,000 gas；必须验证固定调用必成功 |
| L1 证明 witness | 当前结算 8192 字节，其中 proof <=4096 | 新 journal 重新计算总长，不沿用无法容纳新增字段的旧界限 |
| 退出 MPT witness | 当前总 proof <=128 KiB，每路径 <=65 nodes、每 node <=1024 bytes | 双账户/多 slot 逃生路径单独界定并对最大实际状态验证充分性 |
| 未结算 batch 数 | **候选 B_max = 32** | APPEND 强制 `A + 1 - S <= B_max` |
| 未证明存款条数 | **候选 D_max = 32** | DEPOSIT 强制 `d_v + 1 - d_s <= D_max` |
| 用户/系统工作量 | 以上为开发边界 | 不等同于 SP1 cycles 上限，必须标定最坏负载 |

这些是实现起点，不是高速或生产性能承诺。最终 Policy 必须进一步给出每操作的 input/output/dep/witness 总数与总字节、CKB cycles、guest 内存与总指令预算的资格报告。多脚本交易不能只检查一个脚本的 cycles。

EVM gas 之外的费用包括无效输入验签、编码、状态树访问、code bytes、历史 headers 和系统调用。状态/存储见证上限应由受限执行量和树深度推导并验证；若某个可达状态需要的有效见证超过上限，应降低准入负载或修改见证方案，不能到证明阶段才拒绝该规范区间。

### 6.3 时间规则统一

保留当前 L2 **非递减** block timestamp 语义，允许同秒多个 blocks。batch/block 计数严格增加，时间不得倒退。统一 full/native/sparse guest、checkpoint 和 settlement 的判断；不得用 strict timestamp 作为额外防重放条件。

APPEND 在 Anchor input 上要求正确编码的 **absolute timestamp since**，阈值等于该批次最后 L2 timestamp。由 CKB 共识保证该交易不能在阈值之前纳入；脚本验证标志、数值和精确对应关系，不能接受任意旧 header 代替当前时间约束。timestamp 使用秒，header 毫秒与 since 的转换在实现向量中固定。

此规则防止规范历史被任意未来时间戳推进；它不保证 timestamp 足够接近当前墙钟。开发 profile 明确允许滞后，不将其用于协议停滞或退出计时。依赖新鲜时间的金融应用需在开放测试网前单独确定并验证最大滞后规则。

依据为 [CKB since RFC](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0017-tx-valid-since/0017-tx-valid-since.md)。这里用其共识时间条件；所提出的 L2 绑定规则属于 Tactus 新设计。

## 7 证明声明与积压

### 7.1 证明什么

新 journal 按固定版本提交：实例/config/policy/profile、起止完整原生 checkpoint、起止 EVM root/header、连续输入区间 digest、起止 d/C/存款累积 hash、起止 q 向量及 outcome commitment，以及起止固定桥合约的总供应 T、累计 burn B。guest 将 T/B/C 与该固定合约的认证存储状态核对，链上检查 `T=C-B`，不能只接受 host 提供的会计字段。BatchData 必须承诺对应 snapshot 身份和实际消费的用户/存款前缀，使 guest 能重放被 L1 认证的义务，不以 host 自报的“已完成”数量代替。

链上结算同时检查：当前 Control 与起点相等，终点是由真实发布创建的完整 checkpoint，`S_new > S_old`，所有 domain/key/公共输入完全匹配。guest 验证连续区间、执行及相应义务结果。全量可由 genesis 重放起点，增量必须认证起始 root 和全部读见证。程序版本更换不能保留旧身份。

SettlementControl 不直接依赖当前可变 Anchor，只读不可变起止 checkpoint。因此后续排序不应废掉已准备的有效区间证明。另一 prover 先结算造成起点变化时，需要换区间或重做衔接；不能把旧 proof 的 public inputs 改写后重用。

### 7.2 背压和恢复

所有 APPEND 读取当前 RUNNING Control，并检查 `A + 1 - S <= B_max`。所有 DEPOSIT 检查 D_max 及本金范围。积压满时停止新增排序或存款，不禁止 SETTLE、WATCH、FREEZE、已证明 RELEASE 和冻结后领取。

SEAL 不增加 A，可在完整义务已发布且配额用完时执行；即使暂时无法再 APPEND，也不能把资源满解释为丢弃义务。有限 ENQUEUE 仍允许填充剩余 lane 容量；满则在接纳前拒绝，不返回 accepted。

无需每次 APPEND 和 SETTLE 共花同一个 Anchor；但二者共享 Control 依赖形成明确的重试边界。性能目标是跨多个交易批次摊销结算更新，不是声称没有串行状态。

## 8 原生资产和正常提现

### 8.1 资金守恒

RUNNING 中以最后已证明状态为准：

```text
U = P - C                 尚未证明入账本金
T = C - B                 已证明 wCKB 总供应
W = B - R                 已证明销毁但尚未释放
V = P - R = U + T + W
vault_capacity = reserve + V
```

存款金额用 shannon，wCKB 为 8 decimals。所有计算 checked arithmetic；要求 `reserve + V <= u64::MAX`，且 CKB reserve 独立。withdraw 的 recipient lock、amount 和 owner 被永久 commitment 绑定。

首版新实例禁止凭空预置 wCKB，固定合约不允许管理员 mint、升级或 selfdestruct。L1 存款资格及执行 hook 要证明固定 `creditDeposit` 不会因为金额溢出或超过系统 gas 上限中止已接纳批次。若需要改变 bytecode，相应 code hash/profile 必须更新。

### 8.2 正常领取

用户在 L2 调用 withdraw 销毁 wCKB；其执行被真实证明并结算后，任何 relayer 可提供 slot 7 commitment 的 MPT witness 和对应 id/amount/recipient/owner，更新 Vault 的普通领取 nullifier 并支付精确收款锁。无需用户再次向运营方申请签名。

余额 MPT 读取只能证明“某状态下有余额”，不能替代 burn 或冻结授权。领取针对当前已结算 root；root 更新后可重新构造永久 commitment 的证明。候选未来优化可认证历史结算证书，但不属于本版必须引入的额外权威对象。

### 8.3 新存款的退款身份

现有 Receipt 没有 CKB 退款锁，不能凭 tx input 0 猜出实际存款人，特别是多人或代付交易。新 Receipt 必须增加 `refund_lock_hash`，由资金提供者在签署存款交易时确定，并进入存款 id/累积承诺/DA。没有该字段的旧实验凭据不能自动迁移进新退款协议。

RUNNING 期间不允许仅凭超时退款已接纳存款；这些存款可能已经在未证明区间被使用。取消需要新的显式协议，本提案选择在终止冻结后退款。

## 9 证明停滞和终止式退出

### 9.1 WatchTicket 与时间

冻结不是管理员决定。任何人可以对仍未完成的认证工作创建 WatchTicket，支持三类证据：`checkpoint.A > S`、`DepositReceipt.sequence > d_s`、`AdmissionReceipt.sequence >= q_s[lane]`。在创建和 FREEZE 时都验证精确来源和仍未完成。伪造数量、另一个实例的 receipt 和已经履行的义务均无效。

FREEZE 消耗当前 RUNNING Control 和该 WatchTicket，**两个 input 均要求 relative block-number since >= T_stall_blocks**。Control 只有真实推进的 SETTLE 才能重建，空 heartbeat 或复制同一 S 均禁止；WatchTicket 的创建年龄防止系统长时间闲置后，新请求一出现就立即触发冻结。时间阈值是 CKB 区块数，不宣称固定分钟数。

候选 isolated-devnet 取 `T_stall_blocks=120`，仅用于机制实验。公开部署必须按目标硬件下恢复/证明 p99、CKB 确认与重组余量重新标定，并固定在 Policy；不能把实验值直接当生产 SLA。

### 9.2 Freeze 原子边界

FREEZE 只竞争 Control，不要求占用正在 churn 的 Anchor、Lane 或 Vault。SETTLE 与 FREEZE 争用同一个 Control input，CKB 规范链只能接受其中一个。结算先发生则旧冻结交易过期，新的 Control 重新计时；冻结先发生则后续结算和依赖旧 RUNNING cell 的发布/存款/入队/seal 无效。

冻结把最后结算 root/header、S、d_s/C、q_s 和全部身份保存为永久状态。**FROZEN 不存在返回 RUNNING 的转换**。否则有人按旧余额退出后，后来证明同一余额已被转走，会导致双重领取。

过了时间阈值不代表冻结已经发生。FREEZE 仍需要 CKB 纳入，SETTLE 也可竞争成功；UI 在实际冻结之前不能显示退款可领取。重组可能撤销冻结及其后续领取，所有跟踪按 CKB 规范链恢复。

### 9.3 三种互斥资产来源

| 路径 | 资格与认证 | 唯一领取标识 |
| --- | --- | --- |
| 已证明 burn 的 RELEASE | 冻结 root 下的永久 withdraw commitment；未领取 | `(domain,withdrawal,id)`，与冻结前沿用同一 nullifier |
| 未证明入账的 REFUND | 真实 Receipt、sequence > d_s、准确 amount/refund lock；记录必须属于该 Vault | `(domain,refund,deposit_id)` |
| 余额 ESCAPE | 冻结 root 下固定 wCKB 的 slot 3 余额；授权和支持范围如下 | `(domain,balance,owner_address)`，一次领取全部余额 |

大于 d_s 的存款即便已被排序或局部执行，仍属于退款分区，因为冻结后那个未证明后缀永远不会结算。小于等于 d_s 的存款已经进入余额或 burn 分区，不能再退款。

冻结后增加累计退款 `F` 和累计余额逃生 `E`，不回退 P/C/B：

```text
V = P - R - F - E
  = (P - C - F) + (C - B - E) + (B - R)
```

三个分量都不得为负，sum 与实际本金一致。每次领取必须更新相应 nullifier，root 和集合互相隔离；不能仅维护总金额来替代按 claim 去重。未初始化 Control 下无可用余额 root，只有真实未入账存款退款可行。

### 9.4 余额所有者授权和合约范围

EOA 余额领取需要两部分 MPT 认证：固定桥合约账户/代码和余额 slot，以及 owner 账户在同一冻结状态中的空 code hash 或有效账户不存在证明。后者覆盖只持有 ERC-20、尚未创建原生 EVM 账户记录的地址，不能把格式中的零占位当成不存在证明。owner 对包含实例、冻结 Control 身份、root、owner、amount 和 CKB recipient lock 的固定域消息签名；CKB 脚本验证签名，严格处理低 s/恢复规则和编码。relayer 可以代付但不能改收款地址。

空代码地址不必然有人掌握私钥；只能承诺“有相应授权能力的持有人可以领取”。现有 `ckb-state-proof::Claim` 的单 slot 接口不足以自动完成上述双账户授权，需要明确新 witness 格式和资源资格。

合约持有的 wCKB 不属于某个能由 EOA 签名代表的余额。代理合约、多签、AMM 储备、借贷抵押都不能直接转给部署者。首版无 prover 的直接 ESCAPE 只支持上述 EOA 余额；合约资产的正常退出依靠任意独立 prover 继续运行。

对于宣称具备停机退出保障的应用，必须额外交付固定 code hash 的应用退出适配器：证明冻结状态中的受益权、定义份额与债务结算、保证其分配不超过该合约余额、共享该合约的一次性余额消耗边界，并定义授权。适配器只能在 genesis Policy 中固定，不能冻结后管理员临时指定。未完成适配器验证时，应用合约资产不能纳入“无需 prover 也能退出”的产品承诺；这仍是通用 DeFi 上线的实质限制。

**生产阻断条件：**无适配器的 AMM 储备等合约资产可能因终止冻结而永久不可取，即使随后有人恢复 prover 也不能在该域继续执行。因此本候选 freeze 首先用于隔离实验；面向任意合约资金的生产版本，不能仅靠 UI 风险提示放行。必须完成应用级退出覆盖，或另行验证允许恢复执行且与已领取资产不冲突的方案，再重新决定是否采用 terminal freeze。一般 EVM 执行目标不因本节的受限逃生原型而缩减。

若需让一般 EVM 合约在灾难后继续执行并提现，应另行设计能保留同一领取账本的恢复执行域；不能一边执行任意旧状态，一边允许本节全额余额退出。本提案明确选择 terminal freeze，避免把两种不兼容的恢复模型混在一起。

这个“先冻结状态更新、再按冻结状态退出”的顺序参考 [StarkEx 强制操作设计](https://docs.starkware.co/starkex/spot/shared/forced-operations_overview.html)，但其 vault 模型不能直接证明 Tactus 的任意 EVM 合约可退出。

## 10 升级与经济规则

### 10.1 本代不提供原地升级权限

新实验实例的脚本代码、Policy、guest key 和 wrapper/verifier 身份固定。没有委员会签名可以替换它们。软件优化若保持同一语义与证明权限可更新服务；改变程序身份、wire format 或资产规则则创建新 domain。

用户迁移是从旧域完成正常或支持的应急退出，再自愿存入新域。新域不能消费旧 vault 或使旧领取无效。因为没有强制切换日期，旧规则永久保留，不需要虚构一个当前尚未实现的升级通知计时器。

如果未来需要原地升级，必须另做 CKB 强制 notice/exit window、旧规则长期有效、迁移守恒和拒绝提前激活的协议，并重审 G8；不能由可变 type-id 代码替换绕过此决定。

### 10.2 支付与活性

明确四类成本：L2 gas、CKB 发布/结算费用、永久 DA/checkpoint 容量、prover 计算。原生本金不用于暗中支付后三项。

当前 NativeCKB 是 ERC-20，EVM gas 仍由独立的原生 EVM 余额支付。开发配置使用固定公开 allocation 的测试 gas 和有预算的外部代付；其余额不构成 CKB 兑付权。不得宣称“存入 CKB 就能无条件支付 gas”，也不以测试补贴证明商业成本成立。

0.03–0.05 可由公开预算支付实际 prover，所有角色技术上开放。生产之前须选择并验证可持续收费/领取机制，特别是无效优先消息不扣 EVM gas 时的验签和证明费用。首个实现不通过 builder/prover 许可名单解决补贴滥用；所用补贴和耗尽行为写入运行配置。

## 11 恢复和对外状态

节点从固定 genesis 与规范 CKB 历史重建 lane receipts、snapshots、BatchData、存款 records、checkpoints、Control 和 Vault 领取集合。持久缓存不是权威；每次构造交易前重查当前 outpoints，证明提交前重新确认起点和模式。

恢复必须同时跟踪排序链、结算链和 L1 领取链。结算回退时，已经随 CKB 回退的 payout 也必须撤销，不能只回退 EVM root。冻结回退后恢复到 RUNNING 的情况是 L1 重组恢复，不是协议允许主动解冻。

对外暴露 Received、Soft、Ordered、Settled、Withdrawable、Paid，并独立显示 CKB 确认深度与 RUNNING/FROZEN。PoW 确认是风险策略，不是永久不可逆标记。被正常协议拒绝的输入返回可核对 outcome；API 故障不能伪装成执行失败。

观察者需要能够导出提现 commitment、余额和账户 MPT witness、存款 refund receipt 及 claim nullifier 路径。冻结后路径构建不依赖还在提供服务的官方 RPC。不可变记录的 CKB 容量和历史可获取性纳入节点部署/归档要求；生产 pruning 尚未设计，首版不回收这些记录。

## 12 不变量与失败处理

| ID | 必须成立的不变量 | 破坏后果 |
| --- | --- | --- |
| I01 | 每个 domain 只有一条规范 Anchor/Control/Vault 继承链 | 复制结算或重复资产权限 |
| I02 | accepted 外层输入有确定、可界定资源的执行语义 | 规范历史永久无法证明 |
| I03 | `S <= A`，SETTLE 精确接续当前已结算状态 | 跳批次或替换前序状态 |
| I04 | `d_s <= d_o <= d_v`，存款身份/金额/累积承诺一致 | 无资金 mint 或重复入账 |
| I05 | 已封存义务只能按确定前缀推进；publication != settlement | 用伪完成或遗漏解除用户义务 |
| I06 | `A-S <= B_max`、`d_v-d_s <= D_max` | 积压和资产暴露失去约束 |
| I07 | vault 本金等于三个可领取分区之和，reserve 不动 | 资不抵债或侵占容量 |
| I08 | RUNNING 不退款；FROZEN 不接纳/排序/结算、不解冻 | 退款后再次 credit 或双重余额花费 |
| I09 | 普通/退款/余额 claim 各自去重，普通 nullifier 跨 freeze 保留 | 重复付款 |
| I10 | freeze 只固定当前最后证明状态且有成熟未完成工作 | 随意选择旧状态夺取后续资产 |
| I11 | 所有收款者身份及授权绑定实际 proof/receipt/signature | relayer 改地址或账户冒领 |
| I12 | 所有规则、key、数据政策及身份不可被普通交易修改 | 管理员或提交者绕过证明 |

| 故障/攻击 | 规则与处理 | 未消除的条件 |
| --- | --- | --- |
| 用户消息被漏掉 | APPEND 强制固定前缀，错误发布拒绝 | 用户先成功接纳；无法保证 CKB 纳入时仍可能等候 |
| 抢 lane 或填满队列 | 接纳前拒绝、有限期容量、公开失败和等待数据 | 接纳公平性不能靠本表宣称已解决 |
| prover 停机 | 其他 prover 接手；背压限制新增；成熟 WATCH 可 FREEZE | 需要参与者及 CKB 纳入，无自动计算发生 |
| 持续空证明 | S 必须推进，已接纳义务占固定前缀 | 小步推进可延长时间，非固定墙钟 SLA |
| 未证明存款被局部使用 | freeze 后整个未证明后缀不再结算，按 d_s 分区 | Soft/Ordered 的经济活动承担被放弃风险 |
| SETTLE 与 FREEZE 同时提交 | 争用同一 Control，只有规范赢家有效 | loser 重建；到期不是抢占式优先级 |
| release 与 deposit/其他 claim 竞争 | 争用 Vault，重建 nullifier witness | 初始单 vault 有串行吞吐和公平性限制 |
| MPT witness 缺失 | 从 CKB DA 重放构造；不允许信任 host snapshot | 历史数据可得与恢复成本仍是前提 |
| 相同时间戳区间 | 所有层统一非递减判断，以严格计数防重放 | 应用依赖时间新鲜度需额外规则 |
| 超限、溢出或引擎错误 | 准入硬边界、checked arithmetic、故障停止并告警 | 完整最坏资源资格未通过则不得开放资金 |
| 原运营方停止 | 独立恢复、证明、结算或支持的冻结领取 | 合约持仓没有自动通用逃生 |
| CKB 重组 | 由共同祖先重建所有状态与支付 | 不能保证抵抗任意深度重组 |

## 13 实现和完成标准

具体模块、依赖次序与逐项用例见 [0.02 实施与验收计划](V0_02_IMPLEMENTATION_PLAN.md)。本文完成的是设计交付；0.02 实现完成还要求编码、纯状态转换、真实 CKB 边界和反例验证，0.03 再完成同域真实 proof 和 payout。

不得以缩小用户权利、关闭故障路径或把 OPEN 改成 PASSED 来宣称架构闭环。接纳公平性、合约逃生覆盖、资源标定、经济模型和时间新鲜度都有明确后续门槛；它们不阻止隔离实验，但会限制生产与应用能力声明。
