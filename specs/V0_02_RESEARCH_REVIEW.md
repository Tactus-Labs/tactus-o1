# Tactus 0.02 研究审查记录

日期：2026 年 10 月 15 日。研究基线为当前工作树中的 0.01 实现和新增路线图。结果是 [协议设计提案](V0_02_PROTOCOL_DESIGN.md) 与 [实施验收计划](V0_02_IMPLEMENTATION_PLAN.md)，没有改动生产代码或部署。

## 1 研究后收敛的决定

| 问题 | 采用的设计 | 不采用的方案及理由 |
| --- | --- | --- |
| 发布和结算是否共用一个高频可变 head | Anchor 与 SettlementControl 分开，checkpoint 连接 | 共同消耗一个 head 会把发布和长耗时证明竞争绑在一起 |
| 如何限制证明积压并执行 freeze | APPEND/DEPOSIT 读取活的 Control，硬边界；freeze 消耗 Control | 仅服务端限流不可约束其他 builder；只看旧不可变证书不能单独保证 freeze 生效 |
| mutable dependencies 是否全部消除 | 移除 live lanes 对 APPEND 的干扰；明确保留 Control 的模式依赖 | 保留安全模式门控有重试代价，不把“没有 lane 依赖”扩大为“没有竞争” |
| 如何强制处理存款 | SEAL 同交易认证 Vault tail，按 snapshot 固定前缀处理 | 任意挑选真实 Receipt 只能证明单条资金来源，不能证明没漏存款 |
| 如何给强制消息可用执行预算 | 每个强制槽固定 gas 上限/保留量 | 原样使用共享剩余 gas，可能把后续有效提现耗成 BlockGas |
| 如何证明一直没有进展 | Control 仅由严格推进的真实 SETTLE 更新；WATCH 也必须成熟 | heartbeat 重置 timer 会让停机退出永远不可达；旧计时器会误伤新请求 |
| 退款后是否可继续原 L2 历史 | 终止冻结，不能恢复同一执行域 | 未证明存款退款后继续 credit，或余额逃生后继续转账，都产生双重权益 |
| 如何处理升级 | 本代 immutable domain，用户主动退出迁移 | 没有实现强制退出窗口时，不能让管理员换 key 再声称用户有退出机会 |
| 如何承诺 DeFi 灾难退出 | 明确 EOA 与应用适配器边界 | EVM root 中合约有钱，不等于能知道应分给哪位最终用户 |

## 2 从当前代码定位出的实质问题

这些是设计输入，尚未在本轮修改代码或跑真实链上的复现用例。

**时间规则不一致。** `crates/tactus-o1-protocol/src/batch.rs::scan_events` 用 `<` 拒绝时间倒退，所以相等时间有效。`proofs/ckb-native-checkpoint/src/lib.rs::advanced` 要求严格 `<`，`proofs/ckb-native-settlement/src/lib.rs::transition` 用 `>=` 拒绝不严格增加的终点。普通 settlement 仅 sparse feature 改为允许相等。单个合法的 equal-time 区间不能假设已能在所有原生边界结算；新 profile 必须统一，不能靠生成器一直递增时间掩盖问题。

**checkpoint 的存在性需要反向约束。** 原生 checkpoint 脚本验证真实 anchor input/output 与完整后态；原生发布 adapter 目前读取并验证 batch/receipts，没有强制查找 checkpoint 输出的路径。新协议必须让发布脚本拒绝“不创建 checkpoint 的 APPEND”。否则“所有存在的 checkpoint 都是真的”不代表“每个最新规范终点都有 checkpoint”。这里是静态代码边界发现，真实节点正负用例列为 V02-33。

**原生发布和 A3 还是两套实验路径。** 当前 standalone native publication 没有保证所有待处理 deposit 被选入，而 A3 snapshot 仅覆盖原始用户消息。新规则需要同一 seal 和同一批次同时绑定两套义务。

**现有释放格式只覆盖已证明 burn。** vault `Release::verify` 认证固定桥 slot 7，使用普通 withdrawal id 的领取树。它没有退款锁、冻结余额授权或多类领取去重。不能复用这条路径直接实现原状态余额提款；新 Receipt 需要 refund lock，新逃生需要 owner 账户证明与签名。

**原生 CKB 与 gas 不是同一账本。** NativeCKB.sol 是 ERC-20 余额，EVM 原生账户余额仍来自执行配置。桥资产设计不能自动解决用户 gas 资金和 prover 费用。设计保留开发 gas 并将生产收费列为明确门槛。

**已有资源常量不是组合交易资格。** 原生 vault 的 typed-input 限制、A3 每操作 cell 上限和原生 940-byte journal 都来自既有组件。把 Vault 纳入 SEAL、增加 Control 与逃生 witness 后，必须重做完整交易的正面资源验收，不能假设所有常量直接兼容。

## 3 有限状态模型

可复现命令：

```sh
python3 scripts/research-v0.02-state-model.py
```

该模型独立于生产 Rust 实现，仅检查新设计的抽象不变量；不连接网络、不运行 CI、不生成证明。

本次执行结果：

| 范围 | 本次覆盖 | 结果 |
| --- | --- | --- |
| 资产分区和 claim 次序 | 两笔 1–3 单位存款、不同已入账前缀、两地址余额与一个聚合 burn，333 种配置、885 种领取顺序、2184 次领取转换 | 守恒、已入账不得退款、重复领取拒绝、完整可领取集合最终耗尽本金 |
| Control/Watch | 55 种时间组合、两种结算/冻结竞争顺序、7 个定向拒绝 | 双计时、严格推进、Control 版本消费和冻结终止符合预期 |
| 背压 | B_max 取 1–4，共 106 种小规模合法 counter 状态 | 新发布受限，已有结算与成熟冻结仍能推进 |
| 封存队列 | 四 lane 各 0–8 条，共 6561 种占用，每种再检查 0–32 存款 | 八批次的四槽前缀覆盖全部已封存项 |
| 优先 gas | 每槽 0/21000/250000 的 81 种组合 | 四个受限强制槽不相互挤占保留上限 |
| 游标基数 | 25 种 sequence/count 组合及首条 lane 消息回归 | lane 从 0 开始、存款从 1 开始，正确区分未完成条件 |

模型同时明确构造并否定四种错误设计：RUNNING 退款后再入账、逃生后恢复旧域、无结算 heartbeat 重置 timer、前一个优先交易耗尽后续 gas。

**范围限制：**模型不证明 CKB 的 CellDep/since/脚本资源实现，不执行 EVM，不验证 MPT 或签名，不生成 SP1 proof，不证明任意历史长度，也不模拟 miner 公平性、合约受益权或费用激励。授权与真实凭据是抽象前提。它只为会计分区、竞态选择和有界调度的设计提供有限证据；生产条件仍 OPEN。

## 4 外部依据与可迁移范围

- [CKB transaction 文档](https://docs.nervos.org/docs/tech-explanation/transaction)：输入消耗和 cell/header 依赖是构造本设计交易边界的基础；Tactus 的唯一对象及跨脚本约束仍需自行实现。
- [CKB since RFC](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0017-tx-valid-since/0017-tx-valid-since.md)：支持以共识规则约束输入花费时间。本提案的双 relative block timeout 和绝对 L2 时间绑定不是 RFC 已提供的 rollup 功能。
- [StarkEx forced operations](https://docs.starkware.co/starkex/spot/shared/forced-operations_overview.html)：强制请求未履行时冻结，冻结后不再更新状态再退出，是可参考的控制顺序。StarkEx 的业务状态与普通 EVM 合约不同，本提案没有据此推导通用 EVM 清算方案。

## 5 交付与剩余工作

设计要求逐项映射见实施计划第 7 节。0.02 研究交付覆盖状态表、权限和身份、排序和强制处理、资源和时间、背压、资金守恒、停滞退出、升级、恢复、费用、故障矩阵，以及 36 个验收场景。

实际实现与测量仍按 WP1–WP8 执行。A3 接纳公平性、合约资产无 prover 退出覆盖、组合资源上限、时间新鲜度、补贴外收费和归档成本均保留明确资格门槛。当前结论是**可以按这套设计开展下一轮有边界的开发与验证**，不是 0.02 已发布、抗审查已解决或资产可以开放托管。

特别是 terminal freeze 对尚无退出适配器的合约持仓可能造成永久锁定，是生产架构阻断项。此研究没有把 EOA 逃生原型冒充完整通用 EVM 逃生方案；通用 DeFi 目标仍要求验证适配器覆盖或安全恢复执行，再决定冻结策略。
