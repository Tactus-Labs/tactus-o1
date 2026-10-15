#[allow(dead_code)]
#[path = "../examples/support/native_ckb.rs"]
mod bridge;
use alloy_primitives::{keccak256, Address, Bytes, TxKind, B256, U256};
use bridge::*;
use tactus_o1_execution::{Executor, Status};

#[test]
fn compiler_storage_positions_and_constructor_domain_are_fixed() {
    let artifact = artifact();
    for (index, name) in [
        "totalSupply",
        "cumulativeDeposited",
        "cumulativeWithdrawn",
        "balanceOf",
        "allowance",
        "creditedDeposits",
        "withdrawalCount",
        "withdrawals",
    ]
    .iter()
    .enumerate()
    {
        let item = &artifact["contract"]["storageLayout"]["storage"][index];
        assert_eq!(item["label"], *name);
        assert_eq!(item["slot"], index.to_string());
        assert_eq!(item["offset"], 0);
    }
    let mut engine = Executor::new(&genesis(0)).unwrap();
    let address = user(0).create(0);
    let tx = signed(0, 0, TxKind::Create, creation(BRIDGE), 0);
    let outcome = engine
        .apply_batch(&batch(&engine, tx))
        .unwrap()
        .remove(0)
        .outcomes
        .remove(0);
    assert_eq!(outcome.status, Status::Success);
    assert_eq!(outcome.created_address, Some(address));
    let tx = signed(0, 1, TxKind::Call(address), calldata("DOMAIN()", &[]), 0);
    let block = engine.apply_batch(&batch(&engine, tx)).unwrap().remove(0);
    assert_eq!(
        block.outcomes[0].output.as_ref(),
        domain(address, 31337, BRIDGE).as_slice()
    );
    assert_ne!(
        domain(address, 31337, BRIDGE),
        domain(address, 31338, BRIDGE)
    );
    assert_ne!(
        domain(address, 31337, BRIDGE),
        domain(address, 31337, B256::repeat_byte(9))
    );
    assert_ne!(
        domain(address, 31337, BRIDGE),
        domain(CONTRACT, 31337, BRIDGE)
    );
    let tx = signed(0, 2, TxKind::Create, creation(B256::ZERO), 0);
    assert_eq!(
        engine.apply_batch(&batch(&engine, tx)).unwrap()[0].outcomes[0].status,
        Status::Revert
    );
}

#[test]
fn ordinary_calls_cannot_credit_or_replace_permanent_burns() {
    let mut engine = Executor::new(&genesis(1000)).unwrap();
    assert_eq!(
        call(
            &mut engine,
            0,
            "creditDeposit(bytes32,address,uint64)",
            &[quantity(1), address_word(user(0)), quantity(900)]
        )
        .status,
        Status::Revert
    );
    assert_eq!(balance(&engine, 0), U256::from(1000));
    assert_eq!(
        call(
            &mut engine,
            0,
            "withdraw(uint64,bytes32)",
            &[quantity(300), RECIPIENT]
        )
        .status,
        Status::Success
    );
    assert_eq!(
        storage(&engine, slot(quantity(1), 7)),
        U256::from_be_bytes(claim(1, 300, RECIPIENT, user(0)).0)
    );
    assert_eq!(
        call(
            &mut engine,
            1,
            "withdraw(uint64,bytes32)",
            &[quantity(1), RECIPIENT]
        )
        .status,
        Status::Revert
    );
    for args in [
        [quantity(0), RECIPIENT],
        [quantity(1), B256::ZERO],
        [quantity(701), RECIPIENT],
        [B256::repeat_byte(0xff), RECIPIENT],
    ] {
        assert_eq!(
            call(&mut engine, 0, "withdraw(uint64,bytes32)", &args).status,
            Status::Revert
        );
    }
    assert_eq!(
        call(
            &mut engine,
            0,
            "withdraw(uint64,bytes32)",
            &[quantity(700), RECIPIENT]
        )
        .status,
        Status::Success
    );
    assert_eq!(storage(&engine, U256::from(6)), U256::from(2));
    assert_eq!(
        storage(&engine, slot(quantity(1), 7)),
        U256::from_be_bytes(claim(1, 300, RECIPIENT, user(0)).0)
    );
    assert_eq!(
        storage(&engine, slot(quantity(2), 7)),
        U256::from_be_bytes(claim(2, 700, RECIPIENT, user(0)).0)
    );
    conservation(&engine);
    assert_eq!(balance(&engine, 0), U256::ZERO);
}

#[test]
fn allowance_failure_rolls_back_and_transfers_preserve_supply() {
    let mut engine = Executor::new(&genesis(1000)).unwrap();
    assert_eq!(
        call(
            &mut engine,
            0,
            "approve(address,uint256)",
            &[address_word(user(1)), quantity(1200)]
        )
        .status,
        Status::Success
    );
    let outer = slot(address_word(user(0)), 4);
    let nested = U256::from_be_bytes(
        keccak256([address_word(user(1)).as_slice(), &outer.to_be_bytes::<32>()].concat()).0,
    );
    assert_eq!(
        call(
            &mut engine,
            1,
            "transferFrom(address,address,uint256)",
            &[address_word(user(0)), address_word(user(2)), quantity(1001)]
        )
        .status,
        Status::Revert
    );
    assert_eq!(storage(&engine, nested), U256::from(1200));
    assert_eq!(
        call(
            &mut engine,
            1,
            "transferFrom(address,address,uint256)",
            &[address_word(user(0)), address_word(user(2)), quantity(250)]
        )
        .status,
        Status::Success
    );
    assert_eq!(storage(&engine, nested), U256::from(950));
    assert_eq!(
        call(
            &mut engine,
            2,
            "transfer(address,uint256)",
            &[address_word(user(2)), quantity(200)]
        )
        .status,
        Status::Success
    );
    assert_eq!(balance(&engine, 2), U256::from(250));
    assert_eq!(
        call(
            &mut engine,
            0,
            "transfer(address,uint256)",
            &[address_word(user(1)), quantity(0)]
        )
        .status,
        Status::Success
    );
    for recipient in [Address::ZERO, CONTRACT] {
        assert_eq!(
            call(
                &mut engine,
                0,
                "transfer(address,uint256)",
                &[address_word(recipient), quantity(1)]
            )
            .status,
            Status::Revert
        );
    }
    assert_eq!(
        call(
            &mut engine,
            0,
            "approve(address,uint256)",
            &[address_word(user(1)), B256::repeat_byte(0xff)]
        )
        .status,
        Status::Success
    );
    assert_eq!(
        call(
            &mut engine,
            1,
            "transferFrom(address,address,uint256)",
            &[address_word(user(0)), address_word(user(2)), quantity(1)]
        )
        .status,
        Status::Success
    );
    assert_eq!(storage(&engine, nested), U256::MAX);
    conservation(&engine);
}

#[test]
fn system_credit_contract_logic_requires_authenticated_hook_integration() {
    // This deliberately invokes the VM's system-call API. It does not pretend a
    // zero-sender transaction can be signed or that v1 authenticates a deposit.
    use revm::{
        database::InMemoryDB,
        primitives::hardfork::SpecId,
        state::{AccountInfo, Bytecode},
        Context, DatabaseCommit, MainBuilder, MainContext, SystemCallEvm,
    };
    let mut db = InMemoryDB::default();
    let code = Bytecode::new_legacy(runtime());
    db.insert_account_info(
        CONTRACT,
        AccountInfo::new(U256::ZERO, 1, code.hash_slow(), code),
    );
    {
        let mut invoke = |caller: Address, id: B256, recipient: Address, amount: u64| {
            let input = calldata(
                "creditDeposit(bytes32,address,uint64)",
                &[id, address_word(recipient), quantity(amount)],
            );
            let result = Context::mainnet()
                .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::SHANGHAI))
                .with_db(&mut db)
                .build_mainnet()
                .system_call_with_caller(caller, CONTRACT, input)
                .unwrap();
            let status = result.result.is_success();
            let output = result.result.output().cloned().unwrap_or_else(Bytes::new);
            db.commit(result.state);
            (status, output)
        };
        assert!(!invoke(user(0), quantity(1), user(0), 100).0);
        assert!(!invoke(Address::ZERO, B256::ZERO, user(0), 100).0);
        assert!(!invoke(Address::ZERO, quantity(1), user(0), 0).0);
        assert!(!invoke(Address::ZERO, quantity(1), Address::ZERO, 100).0);
        assert!(!invoke(Address::ZERO, quantity(1), CONTRACT, 100).0);
        assert!(invoke(Address::ZERO, quantity(1), user(0), 100).0);
        assert!(!invoke(Address::ZERO, quantity(1), user(1), 200).0);
        assert!(!invoke(Address::ZERO, quantity(2), user(0), u64::MAX).0);
        assert!(invoke(Address::ZERO, quantity(2), user(1), u64::MAX - 100).0);
    }
    let storage = &db.cache.accounts[&CONTRACT].storage;
    assert_eq!(storage[&U256::ZERO], U256::from(u64::MAX));
    assert_eq!(storage[&U256::from(1)], U256::from(u64::MAX));
    assert_eq!(storage[&slot(address_word(user(0)), 3)], U256::from(100));
    assert_eq!(
        storage[&slot(address_word(user(1)), 3)],
        U256::from(u64::MAX - 100)
    );
    assert_eq!(storage[&slot(quantity(1), 5)], U256::from(1));
}

#[test]
fn bounded_transfer_and_burn_sequence_preserves_independent_accounting_model() {
    let mut engine = Executor::new(&genesis(10_000)).unwrap();
    let mut amounts = [10_000u64, 0, 0];
    let mut burnt = 0u64;
    let mut count = 0u64;
    let mut random = 0xdeadbeefu64;
    for step in 0..128 {
        random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
        let from = (random % 3) as usize;
        let to = ((random >> 8) % 3) as usize;
        let amount = (random >> 16) % 1500;
        let is_burn = step % 4 == 0;
        let expected = if amounts[from] >= amount && (!is_burn || amount > 0) {
            Status::Success
        } else {
            Status::Revert
        };
        let outcome = if is_burn {
            call(
                &mut engine,
                from as u8,
                "withdraw(uint64,bytes32)",
                &[quantity(amount), RECIPIENT],
            )
        } else {
            call(
                &mut engine,
                from as u8,
                "transfer(address,uint256)",
                &[address_word(user(to as u8)), quantity(amount)],
            )
        };
        assert_eq!(outcome.status, expected, "step {step}");
        if expected == Status::Success {
            amounts[from] -= amount;
            if is_burn {
                burnt += amount;
                count += 1;
                assert_eq!(
                    storage(&engine, slot(quantity(count), 7)),
                    U256::from_be_bytes(claim(count, amount, RECIPIENT, user(from as u8)).0)
                );
            } else {
                amounts[to] += amount;
            }
        }
        for (index, amount) in amounts.iter().enumerate() {
            assert_eq!(balance(&engine, index as u8), U256::from(*amount));
        }
        assert_eq!(storage(&engine, U256::from(2)), U256::from(burnt));
        assert_eq!(storage(&engine, U256::from(6)), U256::from(count));
        conservation(&engine);
    }
}

#[test]
fn exhausted_withdrawal_counter_reverts_before_any_persistent_burn() {
    let mut g = genesis(100);
    g.accounts
        .get_mut(&CONTRACT)
        .unwrap()
        .storage
        .insert(U256::from(6), U256::from(u64::MAX));
    let mut engine = Executor::new(&g).unwrap();
    let before = engine.account(CONTRACT).unwrap();
    assert_eq!(
        call(
            &mut engine,
            0,
            "withdraw(uint64,bytes32)",
            &[quantity(1), RECIPIENT]
        )
        .status,
        Status::Revert
    );
    assert_eq!(engine.account(CONTRACT).unwrap(), before);
}
