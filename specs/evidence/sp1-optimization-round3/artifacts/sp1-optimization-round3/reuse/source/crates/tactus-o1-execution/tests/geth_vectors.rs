//! Frozen roots from independent Go Ethereum execution, not our own golden output.
use alloy_primitives::{hex, B256};
use serde_json::Value;
use tactus_o1_execution::{Executor, Genesis, Status};

#[test]
fn independent_geth_shanghai_roots_gas_and_rejections_match() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../specs/test-vectors/execution-v1/geth-1.17.8.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["rules_hash"],
        format!("0x{}", hex::encode(tactus_o1_execution::rules_hash()))
    );
    assert_eq!(fixture["geth_version"], "evm version 1.17.8-stable");
    let mut compared = 0;
    for case in fixture["cases"].as_array().unwrap() {
        let genesis: Genesis = serde_json::from_value(case["genesis"].clone()).unwrap();
        let mut engine = Executor::new(&genesis).unwrap();
        let input = hex::decode(case["batch"].as_str().unwrap()).unwrap();
        let blocks = engine.apply_batch(&input).unwrap();
        assert_eq!(blocks.len(), case["geth"].as_array().unwrap().len());
        for (block, oracle) in blocks.iter().zip(case["geth"].as_array().unwrap()) {
            for (actual, key) in [
                (block.header.state_root, "stateRoot"),
                (block.header.transactions_root, "txRoot"),
                (block.header.receipts_root, "receiptsRoot"),
            ] {
                assert_eq!(
                    actual,
                    oracle[key].as_str().unwrap().parse::<B256>().unwrap(),
                    "{} block {} {key}",
                    case["name"],
                    block.header.number
                );
            }
            assert_eq!(
                format!("{}", block.header.logs_bloom),
                oracle["logsBloom"].as_str().unwrap()
            );
            assert_eq!(
                block.header.gas_used,
                u64::from_str_radix(
                    oracle["gasUsed"].as_str().unwrap().trim_start_matches("0x"),
                    16
                )
                .unwrap()
            );
            let expected_rejected = oracle
                .get("rejected")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|item| item["index"].as_u64().unwrap() as usize)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let rejected = block
                .outcomes
                .iter()
                .enumerate()
                .filter(|(_, o)| o.transaction_index.is_none())
                .map(|(i, _)| i)
                .collect::<Vec<_>>();
            assert_eq!(rejected, expected_rejected);
            let outcomes = block
                .outcomes
                .iter()
                .filter(|o| o.transaction_index.is_some())
                .collect::<Vec<_>>();
            let receipts = oracle["receipts"].as_array().unwrap();
            assert_eq!(outcomes.len(), receipts.len());
            for (outcome, receipt) in outcomes.iter().zip(receipts) {
                assert_eq!(
                    outcome.gas_used,
                    u64::from_str_radix(
                        receipt["gasUsed"]
                            .as_str()
                            .unwrap()
                            .trim_start_matches("0x"),
                        16
                    )
                    .unwrap()
                );
                assert_eq!(
                    outcome.status == Status::Success,
                    receipt["status"] == "0x1"
                );
            }
            compared += 1;
        }
    }
    assert_eq!(compared, 14);
}
