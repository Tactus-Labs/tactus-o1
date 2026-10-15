//! Isolated devnet laboratory with two independent signing actors and an
//! append-only transaction evidence log. No production deployment interface.
use crate::{
    molecule, rpc,
    tx::{self, CellOutPoint, DevKey, OutSpec, TX_FEE},
};
use serde_json::{json, Value};
use tactus_o1_ordering_script::{ckb_blake2b, genesis_identity, OrderingHead};

#[derive(Clone)]
pub struct Head {
    pub point: CellOutPoint,
    pub capacity: u64,
    pub state: OrderingHead,
    pub type_script: Vec<u8>,
    pub lock: Vec<u8>,
}

pub struct Wallet {
    pub key: DevKey,
    pub point: CellOutPoint,
    pub capacity: u64,
}

pub struct Lab {
    pub secp: CellOutPoint,
    pub deps: Vec<CellOutPoint>,
    pub wallets: Vec<Wallet>,
    pub ordering_elf: Vec<u8>,
    pub lock_elf: Vec<u8>,
    pub evidence: Vec<Value>,
    pub metadata: Value,
}

pub fn point(hash: &str, index: u32) -> Result<CellOutPoint, String> {
    Ok(CellOutPoint {
        tx_hash: rpc::decode_hex(hash)?
            .try_into()
            .map_err(|_| "hash length")?,
        index,
    })
}

pub fn chain(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut bytes = left.to_vec();
    bytes.extend_from_slice(right);
    ckb_blake2b(&bytes)
}

impl Lab {
    pub fn connect() -> Result<Self, String> {
        Self::connect_with_script("artifacts/tactus_o1_ordering_script.elf")
    }

    /// Deploy a specifically selected experimental type program on the same lab.
    pub fn connect_with_script(script_path: &str) -> Result<Self, String> {
        let consensus = rpc::require_devnet()?;
        let node = rpc::call("local_node_info", json!([]))?;
        let genesis = rpc::get_block_detailed(0)?;
        let secp = tx::find_secp_dep(&genesis)?;
        let ordering_elf = std::fs::read(script_path).map_err(|e| e.to_string())?;
        let lock_elf =
            std::fs::read("artifacts/tactus_o1_head_lock.elf").map_err(|e| e.to_string())?;
        let key = DevKey::dev();
        // Wait for the indexer to reach the current tip before selecting funds.
        let mut funds = Vec::new();
        for _ in 0..100 {
            funds = tx::collect_live_cells(&key.args)?;
            if !funds.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let (fund, capacity) = funds
            .into_iter()
            .max_by_key(|(_, c)| *c)
            .ok_or("no devnet funding cell")?;
        let mut lab = Self {
            secp,
            deps: Vec::new(),
            wallets: vec![Wallet {
                key,
                point: fund,
                capacity,
            }],
            metadata: json!({"consensus":consensus,"node_version":node["version"],
                "ordering_code_hash":rpc::bytes_to_hex(&ckb_blake2b(&ordering_elf)),
                "lock_code_hash":rpc::bytes_to_hex(&ckb_blake2b(&lock_elf)),
                "script_path":script_path,
                "tier":"isolated CKB devnet, deterministic block generation",
                "production_ready":false}),
            ordering_elf,
            lock_elf,
            evidence: Vec::new(),
        };
        let key2 = DevKey::from_seed([0x22; 32]);
        // Immutable code cells: the head lock with empty args always rejects spending.
        let immutable_lock = molecule::script(&ckb_blake2b(&lab.lock_elf), 2, &[]);
        let mut outputs = Vec::new();
        for elf in [&lab.ordering_elf, &lab.lock_elf] {
            outputs.push(OutSpec {
                capacity: OutSpec::required_capacity(&immutable_lock, None, elf.len()),
                lock: immutable_lock.clone(),
                type_script: None,
                data: elf.clone(),
            });
        }
        let code_capacity: u64 = outputs.iter().map(|o| o.capacity).sum();
        let remaining = capacity
            .checked_sub(code_capacity + TX_FEE)
            .ok_or("insufficient funding")?;
        for (key, cap) in [
            (&lab.wallets[0].key, remaining / 2),
            (&key2, remaining - remaining / 2),
        ] {
            outputs.push(OutSpec {
                capacity: cap,
                lock: key.lock_script(),
                type_script: None,
                data: Vec::new(),
            });
        }
        let (_, transaction) = tx::build_and_sign(
            &lab.wallets[0].key,
            &secp,
            &[],
            &[(fund, capacity)],
            &outputs,
            None,
        )?;
        let hash = match lab.commit(
            "deploy immutable code and independent actor funds",
            &transaction,
        ) {
            Ok(hash) => hash,
            Err(error) => {
                let path = std::env::var("TACTUS_EVIDENCE_PATH")
                    .unwrap_or_else(|_| "artifacts/a123-evidence.json".into());
                lab.save(
                    &path,
                    json!({"complete":false,"error":error,"production_ready":false}),
                )?;
                return Err(error);
            }
        };
        lab.deps = vec![point(&hash, 0)?, point(&hash, 1)?];
        lab.wallets[0].point = point(&hash, 2)?;
        lab.wallets[0].capacity = remaining / 2;
        lab.wallets.push(Wallet {
            key: key2,
            point: point(&hash, 3)?,
            capacity: remaining - remaining / 2,
        });
        Ok(lab)
    }

    pub fn commit(&mut self, label: &str, transaction: &Value) -> Result<String, String> {
        let cycles = rpc::call("estimate_cycles", json!([transaction])).ok();
        let (hash, block) = match tx::send_and_wait(transaction, 30) {
            Ok(result) => result,
            Err(error) => {
                self.evidence.push(json!({"label":label,"result":"FAILED","error":error,"transaction":transaction}));
                return Err(error);
            }
        };
        let view = rpc::call("get_transaction", json!([hash]))?;
        let block_hash = view["tx_status"]["block_hash"]
            .as_str()
            .ok_or("commit missing block hash")?;
        let header = rpc::call("get_header", json!([block_hash]))?;
        self.evidence
            .push(json!({"label":label,"result":"committed","hash":hash,
            "block_number":header["number"],"reported_block":block,"block_hash":block_hash,
            "cycles":cycles,"transaction":transaction}));
        println!("{label}: committed {hash}");
        Ok(hash)
    }

    /// Only a consensus/script rejection matching the expected reason counts.
    /// Transport errors and unrelated validation failures abort the experiment.
    pub fn reject(&mut self, label: &str, transaction: &Value, reason: &str) -> Result<(), String> {
        match rpc::send_transaction_json(transaction) {
            Err(error) if rejection_matches(&error, reason, &ckb_blake2b(&self.ordering_elf)) => {
                self.evidence.push(
                    json!({"label":label,"result":"rejected","expected_reason":reason,
                    "error":error,"transaction":transaction}),
                );
                println!("{label}: rejected ({reason})");
                Ok(())
            }
            other => Err(format!("{label}: expected {reason}, got {other:?}")),
        }
    }

    pub fn create_head(&mut self, actor: usize) -> Result<Head, String> {
        let wallet = &self.wallets[actor];
        let seed: [u8; 44] = molecule::cell_input(
            0,
            &molecule::out_point(&wallet.point.tx_hash, wallet.point.index),
        )
        .try_into()
        .unwrap();
        let identity = genesis_identity(&seed, 0);
        let type_script = tx::tactus_o1_type_script(&self.ordering_elf, &identity);
        let lock = molecule::script(&ckb_blake2b(&self.lock_elf), 2, &ckb_blake2b(&type_script));
        let state = OrderingHead {
            rollup_id: identity,
            protocol_version: 1,
            next_batch_number: 0,
            batch_accumulator_root: [0; 32],
            inbox_root: [0; 32],
            inbox_tail: 0,
            processed_inbox_cursor: 0,
            execution_rules_hash: ckb_blake2b(b"experiment-only-no-evm"),
            da_policy_id: ckb_blake2b(b"experiment-only-no-da"),
        };
        let capacity = OutSpec::required_capacity(&lock, Some(&type_script), 188) + 10 * TX_FEE;
        let change = wallet
            .capacity
            .checked_sub(capacity + TX_FEE)
            .ok_or("insufficient head capacity")?;
        let outputs = vec![
            OutSpec {
                capacity,
                lock: lock.clone(),
                type_script: Some(type_script.clone()),
                data: state.to_bytes().to_vec(),
            },
            OutSpec {
                capacity: change,
                lock: wallet.key.lock_script(),
                type_script: None,
                data: Vec::new(),
            },
        ];
        let (_, transaction) = tx::build_and_sign(
            &wallet.key,
            &self.secp,
            &self.deps,
            &[(wallet.point, wallet.capacity)],
            &outputs,
            None,
        )?;
        let hash = self.commit("unique head genesis", &transaction)?;
        self.wallets[actor].point = point(&hash, 1)?;
        self.wallets[actor].capacity = change;
        Ok(Head {
            point: point(&hash, 0)?,
            capacity,
            state,
            type_script,
            lock,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transition_tx(
        &self,
        head: &Head,
        next: OrderingHead,
        commitment: &[u8; 32],
        actor: usize,
        fee: u64,
        refs: &[CellOutPoint],
    ) -> Result<Value, String> {
        let wallet = &self.wallets[actor];
        let change = wallet
            .capacity
            .checked_sub(fee)
            .ok_or("insufficient fee capacity")?;
        let outputs = vec![
            OutSpec {
                capacity: head.capacity,
                lock: head.lock.clone(),
                type_script: Some(head.type_script.clone()),
                data: next.to_bytes().to_vec(),
            },
            OutSpec {
                capacity: change,
                lock: wallet.key.lock_script(),
                type_script: None,
                data: Vec::new(),
            },
        ];
        let mut deps = self.deps.clone();
        deps.extend_from_slice(refs);
        tx::build_with_permissionless_prefix(
            &wallet.key,
            &self.secp,
            &deps,
            &[(head.point, head.capacity), (wallet.point, wallet.capacity)],
            &outputs,
            Some(commitment),
            1,
        )
        .map(|(_, v)| v)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn advance(
        &mut self,
        label: &str,
        head: &mut Head,
        next: OrderingHead,
        commitment: &[u8; 32],
        actor: usize,
        refs: &[CellOutPoint],
    ) -> Result<(), String> {
        let transaction = self.transition_tx(head, next, commitment, actor, TX_FEE, refs)?;
        let hash = self.commit(label, &transaction)?;
        head.point = point(&hash, 0)?;
        head.state = next;
        self.wallets[actor].point = point(&hash, 1)?;
        self.wallets[actor].capacity -= TX_FEE;
        Ok(())
    }

    pub fn publish_cells(
        &mut self,
        label: &str,
        data: &[Vec<u8>],
        actor: usize,
        immutable: bool,
    ) -> Result<Vec<CellOutPoint>, String> {
        let wallet = &self.wallets[actor];
        let lock = if immutable {
            molecule::script(&ckb_blake2b(&self.lock_elf), 2, &[])
        } else {
            wallet.key.lock_script()
        };
        let mut outputs: Vec<OutSpec> = data
            .iter()
            .map(|d| OutSpec {
                capacity: OutSpec::required_capacity(&lock, None, d.len()),
                lock: lock.clone(),
                type_script: None,
                data: d.clone(),
            })
            .collect();
        let total: u64 = outputs.iter().map(|o| o.capacity).sum();
        let change = wallet
            .capacity
            .checked_sub(total + TX_FEE)
            .ok_or("insufficient publishing capacity")?;
        outputs.push(OutSpec {
            capacity: change,
            lock: wallet.key.lock_script(),
            type_script: None,
            data: Vec::new(),
        });
        let (_, transaction) = tx::build_and_sign(
            &wallet.key,
            &self.secp,
            &[],
            &[(wallet.point, wallet.capacity)],
            &outputs,
            None,
        )?;
        let hash = self.commit(label, &transaction)?;
        self.wallets[actor].point = point(&hash, data.len() as u32)?;
        self.wallets[actor].capacity = change;
        (0..data.len()).map(|i| point(&hash, i as u32)).collect()
    }

    /// Build an explicitly shaped transition for negative VM tests. It is
    /// freshly signed after mutation so lock failures cannot mask type failures.
    pub fn shaped_tx(
        &self,
        head: &Head,
        actor: usize,
        mut outputs: Vec<OutSpec>,
        commitment: Option<&[u8]>,
    ) -> Result<Value, String> {
        let wallet = &self.wallets[actor];
        let spent = outputs
            .iter()
            .try_fold(0u64, |s, o| s.checked_add(o.capacity))
            .ok_or("capacity overflow")?;
        let change = wallet
            .capacity
            .checked_add(head.capacity)
            .and_then(|c| c.checked_sub(spent + TX_FEE))
            .ok_or("insufficient capacity")?;
        outputs.push(OutSpec {
            capacity: change,
            lock: wallet.key.lock_script(),
            type_script: None,
            data: Vec::new(),
        });
        tx::build_with_permissionless_prefix(
            &wallet.key,
            &self.secp,
            &self.deps,
            &[(head.point, head.capacity), (wallet.point, wallet.capacity)],
            &outputs,
            commitment,
            1,
        )
        .map(|(_, tx)| tx)
    }

    pub fn attempt(
        &mut self,
        label: &str,
        transaction: &Value,
    ) -> Result<Result<String, String>, String> {
        let result = rpc::send_transaction_json(transaction);
        // Connection errors and script failures indicate a broken harness, never censorship.
        if let Err(error) = &result {
            let code = error
                .strip_prefix("rpc error: ")
                .and_then(|body| serde_json::from_str::<Value>(body).ok())
                .and_then(|v| v["code"].as_i64());
            if !matches!(code, Some(-301 | -1111)) {
                return Err(format!("{label}: unexpected submission failure: {error}"));
            }
        }
        self.evidence.push(
            json!({"label":label,"result":if result.is_ok(){"submitted"}else{"rejected"},
            "hash":result.as_ref().ok(),"error":result.as_ref().err(),"transaction":transaction}),
        );
        Ok(result)
    }

    pub fn record_committed(&mut self, label: &str, hash: &str) -> Result<(), String> {
        let tx = rpc::call("get_transaction", json!([hash]))?;
        if tx["tx_status"]["status"] != "committed" {
            return Err(format!("{label}: not committed"));
        }
        let block_hash = tx["tx_status"]["block_hash"]
            .as_str()
            .ok_or("missing block hash")?;
        let header = rpc::call("get_header", json!([block_hash]))?;
        self.evidence.push(json!({"label":label,"result":"committed","hash":hash,
            "block_hash":block_hash,"block_number":header["number"],"transaction":tx["transaction"]}));
        Ok(())
    }

    pub fn save(&self, path: &str, results: Value) -> Result<(), String> {
        let report = json!({"schema_version":1,"metadata":self.metadata,"results":results,"evidence":self.evidence});
        let bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
        std::fs::write(path, bytes).map_err(|e| e.to_string())
    }
}

pub fn enqueue(head: &Head, message: &[u8; 32]) -> OrderingHead {
    let mut next = head.state;
    next.inbox_tail = next.inbox_tail.checked_add(1).expect("experiment counter");
    next.inbox_root = chain(&next.inbox_root, message);
    next
}
pub fn append(head: &Head, batch: &[u8; 32]) -> OrderingHead {
    let mut next = head.state;
    next.next_batch_number = next
        .next_batch_number
        .checked_add(1)
        .expect("experiment counter");
    next.batch_accumulator_root = chain(&next.batch_accumulator_root, batch);
    next
}

/// Match the named consensus boundary, never a transport error, another script,
/// or a numeric prefix such as code 3 matching code 31.
pub fn rejection_matches(error: &str, reason: &str, ordering_code_hash: &[u8; 32]) -> bool {
    rejection_matches_at(error, reason, ordering_code_hash, "Inputs[0].Type")
        || rejection_matches_at(error, reason, ordering_code_hash, "Outputs[0].Type")
}

pub fn rejection_matches_at(error: &str, reason: &str, code_hash: &[u8; 32], source: &str) -> bool {
    let Some(value) = error
        .strip_prefix("rpc error: ")
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
    else {
        return false;
    };
    if reason == "TransactionFailedToResolve" {
        return value["code"] == -301 && error.contains(reason);
    }
    if reason.starts_with("error code ") {
        return value["code"] == -302
            && error.contains(&format!("{reason} on page "))
            && error.contains(source)
            && error.contains(&rpc::bytes_to_hex(code_hash)[2..]);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejection_evidence_requires_the_exact_type_script_failure() {
        let hash = [42; 32];
        let message = format!(
            "Inputs[0].Type: error code 3 on page /{}",
            rpc::bytes_to_hex(&hash)
        );
        let error = format!("rpc error: {}", json!({"code":-302,"message":message}));
        assert!(rejection_matches(&error, "error code 3", &hash));
        let second = error.replace("Inputs[0]", "Inputs[1]");
        assert!(!rejection_matches(&second, "error code 3", &hash));
        assert!(rejection_matches_at(
            &second,
            "error code 3",
            &hash,
            "Inputs[1].Type"
        ));
        assert!(!rejection_matches_at(
            &second,
            "error code 3",
            &hash,
            "Inputs[0].Type"
        ));
        assert!(!rejection_matches(
            &error.replace("code 3 on", "code 31 on"),
            "error code 3",
            &hash
        ));
        assert!(!rejection_matches(
            &error.replace(".Type", ".Lock"),
            "error code 3",
            &hash
        ));
        assert!(!rejection_matches(&error, "error code 3", &[43; 32]));
        assert!(!rejection_matches(
            "connect: refused",
            "TransactionFailedToResolve",
            &hash
        ));
    }
}
