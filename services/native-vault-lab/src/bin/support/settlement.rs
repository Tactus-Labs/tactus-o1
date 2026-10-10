use super::*;
use tactus_o1_native_proof_journal as journal;
use tactus_o1_native_settlement_script as verify;

pub struct Settlement {
    pub code: [u8; 32],
    pub config: verify::Config,
    pub script: Vec<u8>,
    pub lock: Vec<u8>,
}
impl Settlement {
    pub fn new(lab: &Lab, c: &mut Config, code: [u8; 32]) -> Result<Self, String> {
        if batch::hash(b"", &lab.ordering_elf) != verify::ANCHOR_CODE {
            return Err("unqualified native publisher".into());
        }
        let allocation = genesis::commitment(&allocation(c).allocation_bytes().unwrap()).unwrap();
        let anchor = molecule::script(
            &verify::ANCHOR_CODE,
            2,
            &[c.rollup.as_slice(), &allocation].concat(),
        );
        let config = verify::Config {
            ckb_genesis: c.ckb_genesis,
            anchor_type_hash: batch::hash(b"", &anchor),
            allocation_commitment: allocation,
            vault_identity: c.identity,
        };
        let script = molecule::script(&code, 2, &config.encode());
        c.settlement = batch::hash(b"", &script);
        let lock = molecule::script(&batch::hash(b"", &lab.lock_elf), 2, &c.settlement);
        Ok(Self {
            code,
            config,
            script,
            lock,
        })
    }
    pub fn output(&self, tip: &verify::Tip) -> OutSpec {
        typed(
            self.lock.clone(),
            self.script.clone(),
            tip.encode().to_vec(),
            None,
        )
    }
    pub fn reject(
        &self,
        lab: &mut Lab,
        label: &str,
        tx: &Value,
        code: i8,
        source: &str,
    ) -> Result<(), String> {
        let reason = format!("error code {code}");
        match rpc::send_transaction_json(tx) {
            Err(e) if lab::rejection_matches_at(&e, &reason, &self.code, source) => {
                lab.evidence.push(json!({"label":format!("settlement/{label}"),"result":"rejected","expected_reason":reason,"error":e,"transaction":tx}));
                println!("settlement/{label}: rejected ({reason})");
                Ok(())
            }
            other => Err(format!(
                "settlement/{label}: expected own {source} error {code}, got {other:?}"
            )),
        }
    }
    pub fn genesis_controls(
        &self,
        lab: &mut Lab,
        outputs: &[OutSpec],
        header: [u8; 32],
    ) -> Result<(), String> {
        for (mode, label, code) in [
            (0, "missing joint anchor", 4),
            (1, "wrong vault identity", 6),
            (2, "wrong allocation", 6),
            (3, "wrong network", 6),
            (4, "caller selected guest", 1),
            (5, "initialized genesis", 3),
            (6, "inflated reserve", 10),
            (7, "owner lock", 10),
            (8, "seeded root", 3),
            (9, "duplicate tip", 2),
        ] {
            let mut o = outputs.to_vec();
            match mode {
                0 => o[0].type_script = None,
                1..=3 => {
                    let mut c = self.config.clone();
                    match mode {
                        1 => c.vault_identity[0] ^= 1,
                        2 => c.allocation_commitment[0] ^= 1,
                        _ => c.ckb_genesis[0] ^= 1,
                    };
                    let ty = molecule::script(&self.code, 2, &c.encode());
                    o[3].lock = molecule::script(
                        &batch::hash(b"", &lab.lock_elf),
                        2,
                        &batch::hash(b"", &ty),
                    );
                    o[3].type_script = Some(ty);
                }
                4 => {
                    let mut args = self.config.encode().to_vec();
                    args.extend_from_slice(&[8; 32]);
                    let ty = molecule::script(&self.code, 2, &args);
                    o[3].type_script = Some(ty);
                    o[3].capacity += 32 * 100_000_000;
                }
                5 => o[3].data[8] = 1,
                6 => o[3].capacity += 1,
                7 => o[3].lock = lab.wallets[1].key.lock_script(),
                8 => o[3].data[216] ^= 1,
                _ => o.push(o[3].clone()),
            }
            let tx = build(lab, 0, &[], o, &[], &[header], None)?;
            self.reject(lab, label, &tx, code, "Outputs[3].Type")?;
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn qualify(
        &self,
        lab: &mut Lab,
        result: &mut Value,
        g: &Genesis,
        c: &Config,
        genesis_point: CellOutPoint,
        initial: &verify::Tip,
        anchor_point: CellOutPoint,
        steps: &[Value],
        path: &str,
    ) -> Result<(), String> {
        let point = (genesis_point, self.output(initial).capacity);
        let batches: Vec<Vec<u8>> = steps
            .iter()
            .map(|s| rpc::decode_hex(s["wrapper"].as_str().unwrap()).unwrap())
            .collect();
        let domain = journal::Domain {
            config: c.clone(),
            ordering_type_hash: self.config.anchor_type_hash,
        };
        let allocation = g.allocation_bytes().map_err(|e| e.to_string())?;
        let mut it = batches.iter();
        let j = journal::execute(domain.clone(), &allocation, 0, batches.len() as u64, || {
            it.next().unwrap().clone()
        })
        .map_err(|e| format!("{e:?}"))?;
        let after = verify::Tip {
            initialized: true,
            anchor: j.after.ordering.encode(),
            state_root: j.next_state_root,
            header_hash: j.next_header_hash,
        };
        verify::transition(&self.config, &c.settlement, initial, &after, &j.encode())
            .map_err(|e| format!("structural journal {e}"))?;
        let cp = &result["checkpoints"];
        let latest = lab::point(cp[1]["transaction"].as_str().unwrap(), 2)?;
        let prior = lab::point(cp[0]["transaction"].as_str().unwrap(), 2)?;
        let data = rpc::decode_hex(cp[1]["live"]["cell"]["data"]["content"].as_str().unwrap())?;
        let tx = build(
            lab,
            0,
            &[],
            vec![untyped(
                molecule::script(&batch::hash(b"", &lab.lock_elf), 2, &[]),
                data,
            )],
            &[],
            &[],
            None,
        )?;
        let copied = commit(lab, 0, "settlement/untyped checkpoint copy", &tx)?;
        let copied = lab::point(&copied, 0)?;
        let tx = build(
            lab,
            0,
            &[],
            vec![self.output(initial)],
            &[anchor_point],
            &[],
            None,
        )?;
        self.reject(
            lab,
            "dependency cannot bootstrap",
            &tx,
            4,
            "Outputs[0].Type",
        )?;
        let proof = include_bytes!(
            "../../../../../specs/evidence/sealed-chain-proof/proof/groth16-proof.bin"
        );
        for (mode, label, code) in [
            (0, "missing checkpoint", 8),
            (1, "untyped checkpoint", 8),
            (2, "stale checkpoint", 8),
            (3, "forged endpoint cursor", 8),
            (4, "wrong own identity", 6),
            (5, "wrong profile", 6),
            (6, "wrong output root", 7),
            (7, "inflated tip", 10),
            (8, "tip lock takeover", 10),
            (9, "duplicate successor", 2),
            (10, "malformed witness", 5),
            (11, "v1 proof cannot settle native", 9),
            (12, "destroy tip", 3),
            (13, "nonempty genesis cursor", 7),
        ] {
            let mut public = j.encode();
            let mut o = vec![self.output(&after)];
            let mut deps = vec![latest];
            match mode {
                0 => deps.clear(),
                1 => deps = vec![copied],
                2 => deps = vec![prior],
                3 => public[748] ^= 1,
                4 => public[172] ^= 1,
                5 => public[8] ^= 1,
                6 => o[0].data[216] ^= 1,
                7 => o[0].capacity += 1,
                8 => o[0].lock = lab.wallets[1].key.lock_script(),
                9 => o.push(o[0].clone()),
                12 => o.clear(),
                13 => public[468] ^= 1,
                _ => {}
            }
            let mut witness = b"TO1NSW02".to_vec();
            witness.extend_from_slice(&public);
            witness.extend_from_slice(&(proof.len() as u32).to_le_bytes());
            witness.extend_from_slice(proof);
            if mode == 10 {
                witness.truncate(20);
            }
            let tx = build(lab, 0, &[point], o, &deps, &[], Some(&witness))?;
            self.reject(lab, label, &tx, code, "Inputs[0].Type")?;
        }
        let live = rpc::call(
            "get_live_cell",
            json!([{"tx_hash":hx(&genesis_point.tx_hash),"index":format!("0x{:x}",genesis_point.index)},true]),
        )?;
        if live["status"] != "live" || live["cell"]["data"]["content"] != hx(&initial.encode()) {
            return Err("unproved Tip changed".into());
        }
        result["settlement"] = json!({"script":hx(&self.script),"config":hx(&self.config.encode()),"guest_key":verify::GUEST_KEY,"initial_tip":hx(&initial.encode()),"final_live":live,"tip_point":{"tx_hash":hx(&genesis_point.tx_hash),"index":format!("0x{:x}",genesis_point.index)},"candidate_tip":hx(&after.encode()),"candidate_journal":hx(&j.encode())});
        for prefix in 0..=1 {
            let mut it = batches.iter();
            let expected =
                journal::execute(domain.clone(), &allocation, prefix, 2 - prefix, || {
                    it.next().unwrap().clone()
                })
                .map_err(|e| format!("{e:?}"))?;
            let export = json!({"schema":"native-proof-input-v2","domain_hex":hx(&domain.encode()),"allocation_hex":hx(&allocation),"batches":batches.iter().map(|b|hx(b)).collect::<Vec<_>>(),"prefix_batches":prefix,"expected_journal_hex":hx(&expected.encode()),"guest_verifying_key":verify::GUEST_KEY,"authenticated_publication":false,"source":"actual native joint deployment; authenticate CKB evidence separately"});
            std::fs::write(
                std::path::Path::new(path).with_file_name(format!("proving-input-{prefix}.json")),
                serde_json::to_string_pretty(&export).unwrap() + "\n",
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}
