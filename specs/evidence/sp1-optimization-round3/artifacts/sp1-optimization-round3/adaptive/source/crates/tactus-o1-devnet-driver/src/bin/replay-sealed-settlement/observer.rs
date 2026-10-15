//! Optional live observer qualification during the existing real P2P experiment.
use serde_json::{json, Value};
use std::{
    fs::File,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tactus_o1_devnet_driver::rpc;

pub struct Probe {
    child: Child,
    address: String,
}
impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Probe {
    pub fn start(chain: &[u8], anchor: &[u8], tip: &[u8]) -> Result<Option<Self>, String> {
        let Some(binary) = std::env::var_os("TACTUS_OBSERVER_RPC_BIN") else {
            return Ok(None);
        };
        let address = "127.0.0.1:18545".to_owned();
        // Fail rather than observe an unrelated service on the expected port.
        drop(std::net::TcpListener::bind(&address).map_err(|e| format!("observer port: {e}"))?);
        let root =
            std::path::PathBuf::from(std::env::var("TACTUS_RUN_DIR").map_err(|_| "run dir")?);
        let config = json!({"listen":address,"ckb_rpc":std::env::var("TACTUS_CKB_RPC_ADDR").map_err(|_|"CKB address")?,"ckb_genesis":rpc::bytes_to_hex(chain),"anchor_type_script":rpc::bytes_to_hex(anchor),"settlement_type_script":rpc::bytes_to_hex(tip),"max_batches":64});
        let path = root.join("observer-config.json");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let log = File::create(root.join("observer.log")).map_err(|e| e.to_string())?;
        let child = Command::new(binary)
            .arg(path)
            .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
            .stderr(Stdio::from(log))
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(Some(Self { child, address }))
    }
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        rpc::call_at(&self.address, method, params)
    }
    pub fn observe(
        &mut self,
        expected: u64,
        orphan: Option<&Value>,
        reject_stale: bool,
    ) -> Result<Value, String> {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut unavailable = 0;
        loop {
            if self.child.try_wait().map_err(|e| e.to_string())?.is_some() {
                return Err("observer exited".into());
            }
            match self.call("eth_blockNumber", json!([])) {
                Ok(number) if number == json!(format!("0x{expected:x}")) => break,
                Ok(_) if reject_stale => {
                    return Err("observer served orphan head after canonical reorg".into())
                }
                Ok(_) => {}
                Err(_) => unavailable += 1,
            }
            if Instant::now() > deadline {
                return Err("observer refresh timeout".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let status = self.call("tactus_getStatus", json!([]))?;
        let block = self.call("eth_getBlockByNumber", json!(["latest", false]))?;
        if status["publishedBatches"] != json!(format!("0x{expected:x}"))
            || status["provedBatches"] != "0x0"
            || block["number"] != json!(format!("0x{expected:x}"))
        {
            return Err("observer prefix differs".into());
        }
        let mut transactions = Vec::new();
        let mut receipts = Vec::new();
        let hashes = orphan
            .map(|v| &v["block"]["transactions"])
            .unwrap_or(&block["transactions"]);
        for hash in hashes.as_array().ok_or("observer transaction hashes")? {
            let transaction = self.call("eth_getTransactionByHash", json!([hash]))?;
            let receipt = self.call("eth_getTransactionReceipt", json!([hash]))?;
            if expected == 8 {
                if !transaction.is_null() || !receipt.is_null() {
                    return Err("observer retained orphan transaction".into());
                }
            } else if transaction["blockHash"] != block["hash"]
                || receipt["blockHash"] != block["hash"]
            {
                return Err("observer transaction block differs".into());
            }
            transactions.push(transaction);
            receipts.push(receipt);
        }
        let orphan_block = if let Some(prior) = orphan {
            self.call("eth_getBlockByHash", json!([prior["block"]["hash"], false]))?
        } else {
            Value::Null
        };
        if expected == 8 && !orphan_block.is_null() {
            return Err("observer retained orphan block".into());
        }
        Ok(
            json!({"expected_batches":expected,"unavailable_poll_count":unavailable,"status":status,"block":block,"transactions":transactions,"receipts":receipts,"prior_block_lookup":orphan_block,"process_id":self.child.id()}),
        )
    }
}
