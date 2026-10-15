//! Native custody execution statement. Publication and settlement authority must
//! be authenticated by CKB; a valid execution proof alone does not establish it.
use tactus_o1_execution::{
    native_bridge::{rules_hash, NativeExecutor},
    Genesis,
};
use tactus_o1_protocol::{
    batch, genesis,
    native_bridge::{Anchor, Config, Cursor},
    Hash32,
};

pub const DOMAIN_LEN: usize = 196;
pub const JOURNAL_LEN: usize = 940;
const MAGIC: &[u8; 8] = b"TO1NPR02";
/// Data1 hash of the custody program used by the authenticated native publisher.
pub const VAULT_CODE: Hash32 = [
    0x3b, 0x0c, 0x9f, 0x82, 0xf0, 0x19, 0x40, 0x7a, 0xd1, 0x78, 0x4f, 0xcf, 0x0d, 0x62, 0xfe, 0x69,
    0x5e, 0xba, 0x3c, 0xf2, 0x35, 0xc2, 0xe8, 0xce, 0x47, 0x4a, 0xf5, 0xae, 0xbb, 0xe3, 0x92, 0x37,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Domain,
    Range,
    Allocation,
    Execution,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Domain {
    pub config: Config,
    pub ordering_type_hash: Hash32,
}
impl Domain {
    pub fn encode(&self) -> [u8; DOMAIN_LEN] {
        let mut out = [0; DOMAIN_LEN];
        out[..164].copy_from_slice(&self.config.encode());
        out[164..].copy_from_slice(&self.ordering_type_hash);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != DOMAIN_LEN {
            return Err(Error::Encoding);
        }
        let domain = Self {
            config: Config::decode(&bytes[..164]).map_err(|_| Error::Domain)?,
            ordering_type_hash: bytes[164..].try_into().unwrap(),
        };
        if domain.ordering_type_hash == [0; 32] {
            return Err(Error::Domain);
        }
        Ok(domain)
    }
    pub fn vault_type_hash(&self) -> Hash32 {
        batch::hash(b"", &self.config.vault_script(VAULT_CODE))
    }
}
pub fn profile_id() -> Hash32 {
    batch::hash(b"tactus/o1/native-proof-profile/v2", b"TO1NPR02;full-vault-config;fixed-vault-code;replay-canonical-genesis-prefix;authenticated-publication-required;nonempty-contiguous-interval;native-deposit-cursors;ethereum-state-and-header;ckb-settlement-required")
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub domain: Domain,
    pub allocation_commitment: Hash32,
    pub before: Anchor,
    pub after: Anchor,
    pub previous_state_root: Hash32,
    pub next_state_root: Hash32,
    pub previous_header_hash: Hash32,
    pub next_header_hash: Hash32,
    pub interval_digest: Hash32,
}
impl Journal {
    pub fn encode(&self) -> [u8; JOURNAL_LEN] {
        let mut out = [0; JOURNAL_LEN];
        out[..8].copy_from_slice(MAGIC);
        out[8..40].copy_from_slice(&profile_id());
        out[40..236].copy_from_slice(&self.domain.encode());
        out[236..268].copy_from_slice(&self.allocation_commitment);
        out[268..524].copy_from_slice(&self.before.encode());
        out[524..780].copy_from_slice(&self.after.encode());
        for (i, value) in [
            self.previous_state_root,
            self.next_state_root,
            self.previous_header_hash,
            self.next_header_hash,
            self.interval_digest,
        ]
        .iter()
        .enumerate()
        {
            out[780 + i * 32..812 + i * 32].copy_from_slice(value);
        }
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != JOURNAL_LEN || &bytes[..8] != MAGIC || bytes[8..40] != profile_id() {
            return Err(Error::Encoding);
        }
        let domain = Domain::decode(&bytes[40..236])?;
        let before = Anchor::decode(&bytes[268..524]).map_err(|_| Error::Encoding)?;
        let after = Anchor::decode(&bytes[524..780]).map_err(|_| Error::Encoding)?;
        for anchor in [before, after] {
            if anchor.ordering.rollup_id != domain.config.rollup
                || anchor.ordering.chain_id != domain.config.chain
                || anchor.ordering.execution_rules_hash != rules_hash()
            {
                return Err(Error::Domain);
            }
            if anchor.deposits.count == 0 && anchor.deposits != Cursor::genesis(&domain.config) {
                return Err(Error::Domain);
            }
            if anchor.ordering.next_batch_number == 0 {
                anchor
                    .ordering
                    .validate_genesis()
                    .map_err(|_| Error::Domain)?;
                if anchor.deposits != Cursor::genesis(&domain.config) {
                    return Err(Error::Domain);
                }
            }
        }
        if before.ordering.next_batch_number >= after.ordering.next_batch_number
            || before.ordering.last_block_number >= after.ordering.last_block_number
            || before.ordering.last_timestamp >= after.ordering.last_timestamp
            || before.deposits.count > after.deposits.count
            || before.deposits.cumulative > after.deposits.cumulative
            || (before.deposits.count == after.deposits.count && before.deposits != after.deposits)
            || (before.deposits.count < after.deposits.count
                && before.deposits.cumulative == after.deposits.cumulative)
        {
            return Err(Error::Range);
        }
        Ok(Self {
            domain,
            allocation_commitment: bytes[236..268].try_into().unwrap(),
            before,
            after,
            previous_state_root: bytes[780..812].try_into().unwrap(),
            next_state_root: bytes[812..844].try_into().unwrap(),
            previous_header_hash: bytes[844..876].try_into().unwrap(),
            next_header_hash: bytes[876..908].try_into().unwrap(),
            interval_digest: bytes[908..940].try_into().unwrap(),
        })
    }
}
/// Replay from the committed allocation, including every preceding deposit and
/// user batch. No caller-supplied state snapshot or cursor is trusted. A verifier
/// must match both anchors and the full domain to authenticated CKB state.
pub fn execute(
    domain: Domain,
    allocation: &[u8],
    prefix_batches: u64,
    interval_batches: u64,
    mut next_batch: impl FnMut() -> Vec<u8>,
) -> Result<Journal, Error> {
    Domain::decode(&domain.encode())?;
    if interval_batches == 0 || prefix_batches.checked_add(interval_batches).is_none() {
        return Err(Error::Range);
    }
    let allocation_commitment = genesis::commitment(allocation).map_err(|_| Error::Allocation)?;
    let genesis =
        Genesis::from_allocation(domain.config.rollup.into(), domain.config.chain, allocation)
            .map_err(|_| Error::Allocation)?;
    let mut engine = NativeExecutor::new(&genesis, domain.config.clone(), VAULT_CODE)
        .map_err(|_| Error::Execution)?;
    for _ in 0..prefix_batches {
        engine
            .apply_batch(&next_batch())
            .map_err(|_| Error::Execution)?;
    }
    let before = engine.anchor();
    let previous_state_root = engine.state_root().0;
    let previous_header_hash = engine.head_hash().0;
    let mut interval_digest = batch::hash(
        b"tactus/o1/native-proof-interval/v2",
        &interval_batches.to_le_bytes(),
    );
    for _ in 0..interval_batches {
        let bytes = next_batch();
        engine.apply_batch(&bytes).map_err(|_| Error::Execution)?;
        let mut entry = interval_digest.to_vec();
        entry.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        entry.extend_from_slice(&bytes);
        interval_digest = batch::hash(b"tactus/o1/native-proof-interval-step/v2", &entry);
    }
    let journal = Journal {
        domain,
        allocation_commitment,
        before,
        after: engine.anchor(),
        previous_state_root,
        next_state_root: engine.state_root().0,
        previous_header_hash,
        next_header_hash: engine.head_hash().0,
        interval_digest,
    };
    Journal::decode(&journal.encode())?;
    Ok(journal)
}
