use alloc::{boxed::Box, vec::Vec};
use alloy_primitives::{keccak256, B256, U256};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use tactus_o1_protocol::v02::{
    claim_key, ClaimKind, Config, Control, Deposit, Error, Mode, NullifierProof, Policy, Reader,
    Result, Vault, Wire,
};
use tactus_o1_state_proof_script::{verify, Claim, CLAIM_BYTES, MAX_PROOF_BYTES};

/// No adapter may turn this library's host fixtures into settled roots.
pub struct Context<'a> {
    pub config: &'a Config,
    pub policy: &'a Policy,
    pub control: &'a Control,
    pub control_outpoint: [u8; 36],
    pub vault: &'a Vault,
    /// Resolved from the exact, immutable, same-domain typed CellDep on REFUND.
    pub receipt: Option<([u8; 36], &'a Deposit)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateProof {
    pub claim: Claim,
    pub proof: Vec<u8>,
}
impl StateProof {
    fn validate(&self) -> Result<()> {
        Claim::decode(&self.claim.encode()).map_err(|_| Error::Encoding)?;
        if self.proof.len() > MAX_PROOF_BYTES {
            return Err(Error::Limit);
        }
        Ok(())
    }
    fn bind(&self, control: &Control) -> Result<()> {
        self.validate()?;
        if !control.initialized
            || self.claim.root.0 != control.state_root
            || self.claim.header.0 != control.block_hash
            || self.claim.settled_batches != control.boundary.batches
        {
            return Err(Error::Proof);
        }
        verify(&self.claim, &self.proof).map_err(|_| Error::Proof)
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            claim: Claim::decode(r.take(CLAIM_BYTES)?).map_err(|_| Error::Encoding)?,
            proof: r.blob(MAX_PROOF_BYTES)?.to_vec(),
        })
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.claim.encode());
        put_blob(out, &self.proof);
    }
}
fn put_blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}
fn outpoint(value: &[u8; 36]) -> Result<()> {
    if value[..32] == [0; 32] {
        Err(Error::Identity)
    } else {
        Ok(())
    }
}
fn payout_fields(owner: &[u8; 20], amount: u64, recipient: &[u8; 32]) -> Result<()> {
    if *owner == [0; 20] || amount == 0 || *recipient == [0; 32] {
        Err(Error::Authorization)
    } else {
        Ok(())
    }
}
pub fn bridge_domain(config: &Config) -> B256 {
    keccak256(
        [
            b"TO2BRDG1".as_slice(),
            &config.domain,
            &config.ckb_genesis,
            &U256::from(config.chain).to_be_bytes::<32>(),
            &config.bridge,
        ]
        .concat(),
    )
}
pub fn mapping_slot(key: [u8; 32], slot: u64) -> B256 {
    keccak256([key, U256::from(slot).to_be_bytes::<32>()].concat())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Release {
        id: u64,
        amount: u64,
        recipient: [u8; 32],
        owner: [u8; 20],
        bridge: StateProof,
    },
    Refund {
        receipt_outpoint: [u8; 36],
    },
    Escape {
        owner: [u8; 20],
        amount: u64,
        recipient: [u8; 32],
        signature: [u8; 65],
        bridge: StateProof,
        account: Box<StateProof>,
    },
}
impl Request {
    pub fn kind(&self) -> ClaimKind {
        match self {
            Self::Release { .. } => ClaimKind::Release,
            Self::Refund { .. } => ClaimKind::Refund,
            Self::Escape { .. } => ClaimKind::Escape,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimWitness {
    pub payout: u32,
    pub control_outpoint: [u8; 36],
    pub request: Request,
    pub nullifier: NullifierProof,
}

/// Exact recipient and principal debit. A relayer may supply additional funds
/// to meet occupied capacity; the Vault debit remains exactly `amount`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedPayout {
    pub output: u32,
    pub lock: [u8; 32],
    pub amount: u64,
    pub next: Vault,
}
impl AuthorizedPayout {
    pub fn check_output(
        &self,
        index: u32,
        lock: [u8; 32],
        capacity: u64,
        occupied_capacity: u64,
        has_type: bool,
        data: &[u8],
    ) -> Result<()> {
        if index != self.output
            || lock != self.lock
            || capacity < self.amount
            || capacity < occupied_capacity
            || has_type
            || !data.is_empty()
        {
            return Err(Error::Accounting);
        }
        Ok(())
    }
    pub fn check_vault_capacity(&self, previous: &Vault, input: u64, output: u64) -> Result<()> {
        if input != previous.capacity()?
            || output != self.next.capacity()?
            || input.checked_sub(output) != Some(self.amount)
            || previous.reserve != self.next.reserve
        {
            return Err(Error::Accounting);
        }
        Ok(())
    }
}

pub fn withdrawal_commitment(
    config: &Config,
    id: u64,
    amount: u64,
    recipient: &[u8; 32],
    owner: &[u8; 20],
) -> B256 {
    keccak256(
        [
            b"TO1EXIT1".as_slice(),
            bridge_domain(config).as_slice(),
            &id.to_be_bytes(),
            &amount.to_be_bytes(),
            recipient,
            owner,
        ]
        .concat(),
    )
}

/// EIP-712 hash. `salt` is the full Config commitment; the signed control
/// outpoint is keccak256 of its exact 36-byte CKB serialization.
pub fn escape_digest(
    config: &Config,
    control: &Control,
    control_outpoint: &[u8; 36],
    owner: &[u8; 20],
    amount: u64,
    recipient: &[u8; 32],
) -> Result<[u8; 32]> {
    config.validate()?;
    control.validate()?;
    outpoint(control_outpoint)?;
    if control.mode != Mode::Frozen || control.boundary.config != config.commitment()? {
        return Err(Error::Mode);
    }
    payout_fields(owner, amount, recipient)?;
    let domain = keccak256(
        [
            keccak256(b"EIP712Domain(string name,string version,uint256 chainId,bytes32 salt)").0,
            keccak256(b"Tactus escape").0,
            keccak256(b"0.02").0,
            U256::from(config.chain).to_be_bytes::<32>(),
            config.commitment()?,
        ]
        .concat(),
    );
    let mut address = [0; 32];
    address[12..].copy_from_slice(owner);
    let message = keccak256([
        keccak256(b"Escape(bytes32 controlOutpoint,bytes32 controlCommitment,bytes32 stateRoot,address owner,uint256 amount,bytes32 recipientLock)").0,
        keccak256(control_outpoint).0, control.commitment()?, control.state_root, address,
        U256::from(amount).to_be_bytes::<32>(), *recipient,
    ].concat());
    Ok(keccak256(
        [
            b"\x19\x01".as_slice(),
            domain.as_slice(),
            message.as_slice(),
        ]
        .concat(),
    )
    .0)
}
fn verify_owner(digest: &[u8; 32], owner: &[u8; 20], bytes: &[u8; 65]) -> Result<()> {
    let signature = Signature::from_slice(&bytes[..64]).map_err(|_| Error::Authorization)?;
    if signature.normalize_s().is_some() || bytes[64] > 1 {
        return Err(Error::Authorization);
    }
    let recovery = RecoveryId::from_byte(bytes[64]).ok_or(Error::Authorization)?;
    let public = VerifyingKey::recover_from_prehash(digest, &signature, recovery)
        .map_err(|_| Error::Authorization)?;
    let public = public.to_encoded_point(false);
    if keccak256(&public.as_bytes()[1..])[12..] != *owner {
        return Err(Error::Authorization);
    }
    Ok(())
}
fn bridge_proof(proof: &StateProof, context: &Context<'_>, slot: B256, value: U256) -> Result<()> {
    if !proof.claim.exists
        || proof.claim.address != context.config.bridge
        || proof.claim.code_hash.0 != context.policy.bridge_code_hash
        || proof.claim.nonce != 1
        || proof.claim.slot != slot
        || proof.claim.value != value
    {
        return Err(Error::Proof);
    }
    proof.bind(context.control)
}

impl ClaimWitness {
    /// The Context must be resolved from genuine CKB cells by the adapter.
    /// In particular, a host-provided Control or Deposit is not authority.
    pub fn authorize(&self, context: &Context<'_>) -> Result<AuthorizedPayout> {
        self.validate()?;
        context.control.bind(context.config, context.policy)?;
        context.vault.partitions(context.control)?;
        if self.control_outpoint != context.control_outpoint {
            return Err(Error::Identity);
        }
        let (identity, amount, recipient) = match &self.request {
            Request::Release {
                id,
                amount,
                recipient,
                owner,
                bridge,
            } => {
                bridge_proof(
                    bridge,
                    context,
                    mapping_slot(U256::from(*id).to_be_bytes::<32>(), 7),
                    U256::from_be_bytes(
                        withdrawal_commitment(context.config, *id, *amount, recipient, owner).0,
                    ),
                )?;
                (id.to_le_bytes().to_vec(), *amount, *recipient)
            }
            Request::Refund { receipt_outpoint } => {
                if context.control.mode != Mode::Frozen {
                    return Err(Error::Mode);
                }
                let (source, receipt) = context.receipt.ok_or(Error::Identity)?;
                receipt.validate()?;
                if source != *receipt_outpoint
                    || receipt.config != context.vault.config
                    || receipt.sequence <= context.control.boundary.deposits.count
                    || receipt.sequence > context.vault.deposits.count
                    || receipt.cumulative > context.vault.deposits.cumulative
                {
                    return Err(Error::Authorization);
                }
                (
                    receipt.sequence.to_le_bytes().to_vec(),
                    receipt.amount,
                    receipt.refund_lock,
                )
            }
            Request::Escape {
                owner,
                amount,
                recipient,
                signature,
                bridge,
                account,
            } => {
                if context.control.mode != Mode::Frozen {
                    return Err(Error::Mode);
                }
                let mut key = [0; 32];
                key[12..].copy_from_slice(owner);
                bridge_proof(bridge, context, mapping_slot(key, 3), U256::from(*amount))?;
                if account.claim.address != *owner
                    || account.claim.slot != B256::ZERO
                    || (account.claim.exists && account.claim.code_hash != keccak256([]))
                {
                    return Err(Error::Authorization);
                }
                account.bind(context.control)?;
                verify_owner(
                    &escape_digest(
                        context.config,
                        context.control,
                        &self.control_outpoint,
                        owner,
                        *amount,
                        recipient,
                    )?,
                    owner,
                    signature,
                )?;
                (owner.to_vec(), *amount, *recipient)
            }
        };
        let kind = self.request.kind();
        let key = claim_key(&context.vault.config, kind, &identity)?;
        let root = self.nullifier.insert(
            &context.vault.config,
            kind,
            &key,
            &context.vault.claims[kind as usize],
        )?;
        let next = context
            .vault
            .claim_accounting(context.control, kind, amount, root)?;
        Ok(AuthorizedPayout {
            output: self.payout,
            lock: recipient,
            amount,
            next,
        })
    }
}
impl Wire for ClaimWitness {
    const MAGIC: [u8; 8] = *b"T02CLM01";
    const MAX_BYTES: usize =
        49 + 125 + 2 * (CLAIM_BYTES + 4 + MAX_PROOF_BYTES) + 4 + NullifierProof::MAX_BYTES;
    fn validate(&self) -> Result<()> {
        outpoint(&self.control_outpoint)?;
        if self.payout >= 64 {
            return Err(Error::Limit);
        }
        self.nullifier.validate()?;
        match &self.request {
            Request::Release {
                id,
                amount,
                recipient,
                owner,
                bridge,
            } => {
                if *id == 0 {
                    return Err(Error::Identity);
                }
                payout_fields(owner, *amount, recipient)?;
                bridge.validate()?;
            }
            Request::Refund { receipt_outpoint } => outpoint(receipt_outpoint)?,
            Request::Escape {
                owner,
                amount,
                recipient,
                signature,
                bridge,
                account,
            } => {
                payout_fields(owner, *amount, recipient)?;
                if signature[64] > 1 {
                    return Err(Error::Encoding);
                }
                bridge.validate()?;
                account.validate()?;
            }
        }
        Ok(())
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        out.push(self.request.kind() as u8);
        out.extend_from_slice(&self.payout.to_le_bytes());
        out.extend_from_slice(&self.control_outpoint);
        match &self.request {
            Request::Release {
                id,
                amount,
                recipient,
                owner,
                bridge,
            } => {
                out.extend_from_slice(&id.to_le_bytes());
                out.extend_from_slice(&amount.to_le_bytes());
                out.extend_from_slice(recipient);
                out.extend_from_slice(owner);
                bridge.write(out);
            }
            Request::Refund { receipt_outpoint } => out.extend_from_slice(receipt_outpoint),
            Request::Escape {
                owner,
                amount,
                recipient,
                signature,
                bridge,
                account,
            } => {
                out.extend_from_slice(owner);
                out.extend_from_slice(&amount.to_le_bytes());
                out.extend_from_slice(recipient);
                out.extend_from_slice(signature);
                bridge.write(out);
                account.write(out);
            }
        }
        // validate() has checked count/bitmap agreement; write canonical fields.
        let mut nullifier = NullifierProof::MAGIC.to_vec();
        self.nullifier.write_fields(&mut nullifier);
        put_blob(out, &nullifier);
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        let kind = ClaimKind::try_from(r.u8()?)?;
        let payout = r.u32()?;
        let control_outpoint = r.array()?;
        let request = match kind {
            ClaimKind::Release => Request::Release {
                id: r.u64()?,
                amount: r.u64()?,
                recipient: r.array()?,
                owner: r.array()?,
                bridge: StateProof::read(r)?,
            },
            ClaimKind::Refund => Request::Refund {
                receipt_outpoint: r.array()?,
            },
            ClaimKind::Escape => Request::Escape {
                owner: r.array()?,
                amount: r.u64()?,
                recipient: r.array()?,
                signature: r.array()?,
                bridge: StateProof::read(r)?,
                account: Box::new(StateProof::read(r)?),
            },
        };
        let nullifier = NullifierProof::decode(r.blob(NullifierProof::MAX_BYTES)?)?;
        Ok(Self {
            payout,
            control_outpoint,
            request,
            nullifier,
        })
    }
}
