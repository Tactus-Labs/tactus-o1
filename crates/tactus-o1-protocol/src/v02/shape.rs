//! Exact protocol role combinations. CKB adapters must classify every typed
//! input/output, reject foreign types, and authenticate the bytes behind roles.
use super::{Config, Error, Operation, Result, Role, LANES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoleRef {
    pub role: Role,
    pub index: u64,
}
impl RoleRef {
    pub fn from_args(config: &Config, args: &[u8]) -> Result<Self> {
        if args.len() != 41 || args[..32] != config.domain {
            return Err(Error::Domain);
        }
        Ok(Self {
            role: Role::try_from(args[32])?,
            index: u64::from_le_bytes(args[33..].try_into().map_err(|_| Error::Encoding)?),
        })
    }
    pub fn validate(self, lanes: u8) -> Result<()> {
        match self.role {
            Role::Lane if self.index >= u64::from(lanes) => Err(Error::Identity),
            Role::Anchor
            | Role::Schedule
            | Role::Vault
            | Role::Control
            | Role::Policy
            | Role::Allocation
            | Role::Config
            | Role::Watch
                if self.index != 0 =>
            {
                Err(Error::Identity)
            }
            _ => Ok(()),
        }
    }
}

fn counts(roles: &[RoleRef], lanes: u8) -> Result<[u8; 14]> {
    if roles.len() > 64 {
        return Err(Error::Limit);
    }
    let mut counts = [0; 14];
    for (offset, role) in roles.iter().enumerate() {
        role.validate(lanes)?;
        if roles[..offset].contains(role) {
            return Err(Error::Identity);
        }
        counts[role.role as usize] += 1;
    }
    Ok(counts)
}

/// Untyped funding/payout cells are excluded here and checked separately for
/// exact locks, amounts and occupied capacity. No arbitrary typed cell is exempt.
pub fn check_role_shape(
    operation: Operation,
    inputs: &[RoleRef],
    outputs: &[RoleRef],
    lanes: u8,
) -> Result<()> {
    if lanes == 0 || usize::from(lanes) > LANES {
        return Err(Error::Limit);
    }
    let before = counts(inputs, lanes)?;
    let after = counts(outputs, lanes)?;
    let mut expected_before = [0; 14];
    let mut expected_after = [0; 14];
    let repeated: &[Role] = match operation {
        Operation::Genesis | Operation::Watch | Operation::CloseWatch => &[],
        Operation::Enqueue => &[Role::Lane],
        Operation::Deposit | Operation::Release | Operation::Refund | Operation::Escape => {
            &[Role::Vault]
        }
        Operation::Seal => &[Role::Schedule, Role::Vault],
        Operation::Append => &[Role::Anchor, Role::Schedule],
        Operation::Settle | Operation::Freeze => &[Role::Control],
    };
    for role in repeated {
        expected_before[*role as usize] = 1;
        expected_after[*role as usize] = 1;
    }
    match operation {
        Operation::Genesis => {
            for role in [
                Role::Anchor,
                Role::Schedule,
                Role::Vault,
                Role::Control,
                Role::Policy,
                Role::Allocation,
                Role::Config,
            ] {
                expected_after[role as usize] = 1;
            }
            expected_after[Role::Lane as usize] = lanes;
        }
        Operation::Enqueue => expected_after[Role::AdmissionReceipt as usize] = 1,
        Operation::Deposit => expected_after[Role::DepositReceipt as usize] = 1,
        Operation::Seal => {
            expected_before[Role::Lane as usize] = lanes;
            expected_after[Role::Lane as usize] = lanes;
            expected_after[Role::Snapshot as usize] = 1;
        }
        Operation::Append => {
            expected_after[Role::Batch as usize] = 1;
            expected_after[Role::Checkpoint as usize] = 1;
        }
        Operation::Watch => expected_after[Role::Watch as usize] = 1,
        Operation::CloseWatch | Operation::Freeze => expected_before[Role::Watch as usize] = 1,
        Operation::Settle | Operation::Release | Operation::Refund | Operation::Escape => {}
    }
    if before != expected_before || after != expected_after {
        return Err(Error::Identity);
    }
    // Mutable roles must retain their index, including the one selected lane.
    for role in inputs {
        if repeated.contains(&role.role) && !outputs.contains(role) {
            return Err(Error::Identity);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn r(role: Role, index: u64) -> RoleRef {
        RoleRef { role, index }
    }
    #[test]
    fn publisher_and_enqueue_require_exactly_one_mandatory_record() {
        let inputs = [r(Role::Anchor, 0), r(Role::Schedule, 0)];
        let mut outputs = vec![
            inputs[0],
            inputs[1],
            r(Role::Batch, 1),
            r(Role::Checkpoint, 1),
        ];
        assert!(check_role_shape(Operation::Append, &inputs, &outputs, 4).is_ok());
        outputs.pop();
        assert_eq!(
            check_role_shape(Operation::Append, &inputs, &outputs, 4),
            Err(Error::Identity)
        );
        outputs.extend([r(Role::Checkpoint, 1), r(Role::Checkpoint, 2)]);
        assert_eq!(
            check_role_shape(Operation::Append, &inputs, &outputs, 4),
            Err(Error::Identity)
        );
        let lane = [r(Role::Lane, 1)];
        let correct = [lane[0], r(Role::AdmissionReceipt, 0)];
        assert!(check_role_shape(Operation::Enqueue, &lane, &correct, 4).is_ok());
        assert!(check_role_shape(Operation::Enqueue, &lane, &lane, 4).is_err());
        assert!(check_role_shape(
            Operation::Enqueue,
            &lane,
            &[r(Role::Lane, 2), correct[1]],
            4
        )
        .is_err());
    }
    #[test]
    fn freeze_has_no_anchor_or_vault_contention_and_seal_requires_all_unique_lanes() {
        let inputs = [r(Role::Control, 0), r(Role::Watch, 0)];
        assert!(check_role_shape(Operation::Freeze, &inputs, &inputs[..1], 4).is_ok());
        let mut mixed = inputs.to_vec();
        mixed.push(r(Role::Vault, 0));
        assert!(check_role_shape(Operation::Freeze, &mixed, &inputs[..1], 4).is_err());
        let mut seal = vec![r(Role::Schedule, 0), r(Role::Vault, 0)];
        for index in 0..4 {
            seal.push(r(Role::Lane, index));
        }
        let mut outputs = seal.clone();
        outputs.push(r(Role::Snapshot, 1));
        assert!(check_role_shape(Operation::Seal, &seal, &outputs, 4).is_ok());
        seal[5] = r(Role::Lane, 0);
        assert!(check_role_shape(Operation::Seal, &seal, &outputs, 4).is_err());
        assert!(check_role_shape(
            Operation::Release,
            &[r(Role::Vault, 0)],
            &[r(Role::Vault, 0), r(Role::Control, 0)],
            4
        )
        .is_err());
    }
}
