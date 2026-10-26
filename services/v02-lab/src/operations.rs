//! Operational observations never authorize custody or promise transaction inclusion.
use crate::{build::Cell, err, hash32, number, point_json, recover::Recovered, Result};
use ckb_std::ckb_types::{packed, prelude::*};
use serde_json::{json, Value};
use tactus_o1_devnet_driver::{rpc, tx::OutSpec};
use tactus_o1_protocol::v02::*;

/// Optional local operator inputs. These are outside the immutable consensus
/// Config and must never be used as evidence of fees paid or prover availability.
#[derive(Clone, Debug, Default)]
pub struct Monitoring {
    pub fee_lock: Option<[u8; 32]>,
    pub fee_target: Option<u64>,
    pub prover_budget: Option<(u64, u64)>,
}
fn amount(v: &Value) -> Result<u64> {
    let s = v
        .as_str()
        .ok_or("monitor amounts must be decimal strings")?;
    if s.is_empty() || !s.bytes().all(|v| v.is_ascii_digit()) {
        return Err("invalid monitor amount".into());
    }
    s.parse().map_err(err)
}
impl Monitoring {
    pub fn decode(v: &Value) -> Result<Self> {
        if v.is_null() {
            return Ok(Self::default());
        }
        let fields = v.as_object().ok_or("monitor must be an object")?;
        for key in fields.keys() {
            if ![
                "fee_lock_hash",
                "fee_target_shannons",
                "declared_prover_budget_shannons",
                "quoted_proof_cost_shannons",
            ]
            .contains(&key.as_str())
            {
                return Err(format!("unknown monitor field: {key}"));
            }
        }
        let fee_lock = fields.get("fee_lock_hash").map(hash32).transpose()?;
        let fee_target = fields.get("fee_target_shannons").map(amount).transpose()?;
        if fee_lock.is_some() != fee_target.is_some() || fee_target == Some(0) {
            return Err("fee lock and positive target must be provided together".into());
        }
        let budget = fields
            .get("declared_prover_budget_shannons")
            .map(amount)
            .transpose()?;
        let cost = fields
            .get("quoted_proof_cost_shannons")
            .map(amount)
            .transpose()?;
        if budget.is_some() != cost.is_some() || cost == Some(0) {
            return Err("prover budget and positive quoted cost must be provided together".into());
        }
        Ok(Self {
            fee_lock,
            fee_target,
            prover_budget: budget.zip(cost),
        })
    }
    pub fn funding<'a>(&self, cells: impl Iterator<Item = &'a Cell>) -> Result<Value> {
        let fees = if let (Some(lock), Some(target)) = (self.fee_lock, self.fee_target) {
            let mut largest = 0u64;
            let mut sum = 0u128;
            let mut count = 0u64;
            for cell in cells {
                let o = &cell.output;
                // Exclude all protocol/typed assets and data-bearing cells.
                if o.type_script.is_some() || !o.data.is_empty() || hash(b"", &o.lock) != lock {
                    continue;
                }
                let spare = o
                    .capacity
                    .checked_sub(OutSpec::required_capacity(&o.lock, None, 0))
                    .ok_or("fee cell below occupied capacity")?;
                largest = largest.max(spare);
                sum = sum
                    .checked_add(u128::from(spare))
                    .ok_or("fee total overflow")?;
                count += 1;
            }
            json!({"status":if largest>=target{"target_met"}else{"insufficient_for_target"},
                "lock_hash":rpc::bytes_to_hex(&lock),"target_shannons":target.to_string(),"eligible_cells":count,
                "largest_single_cell_spare_shannons":largest.to_string(),"total_spare_shannons":sum.to_string(),
                "basis":"canonical untyped empty-data cells, preserving occupied capacity in each; target is operator supplied",
                "spend_authority_verified":false,"inclusion_guaranteed":false})
        } else {
            json!({"status":"unconfigured"})
        };
        let prover = match self.prover_budget {
            Some((budget, cost)) => {
                json!({"status":if budget>=cost{"declared_budget_meets_quote"}else{"declared_budget_insufficient"},
                "declared_budget_shannons":budget.to_string(),"quoted_cost_shannons":cost.to_string(),"source":"local operator declaration; not observed payment","provider_commitment_verified":false})
            }
            None => json!({"status":"unobserved","provider_commitment_verified":false}),
        };
        Ok(
            json!({"external_fees":fees,"prover":prover,"vault_principal_or_reserve_available_for_fees":false,"liveness_guaranteed":false}),
        )
    }
}
fn watch_status(
    control: &Control,
    watch: &Watch,
    policy: &Policy,
    control_height: u64,
    ticket_height: u64,
    tip: u64,
) -> Result<Value> {
    let earliest = control_height
        .max(ticket_height)
        .checked_add(policy.stall_blocks)
        .ok_or("freeze height overflow")?;
    let candidate = tip.checked_add(1).ok_or("next height overflow")?;
    let pending = watch
        .work
        .pending(&control.boundary, policy.lanes)
        .map_err(err)?;
    let since = (1u64 << 63) | policy.stall_blocks;
    let structurally_eligible = control
        .freeze_candidate(watch, policy, since, since)
        .is_ok();
    Ok(
        json!({"work":format!("{:?}",watch.work),"pending":pending,"ticket_created_height":ticket_height,
        "control_created_height":control_height,"earliest_candidate_height":earliest,
        "eligible_for_next_block":structurally_eligible&&candidate>=earliest,
        "remaining_blocks_before_candidate":earliest.saturating_sub(candidate),
        "close_allowed":watch.close_allowed(control,policy).is_ok(),
        "refund_lock_hash":rpc::bytes_to_hex(&watch.refund_lock),
        "basis":"relative-block maturity at the next candidate height; current live inputs and actual consensus acceptance are still required"}),
    )
}
impl Recovered {
    pub fn operations(&self) -> Result<Value> {
        let config = &self.manifest.config;
        let policy = &self.manifest.policy;
        let tip = number(&self.tip["number"])?;
        let inclusion = crate::lifecycle::InclusionIndex::new(tip, &self.transitions)?;
        let created = |cell: &Cell| inclusion.height(&cell.point.tx_hash);
        let control = self.cell(Role::Control, 0)?;
        let control_height = created(control)?;
        let mut watches = Vec::new();
        let mut lanes = Vec::new();
        for cell in self.cells.values() {
            let Some(ty) = cell.output.type_script.as_ref() else {
                continue;
            };
            let ty = packed::Script::from_slice(ty).map_err(err)?;
            if ty.code_hash().as_slice() != config.adapter_code_hash || ty.hash_type() != 2u8.into()
            {
                continue;
            }
            let Ok(role) = RoleRef::from_args(config, &ty.args().raw_data()) else {
                continue;
            };
            if role.role == Role::Watch {
                let ticket = Watch::decode(&cell.output.data).map_err(err)?;
                let mut status = watch_status(
                    &self.control,
                    &ticket,
                    policy,
                    control_height,
                    created(cell)?,
                    tip,
                )?;
                status["out_point"] = point_json(cell.point);
                status["source_outpoint_hex"] = json!(rpc::bytes_to_hex(&ticket.source));
                watches.push(status);
            } else if role.role == Role::Lane {
                let lane = Lane::decode(&cell.output.data).map_err(err)?;
                let settled = self.control.boundary.processed[usize::from(lane.lane)];
                lanes.push(json!({"lane":lane.lane,"queued_messages":lane.messages.len(),"admitted_count":lane.next,
                    "settled_count":settled,"unsettled_count":lane.next.checked_sub(settled).ok_or("lane boundary inversion")?}));
            }
        }
        lanes.sort_by_key(|v| v["lane"].as_u64());
        let batches = (self.frames.len() as u64)
            .checked_sub(self.control.boundary.batches)
            .ok_or("batch boundary inversion")?;
        let deposits = self
            .vault
            .deposits
            .count
            .checked_sub(self.control.boundary.deposits.count)
            .ok_or("deposit boundary inversion")?;
        Ok(
            json!({"unsettled_batches":batches,"pending_deposits":deposits,
            "batch_limit_reached":batches>=policy.max_pending_batches,"deposit_limit_reached":deposits>=policy.max_pending_deposits,
            "running_mode":self.control.mode==Mode::Running,"control_created_height":control_height,"stall_blocks":policy.stall_blocks,
            "lanes":lanes,"watches":watches,"funding":self.manifest.monitoring.funding(self.cells.values())?,
            "freeze_requires_live_pending_ticket":true,"creating_a_new_ticket_does_not_inherit_control_age":true,"liveness_guaranteed":false}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tactus_o1_devnet_driver::{molecule, tx::CellOutPoint};
    fn fee_cell(capacity: u64, typed: bool, data: Vec<u8>) -> Cell {
        let lock = molecule::script(&[3; 32], 1, &[4; 20]);
        Cell {
            point: CellOutPoint {
                tx_hash: [5; 32],
                index: 0,
            },
            output: OutSpec {
                capacity,
                lock,
                type_script: typed.then(|| vec![1]),
                data,
            },
        }
    }
    #[test]
    fn external_fee_observation_excludes_assets_and_detects_exhaustion() {
        let baseline = fee_cell(0, false, vec![]);
        let occupied = OutSpec::required_capacity(&baseline.output.lock, None, 0);
        let monitoring = Monitoring {
            fee_lock: Some(hash(b"", &baseline.output.lock)),
            fee_target: Some(1000),
            prover_budget: Some((0, 100)),
        };
        let mut cells = vec![
            fee_cell(occupied + 1000, false, vec![]),
            fee_cell(u64::MAX, true, vec![]),
            fee_cell(u64::MAX, false, vec![1]),
        ];
        let initial = monitoring.funding(cells.iter()).unwrap();
        assert_eq!(initial["external_fees"]["status"], "target_met");
        assert_eq!(initial["external_fees"]["eligible_cells"], 1);
        assert_eq!(initial["prover"]["status"], "declared_budget_insufficient");
        cells[0].output.capacity = occupied;
        let drained = monitoring.funding(cells.iter()).unwrap();
        assert_eq!(
            drained["external_fees"]["status"],
            "insufficient_for_target"
        );
        assert_eq!(drained["external_fees"]["total_spare_shannons"], "0");
        assert_eq!(
            drained["vault_principal_or_reserve_available_for_fees"],
            false
        );
        cells[0].output.capacity = occupied + 600;
        cells.push(fee_cell(occupied + 600, false, vec![]));
        let fragmented = monitoring.funding(cells.iter()).unwrap();
        assert_eq!(fragmented["external_fees"]["total_spare_shannons"], "1200");
        assert_eq!(
            fragmented["external_fees"]["status"],
            "insufficient_for_target"
        );
        cells[0].output.capacity = occupied - 1;
        assert!(monitoring.funding(cells.iter()).is_err());
    }
    #[test]
    fn operator_declarations_are_strict_and_do_not_imply_availability() {
        for bad in [
            json!({"fee_lock_hash":rpc::bytes_to_hex(&[1;32])}),
            json!({"fee_target_shannons":"1"}),
            json!({"quoted_proof_cost_shannons":"0","declared_prover_budget_shannons":"1"}),
            json!({"declared_prover_budget_shannons":1,"quoted_proof_cost_shannons":"1"}),
            json!({"typo":"1"}),
        ] {
            assert!(Monitoring::decode(&bad).is_err());
        }
        let m = Monitoring::decode(
            &json!({"declared_prover_budget_shannons":"10","quoted_proof_cost_shannons":"10"}),
        )
        .unwrap();
        let report = m.funding(std::iter::empty()).unwrap();
        assert_eq!(report["external_fees"]["status"], "unconfigured");
        assert_eq!(report["prover"]["status"], "declared_budget_meets_quote");
        assert_eq!(report["prover"]["provider_commitment_verified"], false);
        assert_eq!(report["liveness_guaranteed"], false);
    }
}
