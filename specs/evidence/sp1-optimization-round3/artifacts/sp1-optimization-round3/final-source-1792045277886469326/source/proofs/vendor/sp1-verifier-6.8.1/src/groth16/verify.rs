use alloc::vec::Vec;
use bn::{pairing_batch, AffineG1, AffineG2, Fr, Gt, G1, G2};

use super::error::Groth16Error;

/// G1 elements of the verification key.
#[derive(Clone, PartialEq)]
pub(crate) struct Groth16G1 {
    pub(crate) alpha: AffineG1,
    pub(crate) k: Vec<AffineG1>,
}

/// G2 elements of the verification key.
#[derive(Clone, PartialEq)]
pub(crate) struct Groth16G2 {
    pub(crate) beta: AffineG2,
    pub(crate) delta: AffineG2,
    pub(crate) gamma: AffineG2,
}

/// Verification key for the Groth16 proof.
#[derive(Clone, PartialEq)]
pub(crate) struct Groth16VerifyingKey {
    pub(crate) g1: Groth16G1,
    pub(crate) g2: Groth16G2,
}

/// Proof for the Groth16 verification.
pub(crate) struct Groth16Proof {
    pub(crate) ar: AffineG1,
    pub(crate) krs: AffineG1,
    pub(crate) bs: AffineG2,
}

/// Prepare the inputs for the Groth16 verification by combining the public inputs with the
/// corresponding elements of the verification key.
fn prepare_inputs(vk: &Groth16VerifyingKey, public_inputs: &[Fr]) -> Result<G1, Groth16Error> {
    if (public_inputs.len() + 1) != vk.g1.k.len() {
        return Err(Groth16Error::PrepareInputsFailed);
    }

    // Keep the accumulator and scalar multiplications in Jacobian coordinates.
    // AffineG1 multiplication normalizes after each addition/doubling, requiring
    // hundreds of field inversions per scalar on CKB's software arithmetic.
    // G1 uses the same group law without those repeated inversions; pairing_batch
    // performs the final normalization. Zero scalars are still skipped.
    Ok(public_inputs.iter().zip(vk.g1.k.iter().skip(1)).fold(
        Into::<G1>::into(vk.g1.k[0]),
        |acc, (i, b)| {
            if *i != Fr::zero() {
                acc + (Into::<G1>::into(*b) * *i)
            } else {
                acc
            }
        },
    ))
}

/// Verify the Groth16 proof using algebraic inputs.
///
/// First, prepare the public inputs by folding them with the verification key.
/// Then, verify the proof by checking the pairing equation.
pub(crate) fn verify_groth16_algebraic(
    vk: &Groth16VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &[Fr],
) -> Result<(), Groth16Error> {
    let prepared_inputs = prepare_inputs(vk, public_inputs)?;

    if pairing_batch(&[
        (-Into::<G1>::into(proof.ar), proof.bs.into()),
        (prepared_inputs, vk.g2.gamma.into()),
        (proof.krs.into(), vk.g2.delta.into()),
        (vk.g1.alpha.into(), -Into::<G2>::into(vk.g2.beta)),
    ]) == Gt::one()
    {
        Ok(())
    } else {
        Err(Groth16Error::ProofVerificationFailed)
    }
}

#[cfg(test)]
mod ckb_tests {
    use super::*;
    use crate::groth16::load_groth16_verifying_key_from_bytes;

    fn affine_reference(vk: &Groth16VerifyingKey, inputs: &[Fr]) -> G1 {
        inputs
            .iter()
            .zip(vk.g1.k.iter().skip(1))
            .fold(vk.g1.k[0], |acc, (i, b)| {
                if *i != Fr::zero() {
                    acc + (*b * *i)
                } else {
                    acc
                }
            })
            .into()
    }

    #[test]
    fn projective_inputs_match_affine_for_release_key_and_scalar_edges() {
        let vk = load_groth16_verifying_key_from_bytes(&crate::GROTH16_VK_BYTES).unwrap();
        let n = vk.g1.k.len() - 1;
        let choices = [
            Fr::zero(),
            Fr::one(),
            -Fr::one(),
            Fr::from_str("2").unwrap(),
            Fr::from_str("18446744073709551616").unwrap(),
        ];
        for value in choices {
            let inputs = alloc::vec![value; n];
            assert!(prepare_inputs(&vk, &inputs).unwrap() == affine_reference(&vk, &inputs));
        }
        for offset in 0..32u64 {
            let inputs: Vec<_> = (0..n)
                .map(|i| {
                    let mut bytes = [0u8; 32];
                    for (j, byte) in bytes.iter_mut().enumerate() {
                        *byte = ((offset * 97 + i as u64 * 53 + j as u64 * 131) % 256) as u8;
                    }
                    bytes[0] &= 0x1f;
                    Fr::from_slice(&bytes).unwrap()
                })
                .collect();
            assert!(prepare_inputs(&vk, &inputs).unwrap() == affine_reference(&vk, &inputs));
        }
        assert!(prepare_inputs(&vk, &[]).is_err());
        assert!(prepare_inputs(&vk, &alloc::vec![Fr::one(); n + 1]).is_err());
    }
}
