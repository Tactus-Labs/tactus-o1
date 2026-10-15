//! CPU-only acceleration for the two BN254 prime fields. External values remain
//! ordinary canonical integers; Montgomery representation never escapes here.
use super::U256;
use ark_ff::{BigInt, Fp256, MontBackend, MontConfig, PrimeField};
use core::convert::TryInto;

#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088696311157297823662689037894645226208583"]
#[generator = "3"]
struct BaseConfig;
type Base = Fp256<MontBackend<BaseConfig, 4>>;

#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[generator = "5"]
struct ScalarConfig;
type Scalar = Fp256<MontBackend<ScalarConfig, 4>>;

fn limbs(value: &U256) -> BigInt<4> {
    BigInt([
        value.0[0] as u64,
        (value.0[0] >> 64) as u64,
        value.0[1] as u64,
        (value.0[1] >> 64) as u64,
    ])
}

fn product<F: PrimeField<BigInt = BigInt<4>>>(a: &U256, b: &U256) -> Option<U256> {
    let a = F::from_bigint(limbs(a))?;
    let b = F::from_bigint(limbs(b))?;
    Some(U256::from((a * b).into_bigint().0))
}

pub(super) fn multiply(a: &U256, b: &U256, modulus: &U256) -> Option<U256> {
    let modulus = limbs(modulus);
    if modulus == Base::MODULUS {
        product::<Base>(a, b)
    } else if modulus == Scalar::MODULUS {
        product::<Scalar>(a, b)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn integer(x: U256) -> BigUint {
        let mut bytes = [0; 32];
        x.to_big_endian(&mut bytes).unwrap();
        BigUint::from_bytes_be(&bytes)
    }

    fn check(a: U256, b: U256, modulus: U256) {
        let expected = (integer(a) * integer(b)) % integer(modulus);
        let mut old = a;
        old.cpu_mul_reference(&b, &modulus);
        let mut new = a;
        new.cpu_mul(&b, &modulus);
        assert_eq!(new, old);
        assert_eq!(integer(new), expected);
    }

    #[test]
    fn canonical_edges_and_noncanonical_fallback_match_two_oracles() {
        for m in [Base::MODULUS, Scalar::MODULUS] {
            let modulus = U256::from(m.0);
            let mut below = modulus;
            below.0[0] -= 1;
            let mut above = modulus;
            above.0[0] += 1;
            let values = [
                U256::from(0),
                U256::from(1),
                U256::from(2),
                below,
                modulus,
                above,
                U256([u128::MAX; 2]),
                U256([1 << 127, 1 << 127]),
            ];
            for a in values {
                for b in values {
                    assert_eq!(
                        multiply(&a, &b, &modulus).is_some(),
                        a < modulus && b < modulus
                    );
                    check(a, b, modulus);
                }
            }
        }
        let modulus = U256::from(97);
        assert!(multiply(&U256::from(12), &U256::from(9), &modulus).is_none());
        check(U256::from(12), U256::from(9), modulus);
    }

    #[test]
    fn seeded_products_match_upstream_and_biguint() {
        let mut seed = 0x435b_f972_18ac_d063u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for modulus in [U256::from(Base::MODULUS.0), U256::from(Scalar::MODULUS.0)] {
            for _ in 0..2048 {
                // Bound the top limb for canonical fast-path operands.
                let a = U256::from([next(), next(), next(), next() & 0x1fff_ffff_ffff_ffff]);
                let b = U256::from([next(), next(), next(), next() & 0x1fff_ffff_ffff_ffff]);
                assert!(multiply(&a, &b, &modulus).is_some());
                check(a, b, modulus);
                check(U256::from([next(), next(), next(), next()]), b, modulus);
            }
        }
    }
}
