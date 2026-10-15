use tactus_o1_protocol::genesis::*;
fn account(address: u8) -> Account {
    let mut balance = [0; 32];
    balance[31] = 1;
    Account {
        address: [address; 20],
        balance,
        nonce: 2,
        code: vec![0x60, 0],
        storage: vec![([3; 32], [4; 32])],
    }
}
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn independent_python_bytes_and_hash_match() {
    let mut lines = include_str!("../../../specs/test-vectors/genesis-v1.txt").lines();
    let bytes = hex(lines.next().unwrap());
    let hash = hex(lines.next().unwrap());
    let a = Allocation {
        accounts: vec![account(1)],
    };
    assert_eq!(a.encode().unwrap(), bytes);
    assert_eq!(Allocation::decode(&bytes).unwrap(), a);
    assert_eq!(commitment(&bytes).unwrap().to_vec(), hash);
}
#[test]
fn every_truncation_suffix_and_bad_magic_is_rejected() {
    let b = Allocation {
        accounts: vec![account(1)],
    }
    .encode()
    .unwrap();
    for i in 0..b.len() {
        assert!(validate(&b[..i]).is_err());
    }
    let mut b = b;
    b.push(0);
    assert_eq!(validate(&b), Err(Error::Encoding));
    b.pop();
    b[0] ^= 1;
    assert_eq!(validate(&b), Err(Error::Encoding));
}
#[test]
fn address_and_storage_order_are_canonical() {
    for accounts in [vec![account(1), account(1)], vec![account(2), account(1)]] {
        assert_eq!(Allocation { accounts }.encode(), Err(Error::Order));
    }
    let mut a = account(1);
    a.storage.push(([3; 32], [5; 32]));
    assert_eq!(Allocation { accounts: vec![a] }.encode(), Err(Error::Order));
}
#[test]
fn zero_storage_empty_accounts_and_supply_overflow_fail() {
    let mut a = account(1);
    a.storage[0].1 = [0; 32];
    assert_eq!(
        Allocation { accounts: vec![a] }.encode(),
        Err(Error::ZeroStorage)
    );
    let mut a = account(1);
    a.balance = [0; 32];
    a.nonce = 0;
    a.code.clear();
    assert_eq!(
        Allocation { accounts: vec![a] }.encode(),
        Err(Error::EmptyAccount)
    );
    let mut a = account(1);
    a.balance[23] = 1;
    assert_eq!(
        Allocation { accounts: vec![a] }.encode(),
        Err(Error::Supply)
    );
    let mut a = account(1);
    a.balance[24..].fill(255);
    assert_eq!(
        Allocation {
            accounts: vec![a, account(2)]
        }
        .encode(),
        Err(Error::Supply)
    );
}
#[test]
fn exact_maximum_allocation_roundtrips_and_limits_reject() {
    let mut accounts = Vec::new();
    for i in 0..11 {
        let mut a = account(i);
        a.storage.clear();
        a.code = vec![0; if i == 10 { 15624 } else { MAX_CODE_BYTES }];
        accounts.push(a);
    }
    let a = Allocation { accounts };
    let bytes = a.encode().unwrap();
    assert_eq!(bytes.len(), MAX_BYTES);
    assert_eq!(Allocation::decode(&bytes).unwrap(), a);
    let mut a = a;
    a.accounts[10].code.push(0);
    assert_eq!(a.encode(), Err(Error::Limit));
    let mut a = account(1);
    a.code = vec![0; MAX_CODE_BYTES + 1];
    assert_eq!(Allocation { accounts: vec![a] }.encode(), Err(Error::Limit));
}
#[test]
fn hostile_counts_are_bounded_before_allocation() {
    let mut bytes = Allocation::default().encode().unwrap();
    bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(Allocation::decode(&bytes), Err(Error::Limit));
    let mut a = account(1);
    a.storage = vec![([0; 32], [1; 32]); MAX_STORAGE_SLOTS + 1];
    assert_eq!(Allocation { accounts: vec![a] }.encode(), Err(Error::Limit));
}
