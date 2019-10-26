use winternitz_ots::wots;

#[test]
fn test (){
    let x = wots::generate_wots();
    let y = x.sign("f7ee6090ba42bddab5899e8e25525922c3279d8563eef37a597f13bcada73df7".to_string());
    let is_right = y.verify();
    assert!(is_right);
}

#[test]
#[should_panic]
fn not_hexadecimal (){
    let x = wots::generate_wots();
    let y = x.sign("f7ux6090ba42bddab5899e8e25525922c3279d8563eef37a597f13bcada73df7".to_string());
    y.verify();
}

#[test]
#[should_panic]
fn too_long_signing (){
    let x = wots::generate_wots();
    let y = x.sign("f7ee6090ba42bddab5899e8e25525922c3279d8563eef37a597f13bcada73df7a0".to_string());
    y.verify();
}