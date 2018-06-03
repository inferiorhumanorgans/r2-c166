test_requires_decode!();

#[test]
fn op_ec() {
    test_disasm_op!([0xEC, 0xF8], "push r8");
}

#[test]
fn op_ec_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0xEC, addr as u8]);
    }
}
