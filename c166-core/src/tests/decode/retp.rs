test_requires_decode!();

#[test]
fn op_eb() {
    test_disasm_op!([0xEB, 0xF0], "retp r0");
}

#[test]
fn op_eb_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0xEB, addr as u8]);
    }
}
