test_requires_decode!();

#[test]
fn op_fc() {
    test_disasm_op!([0xFC, 0x07], "pop MDL");
}

#[test]
fn op_fc_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0xFC, addr as u8]);
    }
}
