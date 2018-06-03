test_requires_decode!();

#[test]
fn op_e2() {
    test_disasm_op!([0xE2, 0x02, 0x08, 0x80], "pcall DPP2, 8008h");
}

#[test]
fn op_e2_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0xE2, addr as u8, 0x25, 0x42]);
    }
}
