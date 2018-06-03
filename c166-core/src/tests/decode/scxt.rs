test_requires_decode!();

#[test]
fn op_c6() {
    test_disasm_op!([0xC6, 0x08, 0x98, 0xF6], "scxt CP, #F698h");
}

#[test]
fn op_c6_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0xC6, addr as u8, 0x25, 0x42]);
    }
}

#[test]
fn op_d6() {
    test_disasm_op!([0xD6, 0x08, 0x98, 0xF6], "scxt CP, F698h");
}

#[test]
fn op_d6_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0xD6, addr as u8, 0x25, 0x42]);
    }
}
