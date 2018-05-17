test_requires!();

#[test]
fn c166_op_c6() {
    test_disasm_op!([0xC6, 0x08, 0x98, 0xF6], "scxt CP, #F698h");
}

#[test]
fn c166_op_d6() {
    test_disasm_op!([0xD6, 0x08, 0x98, 0xF6], "scxt CP, F698h");
}
