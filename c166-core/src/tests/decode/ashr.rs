test_requires!();

#[test]
fn c166_op_ac() {
    test_disasm_op!([0xAC, 0x34], "ashr r3, r4");
}

#[test]
fn c166_op_bc() {
    test_disasm_op!([0xBC, 0x4F], "ashr r15, #04h");
}
