test_requires!();

#[test]
fn c166_op_9c_1() {
    test_disasm_op!([0x9C, 0x0D], "jmpi cc_UC, [r13]");
}

#[test]
fn c166_op_9c_2() {
    test_disasm_op!([0x9C, 0x5D], "jmpi cc_NV, [r13]");
}
