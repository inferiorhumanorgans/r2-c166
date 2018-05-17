test_requires!();

#[test]
fn c166_op_eb() {
    test_disasm_op!([0xEB, 0xF0], "retp r0");
}
