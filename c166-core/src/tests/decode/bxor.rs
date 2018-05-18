test_requires!();

#[test]
fn c166_op_7a() {
    test_disasm_op!([0x7A, 0x8F, 0x27, 0x04], "bxor FD4Eh.4, ONES.0");
}
