test_requires!();

#[test]
fn c166_op_0a() {
    test_disasm_op!([0x0A, 0xB7, 0x80, 0x80], "bfldl S0RIC, #80h, #80h");
}
