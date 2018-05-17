test_requires!();

#[test]
fn c166_op_6c() {
    test_disasm_op!([0x6C, 0x45], "shr r4, r5");
}

#[test]
fn c166_op_7c() {
    test_disasm_op!([0x7C, 0x45 ], "shr r5, #04h");
}
