test_requires!();

#[test]
fn c166_op_a0() {
    test_disasm_op!([0xA0, 0x44], "cmpd1 r4, #04h");
}

#[test]
fn c166_op_a6_1() {
    test_disasm_op!([0xA6, 0xF4, 0x12, 0x34], "cmpd1 r4, #3412h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_a6_2() {
    test_disasm_op!([0xA6, 0xC4, 0x12, 0x34], "invalid");
}

#[test]
fn c166_op_a2_1() {
    test_disasm_op!([0xA2, 0xF4, 0x12, 0x34], "cmpd1 r4, 3412h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_a2_2() {
    test_disasm_op!([0xA2, 0xC4, 0x12, 0x34], "invalid");
}
