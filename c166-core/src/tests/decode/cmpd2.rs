test_requires!();

#[test]
fn c166_op_b0() {
    test_disasm_op!([0xB0, 0x44], "cmpd2 r4, #04h");
}

#[test]
fn c166_op_b6_1() {
    test_disasm_op!([0xB6, 0xF4, 0x12, 0x34], "cmpd2 r4, #3412h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_b6_2() {
    test_disasm_op!([0xB6, 0xC4, 0x12, 0x34], "invalid");
}

#[test]
fn c166_op_b2_1() {
    test_disasm_op!([0xB2, 0xF4, 0x12, 0x34], "cmpd2 r4, 3412h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_b2_2() {
    test_disasm_op!([0xB2, 0xC4, 0x12, 0x34], "invalid");
}
