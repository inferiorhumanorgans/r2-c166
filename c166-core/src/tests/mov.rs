test_requires!();

#[test]
fn c166_op_f0() {
    test_disasm_op!([0xF0, 0x54], "mov r5, r4");
}

#[test]
fn c166_op_e0() {
    test_disasm_op!([0xE0, 0x45], "mov r5, #04h");
}

#[test]
fn c166_op_e6() {
    test_disasm_op!([0xE6, 0x98, 0x24, 0x42], "mov PWMCON0, #4224h");
}

#[test]
fn c166_op_a8() {
    test_disasm_op!([0xA8, 0x54], "mov r5, [r4]");
}

#[test]
fn c166_op_98() {
    test_disasm_op!([0x98, 0x54], "mov r5, [r4+]");
}

#[test]
fn c166_op_b8() {
    test_disasm_op!([0xB8, 0x54], "mov [r4], r5");
}

#[test]
fn c166_op_88() {
    test_disasm_op!([0x88, 0x54], "mov [-r4], r5");
}

#[test]
fn c166_op_c8() {
    test_disasm_op!([0xC8, 0x54], "mov [r5], [r4]");
}

#[test]
fn c166_op_d8() {
    test_disasm_op!([0xD8, 0x54], "mov [r5+], [r4]");
}

#[test]
fn c166_op_e8() {
    test_disasm_op!([0xE8, 0x54], "mov [r5], [r4+]");
}

#[test]
fn c166_op_d4() {
    test_disasm_op!([0xD4, 0x98, 0x24, 0x42], "mov r9, [r8 + #4224h]");
}

#[test]
fn c166_op_c4() {
    test_disasm_op!([0xC4, 0x98, 0x24, 0x42], "mov [r8 + #4224h], r9");
}

#[test]
fn c166_op_84_1() {
    test_disasm_op!([0x84, 0x08, 0x24, 0x42], "mov [r8], 4224h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_84_2() {
    test_disasm_op!([0x84, 0x98, 0x24, 0x42], "invalid");
}

#[test]
fn c166_op_94_1() {
    test_disasm_op!([0x94, 0x08, 0x24, 0x42], "mov 4224h, [r8]");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_94_2() {
    test_disasm_op!([0x94, 0x98, 0x24, 0x42], "invalid");
}

#[test]
fn c166_op_f2() {
    test_disasm_op!([0xF2, 0x98, 0x24, 0x42], "mov PWMCON0, 4224h");
}

#[test]
fn c166_op_f6() {
    test_disasm_op!([0xF6, 0x98, 0x24, 0x42], "mov 4224h, PWMCON0");
}
