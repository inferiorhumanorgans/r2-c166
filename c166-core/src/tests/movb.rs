test_requires!();

#[test]
fn c166_op_f1() {
    test_disasm_op!([0xF1, 0x54], "movb rh2, rl2");
}

#[test]
fn c166_op_e1() {
    test_disasm_op!([0xE1, 0x45], "movb rh2, #04h");
}

#[test]
fn c166_op_e7() {
    test_disasm_op!([0xE7, 0x98, 0x24, 0x42], "movb PWMCON0, #24h");
}

#[test]
fn c166_op_a9() {
    test_disasm_op!([0xA9, 0x54], "movb rh2, [r4]");
}

#[test]
fn c166_op_99() {
    test_disasm_op!([0x99, 0x54], "movb rh2, [r4+]");
}

#[test]
fn c166_op_b9() {
    test_disasm_op!([0xB9, 0x54], "movb [r4], rh2");
}

#[test]
fn c166_op_89() {
    test_disasm_op!([0x89, 0x54], "movb [-r4], rh2");
}

#[test]
fn c166_op_c9() {
    test_disasm_op!([0xC9, 0x54], "movb [r5], [r4]");
}

#[test]
fn c166_op_d9() {
    test_disasm_op!([0xD9, 0x54], "movb [r5+], [r4]");
}

#[test]
fn c166_op_e9() {
    test_disasm_op!([0xE9, 0x54], "movb [r5], [r4+]");
}

#[test]
fn c166_op_f4() {
    test_disasm_op!([0xF4, 0x98, 0x24, 0x42], "movb rh4, [r8 + #4224h]");
}

#[test]
fn c166_op_e4() {
    test_disasm_op!([0xE4, 0x98, 0x24, 0x42], "movb [r8 + #4224h], rh4");
}

#[test]
fn c166_op_a4_1() {
    test_disasm_op!([0xA4, 0x08, 0x24, 0x42], "movb [r8], 4224h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_a4_2() {
    test_disasm_op!([0xA4, 0x98, 0x24, 0x42], "invalid");
}

#[test]
fn c166_op_b4_1() {
    test_disasm_op!([0xB4, 0x08, 0x24, 0x42], "movb 4224h, [r8]");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_b4_2() {
    test_disasm_op!([0xB4, 0x98, 0x24, 0x42], "invalid");
}

#[test]
fn c166_op_f3() {
    test_disasm_op!([0xF3, 0x98, 0x24, 0x42], "movb PWMCON0, 4224h");
}

#[test]
fn c166_op_f7() {
    test_disasm_op!([0xF7, 0x98, 0x24, 0x42], "movb 4224h, PWMCON0");
}
