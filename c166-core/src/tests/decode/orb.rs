test_requires!();

#[test]
fn c166_op_71() {
    test_disasm_op!([0x71, 0x38], "orb rh1, rl4");
}

#[test]
fn c166_op_79_1() {
    test_disasm_op!([0x79, (0x08 << 4) | (0b10 << 2) | 0x02], "orb rl4, [r2]");
}

#[test]
fn c166_op_79_2() {
    test_disasm_op!([0x79, (0x08 << 4) | (0b11 << 2) | 0x02], "orb rl4, [r2+]");
}

#[test]
fn c166_op_79_3() {
    test_disasm_op!([0x79, (0x08 << 4) | (0b00 << 2) | 0x02], "orb rl4, #02h");
}

#[test]
fn c166_op_77() {
    test_disasm_op!([0x77, 0x8E, 0x88, 0x55], "orb ZEROS, #88h");
}

#[test]
fn c166_op_73() {
    test_disasm_op!([0x73, 0x8E, 0x88, 0x55], "orb ZEROS, 5588h");
}

#[test]
fn c166_op_75() {
    test_disasm_op!([0x75, 0x8E, 0x88, 0x55], "orb 5588h, ZEROS");
}
