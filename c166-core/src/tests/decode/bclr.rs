test_requires!();

#[test]
fn c166_op_0e() {
    test_disasm_op!([0x0E, 0xEA], "bclr P8.0");
}

#[test]
fn c166_op_1e() {
    test_disasm_op!([0x1E, 0xEA], "bclr P8.1");
}

#[test]
fn c166_op_2e() {
    test_disasm_op!([0x2E, 0xEA], "bclr P8.2");
}

#[test]
fn c166_op_3e() {
    test_disasm_op!([0x3E, 0xEA], "bclr P8.3");
}

#[test]
fn c166_op_4e() {
    test_disasm_op!([0x4E, 0xEA], "bclr P8.4");
}

#[test]
fn c166_op_5e() {
    test_disasm_op!([0x5E, 0xEA], "bclr P8.5");
}

#[test]
fn c166_op_6e() {
    test_disasm_op!([0x6E, 0xEA], "bclr P8.6");
}

#[test]
fn c166_op_7e() {
    test_disasm_op!([0x7E, 0xEA], "bclr P8.7");
}
