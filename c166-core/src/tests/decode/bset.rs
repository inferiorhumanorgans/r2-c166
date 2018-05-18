test_requires!();

#[test]
fn c166_op_0f() {
    test_disasm_op!([0x0F, 0xEA], "bset P8.0");
}

#[test]
fn c166_op_1f() {
    test_disasm_op!([0x1F, 0xEA], "bset P8.1");
}

#[test]
fn c166_op_2f() {
    test_disasm_op!([0x2F, 0xEA], "bset P8.2");
}

#[test]
fn c166_op_3f() {
    test_disasm_op!([0x3F, 0xEA], "bset P8.3");
}

#[test]
fn c166_op_4f() {
    test_disasm_op!([0x4F, 0xEA], "bset P8.4");
}

#[test]
fn c166_op_5f() {
    test_disasm_op!([0x5F, 0xEA], "bset P8.5");
}

#[test]
fn c166_op_6f() {
    test_disasm_op!([0x6F, 0xEA], "bset P8.6");
}

#[test]
fn c166_op_7f() {
    test_disasm_op!([0x7F, 0xEA], "bset P8.7");
}
