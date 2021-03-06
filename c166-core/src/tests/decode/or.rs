test_requires_decode!();

#[test]
fn op_70() {
    test_disasm_op!([0x70, 0x38], "or r3, r8");
}

#[test]
fn op_78_1() {
    test_disasm_op!([0x78, (0x08 << 4) | (0b10 << 2) | 0x02], "or r8, [r2]");
}

#[test]
fn op_78_2() {
    test_disasm_op!([0x78, (0x08 << 4) | (0b11 << 2) | 0x02], "or r8, [r2+]");
}

#[test]
fn op_78_3() {
    test_disasm_op!([0x78, (0x08 << 4) | (0b00 << 2) | 0x02], "or r8, #02h");
}

#[test]
fn op_76() {
    test_disasm_op!([0x76, 0xFE, 0x88, 0x55], "or r14, #5588h");
}

#[test]
fn op_76_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x76, addr as u8, 0x25, 0x42]);
    }
}

#[test]
fn op_72() {
    test_disasm_op!([0x72, 0x8E, 0x88, 0x55], "or ZEROS, 5588h");
}

#[test]
fn op_72_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x72, addr as u8, 0x25, 0x42]);
    }
}

#[test]
fn op_74() {
    test_disasm_op!([0x74, 0x8E, 0x88, 0x55], "or 5588h, ZEROS");
}

#[test]
fn op_74_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x74, addr as u8, 0x25, 0x42]);
    }
}
