test_requires_decode!();

#[test]
fn op_71() {
    test_disasm_op!([0x71, 0x38], "orb rh1, rl4");
}

#[test]
fn op_79_1() {
    test_disasm_op!([0x79, (0x08 << 4) | (0b10 << 2) | 0x02], "orb rl4, [r2]");
}

#[test]
fn op_79_2() {
    test_disasm_op!([0x79, (0x08 << 4) | (0b11 << 2) | 0x02], "orb rl4, [r2+]");
}

#[test]
fn op_79_3() {
    test_disasm_op!([0x79, (0x08 << 4) | (0b00 << 2) | 0x02], "orb rl4, #02h");
}

#[test]
fn op_77() {
    test_disasm_op!([0x77, 0x8E, 0x88, 0x55], "orb ZEROS, #88h");
}

#[test]
fn op_77_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x77, addr as u8, 0x25, 0x42]);
    }
}

#[test]
fn op_73() {
    test_disasm_op!([0x73, 0x8E, 0x88, 0x55], "orb ZEROS, 5588h");
}

#[test]
fn op_73_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x73, addr as u8, 0x25, 0x42]);
    }
}

#[test]
fn op_75() {
    test_disasm_op!([0x75, 0x8E, 0x88, 0x55], "orb 5588h, ZEROS");
}

#[test]
fn op_75_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x75, addr as u8, 0x25, 0x42]);
    }
}
