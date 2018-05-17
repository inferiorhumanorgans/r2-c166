macro_rules! test_requires {
    () => {
        use ::instruction::Instruction;
        use ::encoding::Encoding;
        use opformat::OpFormat;
    };
}

macro_rules! test_disasm_op {
    ( $input:expr, $expected:expr ) => {
        let bytes = $input;
        let op = Instruction::from_addr_array(&bytes).unwrap();
        let encoding = Encoding::from_encoding_type(&op.encoding).unwrap();
        let format = OpFormat::from_format_type(&op.format).unwrap();
        let values = (encoding.decode)(&bytes);
        let desc = (format.decode)(&op, values);

        assert_eq!(desc, $expected);
    };
}

test_requires!();

#[test]
fn c166_op_50() {
    test_disasm_op!([0x50, 0x08], "xor r0, r8");
}

#[test]
fn c166_op_58_1() {
    test_disasm_op!([0x58, (0x02 << 4) | (0b10 << 2) | 0x03], "xor r2, [r3]");
}

#[test]
fn c166_op_58_2() {
    test_disasm_op!([0x58, (0x02 << 4) | (0b11 << 2) | 0x03], "xor r2, [r3+]");
}

#[test]
fn c166_op_58_3() {
    test_disasm_op!([0x58, (0x02 << 4) | (0b00 << 2) | 0x03], "xor r2, #03h");
}

#[test]
fn c166_op_56_1() {
    test_disasm_op!([0x56, 0x08, 0x25, 0x42], "xor r8, #4225h");
}

#[test]
fn c166_op_56_2() {
    test_disasm_op!([0x56, 0x0F, 0x25, 0x42], "xor r15, #4225h");
}

#[test]
fn c166_op_52_1() {
    test_disasm_op!([0x52, 0x08, 0x25, 0x42], "xor r8, 4225h");
}

#[test]
fn c166_op_52_2() {
    test_disasm_op!([0x52, 0x0F, 0x25, 0x42], "xor r15, 4225h");
}

#[test]
fn c166_op_54_1() {
    test_disasm_op!([0x54, 0x02, 0x25, 0x42], "xor 4225h, r2");
}

#[test]
fn c166_op_54_2() {
    test_disasm_op!([0x54, 0x05, 0x25, 0x42], "xor 4225h, r5");
}
