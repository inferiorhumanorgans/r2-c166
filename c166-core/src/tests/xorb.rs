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

mod xorb {
    test_requires!();

    #[test]
    fn c166_op_51() {
        test_disasm_op!([0x51, 0x08], "xorb rl0, rl4");
    }

    #[test]
    fn c166_op_59() {
        test_disasm_op!([0x59, (0x02 << 4) | (0b10 << 2) | 0x03], "xorb rl1, [r3]");
    }

    #[test]
    fn c166_op_57() {
        test_disasm_op!([0x57, 0x08, 0x25, 0x42], "xorb rl4, #25h");
        test_disasm_op!([0x57, 0x0F, 0x25, 0x42], "xorb rh7, #25h");
    }

    #[test]
    fn c166_op_53() {
        test_disasm_op!([0x53, 0x08, 0x25, 0x42], "xorb rl4, 4225h");
        test_disasm_op!([0x53, 0x0F, 0x25, 0x42], "xorb rh7, 4225h");
    }

    #[test]
    fn c166_op_55() {
        test_disasm_op!([0x55, 0x02, 0x25, 0x42], "xorb 4225, rl1");
        test_disasm_op!([0x55, 0x05, 0x25, 0x42], "xorb 4225, rh2");
    }
}
