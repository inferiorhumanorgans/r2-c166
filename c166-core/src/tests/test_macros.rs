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
        let values = (encoding.decode)(&bytes).expect("Instruction was invalid");
        let desc = (format.decode)(&op, values, 0x0000);

        assert_eq!(desc, $expected);
    };
}
