macro_rules! test_requires_decode {
    () => {
        use std::convert::TryFrom;
        use ::instruction::*;
        use ::encoding::Encoding;
        use opformat::*;
    };
}

macro_rules! test_requires_encode {
    () => {
        use ::parser::*;
    };
}

macro_rules! test_disasm_op {
    ( $input:expr, $expected:expr ) => {
//        eprintln!("crash avoidance");
        let bytes: &[u8] = &$input;
        let op: Instruction = Instruction::try_from(bytes).unwrap();
        let encoding: Encoding = Encoding::from(&op.encoding);
        let values = (encoding.decode)(&op, &bytes).expect("Instruction was invalid");
        let desc: String = format_op(&op, &values, 0x0000 as u32);

        assert_eq!(desc, $expected);
    };
}

macro_rules! test_disasm_op_failure {
    ( $input:expr ) => {
//        eprintln!("crash avoidance");
        let bytes: &[u8] = &$input;
        let op: Instruction = Instruction::try_from(bytes).unwrap();
        let encoding: Encoding = Encoding::from(&op.encoding);
        let values = (encoding.decode)(&op, &bytes);
        assert!(values.is_err());
    };
}

macro_rules! test_disasm_op_no_panic {
    ( $input:expr ) => {
//        eprintln!("crash avoidance");
        let bytes: &[u8] = &$input;
        let op: Instruction = Instruction::try_from(bytes).unwrap();
        let encoding: Encoding = Encoding::from(&op.encoding);
        let values = (encoding.decode)(&op, &bytes);
        assert!(values.is_err() || values.is_ok());
    };
}

macro_rules! test_asm_op {
    ( $input:expr, $expected:expr ) => {
//        eprintln!("crash avoidance");
        let data: &str = concat!($input, "\0");
        let (remainder, asm_ops) = asm_lines(data).unwrap();
        assert_eq!(remainder.len(), 0, "There should be zero bytes remaining from the parser");
        assert_eq!(asm_ops.len(), 1, "There should be exactly one operation");

        let mut op_lut: OpLookUpTable = OpLookUpTable::new();
        build_lut(&mut op_lut);

        let asm_bytes: Vec<u8> = operation_to_bytes(&asm_ops[0], &op_lut).expect("The operation was unable to be encoded");
        let expected_bytes: &[u8] = &$expected;
        assert_eq!(asm_bytes, expected_bytes);
    };
}
