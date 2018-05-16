use std::collections::HashMap;
use ::encoding::EncodingValue;
use ::instruction::Instruction;

#[allow(non_camel_case_types)]
pub enum OpFormatType {
    NO_ARGS,
    INDirang2,
    INDpag__INDirang2,
    INDtrap7,
    Rbn,
    Rbn__INDdata4,
    Rbn__Rbm,
    Rbn__DREFRwmINCINDdata16,
    Rbn__DREFRwmINC,
    Rbn__DREFRwm,
    Rwm__INDirang2,
    Rwn,
    Rwn__INDdata16,
    Rwn__INDdata4,
    Rwn__Rbm,
    Rwn__Rwm,
    Rwn__DREFRwmINCINDdata16,
    Rwn__DREFRwmINC,
    Rwn__DREFRwm,
    Rwn__mem,
    DREFDECRwm__Rbn,
    DREFDECRwm__Rwn,
    DREFRwmINCINDdata16__Rbn,
    DREFRwmINCINDdata16__Rwn,
    DREFRwm__Rbn,
    DREFRwm__Rwn,
    DREFRwnINC__DREFRwm,
    DREFRwn__DREFRwmINC,
    DREFRwn__DREFRwm,
    DREFRwn__mem,
    bitaddrQ_q,
    bitaddrQ_q__rel,
    bitaddrZ_z__bitaddrQ_q,
    bitoffQ__INDmask8__INDdata8,
    cc__DREFRwn,
    cc__caddr,
    cc__rel,
    mem__DREFRwn,
    mem__reg,
    reg,
    reg__INDdata16,
    reg__INDdata8,
    reg__caddr,
    reg__mem,
    rel,
    seg__caddr,
    mem__breg,
    breg__mem,
    breg__INDdata8,
    data3_or_reg,
    data3_or_breg,
}

pub struct OpFormat {
    pub name : &'static str,
    pub decode : fn(&Instruction, HashMap<&str, EncodingValue>) -> String,
    pub esil : fn(&Instruction, HashMap<&str, EncodingValue>) -> String,
}

fn get_condition(condition: u32) -> String {
    if condition > <u8>::max_value() as u32 {
        panic!("Condition shouldn't be over 15, but is actually {}", condition);
    }
    match condition {
        0x0 => { String::from("cc_UC") },
        0x1 => { String::from("cc_NET") },
        0x2 => { String::from("cc_Z") },
        0x3 => { String::from("cc_NZ") },
        0x4 => { String::from("cc_V") },
        0x5 => { String::from("cc_NV") },
        0x6 => { String::from("cc_N") },
        0x7 => { String::from("cc_NN") },
        0x8 => { String::from("cc_C") },
        0x9 => { String::from("cc_NC") },
        0xA => { String::from("cc_SGT") },
        0xB => { String::from("cc_SLE") },
        0xC => { String::from("cc_SLT") },
        0xD => { String::from("cc_SGE") },
        0xE => { String::from("cc_UGT") },
        0xF => { String::from("cc_ULE") },
        _   => { format!("{}", condition) }
    }
}

fn get_word_reg_mnem(register: u32) -> String {
    if register > <u8>::max_value() as u32 {
        panic!("Register shouldn't be over 15, but is actually {}", register);
    }

    let reg : u8 = register as u8;
    format!("r{}", reg)
}

fn get_byte_reg_mnem(register: u32) -> String {
    if register > <u8>::max_value() as u32 {
        panic!("Register shouldn't be over 15, but is actually {}", register);
    }

    let reg : u8 = register as u8;

    if (reg & 0b00000001) == 1 {
        format!("rh{}", reg >> 1)
    } else {
        format!("rl{}", reg >> 1)
    }
}

impl OpFormat {
    pub fn from_format_type(format_type: &OpFormatType) -> Result<OpFormat, &'static str> {
        match format_type {
            OpFormatType::NO_ARGS => {
                Ok(OpFormat{
                    name: "NO_ARGS",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::INDirang2 => {
                Ok(OpFormat{
                    name: "INDirang2",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::INDpag__INDirang2 => {
                Ok(OpFormat{
                    name: "INDpag__INDirang2",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::INDtrap7 => {
                Ok(OpFormat{
                    name: "INDtrap7",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rbn => {
                Ok(OpFormat{
                    name: "Rbn",
                    decode: |op, values| {
                        let reg0 = values.get("register0").unwrap().uint_value().expect("integer value");

                        format!("{} {}", op.mnemonic, get_byte_reg_mnem(reg0))
                    },
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rbn__INDdata4 => {
                Ok(OpFormat{
                    name: "Rbn__INDdata4",
                    decode: |op, values| {
                        let reg0 = values.get("register0").unwrap().uint_value().expect("integer value");
                        let data0 = values.get("data0").unwrap().uint_value().expect("integer value");

                        format!("{} {}, #{:02X}h", op.mnemonic, get_byte_reg_mnem(reg0), data0)
                    },
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rbn__Rbm => {
                Ok(OpFormat{
                    name: "Rbn__Rbm",
                    decode: |op, values| {
                        let reg0 = values.get("register0").unwrap().uint_value().expect("integer value");
                        let reg1 = values.get("register1").unwrap().uint_value().expect("integer value");

                        format!("{} {}, {}", op.mnemonic, get_byte_reg_mnem(reg0), get_byte_reg_mnem(reg1))
                    },
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rbn__DREFRwmINCINDdata16 => {
                Ok(OpFormat{
                    name: "Rbn__DREFRwmINCINDdata16",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rbn__DREFRwmINC => {
                Ok(OpFormat{
                    name: "Rbn__DREFRwmINC",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rbn__DREFRwm => {
                Ok(OpFormat{
                    name: "Rbn__DREFRwm",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rwm__INDirang2 => {
                Ok(OpFormat{
                    name: "Rwm__INDirang2",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rwn => {
                Ok(OpFormat{
                    name: "Rwn",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rwn__INDdata16 => {
                Ok(OpFormat{
                    name: "Rwn__INDdata16",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rwn__INDdata4 => {
                Ok(OpFormat{
                    name: "Rwn__INDdata4",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rwn__Rbm => {
                Ok(OpFormat{
                    name: "Rwn__Rbm",
                    decode: |op, values| {
                        let reg0 = values.get("register0").unwrap().uint_value().expect("integer value");
                        let reg1 = values.get("register1").unwrap().uint_value().expect("integer value");

                        format!("{} {}, {}", op.mnemonic, get_word_reg_mnem(reg0), get_byte_reg_mnem(reg1))
                    },
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rwn__Rwm => {
                Ok(OpFormat{
                    name: "Rwn__Rwm",
                    decode: |op, values| {
                        let reg0 = values.get("register0").unwrap().uint_value().expect("integer value");
                        let reg1 = values.get("register1").unwrap().uint_value().expect("integer value");

                        format!("{} {}, {}", op.mnemonic, get_word_reg_mnem(reg0), get_word_reg_mnem(reg1))
                    },
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rwn__DREFRwmINCINDdata16 => {
                Ok(OpFormat{
                    name: "Rwn__DREFRwmINCINDdata16",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rwn__DREFRwmINC => {
                Ok(OpFormat{
                    name: "Rwn__DREFRwmINC",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rwn__DREFRwm => {
                Ok(OpFormat{
                    name: "Rwn__DREFRwm",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::Rwn__mem => {
                Ok(OpFormat{
                    name: "Rwn__mem",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::DREFDECRwm__Rbn => {
                Ok(OpFormat{
                    name: "DREFDECRwm__Rbn",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::DREFDECRwm__Rwn => {
                Ok(OpFormat{
                    name: "DREFDECRwm__Rwn",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::DREFRwmINCINDdata16__Rbn => {
                Ok(OpFormat{
                    name: "DREFRwmINCINDdata16__Rbn",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::DREFRwmINCINDdata16__Rwn => {
                Ok(OpFormat{
                    name: "DREFRwmINCINDdata16__Rwn",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::DREFRwm__Rbn => {
                Ok(OpFormat{
                    name: "DREFRwm__Rbn",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::DREFRwm__Rwn => {
                Ok(OpFormat{
                    name: "DREFRwm__Rwn",
                    decode: |op, values| {
                        let reg0 = values.get("register0").unwrap().uint_value().expect("integer value");
                        let reg1 = values.get("register1").unwrap().uint_value().expect("integer value");

                        format!("{} [{}], {}", op.mnemonic, get_word_reg_mnem(reg1), get_word_reg_mnem(reg0))
                    },
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::DREFRwnINC__DREFRwm => {
                Ok(OpFormat{
                    name: "DREFRwnINC__DREFRwm",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::DREFRwn__DREFRwmINC => {
                Ok(OpFormat{
                    name: "DREFRwn__DREFRwmINC",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::DREFRwn__DREFRwm => {
                Ok(OpFormat{
                    name: "DREFRwn__DREFRwm",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::DREFRwn__mem => {
                Ok(OpFormat{
                    name: "DREFRwn__mem",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::bitaddrQ_q => {
                Ok(OpFormat{
                    name: "bitaddrQ_q",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::bitaddrQ_q__rel => {
                Ok(OpFormat{
                    name: "bitaddrQ_q__rel",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::bitaddrZ_z__bitaddrQ_q => {
                Ok(OpFormat{
                    name: "bitaddrZ_z__bitaddrQ_q",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::bitoffQ__INDmask8__INDdata8 => {
                Ok(OpFormat{
                    name: "bitoffQ__INDmask8__INDdata8",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::cc__DREFRwn => {
                Ok(OpFormat{
                    name: "cc__DREFRwn",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::cc__caddr => {
                Ok(OpFormat{
                    name: "cc__caddr",
                    decode: |op, values| {
                        let condition0 = values.get("condition0").unwrap().uint_value().expect("integer value");
                        let address0 = values.get("address0").unwrap().uint_value().expect("integer value");

                        format!("{} {}, {:04X}h", op.mnemonic, get_condition(condition0), address0)
                    },
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::cc__rel => {
                Ok(OpFormat{
                    name: "cc__rel",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::mem__DREFRwn => {
                Ok(OpFormat{
                    name: "mem__DREFRwn",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::mem__reg => {
                Ok(OpFormat{
                    name: "mem__reg",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::reg => {
                Ok(OpFormat{
                    name: "reg",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::reg__INDdata16 => {
                Ok(OpFormat{
                    name: "reg__INDdata16",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::reg__INDdata8 => {
                Ok(OpFormat{
                    name: "reg__INDdata8",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::reg__caddr => {
                Ok(OpFormat{
                    name: "reg__caddr",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::reg__mem => {
                Ok(OpFormat{
                    name: "reg__mem",
                    decode: |op, values| {
                        let reg0 = values.get("register0").unwrap().uint_value().expect("integer value");
                        let address0 = values.get("address0").unwrap().uint_value().expect("integer value");

                        format!("{} {}, {:04X}h", op.mnemonic, get_word_reg_mnem(reg0), address0)

                    },
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::rel => {
                Ok(OpFormat{
                    name: "rel",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::seg__caddr => {
                Ok(OpFormat{
                    name: "seg__caddr",
                    decode: |op, values| {
                        let segment0 = values.get("segment0").unwrap().uint_value().expect("integer value");
                        let memory0 = values.get("memory0").unwrap().uint_value().expect("integer value");

                        format!("{} {:02X}h, {:04X}h", op.mnemonic, segment0, memory0)
                    },
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::mem__breg => {
                Ok(OpFormat{
                    name: "mem__breg",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::breg__mem => {
                Ok(OpFormat{
                    name: "breg__mem",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::breg__INDdata8 => {
                Ok(OpFormat{
                    name: "breg__INDdata8",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::data3_or_reg => {
                Ok(OpFormat{
                    name: "data3_or_reg",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            OpFormatType::data3_or_breg => {
                Ok(OpFormat{
                    name: "data3_or_breg",
                    decode: |_op, _values| {String::from("")},
                    esil: |_op, _values| {String::from("")},

                })
            },
            _ => {
                Err("Format type not found")
            }
        }
    }
}
