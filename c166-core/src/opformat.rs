/*
    This file is part of r2-c166.

    r2-c166 is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    r2-c166 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with r2-c166.  If not, see <http://www.gnu.org/licenses/>.
*/

use ::encoding::{InstructionArguments};
use ::instruction::Instruction;
use ::register::*;

#[allow(non_camel_case_types)]
pub enum OpFormatType {
    NO_ARGS,
    INDirang2,
    ext_page_seg,
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

pub enum InstructionParameter {
    None,
    Address,
    Bit0,
    Bit1,
    BitOff0,
    BitOff1,
    Condition,
    Data,
    IRange,
    Mask,
    Memory,
    Mnemonic,
    Page,
    Register0,
    Register1,
    RelativeAddress,
    Segment,
    SubOp,
    Trap
}

pub enum InstructionParameterType {
    None,
    GeneralRegisterWord,
    GeneralRegisterByte,
    SpecialRegister,
    DirectMemory,
    IndirectMemory,
    BitOffset
}

pub struct OpFormat {
    pub name : &'static str,
    pub decode : fn(&Instruction, &InstructionArguments, u32) -> String,
    pub esil : fn(&Instruction, &InstructionArguments) -> String,
    pub src_param : InstructionParameter,
    pub src_type : InstructionParameterType,
    pub dst_param : InstructionParameter,
    pub dst_type : InstructionParameterType
}

fn get_condition(condition: u8) -> String {
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

fn format_bitoff(offset: u8, is_ext : bool) -> String {
    match offset {
        0x00...0x7F => {
            // RAM
            format!("{:04X}h", 0xFD00 + ((2 * offset) as u16))
        },
        0x80...0xEF => {
            // Special fn registers
            if is_ext == false {
                // SFR
                let address : u16 = 0xFF00 + (2 * (offset & 0b01111111)) as u16;
                match get_sfr_mnem_from_physical(address) {
                    Some(mnem) => format!("{}", mnem),
                    None => format!("{:04X}h", address)
                }
            } else {
                // 'reg' accesses to the ESFR area require a preceding EXT*R instruction to switch the base address
                // not available in the SAB 8XC166(W) devices
                // ESFR
                let address = 0xF100 + ((2 * (offset & 0b01111111)) as u16);
                format!("{:04X}", address)
            }
        },
        0xF0...0xFF => {
            let address = offset & 0b00001111;
            format!("{}", get_word_gpr_mnem(address))
        },
        _ => {
            format!("Invalid bit offset {:X}", offset)
        }
    }
}

impl OpFormat {
    pub fn from_format_type(format_type: &OpFormatType) -> Result<OpFormat, &'static str> {
        match format_type {
            OpFormatType::NO_ARGS => {
                Ok(OpFormat{
                    name: "NO_ARGS",
                    decode: |op, _values, _pc| {
                        format!("{}", op.mnemonic)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None

                })
            },
            OpFormatType::INDirang2 => {
                Ok(OpFormat{
                    name: "INDirang2",
                    decode: |op, values, _pc| {
                        let mnem : &Option<String> = &values.mnemonic;
                        let irange : u8 = values.irange.unwrap();

                        match mnem {
                            Some(v) => {
                                format!("{} #{}", v, irange)
                            },
                            _ => {
                                format!("{:02X} #{}", op.id, irange)
                            }
                        }
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::ext_page_seg => {
                Ok(OpFormat{
                    name: "ext_page_seg",
                    decode: |_op, values, _pc| {
                        let mnem : &String = values.mnemonic.as_ref().unwrap();
                        let irange : u8 = values.irange.unwrap();

                        match mnem.as_str() {
                            "extp" | "extpr" => {
                                let page : u16 = values.page.unwrap();
                                format!("{} #{:04X}h, #{}", mnem, page, irange)
                            },
                            "exts" | "extsr" => {
                                let segment : u8 = values.segment.unwrap();
                                format!("{} #{:02X}h, #{}", mnem, segment, irange)
                            },
                            _ => unreachable!()
                        }
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::INDtrap7 => {
                Ok(OpFormat{
                    name: "INDtrap7",
                    decode: |op, values, _pc| {
                        let trap : u8 = values.trap.unwrap();

                        format!("{} #{:02X}h", op.mnemonic, trap)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::Rbn => {
                Ok(OpFormat{
                    name: "Rbn",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();

                        format!("{} {}", op.mnemonic, get_byte_gpr_mnem(register0))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::Rbn__INDdata4 => {
                Ok(OpFormat{
                    name: "Rbn__INDdata4",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let data : u16 = values.data.unwrap();

                        format!("{} {}, #{:02X}h", op.mnemonic, get_byte_gpr_mnem(register0), data)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None

                })
            },
            OpFormatType::Rbn__Rbm => {
                Ok(OpFormat{
                    name: "Rbn__Rbm",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap() as u8;
                        let register1 : u8 = values.register1.unwrap() as u8;

                        format!("{} {}, {}", op.mnemonic, get_byte_gpr_mnem(register0), get_byte_gpr_mnem(register1))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::Rbn__DREFRwmINCINDdata16 => {
                Ok(OpFormat{
                    name: "Rbn__DREFRwmINCINDdata16",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap() as u8;
                        let register1 : u8 = values.register1.unwrap() as u8;
                        let data : u16 = values.data.unwrap();

                        format!("{} {}, [{} + #{:04X}h]", op.mnemonic, get_byte_gpr_mnem(register0), get_word_gpr_mnem(register1), data)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::Rbn__DREFRwmINC => {
                Ok(OpFormat{
                    name: "Rbn__DREFRwmINC",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap() as u8;
                        let register1 : u8 = values.register1.unwrap() as u8;

                        format!("{} {}, [{}+]", op.mnemonic, get_byte_gpr_mnem(register0), get_word_gpr_mnem(register1))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::Rbn__DREFRwm => {
                Ok(OpFormat{
                    name: "Rbn__DREFRwm",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap() as u8;
                        let register1 : u8 = values.register1.unwrap() as u8;

                        format!("{} {}, [{}]", op.mnemonic, get_byte_gpr_mnem(register0), get_word_gpr_mnem(register1))

                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None

                })
            },
            OpFormatType::Rwm__INDirang2 => {
                Ok(OpFormat{
                    name: "Rwm__INDirang2",
                    decode: |_op, values, _pc| {
                        let mnem : &String = values.mnemonic.as_ref().unwrap();
                        let register1 : u8 = values.register1.unwrap() as u8;
                        let irange : u8 = values.irange.unwrap();

                        format!("{} {}, #{}", mnem, get_word_gpr_mnem(register1), irange)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::Rwn => {
                Ok(OpFormat{
                    name: "Rwn",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();

                        format!("{} {}", op.mnemonic, get_word_gpr_mnem(register0))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::Rwn__INDdata16 => {
                Ok(OpFormat{
                    name: "Rwn__INDdata16",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let data : u16 = values.data.unwrap();

                        format!("{} {}, #{:04X}h", op.mnemonic, get_word_gpr_mnem(register0), data)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::Rwn__INDdata4 => {
                Ok(OpFormat{
                    name: "Rwn__INDdata4",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let data : u16 = values.data.unwrap();

                        format!("{} {}, #{:02X}h", op.mnemonic, get_word_gpr_mnem(register0), data)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::Rwn__Rbm => {
                Ok(OpFormat{
                    name: "Rwn__Rbm",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap() as u8;
                        let register1 : u8 = values.register1.unwrap() as u8;

                        format!("{} {}, {}", op.mnemonic, get_word_gpr_mnem(register0), get_byte_gpr_mnem(register1))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None

                })
            },
            OpFormatType::Rwn__Rwm => {
                Ok(OpFormat{
                    name: "Rwn__Rwm",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap() as u8;
                        let register1 : u8 = values.register1.unwrap() as u8;

                        format!("{} {}, {}", op.mnemonic, get_word_gpr_mnem(register0), get_word_gpr_mnem(register1))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::Rwn__DREFRwmINCINDdata16 => {
                Ok(OpFormat{
                    name: "Rwn__DREFRwmINCINDdata16",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap() as u8;
                        let register1 : u8 = values.register1.unwrap() as u8;
                        let data : u16 = values.data.unwrap();

                        format!("{} {}, [{} + #{:04X}h]", op.mnemonic, get_word_gpr_mnem(register0), get_word_gpr_mnem(register1), data)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::Rwn__DREFRwmINC => {
                Ok(OpFormat{
                    name: "Rwn__DREFRwmINC",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap() as u8;
                        let register1 : u8 = values.register1.unwrap() as u8;

                        format!("{} {}, [{}+]", op.mnemonic, get_word_gpr_mnem(register0), get_word_gpr_mnem(register1))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::Rwn__DREFRwm => {
                Ok(OpFormat{
                    name: "Rwn__DREFRwm",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let register1 : u8 = values.register1.unwrap() as u8;

                        format!("{} {}, [{}]", op.mnemonic, get_word_gpr_mnem(register0), get_word_gpr_mnem(register1))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::Rwn__mem => {
                Ok(OpFormat{
                    name: "Rwn__mem",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let memory : u16 = values.memory.unwrap();

                        format!("{} {}, {:04X}h", op.mnemonic, get_word_gpr_mnem(register0), memory)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::DREFDECRwm__Rbn => {
                Ok(OpFormat{
                    name: "DREFDECRwm__Rbn",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let register1 : u8 = values.register1.unwrap() as u8;

                        format!("{} [-{}], {}", op.mnemonic, get_word_gpr_mnem(register1), get_byte_gpr_mnem(register0))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::DREFDECRwm__Rwn => {
                Ok(OpFormat{
                    name: "DREFDECRwm__Rwn",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let register1 : u8 = values.register1.unwrap() as u8;

                        format!("{} [-{}], {}", op.mnemonic, get_word_gpr_mnem(register1), get_word_gpr_mnem(register0))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::DREFRwmINCINDdata16__Rbn => {
                Ok(OpFormat{
                    name: "DREFRwmINCINDdata16__Rbn",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let register1 : u8 = values.register1.unwrap() as u8;
                        let data : u16 = values.data.unwrap();

                        format!("{} [{} + #{:04X}h], {}", op.mnemonic, get_word_gpr_mnem(register1), data, get_byte_gpr_mnem(register0))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::DREFRwmINCINDdata16__Rwn => {
                Ok(OpFormat{
                    name: "DREFRwmINCINDdata16__Rwn",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let register1 : u8 = values.register1.unwrap() as u8;
                        let data : u16 = values.data.unwrap();

                        format!("{} [{} + #{:04X}h], {}", op.mnemonic, get_word_gpr_mnem(register1), data, get_word_gpr_mnem(register0))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None

                })
            },
            OpFormatType::DREFRwm__Rbn => {
                Ok(OpFormat{
                    name: "DREFRwm__Rbn",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let register1 : u8 = values.register1.unwrap() as u8;

                        format!("{} [{}], {}", op.mnemonic, get_word_gpr_mnem(register1), get_byte_gpr_mnem(register0))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::DREFRwm__Rwn => {
                Ok(OpFormat{
                    name: "DREFRwm__Rwn",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let register1 : u8 = values.register1.unwrap() as u8;

                        format!("{} [{}], {}", op.mnemonic, get_word_gpr_mnem(register1), get_word_gpr_mnem(register0))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None

                })
            },
            OpFormatType::DREFRwnINC__DREFRwm => {
                Ok(OpFormat{
                    name: "DREFRwnINC__DREFRwm",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let register1 : u8 = values.register1.unwrap() as u8;

                        format!("{} [{}+], [{}]", op.mnemonic, get_word_gpr_mnem(register0), get_word_gpr_mnem(register1))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::DREFRwn__DREFRwmINC => {
                Ok(OpFormat{
                    name: "DREFRwn__DREFRwmINC",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let register1 : u8 = values.register1.unwrap() as u8;

                        format!("{} [{}], [{}+]", op.mnemonic, get_word_gpr_mnem(register0), get_word_gpr_mnem(register1))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::DREFRwn__DREFRwm => {
                Ok(OpFormat{
                    name: "DREFRwn__DREFRwm",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let register1 : u8 = values.register1.unwrap() as u8;

                        format!("{} [{}], [{}]", op.mnemonic, get_word_gpr_mnem(register0), get_word_gpr_mnem(register1))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::DREFRwn__mem => {
                Ok(OpFormat{
                    name: "DREFRwn__mem",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let memory : u16 = values.memory.unwrap();

                        format!("{} [{}], {:04X}h", op.mnemonic, get_word_gpr_mnem(register0), memory)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None

                })
            },
            OpFormatType::bitaddrQ_q => {
                Ok(OpFormat{
                    name: "bitaddrQ_q",
                    decode: |op, values, _pc| {
                        let bitoff0 : u8 = values.bitoff0.unwrap();
                        let bit0 : u8 = values.bit0.unwrap();

                        format!("{} {}.{}", op.mnemonic, format_bitoff(bitoff0, false), bit0)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None

                })
            },
            OpFormatType::bitaddrQ_q__rel => {
                Ok(OpFormat{
                    name: "bitaddrQ_q__rel",
                    decode: |op, values, pc| {
                        let bitoff0 : u8 = values.bitoff0.unwrap();
                        let bit0 : u8 = values.bit0.unwrap();
                        let relative : u8 = values.relative.unwrap();

                        format!("{} {}.{}, {:04X}h", op.mnemonic, format_bitoff(bitoff0, false), bit0, pc + (( 2 * relative ) as u32))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::bitaddrZ_z__bitaddrQ_q => {
                Ok(OpFormat{
                    name: "bitaddrZ_z__bitaddrQ_q",
                    decode: |op, values, _pc| {
                        let bitoff0 : u8 = values.bitoff0.unwrap();
                        let bit0 : u8 = values.bit0.unwrap();

                        let bitoff1 : u8 = values.bitoff1.unwrap();
                        let bit1 : u8 = values.bit1.unwrap();

                        format!("{} {}.{}, {}.{}", op.mnemonic, format_bitoff(bitoff0, false), bit0, format_bitoff(bitoff1, false), bit1)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::bitoffQ__INDmask8__INDdata8 => {
                Ok(OpFormat{
                    name: "bitoffQ__INDmask8__INDdata8",
                    decode: |op, values, _pc| {
                        let mask : u8 = values.mask.unwrap();
                        let data : u16 = values.data.unwrap();
                        let bitoff0 : u8 = values.bitoff0.unwrap();

                        format!("{} {}, #{:02X}h, #{:02X}h", op.mnemonic, format_bitoff(bitoff0, false), mask, data)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::cc__DREFRwn => {
                Ok(OpFormat{
                    name: "cc__DREFRwn",
                    decode: |op, values, _pc| {
                        let condition : u8 = values.condition.unwrap();
                        let register0 : u8 = values.register0.unwrap();

                        format!("{} {}, [{}]", op.mnemonic, get_condition(condition), get_word_gpr_mnem(register0))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::cc__caddr => {
                Ok(OpFormat{
                    name: "cc__caddr",
                    decode: |op, values, _pc| {
                        let condition : u8 = values.condition.unwrap();
                        let address : u16 = values.memory.unwrap();

                        format!("{} {}, {:04X}h", op.mnemonic, get_condition(condition), address)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::cc__rel => {
                Ok(OpFormat{
                    name: "cc__rel",
                    decode: |op, values, pc| {
                        let condition : u8 = values.condition.unwrap();
                        let relative : u8 = values.relative.unwrap();

                        format!("{} {}, {:04X}h", op.mnemonic, get_condition(condition), pc + (( 2 * relative ) as u32))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::mem__DREFRwn => {
                Ok(OpFormat{
                    name: "mem__DREFRwn",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let memory : u16 = values.memory.unwrap();

                        format!("{} {:04X}h, [{}]", op.mnemonic, memory, get_word_gpr_mnem(register0))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::mem__reg => {
                Ok(OpFormat{
                    name: "mem__reg",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let memory : u16 = values.memory.unwrap();

                        format!("{} {:04X}h, {}", op.mnemonic, memory, get_register_mnem(register0))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::reg => {
                Ok(OpFormat{
                    name: "reg",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();

                        format!("{} {}", op.mnemonic, get_register_mnem(register0))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::reg__INDdata16 => {
                Ok(OpFormat{
                    name: "reg__INDdata16",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let data : u16 = values.data.unwrap();

                        format!("{} {}, #{:04X}h", op.mnemonic, get_register_mnem(register0), data)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::reg__INDdata8 => {
                Ok(OpFormat{
                    name: "reg__INDdata8",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let data : u16 = values.data.unwrap();

                        format!("{} {}, #{:02X}h", op.mnemonic, get_word_gpr_mnem(register0), data)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::reg__caddr => {
                Ok(OpFormat{
                    name: "reg__caddr",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let address : u16 = values.memory.unwrap();

                        format!("{} {}, {:04X}h", op.mnemonic, get_register_mnem(register0), address)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::reg__mem => {
                Ok(OpFormat{
                    name: "reg__mem",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let memory : u16 = values.memory.unwrap();

                        format!("{} {}, {:04X}h", op.mnemonic, get_register_mnem(register0), memory)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::rel => {
                Ok(OpFormat{
                    name: "rel",
                    decode: |op, values, pc| {
                        let relative : u8 = values.relative.unwrap();

                        format!("{} {:04X}h", op.mnemonic, pc + (( 2 * relative ) as u32))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::seg__caddr => {
                Ok(OpFormat{
                    name: "seg__caddr",
                    decode: |op, values, _pc| {
                        let segment : u8 = values.segment.unwrap();
                        let address : u16 = values.memory.unwrap();

                        format!("{} {:02X}h, {:04X}h", op.mnemonic, segment, address)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::mem__breg => {
                Ok(OpFormat{
                    name: "mem__breg",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let memory : u16 = values.memory.unwrap();

                        format!("{} {:04X}h, {}", op.mnemonic, memory, get_byte_register_mnem(register0))
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::breg__mem => {
                Ok(OpFormat{
                    name: "breg__mem",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let memory : u16 = values.memory.unwrap();

                        format!("{} {}, {:04X}h", op.mnemonic, get_byte_register_mnem(register0), memory)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::breg__INDdata8 => {
                Ok(OpFormat{
                    name: "breg__INDdata8",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap();
                        let data : u16 = values.data.unwrap();

                        format!("{} {}, #{:02X}h", op.mnemonic, get_byte_register_mnem(register0), data)
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::data3_or_reg => {
                Ok(OpFormat{
                    name: "data3_or_reg",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap() as u8;
                        let sub_op : &String = values.mnemonic.as_ref().unwrap();
                        let register1 : Option<u8> = values.register1;
                        let data : Option<u16> = values.data;

                        // GROSS
                        let reg0_mnem = match op.mnemonic {
                            "subcb" => get_byte_gpr_mnem(register0),
                            _ => get_word_gpr_mnem(register0)
                        };

                        match sub_op.as_str() {
                            "#data3" => {
                                format!("{} {}, #{:02X}h", op.mnemonic, reg0_mnem, data.unwrap())
                            },
                            "reg" => {
                                format!("{} {}, [{}]", op.mnemonic, reg0_mnem, get_word_gpr_mnem(register1.unwrap()))
                            },
                            "reg_inc" => {
                                format!("{} {}, [{}+]", op.mnemonic, reg0_mnem, get_word_gpr_mnem(register1.unwrap()))
                            },
                            _ => {
                                format!("{} {}, INVALID={}", op.mnemonic, reg0_mnem, sub_op)

                            }
                        }
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            },
            OpFormatType::data3_or_breg => {
                Ok(OpFormat{
                    name: "data3_or_breg",
                    decode: |op, values, _pc| {
                        let register0 : u8 = values.register0.unwrap() as u8;
                        let sub_op : &String = values.mnemonic.as_ref().unwrap();

                        let register1 : Option<u8> = values.register1;
                        let data : Option<u16> = values.data;

                        match sub_op.as_str() {
                            "#data3" => {
                                format!("{} {}, #{:02X}h", op.mnemonic, get_byte_gpr_mnem(register0), data.unwrap())
                            },
                            "reg" => {
                                format!("{} {}, [{}]", op.mnemonic, get_byte_gpr_mnem(register0), get_word_gpr_mnem(register1.unwrap()))
                            },
                            "reg_inc" => {
                                format!("{} {}, [{}+]", op.mnemonic, get_byte_gpr_mnem(register0), get_word_gpr_mnem(register1.unwrap()))
                            },
                            _ => {
                                format!("{} {}, INVALID={}", op.mnemonic, get_byte_gpr_mnem(register0), sub_op)

                            }
                        }
                    },
                    esil: |_op, _values| {String::from("")},
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::None,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::None
                })
            }
        }
    }
}
