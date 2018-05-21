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
use ::instruction::*;
use ::register::*;

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
            match is_ext {
                false => {
                    // SFR
                    let address : u16 = 0xFF00 + (2 * (offset & 0b01111111)) as u16;
                    match get_sfr_mnem_from_physical(address) {
                        Some(mnem) => format!("{}", mnem),
                        None => format!("{:04X}h", address)
                    }
                },
                true => {
                    // 'reg' accesses to the ESFR area require a preceding EXT*R instruction to switch the base address
                    // not available in the SAB 8XC166(W) devices
                    // ESFR
                    let address = 0xF100 + ((2 * (offset & 0b01111111)) as u16);
                    format!("{:04X}", address)
                }
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

#[inline]
fn decode_immediate(parameter: &InstructionParameter, param_type: &InstructionParameterType, values: &InstructionArguments) -> String {
    if param_type.intersects(InstructionParameterType::DATA_3) {
        format!("#{:02X}h", values.data.unwrap())
    } else if param_type.intersects(InstructionParameterType::DATA_4) {
        format!("#{:02X}h", values.data.unwrap())
    } else if param_type.intersects(InstructionParameterType::DATA_8) {
        format!("#{:02X}h", values.data.unwrap())
    } else if param_type.intersects(InstructionParameterType::DATA_16) {
        format!("#{:04X}h", values.data.unwrap())
    } else if *parameter == InstructionParameter::IRange {
        format!("#{:X}", values.irange.unwrap())
    } else if *parameter == InstructionParameter::PageOrSegment {
        match values.page {
            Some(page) => format!("#{:04X}h", page),
            _ => format!("#{:02X}h", values.segment.unwrap()),
        }
    } else {
        let value = values.data.unwrap();
        format!("#{:X}h", value)
    }
}

fn decode_position(mnemonic: &str, parameter: &InstructionParameter, param_type: &InstructionParameterType, values: &InstructionArguments, pc: u32) -> String {
    let mut ret : String = String::from("");

    if param_type.intersects(InstructionParameterType::GENERAL_REGISTER) {
        let value : u8 = match parameter {
            InstructionParameter::Register0 => values.register0.unwrap(),
            InstructionParameter::Register1 => values.register1.unwrap(),
            _ => unreachable!()
        };

        if param_type.intersects(InstructionParameterType::WORD_REGISTER) {
            ret = format!("{}", get_word_gpr_mnem(value));
        } else if param_type.intersects(InstructionParameterType::BYTE_REGISTER) {
            ret = format!("{}", get_byte_gpr_mnem(value));
        }
        
    } else if param_type.intersects(InstructionParameterType::SPECIAL_REGISTER) {
        let value : u8 = match parameter {
            InstructionParameter::Register0 => values.register0.unwrap(),
            InstructionParameter::Register1 => values.register1.unwrap(),
            _ => unreachable!()
        };

        if param_type.intersects(InstructionParameterType::WORD_REGISTER) {
            ret = format!("{}", get_register_mnem(value, false));
        } else if param_type.intersects(InstructionParameterType::BYTE_REGISTER) {
            ret = format!("{}", get_register_mnem(value, true));
        }
    } else if param_type.intersects(InstructionParameterType::DIRECT_MEMORY) {
        match parameter {
            InstructionParameter::Memory => {
                let value : u16 = values.memory.unwrap();
                ret = format!("{:04X}h", value);
            },
            InstructionParameter::RelativeAddress => {
                let value : u32 = values.relative.unwrap() as u32;
                ret = format!("{:04X}h", pc + (2 * value));
            },
            _ => unreachable!()
        };
    } else if param_type.intersects(InstructionParameterType::SEGMENT) {
        let value : u8 = values.segment.unwrap();        

        ret = format!("{:02X}h", value);
    } else if param_type.intersects(InstructionParameterType::IMMEDIATE) {
        ret = decode_immediate(&parameter, &param_type, &values);
    } else if param_type.intersects(InstructionParameterType::TRAP) {
        let value : u8 = values.trap.unwrap();

        ret = format!("#{:02X}h", value);
    } else if param_type.intersects(InstructionParameterType::BIT_OFFSET) {
        let offset : u8;
        let bit : Option<u8>;
        let mask : Option<u8>;

         match parameter {
            InstructionParameter::BitOffset0 => {
                offset = values.bitoff0.unwrap();
                bit = match param_type.intersects(InstructionParameterType::BIT_OFFSET_BIT) {
                    true => values.bit0,
                    false => None
                };
            },
            InstructionParameter::BitOffset1 => {
                offset = values.bitoff1.unwrap();
                bit = match param_type.intersects(InstructionParameterType::BIT_OFFSET_BIT) {
                    true => values.bit1,
                    false => None
                };
            },
            _ => unreachable!()
        };

        mask = match param_type.intersects(InstructionParameterType::BIT_OFFSET_MASK) {
            true => values.mask,
            false => None
        };

        ret = match bit {
            Some(bit) => format!("{}.{}", format_bitoff(offset, false), bit),
            _ => {
                match mask {
                    Some(mask) => format!("{}, #{:02X}h", format_bitoff(offset, false), mask),
                    _ => format!("{}", format_bitoff(offset, false))
                }
            }
        }
    } else if param_type.intersects(InstructionParameterType::CONDITION) {
        let value : u8 = values.condition.unwrap();

        ret = format!("{}", get_condition(value));
    } else if param_type.intersects(InstructionParameterType::DATA_3) {
        // Gross
        let register0 : u8 = values.register0.unwrap();
        let sub_op : u8 = values.sub_op.unwrap();
        let register1 : Option<u8> = values.register1;
        let data : Option<u16> = values.data;

        let reg0_mnem = match mnemonic {
            "subcb" => get_byte_gpr_mnem(register0),
            _ => {
                match param_type.intersects(InstructionParameterType::BYTE_REGISTER) {
                    true => get_byte_gpr_mnem(register0),
                    false => get_word_gpr_mnem(register0)
                }
            }
        };

        ret = match sub_op {
            0b10 => format!("{}, [{}]", reg0_mnem, get_word_gpr_mnem(register1.unwrap())),  /* reg */
            0b11 => format!("{}, [{}+]", reg0_mnem, get_word_gpr_mnem(register1.unwrap())), /* reg_inc */
            _    => format!("{}, #{:02X}h", reg0_mnem, data.unwrap())                       /* data3 */
        };
    }

    if param_type.intersects(InstructionParameterType::INDIRECT) {
        if param_type.intersects(InstructionParameterType::INCREMENT) {
            if param_type.intersects(InstructionParameterType::IMMEDIATE) {
                ret = format!("[{} + {}]", ret, decode_immediate(&parameter, &param_type, &values));
            } else {
                ret = format!("[{}+]", ret);
            }
        } else if param_type.intersects(InstructionParameterType::DECREMENT) {
            ret = format!("[-{}]", ret);
        } else {
            ret = format!("[{}]", ret);
        }
    }

    ret
}

pub fn format_op(op: &Instruction, values: &InstructionArguments, pc: u32) -> String {
        let mut ret = match &values.mnemonic {
            Some(mnem) => format!("{}", mnem),
            _ => format!("{}", op.mnemonic)
        };

        if !op.dst_type.is_empty() {
            ret = format!("{} {}", ret, decode_position(&op.mnemonic, &op.dst_param, &op.dst_type, &values, pc));
            if !op.src_type.is_empty() {
                ret = format!("{}, {}", ret, decode_position(&op.mnemonic, &op.src_param, &op.src_type, &values, pc));
            }
        } else if !op.src_type.is_empty() {
            ret = format!("{} {}", ret, decode_position(&op.mnemonic, &op.src_param, &op.src_type, &values, pc));
        }

        ret
}
