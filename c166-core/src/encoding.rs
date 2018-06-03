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

use byteorder::ByteOrder;
use byteorder::LittleEndian;
use std::convert::TryFrom;
use num_traits::{FromPrimitive, ToPrimitive};

use ::instruction::*;
use ::reg::*;

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum EncodingType {
    NO_ARGS2,
    NO_ARGS4,
    op_d7,
    op_dc,
    op_d1, // atomic_extr
    bitoff8_mask8_data8,
    bitaddr8_bitaddr8_bit4_bit4,
    bitaddr8_rel8_bit4_0,
    bitopcode4_e_bitaddr8,
    bitopcode4_f_bitaddr8,
    cond4_0_mem16,
    cond4_reg4,
    condopcode4_d_rel8s,
    reg8_mem16,
    reg8_data8_nop8,
    reg4_or_data3,
    _0_reg4_mem16,
    _f_reg4_mem16,
    _f_reg4_data16,
    rel8s,
    reg4_data4,
    reg4_0,
    reg4_dup,
    reg4_reg4,
    reg4_reg4_data16,
    reg8,
    reg8_data16,
    seg8_mem16,
    trap7,
}

pub struct Encoding<'a> {
    pub name : &'static str,
    pub length : i32,
    pub encode : fn(&Instruction, &InstructionArguments) -> Result<Vec<u8>, &'static str>,
    pub decode : fn(&'a Instruction, &[u8]) -> Result<InstructionArguments, &'static str>
}

fn get_reg_op_position<'a>(isn: &'a Instruction) -> Option<OperandType> {
    match isn.op1.as_ref().unwrap() {
        OperandType::Indirect(_) |
        OperandType::IndirectPostIncrement(_) |
        OperandType::IndirectPreDecrement(_) |
        OperandType::IndirectAndImmediate(_) |
        OperandType::ByteRegister(_) |
        OperandType::WordRegister(_) => isn.op1,
        _ => isn.op2
    }
}

fn get_reg4<'a>(op_type: &'a OperandType, reg0: u8, reg1: u8) -> Operand {
    // Position in the encoded op, not in the asm statement
    let position: u8 = match &op_type {
        OperandType::Indirect(r) |
        OperandType::IndirectPreDecrement(r) |
        OperandType::IndirectPostIncrement(r) |
        OperandType::ByteRegister(r) |
        OperandType::WordRegister(r) |
        OperandType::IndirectAndImmediate(r) => *r,
        _ => unreachable!(),
    };

    let register = match position {
        0 => reg0,
        1 => reg1,
        _ => unreachable!(),
    };

    match &op_type {
        OperandType::Indirect(r)                => Operand::Indirect(Reg::from_reg4(register, &OperandType::WordRegister(*r)).unwrap()),
        OperandType::IndirectPreDecrement(r)    => Operand::IndirectPreDecrement(Reg::from_reg4(register, &OperandType::WordRegister(*r)).unwrap()),
        OperandType::IndirectPostIncrement(r)   => Operand::IndirectPostIncrement(Reg::from_reg4(register, &OperandType::WordRegister(*r)).unwrap()),
        OperandType::ByteRegister(_) |
        OperandType::WordRegister(_)            => Operand::Register(Reg::from_reg4(register, &op_type).unwrap()),
        OperandType::IndirectAndImmediate(r)    => Operand::IndirectAndImmediate(Reg::from_reg4(register, &OperandType::WordRegister(*r)).unwrap(), 0),
        _ => unreachable!(),
    }
}

impl<'a> From<&'a EncodingType> for Encoding<'a> {
    fn from(encoding_type: &'a EncodingType) -> Self {
        match encoding_type.clone() {
            EncodingType::NO_ARGS2 => {
                Encoding {
                    name: "NO_ARGS2",
                    length: 2,
                    encode: |isn, _args| {
                        match isn.id {
                            0xDB => Ok(vec![0xDB, 0x00]),
                            0xFB => Ok(vec![0xFB, 0x88]),
                            0xCB => Ok(vec![0xCB, 0x00]),
                            0xCC => Ok(vec![0xCC, 0x00]),
                            _ => Err("Invalid OP")
                        }
                    },
                    decode: |_isn, buf| {
                        match &buf[0..2] {
                            [0xDB, 0x00] |
                            [0xFB, 0x88] |
                            [0xCB, 0x00] |
                            [0xCC, 0x00] => Ok(InstructionArguments {..Default::default()}),
                            _ => Err("Invalid instruction")
                        }
                    }
                }
            },

            EncodingType::NO_ARGS4 => {
                Encoding {
                    name: "NO_ARGS4",
                    length: 4,
                    encode: |isn, _args| {
                        match isn.id {
                            0xB7 => Ok(vec![0xB7, 0x48, 0xB7, 0xB7]),
                            0xA7 => Ok(vec![0xA7, 0x58, 0xA7, 0xA7]),
                            0x97 => Ok(vec![0x97, 0x68, 0x97, 0x97]),
                            0xB5 => Ok(vec![0xB5, 0x4A, 0xB5, 0xB5]),
                            0xA5 => Ok(vec![0xA5, 0x5A, 0xA5, 0xA5]),
                            0x87 => Ok(vec![0x87, 0x78, 0x87, 0x87]),
                            _ => Err("Invalid OP")
                        }
                    },
                    decode: |_isn, buf| {
                        match &buf[0..4] {
                            [0xB7, 0x48, 0xB7, 0xB7] |
                            [0xA7, 0x58, 0xA7, 0xA7] |
                            [0x97, 0x68, 0x97, 0x97] |
                            [0xB5, 0x4A, 0xB5, 0xB5] |
                            [0xA5, 0x5A, 0xA5, 0xA5] |
                            [0x87, 0x78, 0x87, 0x87] => Ok(InstructionArguments {..Default::default()}),
                            _ => Err("Invalid instruction")
                        }
                    }
                }
            },

            EncodingType::reg4_data4 => {
                Encoding {
                    name: "In",
                    length: 2,
                    encode: |isn, args| {
                        let data: u16 = match args.op2.expect("Second operand required for EncodingType::reg4_data4") {
                            Operand::Immediate(data, _width) => data,
                            _ => return Err("Second operand must be #data4 for EncodingType::reg4_data4")
                        };

                        if data > 0x0F {
                            return Err("#data4 must be 0x00..=0x0F");
                        }

                        let reg: Reg = match args.op1.expect("First operand required for EncodingType:::reg4_data4.") {
                            Operand::Register(reg) => reg,
                            _ => return Err("First operand must be register for EncodingType::reg4_data4")
                        };

                        let reg4: u8 = reg.to_reg4().expect("Register must be GPR for EncodingType::reg4_data4");

                        let byte: u8 = ((data as u8) << 4) | (reg4 & 0b00001111);

                        Ok(vec![isn.id, byte])
                    },
                    decode: |isn, buf| {
                        let register0 : u8 = buf[1] & 0b00001111;
                        let data : u8 = (buf[1] & 0b11110000) >> 4;

                        let reg_op = get_reg_op_position(&isn);

                        let reg = get_reg4(reg_op.as_ref().unwrap(), register0, register0);

                        if reg_op == isn.op2 {
                            Ok(InstructionArguments {
                                op1: Some(Operand::Immediate(data as u16, 4)),
                                op2: Some(reg),
                                ..Default::default()
                            })
                        } else {
                            Ok(InstructionArguments {
                                op1: Some(reg),
                                op2: Some(Operand::Immediate(data as u16, 4)),
                                ..Default::default()
                            })
                        }
                    }
                }
            },

            EncodingType::_0_reg4_mem16 => {
                Encoding {
                    name: "_0n_MM_MM",
                    length: 4,
                    encode: |isn, args| {
                        let reg0 = match args.op1.as_ref().unwrap() {
                            Operand::Indirect(reg) |
                            Operand::IndirectPostIncrement(reg) |
                            Operand::IndirectPreDecrement(reg) |
                            Operand::Register(reg) => reg.to_reg4().expect("Invalid GPR"),
                            _ => return Err("Invalid Operand 1")
                        };

                        let mem = match args.op2.as_ref().unwrap() {
                            Operand::Direct(direct, _width) => direct,
                            _ => return Err("Invalid operand2 (expected memory)")
                        };

                        Ok(vec![isn.id, reg0 & 0x00FF, (mem & 0x00FF) as u8, ((mem & 0xFF00) >> 8) as u8])
                    },
                    decode: |isn, buf| {
                        match buf[1] & 0b11110000 {
                            0 => {
                                let register0 : u8 = buf[1] & 0b00001111;

                                let slice = &buf[2..4];
                                let memory : u16 = LittleEndian::read_u16(slice);

                                let reg_op = get_reg_op_position(&isn);
                                let op1 = get_reg4(&reg_op.unwrap(), register0, register0);

                                if reg_op == isn.op1 {
                                    Ok(InstructionArguments {
                                        op1: Some(op1),
                                        op2: Some(Operand::Direct(memory, 16)),
                                        ..Default::default()
                                    })
                                } else {
                                    Ok(InstructionArguments {
                                        op1: Some(Operand::Direct(memory, 16)),
                                        op2: Some(op1),
                                        ..Default::default()
                                    })
                                }
                            },
                            _ => Err("Invalid instruction")
                        }
                    }
                }
            },

            EncodingType::condopcode4_d_rel8s => {
                Encoding {
                    name: "cc_rr",
                    length: 2,
                    encode: |isn, args| {
                        let cond = match args.op1.unwrap() {
                            Operand::Condition(cond) => cond.to_u8().unwrap(),
                            _ => unreachable!()
                        };

                        let rel = match args.op2.unwrap() {
                            Operand::Direct(d, _width) => {
                                if d > <i8>::max_value() as u16 {
                                    return Err("Relative values must fit into an i8 type")
                                }

                                d as u8
                            },
                            _ => unreachable!()
                        };

                        Ok(vec![(cond & 0x0F) << 4 | 0x0D, rel / 2])
                    },
                    decode: |_isn, buf| {
                        let condition : u8 = (buf[0] & 0b11110000) >> 4;
                        let relative : u8 = buf[1];

                        let op_condition : OpCondition = try!(OpCondition::try_from(condition));

                        Ok(InstructionArguments {
                            op1: Some(Operand::Condition(op_condition)),
                            op2: Some(Operand::Direct(relative as u16, 8)),
                            ..Default::default()
                        })
                   }
                }
            },

            EncodingType::op_d7 => {
                Encoding {
                    name: "ext_d7",
                    length: 4,
                    encode: |isn, args| {
                        let irange = match args.op2.unwrap() {
                            Operand::Immediate(immed, _width) => (immed - 1) as u8,
                            _ => unreachable!()
                        };

                        match args.mnemonic.as_ref().unwrap().as_str() {
                            "extp"  => {
                                let page = match args.op1.unwrap() {
                                    Operand::Immediate(immed, _width) => immed,
                                    _ => unreachable!()
                                };

                                Ok(vec![isn.id, (0b01 << 6) | (irange << 4), (page & 0xFF) as u8, ((page & 0b1100000000) >> 8) as u8 ])
                            },
                            "extpr" => {
                                let page = match args.op1.unwrap() {
                                    Operand::Immediate(immed, _width) => immed,
                                    _ => unreachable!()
                                };

                                Ok(vec![isn.id, (0b11 << 6) | (irange << 4), (page & 0xFF) as u8, ((page & 0b1100000000) >> 8) as u8 ])
                            },
                            "exts"  => {
                                let seg = match args.op1.unwrap() {
                                    Operand::Immediate(immed, _width) => immed as u8,
                                    _ => unreachable!()
                                };

                                Ok(vec![isn.id, (0b00 << 6) | (irange << 4), seg, 0x00 ])
                            },
                            "extsr" => {
                                let seg = match args.op1.unwrap() {
                                    Operand::Immediate(immed, _width) => immed as u8,
                                    _ => unreachable!()
                                };

                                Ok(vec![isn.id, (0b10 << 6) as u8 | (irange << 4), seg, 0x00 ])
                            },
                            _ => unreachable!()
                        }
                    },
                    decode: |_isn, buf| {
                        if (buf[1] & 0b00001111) != 0 {
                            return Err("Instruction was invalid")
                        }

                        let sub_op : u8 = (buf[1] & 0b11000000) >> 6;

                        let mnem = match sub_op {
                            1 => "extp",
                            3 => "extpr",
                            0 => "exts",
                            2 => "extsr",
                            _ => "InvalidSubOp"
                        };

                        let irange : u8 = ((buf[1] & 0b00110000) >> 4) + 1;

                        if irange > 4 {
                            // This should be unreachable, but...
                            return Err("Instruction was invalid, irange must be 0..=4")
                        }

                        let mut values = InstructionArguments {
                            mnemonic: Some(mnem.to_string()),
                            sub_op: Some(sub_op),
                            op2: Some(Operand::Immediate(irange as u16, 2)),
                            ..Default::default()
                        };

                        match (buf[1] & 0b11000000) >> 6 {
                            0b10 | 0b00 => {
                                // Seg op
                                match buf[3] {
                                    0x00 => {
                                        values.op1 = Some(Operand::Immediate(buf[2] as u16, 8));
                                    },
                                    _    => return Err("Instruction was invalid")
                                }
                            },
                            0b11 | 0b01 => {
                                // Page is 10 bits so the top 6 bits of byte 3 need to be zero
                                match (buf[3] & 0b11111100) >> 2 {
                                    0x00 => {
                                        let page : u16 = ((buf[3] & 0b00000011) as u16) << 8 | buf[2] as u16;
                                        values.op1 = Some(Operand::Immediate(page, 10));
                                    },
                                    _    => return Err("Instruction was invalid")
                                }
                            },
                            _ => unreachable!()
                        }

                        Ok(values)
                    }
                }
            },

            EncodingType::op_dc => {
                Encoding {
                    name: "ext_dc",
                    length: 2,
                    encode: |isn, args| {
                        let reg = match args.op1.unwrap() {
                            Operand::Register(reg) => reg.to_reg4().unwrap(),
                            _ => unreachable!()
                        };

                        let irange = match args.op2.unwrap() {
                            Operand::Immediate(immed, _width) => (immed - 1) as u8,
                            _ => unreachable!()
                        };

                        match args.mnemonic.as_ref().unwrap().as_str() {
                            "extp"  => Ok(vec![isn.id, (0b01 << 6) | (irange << 4) | reg]),
                            "extpr" => Ok(vec![isn.id, (0b11 << 6) | (irange << 4) | reg]),
                            "exts"  => Ok(vec![isn.id, (0b00 << 6) | (irange << 4) | reg]),
                            "extsr" => Ok(vec![isn.id, (0b10 << 6) | (irange << 4) | reg]),
                            _ => unreachable!()
                        }
                    },
                    decode: |isn, buf| {
                        let sub_op : u8 = (buf[1] & 0b11000000) >> 6;

                        let mnem = match sub_op {
                            1 => "extp",
                            3 => "extpr",
                            0 => "exts",
                            2 => "extsr",
                            _ => "InvalidSubOp"
                        };

                        let irange : u8 = ((buf[1] & 0b00110000) >> 4) + 1;

                        let register : u8 = buf[1] & 0b00001111;
                        let op1 = get_reg4(&isn.op1.unwrap(), register, register);
                        Ok(InstructionArguments {
                            mnemonic: Some(mnem.to_string()),
                            sub_op: Some(sub_op),
                            op1: Some(op1),
                            op2: Some(Operand::Immediate(irange as u16, 2)),
                            ..Default::default()
                        })
                    }
                }
            },

            EncodingType::reg4_or_data3 => {
                Encoding {
                    name: "data3_or_reg",
                    length: 2,
                    encode: |isn, args| {
                        let reg = match args.op1.unwrap() {
                            Operand::Register(reg) => reg.to_reg4().unwrap(),
                            _ => unreachable!()
                        };

                        match args.op2.unwrap() {
                            Operand::Immediate(immed, _width) => {
                                Ok(vec![isn.id, (reg << 4) | immed as u8])
                            },
                            Operand::Indirect(reg1) => {
                                let reg_id = reg1.to_reg4().unwrap();
                                if reg_id > 3 {
                                    // TODO: FIX THIS
                                    return Err("This op only works with GPR 0-3, should catch this in the parser")
                                }
                                Ok(vec![isn.id, (reg << 4) | (0b10 << 2) | reg_id & 0b11])
                            },
                            Operand::IndirectPostIncrement(reg1) => {
                                let reg_id = reg1.to_reg4().unwrap();
                                if reg_id > 3 {
                                    return Err("This op only works with GPR 0-3, should catch this in the parser")
                                }
                                Ok(vec![isn.id, (reg << 4) | (0b11 << 2) | reg_id & 0b11])
                            },
                            _ => unreachable!()
                        }
                    },
                    decode: |isn, buf| {
                        let register0 : u8 = (buf[1] & 0b11110000) >> 4;
                        let sub_op : u8 = (buf[1] & 0b00001100) >> 2;

                        let op1 = get_reg4(&isn.op1.unwrap(), register0, register0);

                        let op2 = match sub_op {
                            0b10 => {
                                let register1 : u8 = buf[1] & 0b00000011;
                                get_reg4(&OperandType::Indirect(1), register0, register1)
                            },
                            0b11 => {
                                let register1 : u8 = buf[1] & 0b00000011;
                                get_reg4(&OperandType::IndirectPostIncrement(1), register0, register1)
                            },
                            _ => {
                                let data : u8 = buf[1] & 0b00000111;
                                Operand::Immediate(data as u16, 3)
                            }
                        };

                        Ok(InstructionArguments {
                            sub_op: Some(sub_op),
                            op1: Some(op1),
                            op2: Some(op2),
                            ..Default::default()
                        })
                    }
                }
            },

            EncodingType::op_d1 => {
                Encoding {
                    name: "atomic_extr",
                    length: 2,
                    encode: |isn, args| {
                        let irange = match args.op1.unwrap() {
                            Operand::Immediate(immed, _width) => {
                                match immed {
                                    1..=4 => {},
                                    _ => return Err("#irange2 value must be 1..=4")
                                };

                                (immed - 1) as u8
                            },
                            _ => unreachable!()
                        };

                        match args.mnemonic.as_ref().unwrap().as_str() {
                            "atomic" => {
                                Ok(vec![isn.id, 0b00000000 | (irange & 0b00000011) << 4])
                            },
                            "extr" => {
                                Ok(vec![isn.id, 0b10000000 | (irange & 0b00000011) << 4])
                            },
                            _ => return Err("This encoding is for atomic and extr only")
                        }
                    },
                    decode: |_isn, buf| {
                        match buf[1] & 0b00001111 {
                            0 => {
                                let irange : u8 = ((buf[1] & 0b00110000) >> 4) + 1;
                                let sub_op = (buf[1] & 0b11000000) >> 6;

                                let mut values = InstructionArguments {
                                    op1: Some(Operand::Immediate(irange as u16, 2)),
                                    sub_op: Some(sub_op),
                                    ..Default::default()
                                };

                                if sub_op == 0b00 {
                                    values.mnemonic = Some("atomic".to_string());
                                } else if sub_op == 0b10 {
                                    values.mnemonic = Some("extr".to_string());
                                }

                                Ok(values)
                            },
                            _ => Err("Instruction was invalid")
                        }
                    }
                }
            },

            EncodingType::_f_reg4_data16 => {
                Encoding {
                    name: "Fn_II_II",
                    length: 4,
                    encode: |isn, args| {
                        let reg0 = match args.op1.unwrap() {
                            Operand::Register(reg) => reg.to_reg4().unwrap(),
                            _ => unreachable!()
                        };

                        let immed= match args.op2.unwrap() {
                            Operand::Immediate(immed, _width) => immed,
                            _ => unreachable!()
                        };

                        Ok(vec![isn.id, 0xF0 | (reg0 & 0x0F), (immed & 0x00FF) as u8, ((immed & 0xFF00) >> 8) as u8 ])
                    },
                    decode: |isn, buf| {
                        match (buf[1] & 0b11110000) >> 4 {
                            0x0F => {
                                let register0 : u8 = buf[1] & 0b00001111;

                                let slice = &buf[2..4];
                                let data : u16 = LittleEndian::read_u16(slice);

                                let reg_op = get_reg_op_position(&isn);
                                let reg = get_reg4(reg_op.as_ref().unwrap(), register0, register0);

                                if reg_op == isn.op1 {
                                    Ok(InstructionArguments {
                                        op1: Some(reg),
                                        op2: Some(Operand::Immediate(data, 16)),
                                        ..Default::default()
                                    })
                                } else {
                                    Ok(InstructionArguments {
                                        op1: Some(Operand::Immediate(data, 16)),
                                        op2: Some(reg),
                                        ..Default::default()
                                    })
                                }
                           },
                            _ => Err("Instruction was invalid")
                        }
                    }
                }
            },

            EncodingType::_f_reg4_mem16 => {
                Encoding {
                    name: "Fn_MM_MM",
                    length: 4,
                    encode: |isn, args| {
//                        foo
                        let reg0 = match args.op1.as_ref().unwrap() {
                            Operand::Indirect(reg) |
                            Operand::IndirectPostIncrement(reg) |
                            Operand::IndirectPreDecrement(reg) |
                            Operand::Register(reg) => reg.to_reg4().expect("Invalid register"),
                            _ => return Err("Invalid Operand 1")
                        };

                        let memory = match args.op2.as_ref().unwrap() {
                            Operand::Direct(mem, _) => mem,
                            _ => return Err("Invalid Operand 2")
                        };

                        Ok(vec![isn.id, 0xF0 | reg0, (memory & 0x00FF) as u8, ((memory & 0xFF00) >> 8) as u8 ])
                    },
                    decode: |isn, buf| {
                        match (buf[1] & 0b11110000) >> 4 {
                            0x0F => {
                                let register0 : u8 = buf[1] & 0b00001111;

                                let slice = &buf[2..4];
                                let memory : u16 = LittleEndian::read_u16(slice);

                                let reg_op = get_reg_op_position(&isn);
                                let reg = get_reg4(reg_op.as_ref().unwrap(), register0, register0);

                                if reg_op == isn.op1 {
                                    Ok(InstructionArguments {
                                        op1: Some(reg),
                                        op2: Some(Operand::Direct(memory, 16)),
                                        ..Default::default()
                                    })
                                } else {
                                    Ok(InstructionArguments {
                                        op1: Some(Operand::Direct(memory, 16)),
                                        op2: Some(reg),
                                        ..Default::default()
                                    })
                                }
                            },
                            _ => Err("Instruction was invalid")
                        }
                    }
                }
            },

            EncodingType::bitopcode4_e_bitaddr8 |
            EncodingType::bitopcode4_f_bitaddr8 => {
                Encoding {
                    name: "q_QQ",
                    length: 2,
                    encode: |isn, args| {
                        let (bitoff, bit) = match args.op1.unwrap() {
                            Operand::BitAddr(bitoff, bit) => (bitoff, bit),
                            _ => unreachable!()
                        };

                        match isn.encoding {
                            EncodingType::bitopcode4_e_bitaddr8 => Ok(vec![(bit << 4) | 0x0E, bitoff]),
                            EncodingType::bitopcode4_f_bitaddr8 => Ok(vec![(bit << 4) | 0x0F, bitoff]),
                            _ => unreachable!()
                        }
                    },
                    decode: |_isn, buf| {
                        let bit0 : u8 = (buf[0] & 0b11110000) >> 4;
                        let bitoff0 : u8 = buf[1];

                        Ok(InstructionArguments {
                            op1: Some(Operand::BitAddr(bitoff0, bit0)),
                            ..Default::default()
                        })
                    }
                }
            },

            EncodingType::bitoff8_mask8_data8 => {
                Encoding {
                    name: "QQ_AA_II",
                    length: 4,
                    encode: |isn, args| {
                        let bitoff = match args.op1.unwrap() {
                            Operand::BitAddr(bitoff, _bit) => bitoff,
                            Operand::Register(reg) => {
                                let reg_short_addr = reg.to_reg8().unwrap();
                                reg_short_addr
                            },
                            unknown @ _ => {
                                eprintln!("Got: {:X?}", unknown);
                                return Err("Expect op1 to be a bitaddr/bitoff or a register");
                            }
                        };

                        let mask8 = match args.op2.unwrap() {
                            Operand::Immediate(immed, _width) => {
                                if immed > <u8>::max_value() as u16 {
                                    return Err("And mask must fit into an 8-bit field")
                                }
                                immed as u8
                            },
                            _ => unreachable!()
                        };

                        let data8 = match args.op3.unwrap() {
                            Operand::Immediate(immed, _width) => {
                                if immed > <u8>::max_value() as u16 {
                                    return Err("Or mask must fit into an 8-bit field")
                                }

                                immed as u8
                            },
                            _ => unreachable!()
                        };

                        Ok(vec![isn.id, bitoff, mask8, data8])
                    },
                    decode: |_isn, buf| {
                        let mask : u8 = buf[2];
                        let data : u8 = buf[3];
                        let bitoff0 : u8 = buf[1];

                        Ok(InstructionArguments {
                            op1: Some(Operand::BitAddr(bitoff0, 0xFF)),
                            op2: Some(Operand::Immediate(mask as u16, 8)),
                            op3: Some(Operand::Immediate(data as u16, 8)),
                            ..Default::default()
                        })
                    }
                }
            },

            EncodingType::bitaddr8_bitaddr8_bit4_bit4 => {
                Encoding {
                    name: "QQ_ZZ_qz",
                    length: 4,
                    encode: |isn, args| {
                        let (offset0, bit0) = match args.op1.unwrap() {
                            Operand::BitAddr(offset, bit) => (offset, bit),
                            _ => unreachable!()
                        };

                        let (offset1, bit1) = match args.op2.unwrap() {
                            Operand::BitAddr(offset, bit) => (offset, bit),
                            _ => unreachable!()
                        };
                        let pos = match isn.op1.unwrap() {
                            OperandType::BitAddr(pos) => pos,
                            _ => unreachable!()
                        };

                        if pos == 0 {
                            Ok(vec![isn.id, offset0, offset1, ((bit0 & 0x0F) << 4) | (bit1 & 0x0F)])
                        } else {
                            Ok(vec![isn.id, offset1, offset0, ((bit1 & 0x0F) << 4) | (bit0 & 0x0F) ] )
                        }
                    },
                    decode: |_isn, buf| {
                        let bit1 : u8 = (buf[3] & 0b11110000) >> 4;
                        let bit0 : u8 = buf[3] & 0b00001111;

                        let bitoff1 : u8 = buf[1];
                        let bitoff0 : u8 = buf[2];

                        Ok(InstructionArguments {
                            op1: Some(Operand::BitAddr(bitoff0, bit0)),
                            op2: Some(Operand::BitAddr(bitoff1, bit1)),
                            ..Default::default()
                        })
                    }
                }
            },

            EncodingType::bitaddr8_rel8_bit4_0 => {
                Encoding {
                    name: "QQ_rr_q0",
                    length: 4,
                    encode: |isn, args| {
                        let (bitoff, bit) = match args.op1.unwrap() {
                            Operand::BitAddr(bitoff, bit) => (bitoff, bit),
                            _ => unreachable!()
                        };

                        let rel = match args.op2.unwrap() {
                            Operand::Direct(direct, _) => direct,
                            _ => unreachable!()
                        };

                        if rel > <i8>::max_value() as u16 {
                            return Err("Relative address must be a signed 8 bit value");
                        }

                        // TODO: properly validate relative addresses
                        Ok(vec![isn.id, bitoff, ((rel & 0x00FF) / 2) as u8, bit << 4])
                    },
                    decode: |_isn, buf| {
                        match buf[3] & 0b00001111 {
                            0 => {
                                let bitoff0 : u8 = buf[1];
                                let bit0 : u8 = (buf[3] & 0b11110000) >> 4;
                                let relative : u8 = buf[2];

                                Ok(InstructionArguments {
                                    op1: Some(Operand::BitAddr(bitoff0, bit0)),
                                    op2: Some(Operand::Direct(relative as u16, 8)),
                                    ..Default::default()
                                })
                            },
                            _ => Err("Invalid instruction")
                        }
                    }
                }
            },

            EncodingType::reg8 => {
                Encoding {
                    name: "RR",
                    length: 2,
                    encode: |isn, args| {
                        match args.op1.as_ref().unwrap() {
                            Operand::Register(reg) => Ok(vec![isn.id, reg.to_reg8().expect("Invalid register")]),
                            _ => Err("Invalid Operand")
                        }
                    },
                    decode: |isn, buf| {
                        let reg_addr: u8 = buf[1];

                        match Reg::from_reg8(reg_addr, isn.op1.as_ref().unwrap()) {
                            Ok(reg) => {
                                Ok(InstructionArguments {
                                    op1: Some(Operand::Register(reg)),
                                   ..Default::default()
                                })
                            },
                            Err(_) => Err("Invalid register value")
                        }
                    }
                }
            },

            EncodingType::reg8_data16 => {
                Encoding {
                    name: "RR_II_II",
                    length: 4,
                    encode: |isn, args| {
                        let mut reg: Option<u8> = None;
                        let mut data: Option<u16> = None;
                        for op in [args.op1, args.op2].iter() {
                            match op.as_ref().unwrap() {
                                Operand::Register(r) => {
                                    reg = Some(r.to_reg8().expect("Invalid register"));
                                },
                                Operand::Immediate(imm, _width) => {
                                    data = Some(*imm);
                                }
                                _ => unreachable!()
                            }
                        }

                        Ok(vec![isn.id, reg.unwrap(), (data.unwrap() & 0x00FF) as u8, ((data.unwrap() & 0xFF00) >> 8) as u8])
                    },
                    decode: |isn, buf| {
                        let reg_addr : u8 = buf[1];

                        let slice = &buf[2..4];
                        let data : u16 = LittleEndian::read_u16(slice);

                        let reg_op = get_reg_op_position(&isn);
                        let reg = Reg::from_reg8(reg_addr, reg_op.as_ref().unwrap());

                        match reg {
                            Ok(register) => {
                                Ok(InstructionArguments {
                                    op1: Some(Operand::Register(reg.unwrap())),
                                    op2: Some(Operand::Immediate(data, 16)),
                                    ..Default::default()
                                })
                            },
                            Err(_) => return Err("Invalid register value")
                        }
                    }
                }
            },

            EncodingType::reg8_data8_nop8 => {
                Encoding {
                    name: "RR_II_xx",
                    length: 4,
                    encode: |isn, args| {
                        let mut reg: Option<u8> = None;
                        let mut data: Option<u16> = None;
                        for op in [args.op1, args.op2].iter() {
                            match op.as_ref().unwrap() {
                                Operand::Register(r) => {
                                    reg = Some(r.to_reg8().expect("Invalid register"));
                                },
                                Operand::Immediate(imm, _width) => {
                                    data = Some(*imm);
                                }
                                _ => unreachable!()
                            }
                        }

                        Ok(vec![isn.id, reg.unwrap(), (data.unwrap() & 0x00FF) as u8, 0x42])
                    },
                    decode: |isn, buf| {
                        let reg_addr : u8 = buf[1];
                        let data : u8 = buf[2];

                        let reg_op = get_reg_op_position(&isn);

                        let reg = match reg_op.unwrap() {
                            OperandType::ByteRegister(_) |
                            OperandType::WordRegister(_) => Reg::from_reg8(reg_addr, reg_op.as_ref().unwrap()),
                            _ => unreachable!()
                        };

                        if let Err(_) = reg {
                            return Err("Invalid register value");
                        }

                        if reg_op == isn.op2 {
                            Ok(InstructionArguments {
                                op1: Some(Operand::Immediate(data as u16, 8)),
                                op2: Some(Operand::Register(reg.unwrap())),
                                ..Default::default()
                            })

                        } else {
                            Ok(InstructionArguments {
                                op1: Some(Operand::Register(reg.unwrap())),
                                op2: Some(Operand::Immediate(data as u16, 8)),
                                ..Default::default()
                            })
                        }
                    }
                }
            },

            EncodingType::reg8_mem16 => {
                Encoding {
                    name: "RR_MM_MM",
                    length: 4,
                    encode: |isn, args| {
                        let mut reg: Option<u8> = None;
                        let mut data: Option<u16> = None;
                        for op in [args.op1, args.op2].iter() {
                            match op.as_ref().unwrap() {
                                Operand::Register(r) => {
                                    reg = Some(r.to_reg8().expect("Invalid register"));
                                },
                                Operand::Direct(direct, _width) => {
                                    data = Some(*direct);
                                }
                                _ => unreachable!()
                            }
                        }
                        Ok(vec![isn.id, reg.unwrap(), (data.unwrap() & 0x00FF) as u8, ((data.unwrap() & 0xFF00) >> 8) as u8])
                    },
                    decode: |isn, buf| {
                        let reg_addr: u8 = buf[1];

                        let slice = &buf[2..4];
                        let memory : u16 = LittleEndian::read_u16(slice);

                        let reg_op = get_reg_op_position(&isn);

                        let reg = match reg_op.unwrap() {
                            OperandType::ByteRegister(_) |
                            OperandType::WordRegister(_) => Reg::from_reg8(reg_addr, reg_op.as_ref().unwrap()),
                            _ => unreachable!()
                        };

                        if let Err(_) = reg {
                            return Err("Invalid register value");
                        }

                        if let OperandType::DirectMemory16 = isn.op1.unwrap() {
                            Ok(InstructionArguments {
                                op1: Some(Operand::Direct(memory, 16)),
                                op2: Some(Operand::Register(reg.unwrap())),
                                ..Default::default()
                            })

                        } else {
                            Ok(InstructionArguments {
                                op1: Some(Operand::Register(reg.unwrap())),
                                op2: Some(Operand::Direct(memory, 16)),
                                ..Default::default()
                            })
                        }
                    }
                }
            },

            EncodingType::seg8_mem16 => {
                Encoding {
                    name: "SS_MM_MM",
                    length: 4,
                    encode: |isn, args| {
                        let seg: u8 = match args.op1.expect("Needed op1 = segment") {
                            Operand::Direct(d, _width) => d as u8,
                            _ => return Err("Needed op1=segment")
                        };

                        let mem: u16 = match args.op2.expect("needed op2=caddr16") {
                            Operand::Direct(d, _width) => d,
                            _ => return Err("Needed op2 = caddr16")
                        };

                        Ok(vec![isn.id, seg, (mem & 0x00FF) as u8, ((mem & 0x0FF00) >> 8) as u8])
                    },
                    decode: |_isn, buf| {
                        let segment : u8 = buf[1];

                        let slice = &buf[2..4];
                        let memory : u16 = LittleEndian::read_u16(slice);

                        Ok(InstructionArguments {
                            op1: Some(Operand::Direct(segment as u16, 8)),
                            op2: Some(Operand::Direct(memory, 16)),
                            ..Default::default()
                        })
                    }
                }
            },

            EncodingType::cond4_0_mem16 => {
                Encoding {
                    name: "c0_MM_MM",
                    length: 4,
                    encode: |isn, args| {
                        // foo
                        let cond = match args.op1.unwrap() {
                            Operand::Condition(cond) => cond.to_u8().unwrap(),
                            _ => unreachable!()
                        };
                        let mem = match args.op2.unwrap() {
                            Operand::Direct(mem, _) => mem,
                            _ => unreachable!()
                        };

                        Ok(vec![isn.id, cond << 4, (mem & 0x00FF) as u8, ((mem & 0xFF00) >> 8) as u8])
                    },
                    decode: |_isn, buf| {
                        match buf[1] & 0b00001111 {
                            0 => {
                                let condition : u8 = (buf[1] & 0b11110000) >> 4;

                                let slice = &buf[2..4];
                                let memory : u16 = LittleEndian::read_u16(slice);

                                Ok(InstructionArguments {
                                    op1: Some(Operand::Condition(OpCondition::from_u8(condition).unwrap())),
                                    op2: Some(Operand::Direct(memory, 16)),
                                    ..Default::default()
                                })
                            },
                            _ => Err("Invalid instruction")
                        }
                    }
                }
            },

            EncodingType::cond4_reg4 => {
                Encoding {
                    name: "cn",
                    length: 2,
                    encode: |isn, args| {
                        let cond = match args.op1.unwrap() {
                            Operand::Condition(cond) => cond,
                            _ => unreachable!()
                        };

                        let reg = match args.op2.unwrap() {
                            Operand::Indirect(reg) => reg.to_reg4().unwrap(),
                            _ => unreachable!()
                        };

                        Ok(vec![isn.id, (cond.to_u8().unwrap() << 4) | reg])
                    },
                    decode: |isn, buf| {
                        let condition : u8 = (buf[1] & 0b11110000) >> 4;
                        let register0 = buf[1] & 0b00001111;
                        let reg = get_reg4(&isn.op2.unwrap(), register0, register0);
                        Ok(InstructionArguments {
                            op1: Some(Operand::Condition(OpCondition::from_u8(condition).unwrap())),
                            op2: Some(reg),
                            ..Default::default()
                        })
                    }
                }
            },

            EncodingType::reg4_0 => {
                Encoding {
                    name: "n0",
                    length: 2,
                    encode: |isn, args| {
                        let reg0 = match args.op1.as_ref().unwrap() {
                            Operand::Register(reg) => reg.to_reg4().expect("Invalid GPR"),
                            _ => return Err("Invalid Operand 1")
                        };

                        Ok(vec![isn.id, reg0 << 4])

                    },
                    decode: |isn, buf| {
                        match buf[1] & 0b00001111 {
                            0 => {
                                let register0 = (buf[1] & 0b11110000) >> 4;

                                let op1 = get_reg4(isn.op1.as_ref().unwrap(), register0, register0);

                                Ok(InstructionArguments {
                                    op1: Some(op1),
                                    op2: None,
                                    ..Default::default()
                                })
                            },
                            _ => Err("Instruction was invalid, lower nibble must be zero")
                        }
                    }
                }
            },

            EncodingType::reg4_reg4 => {
                Encoding {
                    name: "nm",
                    length: 2,
                    encode: |isn, args| {
                        let op1_pos = match isn.op1.as_ref().unwrap() {
                            OperandType::ByteRegister(p) |
                            OperandType::WordRegister(p) |
                            OperandType::Indirect(p) |
                            OperandType::IndirectPostIncrement(p) |
                            OperandType::IndirectPreDecrement(p) => *p,
                            _ => unreachable!()
                        };

                        let reg0 = match args.op1.as_ref().unwrap() {
                            Operand::Indirect(reg) |
                            Operand::IndirectPostIncrement(reg) |
                            Operand::IndirectPreDecrement(reg) |
                            Operand::Register(reg) => reg.to_reg4().expect("Invalid register"),
                            _ => return Err("Invalid Operand 1")
                        };

                        let reg1 = match args.op2.as_ref().unwrap() {
                            Operand::Indirect(reg) |
                            Operand::IndirectPostIncrement(reg) |
                            Operand::IndirectPreDecrement(reg) |
                            Operand::Register(reg) => reg.to_reg4().expect("Invalid register"),
                            _ => return Err("Invalid Operand 2")
                        };

                        if op1_pos == 0 {
                            Ok(vec![isn.id, (reg0 << 4) | (reg1 & 0x0F) ])
                        } else {
                            Ok(vec![isn.id, (reg1 << 4) | (reg0 & 0x0F) ])
                        }
                    },
                    decode: |isn, buf| {
                        let register0 : u8 = (buf[1] & 0b11110000) >> 4;
                        let register1 : u8 = buf[1] & 0b00001111;

                        let op1 = get_reg4(isn.op1.as_ref().unwrap(), register0, register1);
                        let op2 = get_reg4(isn.op2.as_ref().unwrap(), register0, register1);

                        Ok(InstructionArguments {
                            op1: Some(op1),
                            op2: Some(op2),
                            ..Default::default()
                        })
                    }
                }
            },

            EncodingType::reg4_reg4_data16 => {
                Encoding {
                    name: "nm_II_II",
                    length: 4,
                    encode: |isn, args| {
                        let reg0 = match args.op1.unwrap() {
                            Operand::Register(reg) => reg.to_reg4().unwrap(),
                            _ => unreachable!()
                        };

                        let (reg1, immed) = match args.op2.unwrap() {
                            Operand::IndirectAndImmediate(reg, immed) => (reg.to_reg4().unwrap(), immed),
                            _ => unreachable!()
                        };

                        Ok(vec![isn.id, (reg0 << 4) | (reg1 & 0x0F), (immed & 0x00FF) as u8, ((immed & 0xFF00) >> 8) as u8 ])
                    },
                    decode: |isn, buf| {
                        let register0 : u8 = (buf[1] & 0b11110000) >> 4;
                        let register1 : u8 = buf[1] & 0b00001111;

                        let slice = &buf[2..4];
                        let data : u16 = LittleEndian::read_u16(slice);

                        let val1 = get_reg4(isn.op1.as_ref().unwrap(), register0, register1);
                        let val2 = get_reg4(isn.op2.as_ref().unwrap(), register0, register1);

                        let op1 = match val1 {
                            Operand::IndirectAndImmediate(r, _) => {
                                let reg: Reg = r.clone();
                                Operand::IndirectAndImmediate(reg, data)
                            }                            ,
                            _ => val1
                        };

                        let op2 = match val2 {
                            Operand::IndirectAndImmediate(r, _) => {
                                let reg: Reg = r.clone();
                                Operand::IndirectAndImmediate(reg, data)
                            }                            ,
                            _ => val2
                        };

                        Ok(InstructionArguments {
                            op1: Some(op1),
                            op2: Some(op2),
//                            immediate: Some(data),
                            ..Default::default()
                        })
                    }
                }
            },

            EncodingType::reg4_dup => {
                Encoding {
                    name: "nn",
                    length: 2,
                    encode: |isn, args| {
                        let reg0 = match args.op1.as_ref().unwrap() {
                            Operand::Register(reg) => reg.to_reg4().expect("Invalid GPR"),
                            _ => return Err("Invalid Operand 1")
                        };

                        Ok(vec![isn.id, (reg0 << 4) | (reg0 & 0x0F) ])
                    },
                    decode: |isn, buf| {
                        let lower : u8 = buf[1] & 0b00001111;
                        let upper : u8 = (buf[1] & 0b11110000) >> 4;

                        if lower == upper {
                            let register0 : u8 = lower;

                            let op1 = get_reg4(isn.op1.as_ref().unwrap(), lower, upper);

                            Ok(InstructionArguments {
                                op1: Some(op1),
                                op2: None,
                                ..Default::default()
                            })
                        } else {
                            Err("Instruction was invalid. Encoding requires upper and lower nibbles must be equal.")
                        }
                    }
                }
            },

            EncodingType::rel8s => {
                Encoding {
                    name: "rr",
                    length: 2,
                    encode: |isn, args| {
                        let relative = match args.op1.unwrap() {
                            // TODO: This should be based on PC or something
                            Operand::Direct(rel, width) => {
                                if width != 8 {
                                    eprintln!("Relative address should be an i8, got {} bits", width);
                                }
                                if rel > <i8>::max_value() as u16 {
                                    return Err("rel8s encoding is an i8, got value which exceeds 8 bits")
                                }
                                rel as u8
                            },
                            _ => return Err("rel8s encoding needs a relative address operand")
                        };

                        Ok(vec![isn.id, relative / 2 ])
                    },
                    decode: |_isn, buf| {
                        let relative : u8 = buf[1];

                        Ok(InstructionArguments {
                            op1: Some(Operand::Direct(relative as u16, 8)),
                            op2: None,
                            ..Default::default()
                        })
                    }
                }
            },

            EncodingType::trap7 => {
                Encoding {
                    name: "trap7",
                    length: 2,
                    encode: |isn, args| {
                        match args.op1.as_ref().unwrap() {
                            Operand::Immediate(imm, _width) => Ok(vec![isn.id, (*imm as u8) << 1]),
                            _ => Err("Invalid Operand")
                        }

                    },
                    decode: |_isn, buf| {
                        let trap : u8 = (buf[1] & 0b11111110) >> 1;

                        Ok(InstructionArguments {
                            op1: Some(Operand::Immediate(trap as u16, 7)),
                            op2: None,
                            ..Default::default()
                        })
                    }
                }
            }
        }
    }
}
