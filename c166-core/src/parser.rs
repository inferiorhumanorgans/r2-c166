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

use nom::*;
use std::str;
use std::str::FromStr;
use std::convert::TryFrom;
use std::collections::HashMap;

use ::instruction::*;
use ::reg::*;
use ::encoding::*;

#[derive(Debug)]
pub struct AsmOperation<'a> {
    pub mnem: &'a str,
    pub operands: Vec<Operand>
}

fn is_digit_s(chr: char) -> bool {
  chr as u8 >= 0x30 && chr as u8 <= 0x39
}

fn is_hex_digit_s(c: char) -> bool {
  match c {
    '0'..='9' | 'a'..='f' | 'A'..='F' => true,
    _ => false,
  }
}

fn is_alphabetic_s(chr: char) -> bool {
  (chr as u8 >= 0x41 && chr as u8 <= 0x5A) || (chr as u8 >= 0x61 && chr as u8 <= 0x7A)
}

fn is_alphanumeric_s(chr: char) -> bool {
  is_alphabetic_s(chr) || is_digit_s(chr)
}

// Per the nom source since we don't want to trim newlines
//  (you never know, r2 could pass in a whole buffer at once)
named!(pub space(&str) -> &str, eat_separator!(&" \t"[..]));

macro_rules! sp (
  ($i:expr, $($args:tt)*) => (
    {
      use nom::Convert;
      use nom::Err;

      match sep!($i, space, $($args)*) {
        Err(e) => Err(e),
        Ok((i1,o))    => {
          match space(i1) {
            Err(e) => Err(Err::convert(e)),
            Ok((i2,_))    => Ok((i2, o))
          }
        }
      }
    }
  )
);

// TODO: Validate list of instruction mnemonics
named!(mnemonic(&str) -> &str,
    do_parse!(
        mnem: take_while1!(is_alphanumeric_s) >>
        (mnem)
    )
);

named!(op_condition(&str) -> Operand,
    do_parse!(
        cond: recognize!(
            preceded!(
                tag_s!("cc_"),
                take_while1!(is_alphanumeric_s)
            )
        ) >>
        (
            Operand::Condition(OpCondition::from_str(cond).unwrap())
        )
    )
);


named!(op_word_gpr(&str) -> Operand,
    do_parse!(
        register: recognize!(
            preceded!(
                tag_s!("r"),
                take_while_m_n!(1, 2, is_digit_s)
            )
        ) >>
        (
            Operand::Register(Reg::from_str(register).unwrap())
        )
    )
);

named!(op_byte_gpr(&str) -> Operand,
    do_parse!(
        register: recognize!(
            preceded!(
                alt!(tag_s!("rl") | tag_s!("rh")),
                take_while_m_n!(1, 1, is_digit_s)
            )
        ) >>
        (
            Operand::Register(Reg::from_str(register).unwrap())
        )
    )
);

// TODO: Validate list of register mnemonics
named!(op_reg(&str) -> Operand,
    do_parse!(
        register: take_while1!(is_alphanumeric_s) >>
        (
            Operand::Register(Reg::from_str(register).unwrap())
        )
    )
);

named!(op_direct(&str) -> Operand,
    do_parse!(
        direct: terminated!(take_while1!(is_hex_digit_s), tag_s!("h")) >>
        (
            Operand::Direct(u16::from_str_radix(direct, 16).unwrap(), 0)
        )
    )
);

named!(op_immediate_hex(&str) -> Operand,
    do_parse!(
        immed: delimited!(
            tag_s!("#"),
            take_while1!(is_hex_digit_s),
            tag_s!("h")
        ) >>
        (
            Operand::Immediate(u16::from_str_radix(immed, 16).unwrap(), 0)
        )
    )
);

named!(op_immediate_dec(&str) -> Operand,
    do_parse!(
        immed: preceded!(tag_s!("#"), take_while_m_n!(1, 1, is_digit_s)) >>
        (
            Operand::Immediate(immed.parse::<u8>().unwrap() as u16, 4)
        )
    )
);

named!(op_immediate(&str) -> Operand,
    do_parse!(
        immed: alt!(op_immediate_hex | op_immediate_dec) >>
        (
            immed
        )
    )
);

named!(op_indirect(&str) -> Operand,
    do_parse!(
        register: delimited!(
            tag_s!("["),
            sp!(alt!(op_word_gpr | op_byte_gpr)),
            tag_s!("]")
        ) >>
        (
            match register {
                Operand::Register(r) => Operand::Indirect(r),
                _ => unreachable!()
            }
        )
    )
);

named!(op_indirect_inc(&str) -> Operand,
    do_parse!(
        register: delimited!(
            tag_s!("["),
            sp!(alt!(op_word_gpr | op_byte_gpr)),
            tag_s!("+]")
        ) >>
        (
            match register {
                Operand::Register(r) => Operand::IndirectPostIncrement(r),
                _ => unreachable!()
            }
        )
    )
);

named!(op_indirect_dec(&str) -> Operand,
    do_parse!(
        register: delimited!(
            tag_s!("[-"),
            sp!(alt!(op_word_gpr | op_byte_gpr)),
            tag_s!("]")
        ) >>
        (
            match register {
                Operand::Register(r) => Operand::IndirectPreDecrement(r),
                _ => unreachable!()
            }
        )
    )
);

named!(op_indirect_imm(&str) -> Operand,
    do_parse!(
        tag_s!("[") >>
        register: sp!(alt!(op_word_gpr | op_byte_gpr)) >>
        sp!(tag_s!("+")) >>
        immediate: sp!(op_immediate) >>
        tag_s!("]") >>
        (
            match register {
                Operand::Register(r) => {
                    Operand::IndirectAndImmediate(
                        r,
                        match immediate {
                            Operand::Immediate(d, _width) => d,
                            _ => unreachable!()
                        }
                    )
                },
                _ => unreachable!()
            }
        )
    )
);

fn get_reg8(op: Operand) -> u8 {
    match op {
        Operand::Register(reg) => reg.to_reg8().unwrap(),
        _ => unreachable!()
    }
}

fn get_bitaddr(bitname: &str, bitpos: &str) -> Operand {
    let pos: u8 = bitpos.parse::<u8>().expect("Bit position must be a valid base-10 number");
    match u16::from_str_radix(&bitname[0..bitname.len()-1], 16) {
        Ok(addr) => {
            match addr {
                0xFD00..=0xFDFE => {
                    // RAM
                    let short_addr: u8 = ((addr - 0xFD00) / 2) as u8;
                    Operand::BitAddr(short_addr, pos)
                },
                0xFF00..=0xFFDE => {
                    // SFR
                    eprintln!("Maybe consider referencing SFR by mnemonic?");
                    let short_addr: u8 = (((addr - 0xFF00)/2) + 0x80) as u8;
                    Operand::BitAddr(short_addr, pos)
                },
                0xF100..=0xF1DE => {
                    // ESFR
                    eprintln!("Maybe consider referencing ESFR by mnemonic?");
                    let short_addr: u8 = (((addr - 0xF100)/2) + 0x80) as u8;
                    Operand::BitAddr(short_addr, pos)
                },
                // TODO: Grab CP and see if we're attempting to frob GPRs directly
                _ => unreachable!()
            }
        },
        Err(_) => {
            let register = Operand::Register(Reg::from_str(bitname).unwrap());
            Operand::BitAddr(get_reg8(register), pos)
        }
    }
}

// TODO: Handle numeric bitoffs
named!(op_bitaddr(&str) -> Operand,
    do_parse!(
        bitname: take_while1!(is_alphanumeric_s) >>
        tag_s!(".") >>
        bit: take_while_m_n!(1, 2, is_digit_s) >>
        (
            get_bitaddr(bitname, bit)
        )
    )
);

named!(operand(&str) -> Operand,
    alt!(
        op_bitaddr      |
        op_direct       |
        op_immediate    |
        op_indirect     |
        op_indirect_inc |
        op_indirect_dec |
        op_indirect_imm |
        op_condition    |
        op_byte_gpr     |
        op_word_gpr     |
        op_reg
    )
);

named!(pub asm_line(&str) -> AsmOperation,
    do_parse!(
        mnem: mnemonic >>
        operands: separated_list_complete!(
            tag!(","),
            sp!(operand)
        ) >>
        alt!(line_ending | tag!("\0")) >>
        (AsmOperation {
            mnem: mnem,
            operands: operands
        })
    )
);

pub fn asm_lines(input: &str) -> IResult<&str, Vec<AsmOperation>> {
    let mut buf = &input[..];
    let mut ops: Vec<AsmOperation> = Vec::new();

    while buf.len() > 0 {
        // eprintln!("Buf: {:?}", buf);
        match asm_line(buf) {
            Ok((remainder, asmop)) => {
                ops.push(asmop);
                buf = remainder;
            },
            _ => break
        };
    }

    Ok((buf, ops))
}

pub fn operation_to_bytes<'a>(asm: &AsmOperation) -> Result<Vec<u8>, &'a str> {
    let panic_on_bad_op: bool = false;
    let mut op_lut: HashMap<&str, Vec<Instruction>> = HashMap::new();

    for id in 0..=0xFF {
        match Instruction::try_from(id) {
            Ok(op) => {
                let mut op_table = &mut op_lut.entry(op.mnemonic).or_insert_with(|| Vec::new());
                op_table.push(op);
            },
            _ => {}
        }
    }

    let mut encode_op: Option<&Instruction> = None;
    let mut args = InstructionArguments {
        ..Default::default()
    };

    match asm.operands.len() {
        0 => {
            let lut = op_lut.get(asm.mnem).expect("Invalid mnemonic");

            args.mnemonic = Some(asm.mnem.to_string());

            for isn in lut {
                match isn.encoding {
                    EncodingType::NO_ARGS2 |
                    EncodingType::NO_ARGS4 => {
                        encode_op = Some(&isn);
                        break;
                    },
                    _ => {}
                }
            }
        },
        1 => {
            let lut = match asm.mnem {
                "atomic" | "extr" => op_lut.get("atomic_extr").expect("Invalid mnemonic"),
                _ => op_lut.get(asm.mnem).expect("Invalid mnemonic")
            };

            args.mnemonic = Some(asm.mnem.to_string());

            for isn in lut {
                let op1 = asm.operands[0];
                match (&isn.encoding, op1) {
                    (EncodingType::op_d1, irange @ Operand::Immediate(_, _)) => {
                        args.op1 = Some(irange);
                        encode_op = Some(&isn);
                        break;
                    },
                        (EncodingType::reg4_0, reg @Operand::Register(_)) |
                    (EncodingType::reg4_dup, reg @ Operand::Register(_)) => {
                        args.op1= Some(reg);
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::reg8, Operand::Register(r)) => {
                        if !r.is_word_register() {
                            continue;
                        }
                        args.op1 = Some(op1);
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::rel8s, Operand::Direct(_, _)) => {
                        match isn.op1.as_ref().unwrap() {
                            OperandType::DirectRelative8S => {
                                args.op1 = Some(op1);
                                encode_op = Some(&isn);
                                break;
                            },
                            _ => continue
                        }
                    }
                    (EncodingType::trap7, Operand::Immediate(_, _)) => {
                        args.op1 = Some(op1);
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::bitopcode4_e_bitaddr8, Operand::BitAddr(_, _)) |
                    (EncodingType::bitopcode4_f_bitaddr8, Operand::BitAddr(_, _)) => {
                        args.op1 = Some(op1);
                        encode_op = Some(&isn);
                        break;
                    },
                    _ => {}
                }
            }
        },
        2 => {
            let lut = match asm.mnem {
                "extp" | "extpr" | "exts" | "extsr" => op_lut.get("ext*").expect("Invalid mnemonic"),
                _ => op_lut.get(asm.mnem).expect("Invalid mnemonic")
            };

            args.mnemonic = Some(asm.mnem.to_string());
            for isn in lut {
                match (&isn.encoding, isn.op1.as_ref().unwrap(), &asm.operands[0], isn.op2.as_ref().unwrap(), &asm.operands[1]) {
                    (EncodingType::op_d7, &OperandType::ImmediateData4, immed @ &Operand::Immediate(_, _), &OperandType::ImmediateIrange2, irange @ &Operand::Immediate(_, _)) => {
                        args.op1 = Some(*immed);
                        args.op2 = Some(*irange);
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::op_dc, &OperandType::WordRegister(_), reg @ &Operand::Register(_), &OperandType::ImmediateIrange2, irange @ &Operand::Immediate(_, _)) => {
                        args.op1 = Some(*reg);
                        args.op2 = Some(*irange);
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::reg4_or_data3, reg_type @ &OperandType::ByteRegister(_), reg @ &Operand::Register(_), &OperandType::ImmediateData3, op2 @ &Operand::Indirect(_)) |
                    (EncodingType::reg4_or_data3, reg_type @ &OperandType::ByteRegister(_), reg @ &Operand::Register(_), &OperandType::ImmediateData3, op2 @ &Operand::IndirectPostIncrement(_)) |
                    (EncodingType::reg4_or_data3, reg_type @ &OperandType::ByteRegister(_), reg @ &Operand::Register(_), &OperandType::ImmediateData3, op2 @ &Operand::Immediate(_, _)) |
                    (EncodingType::reg4_or_data3, reg_type @ &OperandType::WordRegister(_), reg @ &Operand::Register(_), &OperandType::ImmediateData3, op2 @ &Operand::Indirect(_)) |
                    (EncodingType::reg4_or_data3, reg_type @ &OperandType::WordRegister(_), reg @ &Operand::Register(_), &OperandType::ImmediateData3, op2 @ &Operand::IndirectPostIncrement(_)) |
                    (EncodingType::reg4_or_data3, reg_type @ &OperandType::WordRegister(_), reg @ &Operand::Register(_), &OperandType::ImmediateData3, op2 @ &Operand::Immediate(_, _)) => {
                        match (reg_type, reg) {
                            (OperandType::ByteRegister(_), Operand::Register(reg)) if reg.is_byte_register() => {},
                            (OperandType::WordRegister(_) , Operand::Register(reg)) if reg.is_word_register() => {},
                            _ => continue
                        };

                        match op2 {
                            Operand::Register(r) |
                            Operand::Indirect(r) |
                            Operand::IndirectPostIncrement(r) => {
                                if r.to_reg4().unwrap() > 0b11 {
                                    continue;
                                }
                            },
                            _ => continue
                        }

                        args.op1 = Some(*reg);
                        args.op2 = Some(*op2);
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::condopcode4_d_rel8s, &OperandType::Condition, cond @ &Operand::Condition(_), &OperandType::DirectRelative8S, rel @ &Operand::Direct(_, _)) => {
                        args.op1 = Some(*cond);
                        args.op2 = Some(*rel);
                        encode_op =Some(&isn);
                        break;
                    },
                    (EncodingType::cond4_reg4, &OperandType::Condition, cond @ &Operand::Condition(_), &OperandType::Indirect(_), reg @ &Operand::Indirect(_)) => {
                        args.op1 = Some(*cond);
                        args.op2 = Some(*reg);
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::cond4_0_mem16, &OperandType::Condition, cond @ &Operand::Condition(_), &OperandType::DirectCaddr16, addr @ Operand::Direct(_, _)) => {
                        args.op1 = Some(*cond);
                        args.op2 = Some(*addr);
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::bitaddr8_rel8_bit4_0, &OperandType::BitAddr(_), bitaddr @ &Operand::BitAddr(_, _), &OperandType::DirectRelative8S, direct @ &Operand::Direct(_, _)) => {
                        args.op1 = Some(*bitaddr);
                        args.op2 = Some(*direct);
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::bitaddr8_bitaddr8_bit4_bit4, &OperandType::BitAddr(_), bitaddr0 @ &Operand::BitAddr(_, _), &OperandType::BitAddr(_), bitaddr1 @ &Operand::BitAddr(_, _)) => {
                        args.op1 = Some(*bitaddr0);
                        args.op2 = Some(*bitaddr1);
                        encode_op = Some(&isn);
                    }
                    (EncodingType::_f_reg4_mem16, reg_type @ &OperandType::WordRegister(_), reg @ &Operand::Register(_), &OperandType::DirectMemory16, direct @ &Operand::Direct(_, _)) => {
                        match (reg_type, reg) {
                            (OperandType::ByteRegister(_), Operand::Register(reg)) if reg.is_byte_register() => {},
                            (OperandType::WordRegister(_) , Operand::Register(reg)) if reg.is_word_register() => {},
                            _ => continue
                        };

                        args.op1= Some(*reg);
                        args.op2= Some(*direct);
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::reg4_data4, reg_type @ &OperandType::ByteRegister(_), reg @ &Operand::Register(_), &OperandType::ImmediateData4, &Operand::Immediate(immed,_)) |
                    (EncodingType::reg4_data4, reg_type @ &OperandType::WordRegister(_), reg @ &Operand::Register(_), &OperandType::ImmediateData4, &Operand::Immediate(immed,_)) |
                    (EncodingType::reg4_data4, &OperandType::ImmediateData4, &Operand::Immediate(immed,_), reg_type @ &OperandType::ByteRegister(_), reg @ &Operand::Register(_)) |
                    (EncodingType::reg4_data4, &OperandType::ImmediateData4, &Operand::Immediate(immed,_), reg_type @ &OperandType::WordRegister(_), reg @ &Operand::Register(_)) => {
                        match (reg_type, reg) {
                            (OperandType::ByteRegister(_), Operand::Register(reg)) if reg.is_byte_register() => {},
                            (OperandType::WordRegister(_) , Operand::Register(reg)) if reg.is_word_register() => {},
                            _ => continue
                        };

                        if immed > 0b00001111 {
                            continue;
                        }

                        args.op1= Some(*reg);
                        args.op2= Some(Operand::Immediate(immed, 4));
                        encode_op = Some(&isn);
                        break;
                    },
                    (reg4_reg4, reg_type0 @ &OperandType::Indirect(_), reg0 @ &Operand::Indirect(_), reg_type1 @ &OperandType::Indirect(_), reg1 @ &Operand::Indirect(_)) |
                    (reg4_reg4, reg_type0 @ &OperandType::IndirectPostIncrement(_), reg0 @ &Operand::IndirectPostIncrement(_), reg_type1 @ &OperandType::Indirect(_), reg1 @ &Operand::Indirect(_)) |
                    (reg4_reg4, reg_type0 @ &OperandType::Indirect(_), reg0 @ &Operand::Indirect(_), reg_type1 @ &OperandType::IndirectPostIncrement(_), reg1 @ &Operand::IndirectPostIncrement(_)) => {
                        args.op1= Some(*reg0);
                        args.op2= Some(*reg1);
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::reg4_reg4, reg_type0 @ &OperandType::IndirectPreDecrement(_), reg0 @ &Operand::IndirectPreDecrement(_), reg_type1 @ &OperandType::ByteRegister(_), reg1 @ &Operand::Register(_)) |
                    (EncodingType::reg4_reg4, reg_type0 @ &OperandType::IndirectPreDecrement(_), reg0 @ &Operand::IndirectPreDecrement(_), reg_type1 @ &OperandType::WordRegister(_), reg1 @ &Operand::Register(_)) |
                    (EncodingType::reg4_reg4, reg_type0 @ &OperandType::Indirect(_), reg0 @ &Operand::Indirect  (_), reg_type1 @ &OperandType::ByteRegister(_), reg1 @ &Operand::Register(_)) |
                    (EncodingType::reg4_reg4, reg_type0 @ &OperandType::Indirect(_), reg0 @ &Operand::Indirect  (_), reg_type1 @ &OperandType::WordRegister(_), reg1 @ &Operand::Register(_)) |
                    (EncodingType::reg4_reg4, reg_type0 @ &OperandType::ByteRegister(_), reg0 @ &Operand::Register(_), reg_type1 @ &OperandType::Indirect(_), reg1 @ &Operand::Indirect(_)) |
                    (EncodingType::reg4_reg4, reg_type0 @ &OperandType::ByteRegister(_), reg0 @ &Operand::Register(_), reg_type1 @ &OperandType::IndirectPostIncrement(_), reg1 @ &Operand::IndirectPostIncrement(_)) |
                    (EncodingType::reg4_reg4, reg_type0 @ &OperandType::WordRegister(_), reg0 @ &Operand::Register(_), reg_type1 @ &OperandType::Indirect(_), reg1 @ &Operand::Indirect(_)) |
                    (EncodingType::reg4_reg4, reg_type0 @ &OperandType::WordRegister(_), reg0 @ &Operand::Register(_), reg_type1 @ &OperandType::IndirectPostIncrement(_), reg1 @ &Operand::IndirectPostIncrement(_)) |
                    (EncodingType::reg4_reg4, reg_type0 @ &OperandType::ByteRegister(_), reg0 @ &Operand::Register(_), reg_type1 @ &OperandType::ByteRegister(_), reg1 @ &Operand::Register(_)) |
                    (EncodingType::reg4_reg4, reg_type0 @ &OperandType::WordRegister(_), reg0 @ &Operand::Register(_), reg_type1 @ &OperandType::WordRegister(_), reg1 @ &Operand::Register(_)) |
                    (EncodingType::reg4_reg4, reg_type0 @ &OperandType::WordRegister(_), reg0 @ &Operand::Register(_), reg_type1 @ &OperandType::ByteRegister(_), reg1 @ &Operand::Register(_)) => {
                        match (reg_type0, reg0) {
                            (OperandType::ByteRegister(_), Operand::Register(reg)) if reg.is_byte_register() => {},
                            (OperandType::WordRegister(_) , Operand::Register(reg)) if reg.is_word_register() => {},
                            (OperandType::Indirect(_), Operand::Indirect(reg)) if reg.is_word_register() => {},
                            (OperandType::IndirectPreDecrement(_), Operand::IndirectPreDecrement(reg)) if reg.is_word_register() => {},
                            (OperandType::IndirectPostIncrement(_), Operand::IndirectPostIncrement(reg)) if reg.is_word_register() => {},
                            _ => continue
                        };

                        match (reg_type1, reg1) {
                            (OperandType::ByteRegister(_), Operand::Register(reg)) if reg.is_byte_register() => {},
                            (OperandType::WordRegister(_) , Operand::Register(reg)) if reg.is_word_register() => {},
                            (OperandType::Indirect(_), Operand::Indirect(reg)) if reg.is_word_register() => {},
                            (OperandType::IndirectPreDecrement(_), Operand::IndirectPreDecrement(reg)) if reg.is_word_register() => {},
                            (OperandType::IndirectPostIncrement(_), Operand::IndirectPostIncrement(reg)) if reg.is_word_register() => {},
                            _ => continue
                        };

                        args.op1= Some(*reg0);
                        args.op2= Some(*reg1);
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::_0_reg4_mem16, ind_type @ &OperandType::Indirect(_), reg @ &Operand::Indirect(_), &OperandType::DirectMemory16, direct @ &Operand::Direct(_, _)) |
                    (EncodingType::_0_reg4_mem16, &OperandType::DirectMemory16, direct @ &Operand::Direct(_, _), ind_type @ &OperandType::Indirect(_), reg @ &Operand::Indirect(_)) => {
                        args.op1 = Some(*reg);
                        args.op2 = Some(*direct);
                        encode_op = Some(&isn);
                        break;
                    }
                    (EncodingType::_f_reg4_data16, reg_type @ &OperandType::WordRegister(_), reg @ &Operand::Register(_), &OperandType::ImmediateData16, immed @ &Operand::Immediate(_, _)) => {
                        match (reg_type, reg) {
                            (OperandType::ByteRegister(_), Operand::Register(reg)) if reg.is_byte_register() => {},
                            (OperandType::WordRegister(_) , Operand::Register(reg)) if reg.is_word_register() => {},
                            _ => continue
                        };

                        args.op1 = Some(*reg);
                        args.op2 = Some(*immed);
                        encode_op = Some(&isn);
                        break;
                    }
                    (EncodingType::reg4_reg4_data16, reg_type @ &OperandType::ByteRegister(_), reg @ &Operand::Register(_), &OperandType::IndirectAndImmediate (_), ind @ &Operand::IndirectAndImmediate(_, _)) |
                    (EncodingType::reg4_reg4_data16, reg_type @ &OperandType::WordRegister(_), reg @ &Operand::Register(_), &OperandType::IndirectAndImmediate (_), ind @ &Operand::IndirectAndImmediate(_, _)) |
                    (EncodingType::reg4_reg4_data16, &OperandType::IndirectAndImmediate (_), ind @ &Operand::IndirectAndImmediate(_, _), reg_type @ &OperandType::ByteRegister(_), reg @ &Operand::Register(_)) |
                    (EncodingType::reg4_reg4_data16, &OperandType::IndirectAndImmediate (_), ind @ &Operand::IndirectAndImmediate(_, _), reg_type @ &OperandType::WordRegister(_), reg @ &Operand::Register(_)) => {
                        match (reg_type, reg) {
                            (OperandType::ByteRegister(_), Operand::Register(reg)) if reg.is_byte_register() => {},
                            (OperandType::WordRegister(_) , Operand::Register(reg)) if reg.is_word_register() => {},
                            _ => continue
                        };

                        args.op1 = Some(*reg);
                        args.op2 = Some(*ind);
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::reg8_data8_nop8, reg_type @ &OperandType::ByteRegister(_), reg @ &Operand::Register(_), &OperandType::ImmediateData8, &Operand::Immediate(imm, width)) |
                    (EncodingType::reg8_data8_nop8, reg_type @ &OperandType::WordRegister(_), reg @ &Operand::Register(_), &OperandType::ImmediateData8, &Operand::Immediate(imm, width)) |
                    (EncodingType::reg8_data16, reg_type @ &OperandType::ByteRegister(_), reg @ &Operand::Register(_), &OperandType::ImmediateData16, &Operand::Immediate(imm, width)) |
                    (EncodingType::reg8_data16, reg_type @ &OperandType::WordRegister(_), reg @ &Operand::Register(_), &OperandType::ImmediateData16, &Operand::Immediate(imm, width)) => {
                        match (reg_type, reg) {
                            (OperandType::ByteRegister(_), Operand::Register(reg)) if reg.is_byte_register() => {},
                            (OperandType::WordRegister(_) , Operand::Register(reg)) if reg.is_word_register() => {},
                            _ => continue
                        };

                        // TODO: Make this less gross
                        // Hope for a data3 variant
                        if imm <= 0b111 {
                            continue;
                        }

                        args.op1 = Some(asm.operands[0]);
                        args.op2 = Some(asm.operands[1]);
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::reg8_mem16, &OperandType::DirectMemory16, &Operand::Direct(dir, width), reg_type @ &OperandType::ByteRegister(_), reg @ &Operand::Register(_)) |
                    (EncodingType::reg8_mem16, &OperandType::DirectMemory16, &Operand::Direct(dir, width), reg_type @ &OperandType::WordRegister(_), reg @ &Operand::Register(_)) |
                    (EncodingType::reg8_mem16, reg_type @ &OperandType::ByteRegister(_), reg @ &Operand::Register(_), &OperandType::DirectMemory16, &Operand::Direct(dir, width)) |
                    (EncodingType::reg8_mem16, reg_type @ &OperandType::WordRegister(_), reg @ &Operand::Register(_), &OperandType::DirectCaddr16, &Operand::Direct(dir, width)) |
                    (EncodingType::reg8_mem16, reg_type @ &OperandType::WordRegister(_), reg @ &Operand::Register(_), &OperandType::DirectMemory16, &Operand::Direct(dir, width)) => {
                        match (reg_type, reg) {
                            (OperandType::ByteRegister(_), Operand::Register(reg)) if reg.is_byte_register() => {},
                            (OperandType::WordRegister(_) , Operand::Register(reg)) if reg.is_word_register() => {},
                            _ => continue
                        };

                        args.op1 = Some(*reg);
                        args.op2 = Some(Operand::Direct(dir, 16));
                        encode_op = Some(&isn);
                        break;
                    },
                    (EncodingType::seg8_mem16, &OperandType::DirectSegment8, seg @ &Operand::Direct(_, _), &OperandType::DirectCaddr16, caddr @ &Operand::Direct(_, _)) => {
                        args.op1 = Some(*seg);
                        args.op2 = Some(*caddr);
                        encode_op = Some(&isn);
                        break;
                    }
                    _ => {}
                }
            }
        },
        3 => {
            let lut = op_lut.get(asm.mnem).expect("Invalid mnemonic");
            for isn in lut {
                match &isn.encoding {
                    EncodingType::bitoff8_mask8_data8 => {
                        args.op1 = Some(asm.operands[0]);
                        args.op2 = Some(asm.operands[1]);
                        args.op3 = Some(asm.operands[2]);
                        encode_op = Some(&isn);
                        break;
                    },
                    _ => return Err("we should only have one ternary encoding")
                }
            }
        },
        _ => unreachable!()
    }
    match encode_op {
        Some(isn) => {
            let encoding = Encoding::from(&isn.encoding);
            let mut ret: Vec<u8> = (encoding.encode)(&isn, &args).expect("Encoding failure");
            Ok(ret)
        },
        None => Err("No suitable encoding found")
    }
}
