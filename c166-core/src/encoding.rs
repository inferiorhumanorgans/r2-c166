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
use byteorder::{LittleEndian};

#[allow(non_camel_case_types)]
pub enum EncodingType {
    NO_ARGS2,	// NO_ARGS
    NO_ARGS4,	// NO_ARGS
    In,	        // #n
    _0n_MM_MM,	// 0n MM MM
    cc_rr,	    // JMPR
    ext_d7,
    ext_dc,
    data3_or_reg,
    atomic_extr,// :00##-0
    Fn_II_II,   // Fn ## ##
    Fn_MM_MM,	// Fn MM MM
    q_QQ,	    // QQ
    QQ_AA_II,	// QQ @@ ##
    QQ_ZZ_qz,	// QQ ZZ qz
    QQ_rr_q0,	// QQ rr q0
    RR,	        // RR
    RR_II_II,	// RR ## ##
    RR_II_xx,	// RR ## xx
    RR_MM_MM,	// RR MM MM
    SS_MM_MM,   // SS MM MM
    c0_MM_MM,	// c0 MM MM
    cn,	        // cn
    mn,	        // mn
    n0,	        // n0
    nbit10ii,	// n:10ii
    nbit11ii,	// n:11ii
    nm,	        // nm
    nm_II_II,	// nm ## ##
    nn,	        // nn
    rr,	        // rr
    trap7,	    // t:ttt0
}

#[derive(Default)]
pub struct InstructionArguments {
    pub bit0 : Option<u8>,
    pub bit1 : Option<u8>,
    pub bitoff0 : Option<u8>,
    pub bitoff1 : Option<u8>,
    pub condition : Option<u8>,
    pub data   : Option<u16>,
    pub irange : Option<u8>,
    pub mask : Option<u8>,
    pub memory : Option<u16>,
    pub mnemonic : Option<String>,
    pub page : Option<u16>,
    pub register0 : Option<u8>,
    pub register1 : Option<u8>,
    pub relative : Option<u8>,
    pub segment : Option<u8>,
    pub sub_op : Option<u8>,
    pub trap : Option<u8>
}

pub struct Encoding {
    pub name : &'static str,
    pub length : i32,
    pub decode : fn(&[u8]) -> Result<InstructionArguments, &'static str>
}

impl Encoding {
    pub fn from_encoding_type(encoding_type: &EncodingType) -> Result<Encoding, &'static str> {
        match encoding_type {
            EncodingType::NO_ARGS2 => {
                Ok(Encoding {
                    name: "NO_ARGS2",
                    length: 2,
                    decode: |buf| {
                        match &buf[0..2] {
                            [0xDB, 0x00] |
                            [0xFB, 0x88] |
                            [0xCB, 0x00] |
                            [0xCC, 0x00] => Ok(InstructionArguments {..Default::default()}),
                            _ => Err("Invalid instruction")
                        }
                    }
                })
            },

            EncodingType::NO_ARGS4 => {
                Ok(Encoding {
                    name: "NO_ARGS4",
                    length: 4,
                    decode: |buf| {
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
                })
            },

            EncodingType::In => {
                Ok(Encoding {
                    name: "In",
                    length: 2,
                    decode: |buf| {
                        let register0 : u8 = buf[1] & 0b00001111;
                        let data : u8 = (buf[1] & 0b11110000) >> 4;

                        Ok(InstructionArguments {
                            data: Some(data as u16),
                            register0: Some(register0),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::_0n_MM_MM => {
                Ok(Encoding {
                    name: "_0n_MM_MM",
                    length: 4,
                    decode: |buf| {
                        match buf[1] & 0b11110000 {
                            0 => {
                                let register0 : u8 = buf[1] & 0b00001111;

                                let slice = &buf[2..4];
                                let memory : u16 = LittleEndian::read_u16(slice);

                                Ok(InstructionArguments {
                                    register0: Some(register0),
                                    memory: Some(memory),
                                    ..Default::default()
                                })
                            },
                            _ => Err("Invalid instruction")
                        }
                    }
                })
            },

            EncodingType::cc_rr => {
                Ok(Encoding {
                    name: "cc_rr",
                    length: 2,
                    decode: |buf| {
                        let condition : u8 = (buf[0] & 0b11110000) >> 4;
                        let relative : u8 = buf[1];

                        Ok(InstructionArguments {
                            condition: Some(condition),
                            relative: Some(relative),
                            ..Default::default()
                        })
                   }
                })
            },

            EncodingType::ext_d7 => {
                Ok(Encoding {
                    name: "ext_d7",
                    length: 4,
                    decode: |buf| {
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
                            return Err("Instruction was invalid")
                        }

                        let mut values = InstructionArguments {
                            mnemonic: Some(mnem.to_string()),
                            sub_op: Some(sub_op),
                            irange: Some(irange),
                            ..Default::default()
                        };

                        match (buf[1] & 0b11000000) >> 6 {
                            0b10 | 0b00 => {
                                // Seg op
                                match buf[3] {
                                    0x00 => {
                                        values.segment = Some(buf[2]);
                                    },
                                    _    => return Err("Instruction was invalid")
                                }
                            },
                            0b11 | 0b01 => {
                                // Page is 10 bits so the top 6 bits of byte 3 need to be zero
                                match (buf[3] & 0b11111100) >> 2 {
                                    0x00 => {
                                        let page : u16 = ((buf[3] & 0b00000011) as u16) << 8 | buf[2] as u16;
                                        values.page = Some(page);
                                    },
                                    _    => return Err("Instruction was invalid")
                                }
                            },
                            _ => unreachable!()
                        }

                        Ok(values)
                    }
                })
            },

            EncodingType::ext_dc => {
                Ok(Encoding {
                    name: "ext_dc",
                    length: 2,
                    decode: |buf| {
                        let sub_op : u8 = (buf[1] & 0b11000000) >> 6;

                        let mnem = match sub_op {
                            1 => "extp",
                            3 => "extpr",
                            0 => "exts",
                            2 => "extsr",
                            _ => "InvalidSubOp"
                        };

                        let irange : u8 = ((buf[1] & 0b00110000) >> 4) + 1;

                        let register1 : u8 = buf[1] & 0b00001111;

                        Ok(InstructionArguments {
                            mnemonic: Some(mnem.to_string()),
                            sub_op: Some(sub_op),
                            irange: Some(irange),
                            register1: Some(register1),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::data3_or_reg => {
                Ok(Encoding {
                    name: "data3_or_reg",
                    length: 2,
                    decode: |buf| {
                        let register0 : u8 = (buf[1] & 0b11110000) >> 4;
                        let sub_op : u8 = (buf[1] & 0b00001100) >> 2;

                        let mut values = InstructionArguments {
                            register0: Some(register0),
                            sub_op: Some(sub_op),
                            ..Default::default()
                        };

                        match sub_op {
                            0b10 => {
                                values.mnemonic = Some("reg".to_string());
                                let register1 : u8 = buf[1] & 0b00000011;
                                values.register1 = Some(register1);
                            },
                            0b11 => {
                                values.mnemonic = Some("reg_inc".to_string());
                                let register1 : u8 = buf[1] & 0b00000011;
                                values.register1 = Some(register1);
                            },
                            _ => {
                                values.mnemonic = Some("#data3".to_string());
                                let data : u8 = buf[1] & 0b00000111;
                                values.data = Some(data as u16);
                            }
                        }

                        Ok(values)
                    }
                })
            },

            EncodingType::atomic_extr => {
                Ok(Encoding {
                    name: "atomic_extr",
                    length: 2,
                    decode: |buf| {
                        match buf[1] & 0b00001111 {
                            0 => {
                                let irange : u8 = ((buf[1] & 0b00110000) >> 4) + 1;
                                let sub_op = (buf[1] & 0b11000000) >> 6;

                                let mut values = InstructionArguments {
                                    irange: Some(irange),
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
                })
            },

            EncodingType::Fn_II_II => {
                Ok(Encoding {
                    name: "Fn_II_II",
                    length: 4,
                    decode: |buf| {
                        match (buf[1] & 0b11110000) >> 4 {
                            0x0F => {
                                let register0 : u8 = buf[1] & 0b00001111;

                                let slice = &buf[2..4];
                                let data : u16 = LittleEndian::read_u16(slice);

                                Ok(InstructionArguments {
                                    data: Some(data),
                                    register0: Some(register0),
                                    ..Default::default()
                                })
                           },
                            _ => Err("Instruction was invalid")
                        }
                    }
                })
            },

            EncodingType::Fn_MM_MM => {
                Ok(Encoding {
                    name: "Fn_MM_MM",
                    length: 4,
                    decode: |buf| {
                        match (buf[1] & 0b11110000) >> 4 {
                            0x0F => {
                                let register0 : u8 = buf[1] & 0b00001111;

                                let slice = &buf[2..4];
                                let memory : u16 = LittleEndian::read_u16(slice);

                                Ok(InstructionArguments {
                                    register0: Some(register0),
                                    memory: Some(memory),
                                    ..Default::default()
                                })
                            },
                            _ => Err("Instruction was invalid")
                        }
                    }
                })
            },

            EncodingType::q_QQ => {
                Ok(Encoding {
                    name: "q_QQ",
                    length: 2,
                    decode: |buf| {
                        let bit0 : u8 = (buf[0] & 0b11110000) >> 4;
                        let bitoff0 : u8 = buf[1];

                        Ok(InstructionArguments {
                            bit0: Some(bit0),
                            bitoff0: Some(bitoff0),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::QQ_AA_II => {
                Ok(Encoding {
                    name: "QQ_AA_II",
                    length: 4,
                    decode: |buf| {
                        let mask : u8 = buf[2];
                        let data : u8 = buf[3];
                        let bitoff0 : u8 = buf[1];

                        Ok(InstructionArguments {
                            bitoff0: Some(bitoff0),
                            data: Some(data as u16),
                            mask: Some(mask),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::QQ_ZZ_qz => {
                Ok(Encoding {
                    name: "QQ_ZZ_qz",
                    length: 4,
                    decode: |buf| {
                        let bit1 : u8 = (buf[3] & 0b11110000) >> 4;
                        let bit0 : u8 = buf[3] & 0b00001111;

                        let bitoff1 : u8 = buf[1];
                        let bitoff0 : u8 = buf[2];

                        Ok(InstructionArguments {
                            bit0: Some(bit0),
                            bitoff0: Some(bitoff0),
                            bit1: Some(bit1),
                            bitoff1: Some(bitoff1),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::QQ_rr_q0 => {
                Ok(Encoding {
                    name: "QQ_rr_q0",
                    length: 4,
                    decode: |buf| {
                        match buf[3] & 0b00001111 {
                            0 => {
                                let bitoff0 : u8 = buf[1];
                                let bit0 : u8 = (buf[3] & 0b11110000) >> 4;
                                let relative : u8 = buf[2];

                                Ok(InstructionArguments {
                                    bit0: Some(bit0),
                                    bitoff0: Some(bitoff0),
                                    relative: Some(relative),
                                    ..Default::default()
                                })
                            },
                            _ => Err("Invalid instruction")
                        }
                    }
                })
            },

            EncodingType::RR => {
                Ok(Encoding {
                    name: "RR",
                    length: 2,
                    decode: |buf| {
                        let register0 : u8 = buf[1];

                        Ok(InstructionArguments {
                            register0: Some(register0),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::RR_II_II => {
                Ok(Encoding {
                    name: "RR_II_II",
                    length: 4,
                    decode: |buf| {
                        let register0 : u8 = buf[1];

                        let slice = &buf[2..4];
                        let data : u16 = LittleEndian::read_u16(slice);

                        Ok(InstructionArguments {
                            data: Some(data),
                            register0: Some(register0),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::RR_II_xx => {
                Ok(Encoding {
                    name: "RR_II_xx",
                    length: 4,
                    decode: |buf| {
                        let register0 : u8 = buf[1];
                        let data : u8 = buf[2];

                        Ok(InstructionArguments {
                            data: Some(data as u16),
                            register0: Some(register0),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::RR_MM_MM => {
                Ok(Encoding {
                    name: "RR_MM_MM",
                    length: 4,
                    decode: |buf| {
                        let register0 : u8 = buf[1];

                        let slice = &buf[2..4];
                        let memory : u16 = LittleEndian::read_u16(slice);

                        Ok(InstructionArguments {
                            memory: Some(memory),
                            register0: Some(register0),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::SS_MM_MM => {
                Ok(Encoding {
                    name: "SS_MM_MM",
                    length: 4,
                    decode: |buf| {
                        let segment : u8 = buf[1];

                        let slice = &buf[2..4];
                        let memory : u16 = LittleEndian::read_u16(slice);

                        Ok(InstructionArguments {
                            memory: Some(memory),
                            segment: Some(segment),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::c0_MM_MM => {
                Ok(Encoding {
                    name: "c0_MM_MM",
                    length: 4,
                    decode: |buf| {
                        match buf[1] & 0b00001111 {
                            0 => {
                                let condition : u8 = (buf[1] & 0b11110000) >> 4;

                                let slice = &buf[2..4];
                                let memory : u16 = LittleEndian::read_u16(slice);

                                Ok(InstructionArguments {
                                    memory: Some(memory),
                                    condition: Some(condition),
                                    ..Default::default()
                                })
                            },
                            _ => Err("Invalid instruction")
                        }
                    }
                })
            },

            EncodingType::cn => {
                Ok(Encoding {
                    name: "cn",
                    length: 2,
                    decode: |buf| {
                        let condition : u8 = (buf[1] & 0b11110000) >> 4;
                        let register0 = buf[1] & 0b00001111;

                        Ok(InstructionArguments {
                            register0: Some(register0),
                            condition: Some(condition),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::mn => {
                Ok(Encoding {
                    name: "mn",
                    length: 2,
                    decode: |buf| {
                        let register0 : u8 = buf[1] & 0b00001111;
                        let register1 : u8 = (buf[1] & 0b11110000) >> 4;

                        Ok(InstructionArguments {
                            register0: Some(register0),
                            register1: Some(register1),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::n0 => {
                Ok(Encoding {
                    name: "n0",
                    length: 2,
                    decode: |buf| {
                        match buf[1] & 0b00001111 {
                            0 => {
                                let register0 = (buf[1] & 0b11110000) >> 4;

                                Ok(InstructionArguments {
                                    register0: Some(register0),
                                    ..Default::default()
                                })
                            }
                            _ => Err("Instruction was invalid")
                        }
                    }
                })
            },

            EncodingType::nbit10ii => {
                Ok(Encoding {
                    name: "nbit10ii",
                    length: 2,
                    decode: |_buf| {
                        Ok(InstructionArguments {
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::nbit11ii => {
                Ok(Encoding {
                    name: "nbit11ii",
                    length: 2,
                    decode: |_buf| {
                        Ok(InstructionArguments {
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::nm => {
                Ok(Encoding {
                    name: "nm",
                    length: 2,
                    decode: |buf| {
                        let register0 : u8 = (buf[1] & 0b11110000) >> 4;
                        let register1 : u8 = buf[1] & 0b00001111;

                        Ok(InstructionArguments {
                            register0: Some(register0),
                            register1: Some(register1),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::nm_II_II => {
                Ok(Encoding {
                    name: "nm_II_II",
                    length: 4,
                    decode: |buf| {
                        let register0 : u8 = (buf[1] & 0b11110000) >> 4;
                        let register1 : u8 = buf[1] & 0b00001111;

                        let slice = &buf[2..4];
                        let data : u16 = LittleEndian::read_u16(slice);

                        Ok(InstructionArguments {
                            register0: Some(register0),
                            register1: Some(register1),
                            data: Some(data),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::nn => {
                Ok(Encoding {
                    name: "nn",
                    length: 2,
                    decode: |buf| {
                        let lower : u8 = buf[1] & 0b00001111;
                        let upper : u8 = (buf[1] & 0b11110000) >> 4;

                        if lower == upper {
                            let register0 : u8 = lower;

                            Ok(InstructionArguments {
                                register0: Some(register0),
                                ..Default::default()
                            })
                        } else {
                            Err("Instruction was invalid")
                        }
                    }
                })
            },

            EncodingType::rr => {
                Ok(Encoding {
                    name: "rr",
                    length: 2,
                    decode: |buf| {
                        let relative : u8 = buf[1];

                        Ok(InstructionArguments {
                            relative: Some(relative),
                            ..Default::default()
                        })
                    }
                })
            },

            EncodingType::trap7 => {
                Ok(Encoding {
                    name: "trap7",
                    length: 2,
                    decode: |buf| {
                        let trap0 : u8 = (buf[1] & 0b11111110) >> 1;

                        Ok(InstructionArguments {
                            trap: Some(trap0),
                            ..Default::default()
                        })
                    }
                })
            }
        }
    }
}
