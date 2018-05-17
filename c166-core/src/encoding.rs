use std::collections::HashMap;
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

#[derive(Debug)]
pub enum EncodingValue<'a> {
    String(&'a str),
    UInt(u32),
    Int(i32),
    Null()
}

impl<'a> EncodingValue<'a> {
    pub fn uint_value(&self) -> Option<u32> {
       match *self {
            EncodingValue::UInt(v) => Some(v),
            _ => None,
        }
    }

    pub fn str_value(&self) -> Option<&'a str> {
       match *self {
            EncodingValue::String(v) => Some(v),
            _ => None,
        }
    }
}

pub struct Encoding {
    pub name : &'static str,
    pub length : i32,
    pub decode : fn(&[u8]) -> Result<HashMap<&str, EncodingValue>, &'static str>
}

impl Encoding {
    pub fn from_encoding_type(encoding_type: &EncodingType) -> Result<Encoding, &'static str> {
        match encoding_type {
            EncodingType::NO_ARGS2 => {
                Ok(Encoding {
                    name: "NO_ARGS2",
                    length: 2,
                    decode: |buf| {
                        let values = HashMap::<&str, EncodingValue>::new();
                        match &buf[0..2] {
                            [0xDB, 0x00] => Ok(values),
                            [0xFB, 0x88] => Ok(values),
                            [0xCB, 0x00] => Ok(values),
                            [0xCC, 0x00] => Ok(values),
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
                        let values = HashMap::<&str, EncodingValue>::new();
                        match &buf[0..4] {
                            [0xB7, 0x48, 0xB7, 0xB7] => Ok(values),
                            [0xA7, 0x58, 0xA7, 0xA7] => Ok(values),
                            [0x97, 0x68, 0x97, 0x97] => Ok(values),
                            [0xB5, 0x4A, 0xB5, 0xB5] => Ok(values),
                            [0xA5, 0x5A, 0xA5, 0xA5] => Ok(values),
                            [0x87, 0x78, 0x87, 0x87] => Ok(values),
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
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = buf[1] & 0b00001111;
                        let data0 : u8 = (buf[1] & 0b11110000) >> 4;

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("data0", EncodingValue::UInt(data0 as u32));

                        Ok(values)
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
                                let mut values = HashMap::<&str, EncodingValue>::new();

                                let register0 : u8 = buf[1] & 0b00001111;

                                let slice = &buf[2..4];
                                let address0 : u32 = LittleEndian::read_u16(slice) as u32;

                                values.insert("register0", EncodingValue::UInt(register0 as u32));
                                values.insert("address0", EncodingValue::UInt(address0));

                                Ok(values)
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
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let condition0 : u8 = (buf[0] & 0b11110000) >> 4;
                        let relative0 : u8 = buf[1];

                        values.insert("condition0", EncodingValue::UInt(condition0 as u32));
                        values.insert("relative0", EncodingValue::UInt(relative0 as u32));

                        Ok(values)
                    }
                })
            },

            EncodingType::ext_d7 => {
                Ok(Encoding {
                    name: "ext_d7",
                    length: 4,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

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

                        values.insert("mnemonic", EncodingValue::String(mnem));
                        values.insert("sub_op", EncodingValue::UInt(sub_op as u32));
                        values.insert("irange0", EncodingValue::UInt(irange as u32));

                        match (buf[1] & 0b11000000) >> 6 {
                            0b10 | 0b00 => {
                                // Seg op
                                match buf[3] {
                                    0x00 => {
                                        let segment0 = buf[2];
                                        values.insert("segment0", EncodingValue::UInt(segment0 as u32));
                                    },
                                    _    => return Err("Instruction was invalid")
                                }
                            },
                            0b11 | 0b01 => {
                                // Page is 10 bits so the top 6 bits of byte 3 need to be zero
                                match (buf[3] & 0b11111100) >> 2 {
                                    0x00 => {
                                        let page : u16 = ((buf[3] & 0b00000011) as u16) << 8 | buf[2] as u16;
                                        values.insert("page0", EncodingValue::UInt(page as u32));
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
                        let mut values = HashMap::<&str, EncodingValue>::new();

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

                        values.insert("mnemonic", EncodingValue::String(mnem));
                        values.insert("sub_op", EncodingValue::UInt(sub_op as u32));
                        values.insert("irange0", EncodingValue::UInt(irange as u32));
                        values.insert("register1", EncodingValue::UInt(register1 as u32));

                        Ok(values)
                    }
                })
            },

            EncodingType::data3_or_reg => {
                Ok(Encoding {
                    name: "data3_or_reg",
                    length: 2,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = (buf[1] & 0b11110000) >> 4;

                        let sub_op : u8 = (buf[1] & 0b00001100) >> 2;

                        let sub_mnem;
                        match sub_op {
                            2 => {
                                sub_mnem = "reg";
                                let register1 : u8 = buf[1] & 0b00000011;
                                values.insert("register1", EncodingValue::UInt(register1 as u32));
                            },
                            3 => {
                                sub_mnem = "reg_inc";
                                let register1 : u8 = buf[1] & 0b00000011;
                                values.insert("register1", EncodingValue::UInt(register1 as u32));
                            },
                            _ => {
                                sub_mnem = "#data3";
                                let data0 : u8 = buf[1] & 0b00000111;
                                values.insert("data0", EncodingValue::UInt(data0 as u32));
                            }
                        }

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("sub_op", EncodingValue::String(sub_mnem));

                        Ok(values)
                    }
                })
            },

            EncodingType::atomic_extr => {
                Ok(Encoding {
                    name: "atomic_extr",
                    length: 2,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let sub_op = (buf[1] & 0b11000000) >> 6;

                        if sub_op == 0b00 {
                            values.insert("mnemonic", EncodingValue::String("atomic"));
                        } else if sub_op == 0b10 {
                            values.insert("mnemonic", EncodingValue::String("extr"));
                        }

                        let irange0 = ((buf[1] & 0b00110000) >> 4) + 1;
                        values.insert("irange0", EncodingValue::UInt(irange0 as u32));

                        Ok(values)
                    }
                })
            },

            EncodingType::Fn_II_II => {
                Ok(Encoding {
                    name: "Fn_II_II",
                    length: 4,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = buf[1] & 0b00001111;

                        let slice = &buf[2..4];
                        let data0 : u32 = LittleEndian::read_u16(slice) as u32;

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("data0", EncodingValue::UInt(data0));

                        Ok(values)
                    }
                })
            },

            EncodingType::Fn_MM_MM => {
                Ok(Encoding {
                    name: "Fn_MM_MM",
                    length: 4,
                    decode: |_buf| {
                        Ok(HashMap::<&str, EncodingValue>::new())
                    }
                })
            },

            EncodingType::q_QQ => {
                Ok(Encoding {
                    name: "q_QQ",
                    length: 2,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let bit0 : u8 = (buf[0] & 0b11110000) >> 4;
                        let bitoff0 : u8 = buf[1];

                        values.insert("bit0", EncodingValue::UInt(bit0 as u32));
                        values.insert("bitoff0", EncodingValue::UInt(bitoff0 as u32));

                        Ok(values)
                    }
                })
            },

            EncodingType::QQ_AA_II => {
                Ok(Encoding {
                    name: "QQ_AA_II",
                    length: 4,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let mask0 : u8 = buf[2];
                        let data0 : u8 = buf[3];
                        let bitoff0 : u8 = buf[1];

                        values.insert("mask0", EncodingValue::UInt(mask0 as u32));
                        values.insert("data0", EncodingValue::UInt(data0 as u32));
                        values.insert("bitoff0", EncodingValue::UInt(bitoff0 as u32));

                        Ok(values)
                    }
                })
            },

            EncodingType::QQ_ZZ_qz => {
                Ok(Encoding {
                    name: "QQ_ZZ_qz",
                    length: 4,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let bit1 : u8 = (buf[3] & 0b11110000) >> 4;
                        let bit0 : u8 = buf[3] & 0b00001111;

                        let bitoff1 : u8 = buf[1];
                        let bitoff0 : u8 = buf[2];

                        values.insert("bit0", EncodingValue::UInt(bit0 as u32));
                        values.insert("bitoff0", EncodingValue::UInt(bitoff0 as u32));
                        values.insert("bit1", EncodingValue::UInt(bit1 as u32));
                        values.insert("bitoff1", EncodingValue::UInt(bitoff1 as u32));

                        Ok(values)
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
                                let mut values = HashMap::<&str, EncodingValue>::new();

                                let bitoff0 : u8 = buf[1];
                                let bit0 : u8 = (buf[3] & 0b11110000) >> 4;
                                let relative0 : u8 = buf[2];

                                values.insert("bit0", EncodingValue::UInt(bit0 as u32));
                                values.insert("bitoff0", EncodingValue::UInt(bitoff0 as u32));
                                values.insert("relative0", EncodingValue::UInt(relative0 as u32));

                                Ok(values)
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
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = buf[1];
                        values.insert("register0", EncodingValue::UInt(register0 as u32));

                        Ok(values)
                    }
                })
            },

            EncodingType::RR_II_II => {
                Ok(Encoding {
                    name: "RR_II_II",
                    length: 4,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = buf[1];

                        let slice = &buf[2..4];
                        let data0 : u32 = LittleEndian::read_u16(slice) as u32;

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("data0", EncodingValue::UInt(data0));

                        Ok(values)
                    }
                })
            },

            EncodingType::RR_II_xx => {
                Ok(Encoding {
                    name: "RR_II_xx",
                    length: 4,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = buf[1];
                        let data0 : u8 = buf[2];

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("data0", EncodingValue::UInt(data0 as u32));

                        Ok(values)
                    }
                })
            },

            EncodingType::RR_MM_MM => {
                Ok(Encoding {
                    name: "RR_MM_MM",
                    length: 4,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = buf[1];

                        let slice = &buf[2..4];
                        let address0 : u32 = LittleEndian::read_u16(slice) as u32;

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("address0", EncodingValue::UInt(address0));

                        Ok(values)
                    }
                })
            },

            EncodingType::SS_MM_MM => {
                Ok(Encoding {
                    name: "SS_MM_MM",
                    length: 4,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let segment0 : u8 = buf[1];

                        let slice = &buf[2..4];
                        let memory0 : u32 = LittleEndian::read_u16(slice) as u32;

                        let address0 : u32 = (segment0 as u32 * 0x10000) + memory0;

                        values.insert("segment0", EncodingValue::UInt(segment0 as u32));
                        values.insert("memory0", EncodingValue::UInt(memory0));
                        values.insert("address0", EncodingValue::UInt(address0));

                        Ok(values)
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
                                let mut values = HashMap::<&str, EncodingValue>::new();

                                let condition0 : u8 = (buf[1] & 0b11110000) >> 4;

                                let slice = &buf[2..4];
                                let address0 : u32 = LittleEndian::read_u16(slice) as u32;

                                values.insert("condition0", EncodingValue::UInt(condition0 as u32));
                                values.insert("address0", EncodingValue::UInt(address0));

                                Ok(values)
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
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let condition0 : u8 = (buf[1] & 0b11110000) >> 4;
                        let register0 = buf[1] & 0b00001111;

                        values.insert("condition0", EncodingValue::UInt(condition0 as u32));
                        values.insert("register0", EncodingValue::UInt(register0 as u32));

                        Ok(values)
                    }
                })
            },

            EncodingType::mn => {
                Ok(Encoding {
                    name: "mn",
                    length: 2,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = buf[1] & 0b00001111;
                        let register1 : u8 = (buf[1] & 0b11110000) >> 4;

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("register1", EncodingValue::UInt(register1 as u32));

                        Ok(values)
                    }
                })
            },

            EncodingType::n0 => {
                Ok(Encoding {
                    name: "n0",
                    length: 2,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 = (buf[1] & 0b11110000) >> 4;
                        values.insert("register0", EncodingValue::UInt(register0 as u32));

                        Ok(values)
                    }
                })
            },

            EncodingType::nbit10ii => {
                Ok(Encoding {
                    name: "nbit10ii",
                    length: 2,
                    decode: |_buf| {
                        Ok(HashMap::<&str, EncodingValue>::new())
                    }
                })
            },

            EncodingType::nbit11ii => {
                Ok(Encoding {
                    name: "nbit11ii",
                    length: 2,
                    decode: |_buf| {
                        Ok(HashMap::<&str, EncodingValue>::new())
                    }
                })
            },

            EncodingType::nm => {
                Ok(Encoding {
                    name: "nm",
                    length: 2,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = (buf[1] & 0b11110000) >> 4;
                        let register1 : u8 = buf[1] & 0b00001111;

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("register1", EncodingValue::UInt(register1 as u32));

                        Ok(values)
                    }
                })
            },

            EncodingType::nm_II_II => {
                Ok(Encoding {
                    name: "nm_II_II",
                    length: 4,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = (buf[1] & 0b11110000) >> 4;
                        let register1 : u8 = buf[1] & 0b00001111;

                        let slice = &buf[2..4];
                        let data0 : u32 = LittleEndian::read_u16(slice) as u32;

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("register1", EncodingValue::UInt(register1 as u32));
                        values.insert("data0", EncodingValue::UInt(data0));

                        Ok(values)
                    }
                })
            },

            EncodingType::nn => {
                Ok(Encoding {
                    name: "nn",
                    length: 2,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = (buf[1] & 0b11110000) >> 4;
                        values.insert("register0", EncodingValue::UInt(register0 as u32));

                        Ok(values)
                    }
                })
            },

            EncodingType::rr => {
                Ok(Encoding {
                    name: "rr",
                    length: 2,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();
                        let relative0 : u8 = buf[1];
                        values.insert("relative0", EncodingValue::UInt(relative0 as u32));

                        Ok(values)
                    }
                })
            },

            EncodingType::trap7 => {
                Ok(Encoding {
                    name: "trap7",
                    length: 2,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let trap0 = (buf[1] & 0b11111110) >> 1;
                        values.insert("trap0", EncodingValue::UInt(trap0 as u32));

                        Ok(values)
                    }
                })
            }
        }
    }
}
