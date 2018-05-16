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
    nop,
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
    tbitttt0,	// t:ttt0
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
    pub decode : fn(&[u8]) -> HashMap<&str, EncodingValue>
}

impl Encoding {
    pub fn from_encoding_type(encoding_type: &EncodingType) -> Result<Encoding, &'static str> {
        match encoding_type {
            EncodingType::NO_ARGS2 => {
                Ok(Encoding {
                    name: "NO_ARGS2",
                    length: 2,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
                })
            },

            EncodingType::NO_ARGS4 => {
                Ok(Encoding {
                    name: "NO_ARGS4",
                    length: 4,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
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

                        values 
                    }
                })
            },

            EncodingType::_0n_MM_MM => {
                Ok(Encoding {
                    name: "_0n_MM_MM",
                    length: 4,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
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

                        values
                    }
                })
            },

            EncodingType::ext_d7 => {
                Ok(Encoding {
                    name: "ext_d7",
                    length: 4,
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

                        let segment0 = buf[2];

                        values.insert("mnemonic", EncodingValue::String(mnem));
                        values.insert("sub_op", EncodingValue::UInt(sub_op as u32));
                        values.insert("irange0", EncodingValue::UInt(irange as u32));
                        values.insert("segment0", EncodingValue::UInt(segment0 as u32));

                        values
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

                        let register1 : u8 = (buf[1] & 0b00001111);

                        values.insert("mnemonic", EncodingValue::String(mnem));
                        values.insert("sub_op", EncodingValue::UInt(sub_op as u32));
                        values.insert("irange0", EncodingValue::UInt(irange as u32));
                        values.insert("register1", EncodingValue::UInt(register1 as u32));

                        values
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

                        values
                    }
                })
            },

            EncodingType::nop => {
                Ok(Encoding {
                    name: "nop",
                    length: 2,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
                })
            },

            EncodingType::atomic_extr => {
                Ok(Encoding {
                    name: "atomic_extr",
                    length: 2,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
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

                        values
                    }
                })
            },

            EncodingType::Fn_MM_MM => {
                Ok(Encoding {
                    name: "Fn_MM_MM",
                    length: 4,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
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

                        values
                    }
                })
            },

            EncodingType::QQ_AA_II => {
                Ok(Encoding {
                    name: "QQ_AA_II",
                    length: 4,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
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

                        values
                    }
                })
            },

            EncodingType::QQ_rr_q0 => {
                Ok(Encoding {
                    name: "QQ_rr_q0",
                    length: 4,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
                })
            },

            EncodingType::RR => {
                Ok(Encoding {
                    name: "RR",
                    length: 2,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
                })
            },

            EncodingType::RR_II_II => {
                Ok(Encoding {
                    name: "RR_II_II",
                    length: 4,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = buf[1] & 0b00001111;

                        let slice = &buf[2..4];
                        let data0 : u32 = LittleEndian::read_u16(slice) as u32;

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("data0", EncodingValue::UInt(data0));

                        values
                    }
                })
            },

            EncodingType::RR_II_xx => {
                Ok(Encoding {
                    name: "RR_II_xx",
                    length: 4,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = buf[1] & 0b00001111;
                        let data0 : u8 = buf[2];

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("data0", EncodingValue::UInt(data0 as u32));

                        values
                    }
                })
            },

            EncodingType::RR_MM_MM => {
                Ok(Encoding {
                    name: "RR_MM_MM",
                    length: 4,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = buf[1] & 0b00001111;

                        let slice = &buf[2..4];
                        let address0 : u32 = LittleEndian::read_u16(slice) as u32;

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("address0", EncodingValue::UInt(address0));

                        values
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

                        values
                    }
                })
            },

            EncodingType::c0_MM_MM => {
                Ok(Encoding {
                    name: "c0_MM_MM",
                    length: 4,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let condition0 : u8 = (buf[1] & 0b11110000) >> 4;

                        let slice = &buf[2..4];
                        let address0 : u32 = LittleEndian::read_u16(slice) as u32;

                        values.insert("condition0", EncodingValue::UInt(condition0 as u32));
                        values.insert("address0", EncodingValue::UInt(address0));

                        values
                    }
                })
            },

            EncodingType::cn => {
                Ok(Encoding {
                    name: "cn",
                    length: 2,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
                })
            },

            EncodingType::mn => {
                Ok(Encoding {
                    name: "mn",
                    length: 2,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = (buf[1] & 0b00001111);
                        let register1 : u8 = (buf[1] & 0b11110000) >> 4;

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("register1", EncodingValue::UInt(register1 as u32));

                        values
                    }
                })
            },

            EncodingType::n0 => {
                Ok(Encoding {
                    name: "n0",
                    length: 2,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
                })
            },

            EncodingType::nbit10ii => {
                Ok(Encoding {
                    name: "nbit10ii",
                    length: 2,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
                })
            },

            EncodingType::nbit11ii => {
                Ok(Encoding {
                    name: "nbit11ii",
                    length: 2,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
                })
            },

            EncodingType::nm => {
                Ok(Encoding {
                    name: "nm",
                    length: 2,
                    decode: |buf| {
                        let mut values = HashMap::<&str, EncodingValue>::new();

                        let register0 : u8 = (buf[1] & 0b11110000) >> 4;
                        let register1 : u8 = (buf[1] & 0b00001111);

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("register1", EncodingValue::UInt(register1 as u32));

                        values
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
                        let register1 : u8 = (buf[1] & 0b00001111);

                        let slice = &buf[2..4];
                        let data0 : u32 = LittleEndian::read_u16(slice) as u32;

                        values.insert("register0", EncodingValue::UInt(register0 as u32));
                        values.insert("register1", EncodingValue::UInt(register1 as u32));
                        values.insert("data0", EncodingValue::UInt(data0));

                        values
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

                        values
                    }
                })
            },

            EncodingType::rr => {
                Ok(Encoding {
                    name: "rr",
                    length: 2,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
                })
            },

            EncodingType::tbitttt0 => {
                Ok(Encoding {
                    name: "tbitttt0",
                    length: 2,
                    decode: |_buf| {HashMap::<&str, EncodingValue>::new()}
                })
            },
/*            _ => {
                Err("NOT YET IMPLEMENTED")
            }*/
        }
    }
}
