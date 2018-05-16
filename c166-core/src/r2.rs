#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
include!("../../src/ffi.rs");

impl _RAnalOpType {
    pub fn uint_value(&self) -> u32 {
       match *self {
            _RAnalOpType(v) => v,
        }
    }
}

impl _RAnalCond {
    pub fn uint_value(&self) -> u32 {
       match *self {
            _RAnalCond(v) => v,
        }
    }
}
