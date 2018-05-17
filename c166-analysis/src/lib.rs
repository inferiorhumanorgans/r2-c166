extern crate c166_core;

use c166_core::r2::*;
use c166_core::instruction::Instruction;
use c166_core::encoding::Encoding;

use std::os::raw::c_void;
use std::os::raw::c_char;

// https://github.com/rust-lang/rfcs/issues/400
macro_rules! cstr_mut {
  ($s:expr) => (
    concat!($s, "\0") as *const str as *const [c_char] as *mut c_char
  );
}

const MY_NAME : *mut c_char  = cstr_mut!("c166.rs");
const MY_VERSION : *mut c_char = cstr_mut!("0.1.0");
const MY_ARCH : *mut c_char = cstr_mut!("c166");
const MY_DESC : *mut c_char = cstr_mut!("c166 analysis plugin in Rust");
const MY_LICENSE : *mut c_char = cstr_mut!("GPL3");
const MY_AUTHOR : *mut c_char = cstr_mut!("inferiorhumanorgans");

fn condition_to_r2(condition: u32) -> _RAnalCond {
    if condition > 15 {
        panic!("Condition shouldn't be over 15, but is actually {}", condition);
    }

    match condition {
        0x0 => _RAnalCond::R_ANAL_COND_AL, // cc_UC
        0x1 => _RAnalCond::R_ANAL_COND_NE, // cc_NET
        0x2 => _RAnalCond::R_ANAL_COND_EQ, // cc_Z
        0x3 => _RAnalCond::R_ANAL_COND_NE, // cc_NZ
        0x4 => _RAnalCond::R_ANAL_COND_VS, // cc_V
        0x5 => _RAnalCond::R_ANAL_COND_VC, // cc_NV
        0x6 => _RAnalCond::R_ANAL_COND_MI, // cc_N
        0x7 => _RAnalCond::R_ANAL_COND_PL, // cc_NN
        0x8 => _RAnalCond::R_ANAL_COND_HS, // cc_C
        0x9 => _RAnalCond::R_ANAL_COND_LO, // cc_NC
        0xA => _RAnalCond::R_ANAL_COND_GT, // cc_SGT
        0xB => _RAnalCond::R_ANAL_COND_LE, // cc_SLE
        0xC => _RAnalCond::R_ANAL_COND_LT, // cc_SLT
        0xD => _RAnalCond::R_ANAL_COND_GE, // cc_SGE
        0xE => _RAnalCond::R_ANAL_COND_HI, // cc_UGT
        0xF => _RAnalCond::R_ANAL_COND_LS, // cc_ULE
        _   => _RAnalCond::R_ANAL_COND_AL,
    }
}

extern "C" fn _op(_a: *mut RAnal, raw_op: *mut RAnalOp, addr: u64, buf: *const u8, len: i32) -> i32 {
    let out_op : &mut RAnalOp;
    let bytes;

    unsafe {
        out_op = &mut (*raw_op);
        bytes = std::slice::from_raw_parts(buf as *const u8, len as usize);
    }

    match Instruction::from_addr_array(bytes) {
        Ok(op) => {
            let encoding = Encoding::from_encoding_type(&op.encoding).unwrap();
            // let format = OpFormat::from_format_type(&op.format).unwrap();

            if encoding.length <= len {
                out_op.type_ = op.r2_op_type.uint_value();
                out_op.size = encoding.length;

                let jump_type : u32 = _RAnalOpType::R_ANAL_OP_TYPE_JMP.uint_value();
                let call_type : u32 = _RAnalOpType::R_ANAL_OP_TYPE_CALL.uint_value();
                let raw_type : u32 =  op.r2_op_type.uint_value() & 0b11111111;
                if (raw_type & jump_type) > 0 || (raw_type & call_type) > 0 {
                    out_op.fail = addr + out_op.size as u64;
                    let values = (encoding.decode)(bytes);
                    let condition = match values.get("condition0") {
                        Some(condition) => condition.uint_value().expect("integer value"),
                        _ => 0
                    };
                    out_op.cond = condition_to_r2(condition).uint_value() as i32;
                    match values.get("address0") {
                        Some(address) => {
                            let jump_target = address.uint_value().expect("integer value");
                            out_op.jump = jump_target as u64;
                        },
                        _ => {
                            match values.get("relative0") {
                                Some(relative) => {
                                    let rel_target = relative.uint_value().expect("integer value");
                                    out_op.jump = addr + (rel_target * 2) as u64;
                                },
                                _ => {}
                            }
                        }
                    }
                }
            } else {
                // Not enough room in da buffer
                out_op.size = -1;
                out_op.type_ = _RAnalOpType::R_ANAL_OP_TYPE_ILL.uint_value();
            }
        },
        Err(_) => {
            out_op.size = -1;
            out_op.type_ = _RAnalOpType::R_ANAL_OP_TYPE_ILL.uint_value();
        }
    }

    out_op.size
}

#[allow(non_upper_case_globals)]
const r_anal_plugin_c166rs: RAnalPlugin = RAnalPlugin {
    name: MY_NAME,
    desc: MY_DESC,
    license: MY_LICENSE,
    arch: MY_ARCH,
    author: MY_AUTHOR,
    version: MY_VERSION,
    bits: 16,
    esil: 0,
    fileformat_type: 0,
    custom_fn_anal: 0,
    init: None,
    fini: None,
    reset_counter: None,
    archinfo: None,
    anal_mask: None,
    op: Some(_op),
    bb: None,
    fcn: None,
    analyze_fns: None,
    op_from_buffer: None,
    bb_from_buffer: None,
    fn_from_buffer: None,
    analysis_algorithm: None,
    pre_anal: None,
    pre_anal_fn_cb: None,
    pre_anal_op_cb: None,
    post_anal_op_cb: None,
    pre_anal_bb_cb: None,
    post_anal_bb_cb: None,
    post_anal_fn_cb: None,
    post_anal: None,
    revisit_bb_anal: None,
    cmd_ext: None,
    set_reg_profile: None,
    get_reg_profile: None,
    fingerprint_bb: None,
    fingerprint_fcn: None,
    diff_bb: None,
    diff_fcn: None,
    diff_eval: None,
    is_valid_offset: None,
    esil_init: None,
    esil_post_loop: None,
    esil_intr: None,
    esil_trap: None,
    esil_fini: None
};

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static mut radare_plugin: RLibStruct = RLibStruct {
    type_ : R_LIB_TYPE_ANAL as i32,
    data : ((&r_anal_plugin_c166rs) as *const RAnalPlugin) as *mut c_void,
    version : R2_VERSION   as *const [u8] as *const c_char,
    free : None
};
