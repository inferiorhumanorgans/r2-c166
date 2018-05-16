extern crate c166_core;

use c166_core::r2::*;

use std::os::raw::c_void;
use std::os::raw::c_char;
use std::ptr;

// https://github.com/rust-lang/rfcs/issues/400
macro_rules! cstr {
  ($s:expr) => (
    concat!($s, "\0") as *const str as *const [c_char] as *const c_char
  );
}

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
const EMPTY_STRING : *const c_char = b"\0" as *const [u8] as *const c_char;

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
    op: None,
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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
