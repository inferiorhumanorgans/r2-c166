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

#![feature(try_from)]

extern crate c166_core;

use std::os::raw::c_void;
use std::os::raw::c_char;
use std::ptr;

use c166_core::r2::*;

mod asm;
mod disasm;
mod mnemonics;

// https://github.com/rust-lang/rfcs/issues/400
macro_rules! cstr {
  ($s:expr) => (
    concat!($s, "\0") as *const str as *const [c_char] as *const c_char
  );
}
const EMPTY_STRING : *const c_char = b"\0" as *const [u8] as *const c_char;

#[allow(non_upper_case_globals)]
const C166_ASM_PLUGIN: RAsmPlugin = RAsmPlugin {
    name:           cstr!("c166"),
    arch:           cstr!("c166"),
    author:         cstr!("inferiorhumanorgans"),
    version:        cstr!(env!("CARGO_PKG_VERSION")),
    license:        cstr!("GPL3"),
    user:           ptr::null_mut(),
    cpus:           EMPTY_STRING,
    desc:           cstr!("c166 assembler plugin"),
    bits:           16,
    endian:         0,
    disassemble:    Some(disasm::c166_disassemble),
    assemble:       Some(asm::c166_assemble),
    init:           None,
    fini:           None,
    modify:         None,
    set_subarch:    None,
    mnemonics:      Some(mnemonics::c166_mnemonic_by_id),
    features:       EMPTY_STRING,
};

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static mut radare_plugin: RLibStruct = RLibStruct {
    type_:  R_LIB_TYPE_ASM as i32,
    data:   ((&C166_ASM_PLUGIN) as *const RAsmPlugin) as *mut c_void,
    version:R2_VERSION as *const [u8] as *const c_char,
    free:   None
};
