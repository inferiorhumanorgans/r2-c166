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

extern crate c166_core;

use std::ffi::CString;
use std::os::raw::c_void;
use std::os::raw::c_char;

use std::ptr;
use std::boxed::Box;

use c166_core::r2::*;

// https://github.com/rust-lang/rfcs/issues/400
macro_rules! cstr_mut {
  ($s:expr) => (
    concat!($s, "\0") as *const str as *const [c_char] as *mut c_char
  );
}

extern "C" fn c166_load(_: *mut RBinFile) -> bool {
    true
}

extern "C" fn c166_destroy(raw_rbf: *mut RBinFile) -> i32 {
    // Tell r2 to not free our info object >_<
    unsafe {
        let obj_list = (*raw_rbf).objs;
        let head = (*obj_list).head;
        let data : *mut RBinObject = (*head).data as *mut RBinObject;
        let rbo : &mut RBinObject = &mut (*data);
        rbo.info = ptr::null_mut();
    }

	0
}

extern "C" fn c166_baddr(_: *mut RBinFile) -> u64{
	0
}

extern "C" fn c166_entries(_raw_bf: *mut RBinFile) -> *mut RList {
    let list : *mut RList = unsafe { r_list_new() };

    unsafe {
        // (*list).free = None; // Ugh
        let addr : RBinAddr = RBinAddr {
            bits:  0,
            haddr: 0,
            paddr: 0,
            vaddr: 0,
            type_: R_BIN_ENTRY_TYPE_PROGRAM as i32

        };
        let b = Box::into_raw(Box::new(addr));
        r_list_append(list, b as *mut std::os::raw::c_void);
    }

    list
}

fn append_symbol(list: *mut RList, name: &str, addr: u32) {

    let c_string = CString::new(name).unwrap();
    let p = c_string.as_ptr();
    // Don't free us...
    std::mem::forget(c_string);

    let sym : RBinSymbol = RBinSymbol {
        name: p as *mut c_char,
        dname: ptr::null_mut(),
        classname: ptr::null_mut(),
        forwarder: ptr::null_mut(),
        bind: ptr::null(),
        type_: ptr::null(),
        rtype: ptr::null(),
        visibility_str: cstr_mut!("default"),
        vaddr: addr as u64,
        paddr: addr as u64,
        size: 4,
        ordinal: 0,
        visibility: 0,
        bits: 0,
        method_flags: 0,
        dup_count: 0
    };

    unsafe {
        // (*list).free = None; // Ugh
        let b = Box::into_raw(Box::new(sym));
        r_list_append(list, b as *mut std::os::raw::c_void);
    }
}

extern "C" fn c166_symbols(_raw_bf: *mut RBinFile) -> *mut RList {
    let list : *mut RList = unsafe { r_list_new() };

    // Hardcoded stuff from the docs
    append_symbol(list, "RESET", 0x0000);
    append_symbol(list, "NMITRAP", 0x0008);
    append_symbol(list, "STOTRAP", 0x0010);
    append_symbol(list, "STUTRAP", 0x0018);
    append_symbol(list, "CC0INT", 0x0040);
    append_symbol(list, "CC1INT", 0x0044);
    append_symbol(list, "CC2INT", 0x0048);
    append_symbol(list, "CC3INT", 0x004C);
    append_symbol(list, "CC4INT", 0x0050);
    append_symbol(list, "CC5INT", 0x0054);
    append_symbol(list, "CC6INT", 0x0058);
    append_symbol(list, "CC7INT", 0x005C);
    append_symbol(list, "CC8INT", 0x0060);
    append_symbol(list, "CC9INT", 0x0064);
    append_symbol(list, "CC10INT", 0x0068);
    append_symbol(list, "CC11INT", 0x006C);
    append_symbol(list, "CC12INT", 0x0070);
    append_symbol(list, "CC13INT", 0x0074);
    append_symbol(list, "CC14INT", 0x0078);
    append_symbol(list, "CC15INT", 0x007C);
    append_symbol(list, "CC16INT", 0x00C0);
    append_symbol(list, "CC17INT", 0x00C4);
    append_symbol(list, "CC18INT", 0x00C8);
    append_symbol(list, "CC19INT", 0x00CC);
    append_symbol(list, "CC20INT", 0x00D0);
    append_symbol(list, "CC21INT", 0x00D4);
    append_symbol(list, "CC22INT", 0x00D8);
    append_symbol(list, "CC23INT", 0x00DC);
    append_symbol(list, "CC24INT", 0x00E0);
    append_symbol(list, "CC25INT", 0x00E4);
    append_symbol(list, "CC26INT", 0x00E8);
    append_symbol(list, "CC27INT", 0x00EC);
    append_symbol(list, "CC28INT", 0x00F0);
    append_symbol(list, "CC29INT", 0x0110);
    append_symbol(list, "CC30INT", 0x0114);
    append_symbol(list, "CC31INT", 0x0118);
    append_symbol(list, "T0INT", 0x0080);
    append_symbol(list, "T1INT", 0x0084);
    append_symbol(list, "T7INT", 0x00F4);
    append_symbol(list, "T8INT", 0x00F8);
    append_symbol(list, "T2INT", 0x0088);
    append_symbol(list, "T3INT", 0x008C);
    append_symbol(list, "T4INT", 0x0090);
    append_symbol(list, "T5INT", 0x0094);
    append_symbol(list, "T6INT", 0x0098);
    append_symbol(list, "CRINT", 0x009C);
    append_symbol(list, "ADCINT", 0x00A0);
    append_symbol(list, "ADEINT", 0x00A4);
    append_symbol(list, "S0TINT", 0x00A8);
    append_symbol(list, "S0TBINT", 0x011C);
    append_symbol(list, "S0RINT", 0x00AC);
    append_symbol(list, "S0EINT", 0x00B0);
    append_symbol(list, "SSCTINT", 0x00B4);
    append_symbol(list, "SSCRINT", 0x00B8);
    append_symbol(list, "SSCEINT", 0x00BC);
    append_symbol(list, "PWMINT", 0x00FC);
    append_symbol(list, "XP0INT", 0x0100);
    append_symbol(list, "XP1INT", 0x0104);
    append_symbol(list, "XP2INT", 0x0108);
    append_symbol(list, "XP3INT", 0x010C);

    list
}

extern "C" fn c166_info(_: *mut RBinFile) -> *mut RBinInfo {
    let empty_hash : RBinHash = RBinHash {
        type_: ptr::null(),
        addr: 0,
        len: 0,
        from: 0,
        to: 0,
        buf: [0; 32],
        cmd: ptr::null()
    };

    let info : RBinInfo = RBinInfo {
        file: ptr::null_mut(),
        type_: ptr::null_mut(),
        bclass: ptr::null_mut(),
        rclass: ptr::null_mut(),
        arch: cstr_mut!("c166"),
        cpu: cstr_mut!("c166"),
        machine: ptr::null_mut(),
        os: ptr::null_mut(),
        subsystem: ptr::null_mut(),
        rpath: ptr::null_mut(),
        guid: ptr::null_mut(),
        debug_file_name: ptr::null_mut(),
        lang: ptr::null(),
        bits: 16,
        has_va: 0,
        has_pi: 0,
        has_canary: 0,
        has_crypto: 0,
        has_nx: 0,
        big_endian: 0,
        has_lit: false,
        actual_checksum: ptr::null_mut(),
        claimed_checksum: ptr::null_mut(),
        pe_overlay: 0,
        signature: false,
        dbg_info: 0,
        sum: [empty_hash; 3],
        baddr: 0,
        intrp: ptr::null_mut()
    };

    Box::into_raw(Box::new(info))
}


const C166_BIN_PLUGIN: RBinPlugin = RBinPlugin {
    name: cstr_mut!("c166-rom"),
    desc: cstr_mut!("C166 ROM images"),
    author: cstr_mut!("inferiorhumanorgans"),
    version: cstr_mut!(env!("CARGO_PKG_VERSION")),
    license: cstr_mut!("GPL3"),
    init: None,
    fini: None,
    get_sdb: None,
    load: Some(c166_load),
    load_bytes: None,
    load_buffer: None,
    size: None,
    destroy: Some(c166_destroy),
    check_bytes: None,
    baddr: Some(c166_baddr),
    boffset: None,
    binsym: None,
    entries: Some(c166_entries),
    sections: None,
    lines: None,
    symbols: Some(c166_symbols),
    imports: None,
    strings: None,
    info: Some(c166_info),
    fields: None,
    libs: None,
    relocs: None,
    classes: None,
    mem: None,
    patch_relocs: None,
    maps: None,
    header: None,
    signature: None,
    demangle_type: None,
    dbginfo: ptr::null_mut(),
    write: ptr::null_mut(),
    get_offset: None,
    get_name: None,
    get_vaddr: None,
    create: None,
    demangle: None,
    regstate: None,
    file_type: None,
    minstrlen: 0,
    strfilter: 0,
    user: ptr::null_mut(),
};

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static mut radare_plugin: RLibStruct = RLibStruct {
    type_:  R_LIB_TYPE_BIN as i32,
    data:   ((&C166_BIN_PLUGIN) as *const RBinPlugin) as *mut c_void,
    version:R2_VERSION as *const [u8] as *const c_char,
    free:   None
};
