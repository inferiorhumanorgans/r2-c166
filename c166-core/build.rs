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

extern crate bindgen;

use std::env;
use std::path::Path;
use std::path::PathBuf;

fn build_bindings(in_path: &PathBuf, out_path: &PathBuf) {
    bindgen::builder()
        .header(in_path.to_str().unwrap())
        .clang_arg("-I/usr/include/libr/")
        .clang_arg("-I/usr/local/include/libr/")
        .clang_arg("-I/opt/include/libr/")
        .bitfield_enum("_RAnalOpType")
        .bitfield_enum("_RAnalCond")
        .blacklist_type("IPPORT_RESERVED") 
        .generate()
        .unwrap()
        .write_to_file(Path::new(&out_path).join("ffi.rs"))
        .unwrap()
}

fn main() {
    let manifest_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    let path_bindings_h = Path::new(&manifest_path).join("..").join("bindings.h").canonicalize().unwrap();

    println!("cargo:rerun-if-changed={}", path_bindings_h.to_str().unwrap());
    build_bindings(&path_bindings_h, &out_path);
}
