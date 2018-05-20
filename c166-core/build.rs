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
