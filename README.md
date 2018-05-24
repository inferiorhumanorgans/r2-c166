# README

[![Build Status](https://travis-ci.com/inferiorhumanorgans/r2-c166.svg?branch=master)](https://travis-ci.com/inferiorhumanorgans/r2-c166)

Siemens C166 family (dis)assembly and analysis plugins for radare2.  This project is written in rust, and depends on the nightly
toolchain.

## Installation and Usage

* If you don't have clang installed already, install it.  On FreeBSD `pkg install llvm60` is sufficient.
* Install `rustfmt-nightly` globally via cargo before building.
* Run `make` to build and install the library.  Optionally, take a look at the travis.yml file to see how to build (but not install) using just cargo.
* Run `make test-asm` to validate the instruction decoding or `make test` / `cargo test` to run all the tests.  One of the bindgen generated tests is known to fail.

## Notes

* `rasm2` currently does not look in the user's plugin path so you may have to symlink or copy the installed library into a different location.

### Building on OSX

`r2-c166` is known to not build on older versions of OSX.  This is due to an old version of clang being installed.  Similar to: <https://github.com/rustwasm/wasm-bindgen/issues/186>.  Newer versions of OSX require that you tell clang to allow undefined symbols in libraries via a `~/.cargo/config` stanza like so:

```
[target.x86_64-apple-darwin]
rustflags = [
  "-C", "link-arg=-undefined",
  "-C", "link-arg=dynamic_lookup"
]
```
Additionally if you install `radare2` via `brew` you'll need to edit build.rs to search for the `radare2` and `openssl` headers in the appropriate directory.  TODO: update the build script to take additional include search paths in via an environment variable.
