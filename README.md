# README

[![Build Status](https://travis-ci.com/inferiorhumanorgans/r2-c166.svg?branch=master)](https://travis-ci.com/inferiorhumanorgans/r2-c166)

Siemens C166 family (dis)assembly and analysis plugins for radare2.  This project is written in rust, and depends on the nightly
toolchain.

## Installation and Usage

* Install `rustfmt-nightly` and  `bindgen` globally via cargo before building.
* Run `make` to build and install the library.
* Run `make test-asm` to validate the instruction decoding.

## Notes

* `rasm2` currently does not look in the user's plugin path so you may have to symlink or copy the installed library into a different location.
* This is known to not work on older versions of OSX.  Probably due to something like: <https://github.com/rustwasm/wasm-bindgen/issues/186>
