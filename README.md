# README

[![Build Status](https://travis-ci.com/inferiorhumanorgans/r2-c166.svg?branch=master)](https://travis-ci.com/inferiorhumanorgans/r2-c166)

Siemens C166 family (dis)assembly and analysis plugins for radare2.  This project is written in rust, and depends on the nightly
toolchain.

## Installation and Usage

* If you don't have clang installed already, install it.  Version 5.0 or newer is required.
* Install `rustfmt-nightly` globally via `cargo` before building.
* Run (GNU) `make` to build and install the library.  Optionally, take a look at the travis.yml file to see how to build (but not install) using just cargo.
* Run `make test-asm` to validate the instruction decoding or `make test` / `cargo test` to run all the tests.  One of the bindgen generated tests is known to fail.

## Feature Status

<table width=85%>
  <thead>
    <tr>
      <th width=25%>Feature</th>
      <th>Status</th>
    </tr>
  </thead>

  <tbody>
    <tr>
      <th colspan=2>c166-analysis</th>
    </tr>
    <tr>
      <td>Resolve memory references</td>
      <td>Does not track DPP / extended ops</td>
    </tr>
    <tr>
      <td>Mark call/jump targets</td>
      <td>✔?</td>
    </tr>
    <tr>
      <td>Translate jump conditions</td>
      <td>✔</td>
    </tr>
    <tr>
      <td>Generate ESIL</td>
      <td>WIP</td>
    </tr>
    <tr>
      <td>Annotate SFR config / ops</td>
      <td>WIP</td>
    </tr>
  </tbody>

  <tbody>
    <tr>
      <th colspan=2>c166-asm</th>
    </tr>
    <tr>
      <td>Assembler</td>
      <td>WIP</td>
    </tr>
    <tr>
      <td>Disassembler</td>
      <td>All opcodes decoded<br>Extended reg/mem ops not tracked (SFR vs ESFR)</td>
    </tr>
    <tr>
      <td>Mnemonics</td>
      <td>✔</td>
    </tr>
  </tbody>

  <tbody>
    <tr>
      <th colspan=2>c166-bin</th>
    </tr>
    <tr>
      <td>Mark entry point</td>
      <td>✔</td>
    </tr>
    <tr>
      <td>Mark interrupt / trap vectors</td>
      <td>✔</td>
    </tr>
    <tr>
      <td>Mark interrupt / trap handlers/thunks</td>
      <td></td>
    </tr>
    <tr>
      <td>Mark main() function</td>
      <td></td>
    </tr>
    <tr>
      <td>Make generated segment definitions optional</td>
      <td></td>
    </tr>
  </tbody>

  <tbody>
</table>

## Notes

* `rasm2` currently does not look in the user's plugin path so you may have to symlink or copy the installed library into a different location.

### Building on FreeBSD

On FreeBSD `pkg install gmake llvm60` should be sufficient.

### Building on OSX

Older versions of OSX may not have a new enough version of LLVM per [rust-lang-nursery/bindgen#1006](https://github.com/rust-lang-nursery/rust-bindgen/issues/1006).  Download binaries from the [LLVM download page](http://releases.llvm.org/download.html) and set `LIBCLANG_PATH` appropriately.

OSX appears to require that you tell clang to allow undefined symbols in libraries via a `~/.cargo/config` stanza like so:

```
[target.x86_64-apple-darwin]
rustflags = [
  "-C", "link-arg=-undefined",
  "-C", "link-arg=dynamic_lookup"
]
```

Additionally if you install `radare2` via `brew` you'll need to edit `c166-core/build.rs` to search for the `radare2` and `openssl` headers in the appropriate directory.

TODO: update the build script to take additional include search paths in via an environment variable.
