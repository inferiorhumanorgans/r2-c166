INST_DIR ?= ~/.config/radare2/plugins/
BIN_FILE ?= /dev/null
BUILD_MODE ?= debug
BUILD_DIR=target/${BUILD_MODE}
CARGO_FLAGS=

ifeq ($(BUILD_MODE),release)
  CARGO_FLAGS+=--release
endif

all: ffi
	@echo "Building ${BUILD_MODE}"
	@cargo build ${CARGO_FLAGS}
	@echo

# Need to find the proper directory for rasm2 plugins :(
# https://github.com/radare/radare2/issues/4495
	@echo "Installing to ${INST_DIR}"
	@cp -f ${BUILD_DIR}/libc166_asm.so ${BUILD_DIR}/libc166_analysis.so ${INST_DIR}/
	@echo

run: all
	@echo Running ${TEST_FILE}
	@radare2 -q -i ${TEST_FILE} ${BIN_FILE}
	@echo

interactive: all
	@RUST_BACKTRACE=1 radare2 -i interactive.r2 ${BIN_FILE}

ffi: src/ffi.rs

src/ffi.rs: ./bindings.h
	@echo "Generating FFI bindings with bindgen"
	@bindgen bindings.h --bitfield-enum=_RAnalOpType --bitfield-enum=_RAnalCond --blacklist-type=IPPORT_RESERVED -- -I/usr/include/libr -I/usr/local/include/libr > src/ffi.rs || rm -f src/ffi.rs
	@echo

test-asm:
	@cargo test c166 --no-fail-fast

test:
	@cargo test --no-fail-fast
