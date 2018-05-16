INST_DIR=~/.config/radare2/plugins/
TEST_FILE=test.r2
BIN_FILE=/dev/null
BUILD_DIR=target/debug

all: ffi
	@echo "Building"
	@cargo build
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

ffi: src/ffi.rs

src/ffi.rs: ./bindings.h
	@echo "Generating FFI bindings with bindgen"
	@bindgen bindings.h --bitfield-enum=_RAnalOpType --blacklist-type=IPPORT_RESERVED -- -I/usr/include/libr > src/ffi.rs
	@echo
