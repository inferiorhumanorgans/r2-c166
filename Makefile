INST_DIR ?= ~/.config/radare2/plugins/
BIN_FILE ?= /dev/null
BUILD_MODE ?= debug
BUILD_DIR=target/${BUILD_MODE}
CARGO_FLAGS=

ifeq ($(BUILD_MODE),release)
  CARGO_FLAGS+=--release
endif

all:
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

test-asm:
	@cargo test c166 --no-fail-fast

test:
	@cargo test --all --no-fail-fast -- --skip r2::bindgen_test_layout_max_align_t
