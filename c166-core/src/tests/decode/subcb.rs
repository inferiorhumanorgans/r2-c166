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

test_requires_decode!();

#[test]
fn op_31() {
    test_disasm_op!([0x31, (0x03 << 4) | 0x06], "subcb rh1, rl3");
}

#[test]
fn op_39_1() {
    test_disasm_op!([0x39, (0x03 << 4) | (0b10 << 2) | 0x03], "subcb rh1, [r3]");
}

#[test]
fn op_39_2() {
    test_disasm_op!([0x39, (0x03 << 4) | (0b11 << 2) | 0x03], "subcb rh1, [r3+]");
}

#[test]
fn op_39_3() {
    test_disasm_op!([0x39, (0x03 << 4) | (0b00 << 2) | 0x05], "subcb rh1, #05h");
}

#[test]
fn op_37() {
    test_disasm_op!([0x37, 0xFC, 0xFF, 0xCC], "subcb rl6, #FFh");
}

#[test]
fn op_37_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x37, addr as u8, 0x25, 0x42]);
    }
}

#[test]
fn op_33() {
    test_disasm_op!([0x33, 0x0B, 0xFF, 0xCC], "subcb STKUN, CCFFh");
}

#[test]
fn op_33_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x33, addr as u8, 0x25, 0x42]);
    }
}

#[test]
fn op_35() {
    test_disasm_op!([0x35, 0xFC, 0xFF, 0xCC], "subcb CCFFh, rl6");
}
