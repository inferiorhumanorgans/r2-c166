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
fn op_51() {
    test_disasm_op!([0x51, 0x08], "xorb rl0, rl4");
}

#[test]
fn op_59_1() {
    test_disasm_op!([0x59, (0x02 << 4) | (0b10 << 2) | 0x03], "xorb rl1, [r3]");
}

#[test]
fn op_59_2() {
    test_disasm_op!([0x59, (0x02 << 4) | (0b11 << 2) | 0x03], "xorb rl1, [r3+]");
}

#[test]
fn op_59_3() {
    test_disasm_op!([0x59, (0x02 << 4) | (0b00 << 2) | 0x03], "xorb rl1, #03h");
}

#[test]
fn op_57_1() {
    test_disasm_op!([0x57, 0xF8, 0x25, 0x42], "xorb rl4, #25h");
}

#[test]
fn op_57_2() {
    test_disasm_op!([0x57, 0xFF, 0x25, 0x42], "xorb rh7, #25h");
}

#[test]
fn op_53_1() {
    test_disasm_op!([0x53, 0xF8, 0x25, 0x42], "xorb rl4, 4225h");
}

#[test]
fn op_53_2() {
    test_disasm_op!([0x53, 0xFF, 0x25, 0x42], "xorb rh7, 4225h");
}

#[test]
fn op_55_1() {
    test_disasm_op!([0x55, 0xF2, 0x25, 0x42], "xorb 4225h, rl1");
}

#[test]
fn op_55_2() {
    test_disasm_op!([0x55, 0xF5, 0x25, 0x42], "xorb 4225h, rh2");
}
