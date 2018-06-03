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
fn op_dc() {
    test_disasm_op!([0xDC, (0b11 << 6) | (0x3 << 4) | 0x0F], "extpr r15, #4");
}

#[test]
fn op_d7_1() {
    test_disasm_op!([0xD7, (0b11 << 6) | (0x3 << 4) | 0x00, 0x20, 0x00], "extpr #0020h, #4");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn op_d7_2() {
    test_disasm_op!([0xD7, (0b11 << 6) | (0x3 << 4) | 0x05, 0x20, 0x00], "invalid");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn op_d7_3() {
    test_disasm_op!([0xD7, (0b11 << 6) | (0x3 << 4) | 0x05, 0x20, 0x40], "invalid");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn op_d7_4() {
    // The upper 6 bits of the last byte should be 0 per the ISM
    test_disasm_op!([0xD7, (0b11 << 6) | (0x3 << 4) | 0x00, 0x20, 0x04], "invalid");
}
