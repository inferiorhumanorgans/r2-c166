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
fn op_41() {
    test_disasm_op!([0x41, 0x44], "cmpb rl2, rl2");
}

#[test]
fn op_49_1() {
    test_disasm_op!([0x49, (0x04 << 4) | (0b10 << 2) | 0x03], "cmpb rl2, [r3]");
}

#[test]
fn op_49_2() {
    test_disasm_op!([0x49, (0x04 << 4) | (0b11 << 2) | 0x03], "cmpb rl2, [r3+]");
}

#[test]
fn op_49_3() {
    test_disasm_op!([0x49, (0x04 << 4) | (0b00 << 2) | 0x04], "cmpb rl2, #04h");
}

#[test]
fn op_47() {
    test_disasm_op!([0x47, 0x03, 0x56, 0x78], "cmpb DPP3, #56h");
}

#[test]
fn op_43() {
    test_disasm_op!([0x43, 0x03, 0x56, 0x78], "cmpb DPP3, 7856h");
}

