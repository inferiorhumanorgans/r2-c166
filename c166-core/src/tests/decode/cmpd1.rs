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
fn op_a0() {
    test_disasm_op!([0xA0, 0x44], "cmpd1 r4, #04h");
}

#[test]
fn op_a6_1() {
    test_disasm_op!([0xA6, 0xF4, 0x12, 0x34], "cmpd1 r4, #3412h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn op_a6_2() {
    test_disasm_op!([0xA6, 0xC4, 0x12, 0x34], "invalid");
}

#[test]
fn op_a2_1() {
    test_disasm_op!([0xA2, 0xF4, 0x12, 0x34], "cmpd1 r4, 3412h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn op_a2_2() {
    test_disasm_op!([0xA2, 0xC4, 0x12, 0x34], "invalid");
}
