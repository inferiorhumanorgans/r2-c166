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
fn op_40() {
    test_disasm_op!([0x40, 0x44], "cmp r4, r4");
}

#[test]
fn op_48_1() {
    test_disasm_op!([0x48, (0x04 << 4) | (0b10 << 2) | 0x03], "cmp r4, [r3]");
}

#[test]
fn op_48_2() {
    test_disasm_op!([0x48, (0x04 << 4) | (0b11 << 2) | 0x03], "cmp r4, [r3+]");
}

#[test]
fn op_48_3() {
    test_disasm_op!([0x48, (0x04 << 4) | (0b00 << 2) | 0x04], "cmp r4, #04h");
}

#[test]
fn op_46() {
    test_disasm_op!([0x46, 0x03, 0x56, 0x78], "cmp DPP3, #7856h");
}

#[test]
fn op_42() {
    test_disasm_op!([0x42, 0x03, 0x56, 0x78], "cmp DPP3, 7856h");
}

