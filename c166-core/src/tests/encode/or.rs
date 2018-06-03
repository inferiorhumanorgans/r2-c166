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

test_requires_encode!();

#[test]
fn op_70() {
    test_asm_op!("or r3, r8", [0x70, 0x38]);
}

#[test]
fn op_78_1() {
    test_asm_op!("or r8, [r2]", [0x78, (0x08 << 4) | (0b10 << 2) | 0x02]);
}

#[test]
fn op_78_2() {
    test_asm_op!("or r8, [r2+]", [0x78, (0x08 << 4) | (0b11 << 2) | 0x02]);
}

#[test]
fn op_78_3() {
    test_asm_op!("or r8, #02h", [0x78, (0x08 << 4) | (0b00 << 2) | 0x02]);
}

#[test]
fn op_76() {
    test_asm_op!("or r14, #5588h", [0x76, 0xFE, 0x88, 0x55]);
}

#[test]
fn op_72() {
    test_asm_op!("or ZEROS, 5588h", [0x72, 0x8E, 0x88, 0x55]);
}

#[test]
fn op_74() {
    test_asm_op!("or 5588h, ZEROS", [0x74, 0x8E, 0x88, 0x55]);
}
