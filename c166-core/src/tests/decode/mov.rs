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
fn op_f0() {
    test_disasm_op!([0xF0, 0x54], "mov r5, r4");
}

#[test]
fn op_e0() {
    test_disasm_op!([0xE0, 0x45], "mov r5, #04h");
}

#[test]
fn op_e6() {
    test_disasm_op!([0xE6, 0x98, 0x24, 0x42], "mov PWMCON0, #4224h");
}

#[test]
fn op_a8() {
    test_disasm_op!([0xA8, 0x54], "mov r5, [r4]");
}

#[test]
fn op_98() {
    test_disasm_op!([0x98, 0x54], "mov r5, [r4+]");
}

#[test]
fn op_b8() {
    test_disasm_op!([0xB8, 0x54], "mov [r4], r5");
}

#[test]
fn op_88() {
    test_disasm_op!([0x88, 0x54], "mov [-r4], r5");
}

#[test]
fn op_c8() {
    test_disasm_op!([0xC8, 0x54], "mov [r5], [r4]");
}

#[test]
fn op_d8() {
    test_disasm_op!([0xD8, 0x54], "mov [r5+], [r4]");
}

#[test]
fn op_e8() {
    test_disasm_op!([0xE8, 0x54], "mov [r5], [r4+]");
}

#[test]
fn op_d4() {
    test_disasm_op!([0xD4, 0x98, 0x24, 0x42], "mov r9, [r8 + #4224h]");
}

#[test]
fn op_c4() {
    test_disasm_op!([0xC4, 0x98, 0x24, 0x42], "mov [r8 + #4224h], r9");
}

#[test]
fn op_84_1() {
    test_disasm_op!([0x84, 0x08, 0x24, 0x42], "mov [r8], 4224h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn op_84_2() {
    test_disasm_op!([0x84, 0x98, 0x24, 0x42], "invalid");
}

#[test]
fn op_94_1() {
    test_disasm_op!([0x94, 0x08, 0x24, 0x42], "mov 4224h, [r8]");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn op_94_2() {
    test_disasm_op!([0x94, 0x98, 0x24, 0x42], "invalid");
}

#[test]
fn op_f2() {
    test_disasm_op!([0xF2, 0x98, 0x24, 0x42], "mov PWMCON0, 4224h");
}

#[test]
fn op_f6() {
    test_disasm_op!([0xF6, 0x98, 0x24, 0x42], "mov 4224h, PWMCON0");
}
