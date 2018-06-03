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
fn op_f1() {
    test_asm_op!("movb rh2, rl2", [0xF1, 0x54]);
}

#[test]
fn op_e1() {
    test_asm_op!("movb rh2, #04h", [0xE1, 0x45]);
}

#[test]
fn op_e7() {
    test_asm_op!("movb PWMCON0, #24h", [0xE7, 0x98, 0x24, 0x42]);
}

#[test]
fn op_a9() {
    test_asm_op!("movb rh2, [r4]", [0xA9, 0x54]);
}

#[test]
fn op_99() {
    test_asm_op!("movb rh2, [r4+]", [0x99, 0x54]);
}

#[test]
fn op_b9() {
    test_asm_op!("movb [r4], rh2", [0xB9, 0x54]);
}

#[test]
fn op_89() {
    test_asm_op!("movb [-r4], rh2", [0x89, 0x54]);
}

#[test]
fn op_c9() {
    test_asm_op!("movb [r5], [r4]", [0xC9, 0x54]);
}

#[test]
fn op_d9() {
    test_asm_op!("movb [r5+], [r4]", [0xD9, 0x54]);
}

#[test]
fn op_e9() {
    test_asm_op!("movb [r5], [r4+]", [0xE9, 0x54]);
}

#[test]
fn op_f4() {
    test_asm_op!("movb rh4, [r8 + #4224h]", [0xF4, 0x98, 0x24, 0x42]);
}

#[test]
fn op_e4() {
    test_asm_op!("movb [r8 + #4224h], rh4", [0xE4, 0x98, 0x24, 0x42]);
}

#[test]
fn op_a4_1() {
    test_asm_op!("movb [r8], 4224h", [0xA4, 0x08, 0x24, 0x42]);
}

#[test]
fn op_b4_1() {
    test_asm_op!("movb 4224h, [r8]", [0xB4, 0x08, 0x24, 0x42]);
}

#[test]
fn op_f3() {
    test_asm_op!("movb PWMCON0, 4224h", [0xF3, 0x98, 0x24, 0x42]);
}

#[test]
fn op_f7() {
    test_asm_op!("movb 4224h, PWMCON0", [0xF7, 0x98, 0x24, 0x42]);
}
