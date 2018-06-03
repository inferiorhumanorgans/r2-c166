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
fn op_f1() {
    test_disasm_op!([0xF1, 0x54], "movb rh2, rl2");
}

#[test]
fn op_e1() {
    test_disasm_op!([0xE1, 0x45], "movb rh2, #04h");
}

#[test]
fn op_e7() {
    test_disasm_op!([0xE7, 0x98, 0x24, 0x42], "movb PWMCON0, #24h");
}

#[test]
fn op_a9() {
    test_disasm_op!([0xA9, 0x54], "movb rh2, [r4]");
}

#[test]
fn op_99() {
    test_disasm_op!([0x99, 0x54], "movb rh2, [r4+]");
}

#[test]
fn op_b9() {
    test_disasm_op!([0xB9, 0x54], "movb [r4], rh2");
}

#[test]
fn op_89() {
    test_disasm_op!([0x89, 0x54], "movb [-r4], rh2");
}

#[test]
fn op_c9() {
    test_disasm_op!([0xC9, 0x54], "movb [r5], [r4]");
}

#[test]
fn op_d9() {
    test_disasm_op!([0xD9, 0x54], "movb [r5+], [r4]");
}

#[test]
fn op_e9() {
    test_disasm_op!([0xE9, 0x54], "movb [r5], [r4+]");
}

#[test]
fn op_f4() {
    test_disasm_op!([0xF4, 0x98, 0x24, 0x42], "movb rh4, [r8 + #4224h]");
}

#[test]
fn op_e4() {
    test_disasm_op!([0xE4, 0x98, 0x24, 0x42], "movb [r8 + #4224h], rh4");
}

#[test]
fn op_a4_1() {
    test_disasm_op!([0xA4, 0x08, 0x24, 0x42], "movb [r8], 4224h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn op_a4_2() {
    test_disasm_op!([0xA4, 0x98, 0x24, 0x42], "invalid");
}

#[test]
fn op_b4_1() {
    test_disasm_op!([0xB4, 0x08, 0x24, 0x42], "movb 4224h, [r8]");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn op_b4_2() {
    test_disasm_op!([0xB4, 0x98, 0x24, 0x42], "invalid");
}

#[test]
fn op_f3() {
    test_disasm_op!([0xF3, 0x98, 0x24, 0x42], "movb PWMCON0, 4224h");
}

#[test]
fn op_f7() {
    test_disasm_op!([0xF7, 0x98, 0x24, 0x42], "movb 4224h, PWMCON0");
}
