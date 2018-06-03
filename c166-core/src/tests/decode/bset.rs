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
fn op_0f() {
    test_disasm_op!([0x0F, 0xEA], "bset P8.0");
}

#[test]
fn op_1f() {
    test_disasm_op!([0x1F, 0xEA], "bset P8.1");
}

#[test]
fn op_2f() {
    test_disasm_op!([0x2F, 0xEA], "bset P8.2");
}

#[test]
fn op_3f() {
    test_disasm_op!([0x3F, 0xEA], "bset P8.3");
}

#[test]
fn op_4f() {
    test_disasm_op!([0x4F, 0xEA], "bset P8.4");
}

#[test]
fn op_5f() {
    test_disasm_op!([0x5F, 0xEA], "bset P8.5");
}

#[test]
fn op_6f() {
    test_disasm_op!([0x6F, 0xEA], "bset P8.6");
}

#[test]
fn op_7f() {
    test_disasm_op!([0x7F, 0xEA], "bset P8.7");
}
