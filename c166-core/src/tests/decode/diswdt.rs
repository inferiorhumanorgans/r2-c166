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
fn op_a5_1() {
    test_disasm_op!([0xA5, 0x5A, 0xA5, 0xA5], "diswdt");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn op_a5_2() {
    test_disasm_op!([0xA5, 0x5A, 0xB5, 0xA5], "invalid");
}
