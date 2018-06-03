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
fn op_ea_1() {
    test_asm_op!("jmpa cc_UC, 0501h", [0xEA, 0x00, 0x01, 0x05]);
}

#[test]
fn op_ea_2() {
    test_asm_op!("jmpa cc_NN, 0501h", [0xEA, 0x70, 0x01, 0x05]);
}