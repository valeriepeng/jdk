/*
 * Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * @test
 * @bug 8351660
 * @summary Test that modulo by zero throws an exception at runtime in case of unsigned values.
 * @library /test/lib
 * @run main/othervm -Xbatch
 *                   -XX:CompileCommand=compileonly,compiler.integerArithmetic.TestUnsignedModByZero::testInt
 *                   -XX:CompileCommand=compileonly,compiler.integerArithmetic.TestUnsignedModByZero::testLong
 *                   compiler.integerArithmetic.TestUnsignedModByZero
 */

 package compiler.integerArithmetic;

 import jdk.test.lib.Asserts;


 public class TestUnsignedModByZero {

     public static Object testInt() {
        double x = 1.0;
        return Integer.remainderUnsigned(1, (int)(x % x));
    }

     public static Object testLong() {
        double x = 1.0;
        return Long.remainderUnsigned(1, (long)(x % x));
    }

     public static void main(String[] args) {
        for (int i = 0; i < 10_000; i++) {
             Asserts.assertThrows(ArithmeticException.class, TestUnsignedModByZero::testInt);
             Asserts.assertThrows(ArithmeticException.class, TestUnsignedModByZero::testLong);
        }
     }
 }