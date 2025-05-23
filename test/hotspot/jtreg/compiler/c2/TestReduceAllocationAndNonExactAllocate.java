/*
 * Copyright (c) 2024, Oracle and/or its affiliates. All rights reserved.
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
 * @bug 8330247
 * @summary Check that Reduce Allocation Merges doesn't try to reduce non-exact allocations.
 * @library /test/lib /
 * @modules java.base/jdk.internal.misc
 * @requires vm.debug & vm.flagless & vm.compiler2.enabled & vm.opt.final.EliminateAllocations
 * @run main/othervm -XX:CompileCommand=compileonly,*TestReduceAllocationAndNonExactAllocate*::test
 *                   -XX:CompileCommand=compileonly,*::allocateInstance
 *                   -XX:CompileCommand=dontinline,*TestReduceAllocationAndNonExactAllocate*::*
 *                   -XX:+UnlockDiagnosticVMOptions
 *                   -XX:+TraceReduceAllocationMerges
 *                   -XX:-TieredCompilation
 *                   -Xbatch
 *                   -Xcomp
 *                   compiler.c2.TestReduceAllocationAndNonExactAllocate
 */

package compiler.c2;

import jdk.internal.misc.Unsafe;

public class TestReduceAllocationAndNonExactAllocate {
    private static final Unsafe UNSAFE = Unsafe.getUnsafe();

    public static void main(String[] args) {
        try {
            if (test(20, Integer.class) != 2032) {
                throw new RuntimeException("Expected the value to be 2032.");
            }
        }
        catch (InstantiationException e) {
            e.printStackTrace();
        }
    }

    public static int test(int val, Class<?> c) throws InstantiationException {
        Object p = null;

        if (val == 20) {
            p = UNSAFE.allocateInstance(c);
        }

        dummy();
        return p != null ? 2032 : 3242;
    }

    static int dummy() { return 42; }
}
