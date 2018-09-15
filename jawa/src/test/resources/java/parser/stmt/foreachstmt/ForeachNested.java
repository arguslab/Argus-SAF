/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package parser.stmt.foreachstmt;

public class ForeachNested {
    public static int main() {
        int[] nums = new int[]{1, 2, 3, 4};
        int x = 0;
        for(int num1: nums) {
            for(int num2: nums) {
                x += num1 + num2;
            }
        }
        return x;
    }
}