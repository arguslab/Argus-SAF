/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package parser.expr.arraycreationexpr;

public class ArrayCreationComplex {
    public static int main() {
        int[][][][][] i = new int[1][2][3][4][5];
        int[][][][] j = new int[][][][]{{{{10, 11, 12, 13, 14}, {15, 16}}}};
        i[0] = j;
        return i[0][0][0][0][1];
    }
}