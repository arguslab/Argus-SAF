/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package parser.stmt.whilestmt;

public class WhileNested {
    public static int main() {
        int i = 0;
        while (i <= 1000) {
            while (i <= 200) {
                int j = 1;
                i += j;
                while (j <= 100) {
                    j++;
                }
            }
            while (i <= 1000) {
                int j = 10;
                i += j;
            }
            i++;
        }
        return i;
    }
}