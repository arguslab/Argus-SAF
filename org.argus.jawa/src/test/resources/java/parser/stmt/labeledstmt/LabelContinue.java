/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package parser.stmt.labeledstmt;

public class LabelContinue {
    public static int main() {
        int i = 0;
        label:
        for(;i < 10;) {
            i++;
            for(;i < 100;) {
                i++;
                if (i == 11) {
                    continue label;
                }
            }
        }
        return i;
    }
}