/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package parser.stmt.forstmt;

public class ForNested {
    public static int main() {
        int x = 0;
        for (int i = 1; i <= 5; i++) {   // outer loop iterates 5 times.
            for (int j = 1; j <= 10; j++) {  // for each iteration of outer loop,
                // inner loop iterates 10 times
                x = i * j;
            }
        }
        return x;
    }
}