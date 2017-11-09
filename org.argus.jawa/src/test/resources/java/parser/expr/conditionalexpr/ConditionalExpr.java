/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package parser.expr.conditionalexpr;

public class ConditionalExpr {
    public static int main() {
        boolean b = true;
        int i = b ? 1 : 0;
        int j = b ? i + 2 : i + 1;
        return j;
    }
}