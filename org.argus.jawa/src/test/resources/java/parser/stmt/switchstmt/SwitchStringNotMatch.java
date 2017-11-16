/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package parser.stmt.switchstmt;

public class SwitchStringNotMatch {
    public static int main() {
        int i = 1;
        String str = "2";
        switch (str) {
            case "1":
                i += 10;
                break;
            case "3":
                i += 1000;
                break;
        }
        return i;
    }
}