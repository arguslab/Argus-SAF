/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package parser.stmt.localclassdeclarationstmt;

public class LocalClassMulti {
    public static int main() {
        class Local {
            int l() {
                return 1;
            }
        }
        Local lo = new Local();
        class Else {
            int l() {
                return 3;
            }
        }
        Else e = new Else();
        return lo.l() + foo() + e.l();
    }

    public static int foo() {
        class Local {
            int l() {
                return 2;
            }
        }
        Local lo = new Local();
        return lo.l();
    }
}