/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package parser.expr.objectcreationexpr;

public class AnonymousClassScope {
    class C {
        public int i() {
            return 1;
        }
    }
    public static int main() {
        AnonymousClassScope m = new AnonymousClassScope();
        C c = m.new C() {
            public int i() {
                return 2;
            }
        };
        return c.i();
    }
}