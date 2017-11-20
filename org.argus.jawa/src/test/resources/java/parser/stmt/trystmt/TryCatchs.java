/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package parser.stmt.trystmt;

import java.io.IOException;

public class TryCatchs {
    public static int main() {
        int i = 0;
        try {
            throw new RuntimeException();
        } catch(IOException ie) {
            i += 2;
        } catch(ArithmeticException ae) {
            i += 3;
        } catch(RuntimeException e) {
            i += 4;
        }
        return i;
    }
}