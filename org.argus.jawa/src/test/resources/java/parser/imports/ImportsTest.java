/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package parser.imports;

import parser.imports.pkg1.Ana;
import parser.imports.pkg2.*;

public class ImportsTest {
    public static int main() {
        Ana a = new Ana(); // Should able to get direct import
        Bob b = new Bob(); // Should able to get asterisk import
        int sum = a.i + b.i;
        return sum;
    }
}