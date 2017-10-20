/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package java.parser;


import java.io.*;
import java.lang.annotation.Documented;
import java.util.Random;

@Documented
public class HelloWorld extends Serializable implements MyInterface {

    public java.lang.String[] a, b[], c;
    protected static Random r = new Random();

    HelloWorld() {
        a = new String[1];
        a[0] = 1;
    }

    public static void main(String[] args) {
        // Prints "Hello, World" to the terminal window.
        System.out.println("Hello, World");
    }

    class TestInner {}

}