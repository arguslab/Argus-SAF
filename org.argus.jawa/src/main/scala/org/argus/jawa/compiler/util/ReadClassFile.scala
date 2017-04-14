/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.util

import java.io.File
import java.io.PrintWriter
import java.io.FileInputStream

import org.apache.commons.brut.io.IOUtils
import org.argus.jawa.compiler.codegen.JavaByteCodeGenerator

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object ReadClassFile {
  
  def main(args: Array[String]): Unit = {
    val file: File = new File(args(0))
    read(file)
  }
  
  class CustomClassLoader extends ClassLoader {
    def loadClass(name: String, bytecodes: Array[Byte]): Class[_ <: Any] = {
      defineClass(name, bytecodes, 0, bytecodes.length)
    }
  }
  
  def read(file: File): Unit = {
    val bytecodes = IOUtils.toByteArray(new FileInputStream(file))
    val ccl: CustomClassLoader = new CustomClassLoader()
    val pw = new PrintWriter(System.out)
    JavaByteCodeGenerator.outputByteCodes(pw, bytecodes)
//    println("result: " + r)
  }
}
