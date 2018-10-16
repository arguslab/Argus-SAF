/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.ast.classfile

import org.argus.jawa.core.ast.MyClass
import org.argus.jawa.core.elements.{JavaKnowledge, JawaType}
import org.argus.jawa.core.io.{AbstractFile, DefaultSourceFile, Reporter}
import org.argus.jawa.core.ast.jawafile.JawaAstParser
import org.argus.jawa.core.util._
import org.objectweb.asm.{ClassReader, ClassVisitor, Opcodes}

class JavaClassFile(file: AbstractFile) extends DefaultSourceFile(file) {
  def getType: JawaType = {
    var typ: Option[JawaType] = None
    class ClassNameVisitor(api: Int) extends ClassVisitor(api) {
      private def getClassName(name: String): String = {
        name.replaceAll("/", ".")
      }

      override def visit(
          version: Int,
          access: Int,
          name: String,
          signature: String,
          superName: String,
          interfaces: scala.Array[String]): Unit = {
        typ = Some(JavaKnowledge.getTypeFromJawaName(getClassName(name)))
      }
    }
    val cr = new ClassReader(file.toByteArray)
    val mcv = new ClassNameVisitor(Opcodes.ASM5)
    cr.accept(mcv, ClassReader.SKIP_CODE)
    typ.getOrElse(throw new RuntimeException(s"Cannot find class name in $file, it's weird!"))
  }

  def parse(reporter: Reporter): IMap[JawaType, MyClass] = {
    val cu = DeBytecode.process(this)
    JawaAstParser.resolve(cu)
  }
}