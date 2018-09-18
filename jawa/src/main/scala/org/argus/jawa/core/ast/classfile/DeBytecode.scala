/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.ast.classfile

import org.argus.jawa.core.ast.CompilationUnit
import org.objectweb.asm.{ClassReader, Opcodes}

/**
  * Translate Java bytecode to Jawa AST
  */
object DeBytecode {
  def process(classfile: JavaClassFile): CompilationUnit = {
    val cr = new ClassReader(classfile.file.toByteArray)
    val mcv = new ClassResolver(Opcodes.ASM5)
    cr.accept(mcv, ClassReader.SKIP_FRAMES)
    val cid = mcv.cid
    CompilationUnit(List(cid))(cid.pos)
  }
}

case class DeBytecodeException(msg: String) extends RuntimeException(msg)