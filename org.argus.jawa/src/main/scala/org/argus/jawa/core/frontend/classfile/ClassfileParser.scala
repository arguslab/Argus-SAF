/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.frontend.classfile

import org.argus.jawa.core.{JawaType, Reporter}
import org.argus.jawa.core.frontend.MyClass
import org.argus.jawa.core.io.AbstractFile
import org.argus.jawa.core.util._
import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes


/** This object implements a class file parser.
 */
object ClassfileParser {
  def parse(file: AbstractFile, reporter: Reporter): IMap[JawaType, MyClass] = {
    val cr = new ClassReader(file.toByteArray)
    val mcv = new MyClassVisitor(Opcodes.ASM5)
    cr.accept(mcv, ClassReader.SKIP_CODE)
    mcv.getClasses
  }
}
