/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.ast.classfile

import org.argus.jawa.ast._
import org.argus.jawa.core.{AccessFlag, JavaKnowledge, JawaType, Signature}
import org.argus.jawa.core.io.NoPosition
import org.argus.jawa.core.util._
import org.objectweb.asm.{Handle, Label, MethodVisitor}

class NullResolver(bytecodes: BytecodeInstructions) {

  private def getClassName(name: String): String = {
    name.replaceAll("/", ".")
  }

  // -------------------------------------------------------------------------
  // Stack management
  // -------------------------------------------------------------------------

  private val nullTypes: MMap[Int, VariableInfo] = mmapEmpty

  class VariableInfo(kind: Option[Int]) {
    var typ: JawaType = JavaKnowledge.OBJECT
  }

  private var stackVars: IList[VariableInfo] = ilistEmpty

  // push null
  private def push(i: Int): VariableInfo = {
    val vi = new VariableInfo(None)
    nullTypes(i) = vi
    vi.typ = JavaKnowledge.OBJECT.toUnknown
    stackVars = vi :: stackVars
    vi
  }

  // resolve null
  private def pop(expectedType: Option[JawaType]): Unit = {
    if(stackVars.isEmpty) return
    val typ :: tail = stackVars
    stackVars = tail
    if(typ.typ.baseType.unknown) {
      expectedType match {
        case Some(e) =>
          typ.typ = e
        case None =>
      }
    }
    typ
  }

  private val labelStack: MMap[Label, IList[VariableInfo]] = mmapEmpty

  private def logStack(label: Label): Unit = labelStack(label) = stackVars

  import org.objectweb.asm.Opcodes._

  def resolve(): Unit = {
    val instructions = bytecodes.getInstructions
    instructions.zipWithIndex.foreach { case (instruction, i) =>
      instruction match {
        case bytecodes.Insn(op) =>
          op match {
            case ACONST_NULL =>
              push(i)
            case
          }
      }
    }
  }
}