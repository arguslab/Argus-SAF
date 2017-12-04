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

class NullResolver(
    api: Int,
    accessFlag: Int,
    signature: Signature,
    methods: MList[MethodDeclaration]) extends MethodVisitor(api) {

  val returnType: Type = new Type(signature.getReturnType)
  val methodSymbol: MethodDefSymbol = new MethodDefSymbol(signature.methodName)
  methodSymbol.signature = signature

  val annotations: IList[Annotation] = List(
    new Annotation("signature", SymbolValue(new SignatureSymbol(signature))(NoPosition)),
    new Annotation("AccessFlag", new TokenValue(AccessFlag.getAccessFlagString(accessFlag)))
  )

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
  private def push(): VariableInfo = {
    val vi = new VariableInfo(None)
    nullTypes(idx) = vi
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

  // -------------------------------------------------------------------------
  // Normal instructions
  // -------------------------------------------------------------------------
  import org.objectweb.asm.Opcodes._

  private var idx = 0

  override def visitInsn(opcode: Int): Unit = {
    opcode match {
      case ACONST_NULL =>
        push()
      case AALOAD =>
              val idx = pop
              val base = pop
              val typ = getVarType(base)
              val tempType = JawaType.addDimensions(typ, -1)
              val temp = push(tempType)
              val ie = new IndexingExpression(base, List(idx))
              stmt = Some(new AssignmentStatement(temp, ie, List(objectAnnotation)))
      case _ =>
    }
    //    insns += Insn(opcode)
    idx += 1
  }

  override def visitIntInsn(opcode: Int, operand: Int): Unit = {

    //    insns += IntInsn(opcode, operand)
    idx += 1
  }

  override def visitVarInsn(opcode: Int, v: Int): Unit = {
    //    insns += VarInsn(opcode, v)
    idx += 1
  }

  override def visitTypeInsn(opcode: Int, t: String): Unit = {
    //    insns += TypeInsn(opcode, t)
    idx += 1
  }


  override def visitFieldInsn(opcode: Int, owner: String, name: String, desc: String): Unit = {
    //    insns += FieldInsn(opcode, owner, name, desc)
    idx += 1
  }

  override def visitMethodInsn(opcode: Int, owner: String, name: String, desc: String, itf: Boolean): Unit = {
    //    insns += MethodInsn(opcode, owner, name, desc, itf)
    idx += 1
  }


  override def visitInvokeDynamicInsn(name: FileResourceUri, desc: FileResourceUri, bsm: Handle, bsmArgs: AnyRef*): Unit = {
    //    insns += InvokeDynamicInsn(name, desc, bsm, bsmArgs)
    idx += 1
  }

  override def visitJumpInsn(opcode: Int, label: Label): Unit = {
    //    insns += JumpInsn(opcode, label)
    idx += 1
  }

  // -------------------------------------------------------------------------
  // Special instructions
  // -------------------------------------------------------------------------

  override def visitLdcInsn(cst: Any): Unit = {
    //    insns += LdcInsn(cst)
    idx += 1
  }

  override def visitIincInsn(v: Int, increment: Int): Unit = {
    //    insns += IincInsn(v, increment)
    idx += 1
  }

  override def visitTableSwitchInsn(min: Int, max: Int, dflt: Label, labels: Label*): Unit = {
    //    insns += TableSwitchInsn(min, max, dflt, labels)
    idx += 1
  }

  override def visitLookupSwitchInsn(dflt: Label, keys: Array[Int], labels: Array[Label]): Unit = {
    //    insns += LookupSwitchInsn(dflt, keys, labels)
    idx += 1
  }

  override def visitMultiANewArrayInsn(desc: String, dims: Int): Unit = {
    //    insns += MultiANewArrayInsn(desc, dims)
    idx += 1
  }

}