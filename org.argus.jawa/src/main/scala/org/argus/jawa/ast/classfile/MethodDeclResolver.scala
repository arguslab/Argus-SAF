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
import org.argus.jawa.core._
import org.argus.jawa.core.io.NoPosition
import org.argus.jawa.core.util._
import org.objectweb.asm.{Handle, Label, MethodVisitor}

class MethodDeclResolver(
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

  val bytecodes: BytecodeInstructions = new BytecodeInstructions(signature, NoPosition)

  private def objectAnnotation = new Annotation("kind", new TokenValue("object"))

  // -------------------------------------------------------------------------
  // Label
  // -------------------------------------------------------------------------
  private var labelCount: Int = 0

  private val labels: MMap[Label, (String, MList[Annotation])] = mmapEmpty

  private def handleLabel(label: Label): (String, MList[Annotation]) = {
    labels.get(label) match {
      case Some(a) => a
      case None =>
        val l = s"Label$labelCount"
        val annos: MList[Annotation] = mlistEmpty
        labels(label) = ((l, annos))
        labelCount += 1
        (l, annos)
    }
  }

  private val labelIdxs: MMap[Label, Int] = mmapEmpty

  var labelIdx: Int = 0
  var currentLabel: Label = _
  override def visitLabel(label: Label): Unit = {
    currentLabel = label
//    insns += LabelInsn(label)
    labelIdxs(label) = labelIdx
    labelIdx += 1
  }

  override def visitLineNumber(line: Int, start: Label): Unit = {
    labels.get(start) match {
      case Some((_, annos)) =>
        annos += new Annotation("line", new TokenValue(s"$line"))
      case _ =>
    }
  }

  // -------------------------------------------------------------------------
  // Variable management
  // -------------------------------------------------------------------------

  private val params: MList[Parameter] = mlistEmpty

  private val parameterIdx: MMap[Int, (Boolean, JawaType)] = mmapEmpty
  private var num: Int = 0
  if(!AccessFlag.isStatic(accessFlag) && !AccessFlag.isInterface(accessFlag)) {
    parameterIdx(num) = ((true, signature.getClassType))
    num += 1
  }
  signature.getParameterTypes.foreach { typ =>
    parameterIdx(num) = ((false, typ))
    if(typ.isDWordPrimitive) {
      num += 2
    } else {
      num += 1
    }
  }

  case class VarScope(start: Label, end: Label, typ: JawaType, name: String) {
    val min: Int = labelIdxs.getOrElse(start, 0)
    val max: Int = labelIdxs.getOrElse(end, Integer.MAX_VALUE)
    def inScope(l: Label): Boolean = {
      val idx = labelIdxs.getOrElse(l, 0)
      min <= idx && idx < max
    }
  }

  private val localVariables: MMap[Int, MSet[VarScope]] = mmapEmpty

  /**
    * Visits a local variable declaration.
    *
    * @param name
    * the name of a local variable.
    * @param desc
    * the type descriptor of this local variable.
    * @param signature
    * the type signature of this local variable. May be
    * <tt>null</tt> if the local variable type does not use generic
    * types.
    * @param start
    * the first instruction corresponding to the scope of this local
    * variable (inclusive).
    * @param end
    * the last instruction corresponding to the scope of this local
    * variable (exclusive).
    * @param index
    * the local variable's index.
    * @throws IllegalArgumentException
    * if one of the labels has not already been visited by this
    * visitor (by the { @link #visitLabel visitLabel} method).
    */
  override def visitLocalVariable(
      name: String,
      desc: String,
      signature: String,
      start: Label,
      end: Label,
      index: Int): Unit = {
    parameterIdx.get(index) match {
      case Some((isThis, t)) =>
        val annos = if(isThis) List(new Annotation("kind", new TokenValue("this"))) else if(t.isObject) List(objectAnnotation) else ilistEmpty
        params += new Parameter(t, name, annos)
        localVariables.getOrElseUpdate(index, msetEmpty) += VarScope(start, end, t, name)
      case None =>
        val t = JavaKnowledge.formatSignatureToType(desc)
        localVariables.getOrElseUpdate(index, msetEmpty) += VarScope(start, end, t, name)
    }
  }

  // -------------------------------------------------------------------------
  // Normal instructions
  // -------------------------------------------------------------------------

  var loc: Int = 0

  override def visitInsn(opcode: Int): Unit = {
    bytecodes.addInsn(bytecodes.Insn(opcode))
  }

  override def visitIntInsn(opcode: Int, operand: Int): Unit = {
    bytecodes.addInsn(bytecodes.IntInsn(opcode, operand))
  }

  override def visitVarInsn(opcode: Int, v: Int): Unit = {
    bytecodes.addInsn(bytecodes.VarInsn(opcode, v))
  }

  override def visitTypeInsn(opcode: Int, t: String): Unit = {
    bytecodes.addInsn(bytecodes.TypeInsn(opcode, t))
  }


  override def visitFieldInsn(opcode: Int, owner: String, name: String, desc: String): Unit = {
    bytecodes.addInsn(bytecodes.FieldInsn(opcode, owner, name, desc))
  }

  override def visitMethodInsn(opcode: Int, owner: String, name: String, desc: String, itf: Boolean): Unit = {
    bytecodes.addInsn(bytecodes.MethodInsn(opcode, owner, name, desc, itf))
  }


  override def visitInvokeDynamicInsn(name: FileResourceUri, desc: FileResourceUri, bsm: Handle, bsmArgs: AnyRef*): Unit = {
    bytecodes.addInsn(bytecodes.InvokeDynamicInsn(name, desc, bsm, bsmArgs))
  }

  override def visitJumpInsn(opcode: Int, label: Label): Unit = {
    handleLabel(label)
    bytecodes.addInsn(bytecodes.JumpInsn(opcode, label))
  }

  // -------------------------------------------------------------------------
  // Special instructions
  // -------------------------------------------------------------------------

  override def visitLdcInsn(cst: Any): Unit = {
    bytecodes.addInsn(bytecodes.LdcInsn(cst))
  }

  override def visitIincInsn(v: Int, increment: Int): Unit = {
    bytecodes.addInsn(bytecodes.IincInsn(v, increment))
  }

  override def visitTableSwitchInsn(min: Int, max: Int, dflt: Label, labels: Label*): Unit = {
    labels.foreach(label => handleLabel(label))
    handleLabel(dflt)
    bytecodes.addInsn(bytecodes.TableSwitchInsn(min, max, dflt, labels))
  }

  override def visitLookupSwitchInsn(dflt: Label, keys: Array[Int], labels: Array[Label]): Unit = {
    labels.foreach(label => handleLabel(label))
    handleLabel(dflt)
    bytecodes.addInsn(bytecodes.LookupSwitchInsn(dflt, keys, labels))
  }

  override def visitMultiANewArrayInsn(desc: String, dims: Int): Unit = {
    bytecodes.addInsn(bytecodes.MultiANewArrayInsn(desc, dims))
  }

  // -------------------------------------------------------------------------
  // Exceptions table entries
  // -------------------------------------------------------------------------

  override def visitTryCatchBlock(start: Label, end: Label, handler: Label, t: String): Unit = {
    handleLabel(start)
    handleLabel(end)
    handleLabel(handler)
    bytecodes.addInsn(bytecodes.TryCatchBlock(start, end, handler, t))
  }

  override def visitEnd(): Unit = {
    val body: Body = UnresolvedBodyBytecode(bytecodes)(NoPosition)
    val md = MethodDeclaration(returnType, methodSymbol, params.toList, annotations, body)(NoPosition)
    methods += md
  }
}