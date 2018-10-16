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

import org.argus.jawa.core.ast._
import org.argus.jawa.core.elements.{AccessFlag, JavaKnowledge, JawaType, Signature}
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

  val lvr: LocalVarResolver = new LocalVarResolver(signature)

  val bytecodes: BytecodeInstructions = new BytecodeInstructions(signature, NoPosition, lvr)

  // -------------------------------------------------------------------------
  // Label
  // -------------------------------------------------------------------------
  private var labelCount: Int = 0
  val labels: MMap[Label, LabelInsn] = mmapEmpty

  private def handleLabel(label: Label): LabelInsn = {
    labels.get(label) match {
      case Some(li) =>
        li
      case None =>
        val l = s"Label$labelCount"
        val annos: MList[Annotation] = mlistEmpty
        val li = LabelInsn(l, annos, None)
        labels(label) = li
        labelCount += 1
        li
    }
  }

  override def visitLabel(label: Label): Unit = {
    val li = handleLabel(label)
    val loc = bytecodes.addInsn(li)
    lvr.labelIdxs(label) = loc
  }

  override def visitLineNumber(line: Int, start: Label): Unit = {
    labels.get(start) match {
      case Some(li) =>
        li.annotations += new Annotation("line", new TokenValue(s"$line"))
      case _ =>
    }
  }

  // -------------------------------------------------------------------------
  // Variable management
  // -------------------------------------------------------------------------

  private val params: MMap[Int, Parameter] = mmapEmpty

  private val parameterIdx: MMap[Int, (Boolean, JawaType)] = mmapEmpty
  private var num: Int = 0
  if(!AccessFlag.isStatic(accessFlag) && !AccessFlag.isInterface(accessFlag)) {
    parameterIdx(num) = (true, signature.getClassType)
    num += 1
  }
  signature.getParameterTypes.foreach { typ =>
    parameterIdx(num) = (false, typ)
    if(typ.isDWordPrimitive) {
      num += 2
    } else {
      num += 1
    }
  }

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
        val annos = if(isThis) List(new Annotation("kind", new TokenValue("this"))) else if(t.isObject) List(new Annotation("kind", new TokenValue("object"))) else ilistEmpty
        params(index) = new Parameter(t, name, annos)
        lvr.localVariables.getOrElseUpdate(index, mlistEmpty) += new lvr.VarScope(start, end, t, name)
      case None =>
        val t = JavaKnowledge.formatSignatureToType(desc)
        lvr.localVariables.getOrElseUpdate(index, mlistEmpty) += new lvr.VarScope(start, end, t, name)
    }
    parameterIdx.remove(index)
  }

  // -------------------------------------------------------------------------
  // Normal instructions
  // -------------------------------------------------------------------------

  var loc: Int = 0

  override def visitInsn(opcode: Int): Unit = {
    bytecodes.addInsn(Insn(opcode))
  }

  override def visitIntInsn(opcode: Int, operand: Int): Unit = {
    bytecodes.addInsn(IntInsn(opcode, operand))
  }

  override def visitVarInsn(opcode: Int, v: Int): Unit = {
    bytecodes.addInsn(VarInsn(opcode, v))
  }

  override def visitTypeInsn(opcode: Int, t: String): Unit = {
    bytecodes.addInsn(TypeInsn(opcode, t))
  }


  override def visitFieldInsn(opcode: Int, owner: String, name: String, desc: String): Unit = {
    bytecodes.addInsn(FieldInsn(opcode, owner, name, desc))
  }

  override def visitMethodInsn(opcode: Int, owner: String, name: String, desc: String, itf: Boolean): Unit = {
    bytecodes.addInsn(MethodInsn(opcode, owner, name, desc, itf))
  }


  override def visitInvokeDynamicInsn(name: FileResourceUri, desc: FileResourceUri, bsm: Handle, bsmArgs: AnyRef*): Unit = {
    bytecodes.addInsn(InvokeDynamicInsn(name, desc, bsm, bsmArgs))
  }

  override def visitJumpInsn(opcode: Int, label: Label): Unit = {
    val li = handleLabel(label)
    bytecodes.addInsn(JumpInsn(opcode, li.label))
  }

  // -------------------------------------------------------------------------
  // Special instructions
  // -------------------------------------------------------------------------

  override def visitLdcInsn(cst: Any): Unit = {
    bytecodes.addInsn(LdcInsn(cst))
  }

  override def visitIincInsn(v: Int, increment: Int): Unit = {
    bytecodes.addInsn(IincInsn(v, increment))
  }

  override def visitTableSwitchInsn(min: Int, max: Int, dflt: Label, labels: Label*): Unit = {
    val ls = labels.map{ label =>
      val li = handleLabel(label)
      li.label
    }
    val dt = handleLabel(dflt)
    bytecodes.addInsn(TableSwitchInsn(min, max, dt.label, ls))
  }

  override def visitLookupSwitchInsn(dflt: Label, keys: Array[Int], labels: Array[Label]): Unit = {
    val ls = labels.map{ label =>
      val li = handleLabel(label)
      li.label
    }
    val dt = handleLabel(dflt)
    bytecodes.addInsn(LookupSwitchInsn(dt.label, keys, ls))
  }

  override def visitMultiANewArrayInsn(desc: String, dims: Int): Unit = {
    bytecodes.addInsn(MultiANewArrayInsn(desc, dims))
  }

  // -------------------------------------------------------------------------
  // Exceptions table entries
  // -------------------------------------------------------------------------

  private def getClassName(name: String): String = {
    name.replaceAll("/", ".")
  }

  /**
    * Visits a try catch block.
    *
    * @param start
    * beginning of the exception handler's scope (inclusive).
    * @param end
    * end of the exception handler's scope (exclusive).
    * @param handler
    * beginning of the exception handler's code.
    * @param t
    * internal name of the type of exceptions handled by the
    * handler, or <tt>null</tt> to catch any exceptions (for
    * "finally" blocks).
    * @throws IllegalArgumentException
    * if one of the labels has already been visited by this visitor
    * (by the { @link #visitLabel visitLabel} method).
    */
  override def visitTryCatchBlock(start: Label, end: Label, handler: Label, t: String): Unit = {
    val typ: JawaType = Option(t) match {
      case Some(str) => JavaKnowledge.getTypeFromName(getClassName(str))
      case None => ExceptionCenter.THROWABLE
    }
    val from = handleLabel(start)
    val to = handleLabel(end)
    val target = handleLabel(handler)
    labels.get(handler) match {
      case Some(li) => li.typ = Some(typ)
      case None =>
    }
    bytecodes.catchClauses +=  new CatchClause(typ, from.label, to.label, target.label)
  }

  override def visitEnd(): Unit = {
    if(parameterIdx.nonEmpty) {
      parameterIdx.toList.sortBy{case (i, _) => i}.foreach { case (index, (isThis, t)) =>
        val name = if(isThis) "this" else s"v$index"
        val annos = if(isThis) List(new Annotation("kind", new TokenValue("this"))) else if(t.isObject) List(new Annotation("kind", new TokenValue("object"))) else ilistEmpty
        params(index) = new Parameter(t, name, annos)
        lvr.localVariables.getOrElseUpdate(index, mlistEmpty) += new lvr.VarScope(0, Integer.MAX_VALUE, t, name)
      }
    }
    val paramList = params.toList.sortBy{case (i, _) => i}.map { case (_, param) =>
      bytecodes.usedVars += param.name
      param
    }
    val body: Body = UnresolvedBodyBytecode(bytecodes)(NoPosition)
    val md = MethodDeclaration(returnType, methodSymbol, paramList, annotations, body)(NoPosition)
    methods += md
  }
}